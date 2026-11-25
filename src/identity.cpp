#include "identity.h"
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QSslCertificate>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

namespace evote {

static QByteArray readAll(const QString &f) { QFile x(f); return x.open(QIODevice::ReadOnly) ? x.readAll() : QByteArray(); }
static bool writeSecret(const QString &f, const QByteArray &data) {
    QFile x(f);
    if (!x.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    x.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return x.write(data) == data.size();
}
static QByteArray bioData(BIO *bio) { char *d = nullptr; long n = BIO_get_mem_data(bio, &d); return QByteArray(d, int(n)); }

bool identityExists(const QString &dir) { return QFileInfo::exists(dir + "/node.key"); }
bool identityEncrypted(const QString &dir) { return readAll(dir + "/node.key").contains("ENCRYPTED PRIVATE KEY"); }

static EVP_PKEY *pkeyFromSeed(const QByteArray &seed) {
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(seed.constData()), 32);
}
static QByteArray pubPem(EVP_PKEY *pk) {
    BIO *b = BIO_new(BIO_s_mem()); PEM_write_bio_PUBKEY(b, pk); const QByteArray out = bioData(b); BIO_free(b); return out;
}

bool encryptIdentity(const QString &dir, const Key &k, const QString &pass, QString &err) {
    if (pass.size() < 8) { err = "the node passphrase must be at least 8 characters"; return false; }
    EVP_PKEY *pk = pkeyFromSeed(k.seed);
    if (!pk) { err = "bad key"; return false; }
    BIO *b = BIO_new(BIO_s_mem());
    QByteArray pw = pass.toUtf8();
    const int rc = PEM_write_bio_PKCS8PrivateKey(b, pk, EVP_aes_256_cbc(), nullptr, 0, nullptr, pw.data());
    const QByteArray priv = bioData(b); BIO_free(b);
    const QByteArray pub = pubPem(pk); EVP_PKEY_free(pk);
    if (rc != 1 || priv.isEmpty()) { err = "could not encrypt the node key"; return false; }
    if (!writeSecret(dir + "/node.key.tmp", priv) || !writeSecret(dir + "/node.pub", pub)) { err = "could not write the key files"; return false; }
    QFile::remove(dir + "/node.key");
    if (!QFile::rename(dir + "/node.key.tmp", dir + "/node.key")) { err = "could not replace node.key"; return false; }
    return true;
}

IdentityResult loadOrCreateIdentity(const QString &dir, const QString &pass) {
    IdentityResult r;
    if (!identityExists(dir)) {
        r.key = generateKey();
        if (!encryptIdentity(dir, r.key, pass, r.err)) return r;
        r.ok = true; r.created = true;
        return r;
    }
    const QByteArray pem = readAll(dir + "/node.key");
    r.legacyUnencrypted = !pem.contains("ENCRYPTED PRIVATE KEY");
    BIO *b = BIO_new_mem_buf(pem.constData(), pem.size());
    QByteArray pw = pass.toUtf8();
    EVP_PKEY *pk = PEM_read_bio_PrivateKey(b, nullptr, nullptr, r.legacyUnencrypted ? nullptr : pw.data());
    BIO_free(b);
    if (!pk) { r.err = r.legacyUnencrypted ? "node.key is not a valid key" : "wrong node passphrase"; return r; }
    unsigned char seed[32]; size_t len = 32;
    const bool raw = EVP_PKEY_id(pk) == EVP_PKEY_ED25519 && EVP_PKEY_get_raw_private_key(pk, seed, &len) == 1 && len == 32;
    EVP_PKEY_free(pk);
    if (!raw) { r.err = "node.key is not an Ed25519 key"; return r; }
    r.key = keyFromSeed(QByteArray(reinterpret_cast<char *>(seed), 32));
    // node.pub must belong to this key (it is what other nodes have in their trusted_peers.txt)
    const QByteArray pubFile = readAll(dir + "/node.pub");
    if (!pubFile.isEmpty() && QString::fromLatin1(pubFile.toBase64()) != r.key.id) { r.err = "node.pub does not match node.key"; return r; }
    if (pubFile.isEmpty()) { EVP_PKEY *p2 = pkeyFromSeed(r.key.seed); writeSecret(dir + "/node.pub", pubPem(p2)); EVP_PKEY_free(p2); }
    r.ok = true;
    return r;
}

bool ensureTlsCert(const QString &dir, QString &err) {
    const QString crt = dir + "/server.crt", key = dir + "/server.key";
    if (QFileInfo::exists(crt) && QFileInfo::exists(key)) return true;
    EVP_PKEY *pk = nullptr;
    EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    const bool gen = kc && EVP_PKEY_keygen_init(kc) > 0 && EVP_PKEY_CTX_set_rsa_keygen_bits(kc, 2048) > 0 && EVP_PKEY_keygen(kc, &pk) > 0;
    EVP_PKEY_CTX_free(kc);
    if (!gen) { err = "could not generate the TLS key"; return false; }
    X509 *x = X509_new();
    X509_set_version(x, 2);
    const QByteArray sn = randomBytes(4);
    ASN1_INTEGER_set(X509_get_serialNumber(x), long(((quint32(quint8(sn[0])) << 24) | (quint8(sn[1]) << 16) | (quint8(sn[2]) << 8) | quint8(sn[3])) & 0x7fffffff));
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 10L * 365 * 86400);
    X509_set_pubkey(x, pk);
    X509_NAME *name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("EVOTE node"), -1, -1, 0);
    X509_set_issuer_name(x, name);
    const bool signedOk = X509_sign(x, pk, EVP_sha256()) > 0;
    BIO *bc = BIO_new(BIO_s_mem()), *bk = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bc, x);
    PEM_write_bio_PrivateKey(bk, pk, nullptr, nullptr, 0, nullptr, nullptr);
    const QByteArray c = bioData(bc), k = bioData(bk);
    BIO_free(bc); BIO_free(bk); X509_free(x); EVP_PKEY_free(pk);
    if (!signedOk || c.isEmpty() || k.isEmpty()) { err = "could not create the TLS certificate"; return false; }
    if (!writeSecret(key, k)) { err = "could not write server.key"; return false; }
    QFile f(crt); if (!f.open(QIODevice::WriteOnly)) { err = "could not write server.crt"; return false; }
    f.write(c);
    return true;
}

QString certFingerprintFile(const QString &certPath) {
    const QList<QSslCertificate> certs = QSslCertificate::fromPath(certPath, QSsl::Pem);
    if (certs.isEmpty()) return QString();
    return QString::fromLatin1(QCryptographicHash::hash(certs.first().toDer(), QCryptographicHash::Sha256).toHex());
}

} // namespace evote
