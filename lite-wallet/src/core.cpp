#include "core.h"
#include <QCryptographicHash>
#include <QDateTime>
#include <QEventLoop>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QTimer>
#include <QUrl>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdexcept>

namespace evote {

static const QByteArray SPKI_PREFIX = QByteArray::fromHex("302a300506032b6570032100");

QByteArray sha256(const QByteArray &d) { return QCryptographicHash::hash(d, QCryptographicHash::Sha256); }
QString sha256Hex(const QByteArray &d) { return QString::fromLatin1(sha256(d).toHex()); }

QByteArray hmacSha256(const QByteArray &key, const QByteArray &msg) {
    unsigned char out[32]; unsigned int len = 0;
    HMAC(EVP_sha256(), key.constData(), key.size(), reinterpret_cast<const unsigned char *>(msg.constData()), msg.size(), out, &len);
    return QByteArray(reinterpret_cast<char *>(out), int(len));
}
QByteArray pbkdf2Sha256(const QByteArray &pass, const QByteArray &salt, int iter, int len) {
    QByteArray out(len, 0);
    PKCS5_PBKDF2_HMAC(pass.constData(), pass.size(), reinterpret_cast<const unsigned char *>(salt.constData()), salt.size(),
                      iter, EVP_sha256(), len, reinterpret_cast<unsigned char *>(out.data()));
    return out;
}
QByteArray randomBytes(int n) {
    QByteArray b(n, 0);
    if (RAND_bytes(reinterpret_cast<unsigned char *>(b.data()), n) != 1) throw std::runtime_error("random generator failed");
    return b;
}

QString pubIdFromRaw(const QByteArray &raw) {
    const QByteArray b64 = (SPKI_PREFIX + raw).toBase64();
    QByteArray pem = "-----BEGIN PUBLIC KEY-----\n";
    for (int i = 0; i < b64.size(); i += 64) pem += b64.mid(i, 64) + "\n";
    pem += "-----END PUBLIC KEY-----\n";
    return QString::fromLatin1(pem.toBase64());
}
// strict base64 (Qt 5.12 has no AbortOnBase64DecodingErrors): only the alphabet, padded to 4
static bool strictB64(const QByteArray &s) {
    static const QRegularExpression re("^[A-Za-z0-9+/]*={0,2}$");
    return !s.isEmpty() && s.size() % 4 == 0 && re.match(QString::fromLatin1(s)).hasMatch();
}
QByteArray rawFromPubId(const QString &id) {
    const QByteArray idb = id.trimmed().toLatin1();
    if (!strictB64(idb)) return {};
    const QByteArray pem = QByteArray::fromBase64(idb);
    if (pem.isEmpty()) return {};
    QString body = QString::fromLatin1(pem);
    body.remove(QRegularExpression("-----(BEGIN|END)[^-]*-----|\\s+"));
    if (!strictB64(body.toLatin1())) return {};
    const QByteArray der = QByteArray::fromBase64(body.toLatin1());
    if (der.size() != 44 || !der.startsWith(SPKI_PREFIX)) return {};
    return der.mid(12);
}
QString shortId(const QString &s, int n) { return s.size() > n * 2 + 1 ? s.left(n) + QString::fromUtf8("…") + s.right(n) : s; }

QString shortAddr(const QString &id) {
    const QByteArray raw = rawFromPubId(id);
    if (raw.isEmpty()) return shortId(id);
    const QString h = QString::fromLatin1(raw.toHex());
    return "ed:" + h.left(6) + QString::fromUtf8("…") + h.right(4);
}
Key keyFromSeed(const QByteArray &seed) {
    Key k;
    if (seed.size() != 32) return k;
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(seed.constData()), 32);
    if (!pk) return k;
    unsigned char pub[32]; size_t len = 32;
    if (EVP_PKEY_get_raw_public_key(pk, pub, &len) == 1 && len == 32) {
        k.seed = seed; k.pubRaw = QByteArray(reinterpret_cast<char *>(pub), 32); k.id = pubIdFromRaw(k.pubRaw);
    }
    EVP_PKEY_free(pk);
    return k;
}
Key generateKey() { return keyFromSeed(randomBytes(32)); }

QByteArray sign(const Key &k, const QByteArray &msg) {
    QByteArray sig;
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(k.seed.constData()), 32);
    if (!pk) return sig;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t len = 64; unsigned char out[64];
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pk) == 1 &&
        EVP_DigestSign(ctx, out, &len, reinterpret_cast<const unsigned char *>(msg.constData()), size_t(msg.size())) == 1)
        sig = QByteArray(reinterpret_cast<char *>(out), int(len));
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(pk);
    return sig;
}
bool verify(const QByteArray &pubRaw, const QByteArray &msg, const QByteArray &sig) {
    if (pubRaw.size() != 32 || sig.size() != 64) return false;
    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(pubRaw.constData()), 32);
    if (!pk) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pk) == 1 &&
              EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char *>(sig.constData()), size_t(sig.size()),
                               reinterpret_cast<const unsigned char *>(msg.constData()), size_t(msg.size())) == 1;
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(pk);
    return ok;
}

// ---------------------------------------------------------------- wallet file
// v3: keystream = HMAC(kE, "ks3" | nonce | be32(block)) per 32 bytes.
// v2 (legacy, decrypt only): 32 keystream bytes per 64-byte block, bytes 32-63 were never encrypted.
static QByteArray be32(quint32 v) { QByteArray b(4, 0); b[0] = char(v >> 24); b[1] = char(v >> 16); b[2] = char(v >> 8); b[3] = char(v); return b; }
static QByteArray stream(const QByteArray &kE, const QByteArray &nonce, const QByteArray &data, bool v3) {
    QByteArray out = data;
    const int step = v3 ? 32 : 64;
    for (int i = 0; i < data.size(); i += step) {
        const QByteArray ks = hmacSha256(kE, (v3 ? QByteArray("ks3") : QByteArray()) + nonce + be32(quint32(i / step)));
        for (int j = 0; j < 32 && i + j < data.size(); j++) out[i + j] = char(data[i + j] ^ ks[j]);
    }
    return out;
}
WalletInfo walletDecrypt(const QJsonObject &f, const QString &pass) {
    if (f.value("format").toString() != "evote-wallet") throw std::runtime_error("not an EVOTE wallet file");
    const bool v3 = f.value("version").toInt(2) == 3;
    const QJsonObject kdf = f.value("kdf").toObject();
    const QByteArray salt = QByteArray::fromBase64(kdf.value("salt").toString().toLatin1());
    const QByteArray nonce = QByteArray::fromBase64(f.value("nonce").toString().toLatin1());
    const QByteArray ct = QByteArray::fromBase64(f.value("ct").toString().toLatin1());
    const QByteArray tag = QByteArray::fromBase64(f.value("tag").toString().toLatin1());
    const int iter = kdf.value("iter").toInt(60000);
    if (salt.isEmpty() || nonce.isEmpty() || ct.isEmpty() || tag.size() != 32 || iter < 1000 || iter > 5000000) throw std::runtime_error("damaged wallet file");
    const QByteArray dk = pbkdf2Sha256(pass.toUtf8(), salt, iter, 64);
    const QByteArray kE = dk.left(32), kM = dk.mid(32);
    const QByteArray want = hmacSha256(kM, QByteArray(v3 ? "evote-wallet-v3" : "evote-wallet-v2") + salt + nonce + ct);
    if (CRYPTO_memcmp(want.constData(), tag.constData(), 32) != 0) throw std::runtime_error("wrong passphrase");
    const QJsonObject data = QJsonDocument::fromJson(stream(kE, nonce, ct, v3)).object();
    WalletInfo w;
    w.key = keyFromSeed(QByteArray::fromHex(data.value("seed").toString().toLatin1()));
    if (!w.key.valid()) throw std::runtime_error("wallet contents unreadable");
    if (w.key.id != f.value("pub").toString()) throw std::runtime_error("wallet public key mismatch");
    w.label = data.value("label").toString(f.value("label").toString());
    w.created = qint64(data.value("created").toDouble(f.value("created").toDouble()));
    w.version = v3 ? 3 : 2;
    return w;
}
QJsonObject walletEncrypt(const Key &k, const QString &pass, const QString &label, qint64 created) {
    if (!created) created = QDateTime::currentSecsSinceEpoch();
    const QByteArray salt = randomBytes(16), nonce = randomBytes(16);
    const int iter = 60000;
    const QByteArray dk = pbkdf2Sha256(pass.toUtf8(), salt, iter, 64);
    const QByteArray kE = dk.left(32), kM = dk.mid(32);
    // same key order as the website's JSON.stringify({ seed, pub, label, created })
    const QByteArray plain = QByteArray("{\"seed\":\"") + k.seed.toHex() + "\",\"pub\":" +
        QJsonDocument(QJsonArray{k.id}).toJson(QJsonDocument::Compact).mid(1).chopped(1) + ",\"label\":" +
        QJsonDocument(QJsonArray{label}).toJson(QJsonDocument::Compact).mid(1).chopped(1) + ",\"created\":" + QByteArray::number(created) + "}";
    const QByteArray ct = stream(kE, nonce, plain, true);
    const QByteArray tag = hmacSha256(kM, QByteArray("evote-wallet-v3") + salt + nonce + ct);
    QJsonObject kdf{{"alg", "pbkdf2-hmac-sha256"}, {"salt", QString::fromLatin1(salt.toBase64())}, {"iter", iter}};
    return QJsonObject{{"format", "evote-wallet"}, {"version", 3}, {"pub", k.id}, {"label", label}, {"created", double(created)},
                       {"kdf", kdf}, {"nonce", QString::fromLatin1(nonce.toBase64())}, {"ct", QString::fromLatin1(ct.toBase64())},
                       {"tag", QString::fromLatin1(tag.toBase64())}};
}

// ---------------------------------------------------------------- lines
QString Line::coin() const {
    if (type == "SIGNED_VOTE") return p.value(6);
    return p.value(5);
}
bool parseLine(const QString &rawIn, Line &out) {
    const QString raw = rawIn.trimmed();
    QStringList parts = raw.split('|');
    if (parts.size() < 6 || parts[1] != "1") return false;
    bool num = false; const qint64 ts = parts[3].toLongLong(&num);
    if (!num || parts[3].contains(QRegularExpression("[^0-9]"))) return false;
    out = Line();
    out.raw = raw; out.type = parts[0]; out.pub = parts[2]; out.ts = ts; out.nonce = parts[4];
    out.sig = QByteArray::fromBase64(parts.takeLast().toLatin1());
    out.p = parts;
    out.hash = sha256Hex(raw.toUtf8());
    out.sigOk = verify(rawFromPubId(out.pub), parts.join('|').toUtf8(), out.sig);
    return true;
}
QString makeLine(const Key &k, const QString &type, const QStringList &fields) {
    QStringList parts{type, "1", k.id, QString::number(QDateTime::currentSecsSinceEpoch()), QString::fromLatin1(randomBytes(16).toBase64())};
    parts += fields;
    const QString payload = parts.join('|');
    return payload + "|" + QString::fromLatin1(sign(k, payload.toUtf8()).toBase64());
}
QString makeTransfer(const Key &k, const QString &coin, const QString &to, qint64 amount, int hours) {
    return makeLine(k, "SIGNED_TRANSFER", {coin, to, QString::number(amount), QString::number(QDateTime::currentSecsSinceEpoch() + qint64(hours) * 3600)});
}
QString makeVote(const Key &k, const QString &coin, const QString &option) {
    return makeLine(k, "SIGNED_VOTE", {QString::fromLatin1(option.toUtf8().toBase64()), coin});
}

QJsonObject makeVoucher(const QString &kind, const QString &signer, const QString &recipient, const QStringList &prov, const QStringList &spends) {
    QJsonArray lines; for (const QString &l : prov) lines.append(l); for (const QString &l : spends) lines.append(l);
    QJsonObject v{{"format", "evote-voucher"}, {"version", 1}, {"kind", kind},
                  {"created", QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)}, {"signer", signer},
                  {"lines", lines}, {"spends", spends.size()}, {"note", "Not yet broadcast. Import on any replica to redeem."}};
    if (!recipient.isEmpty()) v.insert("recipient", recipient);
    return v;
}
bool readTransactions(const QString &textIn, QStringList &all, QStringList &spends, QString &err) {
    all.clear(); spends.clear();
    QString text = textIn.trimmed();
    const QRegularExpressionMatch m = QRegularExpression("#(rawtx|voucher)=(.+)$", QRegularExpression::DotMatchesEverythingOption).match(text);
    if (m.hasMatch()) text = QUrl::fromPercentEncoding(m.captured(2).toUtf8()).trimmed();
    if (text.startsWith('{')) {
        const QJsonObject j = QJsonDocument::fromJson(text.toUtf8()).object();
        if (j.value("format") == "evote-voucher") {
            for (const QJsonValue &v : j.value("lines").toArray()) all << v.toString();
            const int n = qBound(0, j.value("spends").toInt(), all.size());
            spends = all.mid(all.size() - n);
        } else if (j.value("format") == "evote-coins") {
            for (const QJsonValue &c : j.value("coins").toArray()) for (const QJsonValue &v : c.toObject().value("lines").toArray()) all << v.toString();
        } else { err = "not an EVOTE voucher or coins file"; return false; }
    } else {
        for (const QString &l : text.split(QRegularExpression("[\r\n]+"), QString::SkipEmptyParts)) all << l.trimmed();
    }
    if (spends.isEmpty())
        for (const QString &l : all) if (l.startsWith("SIGNED_TRANSFER|") || l.startsWith("SIGNED_VOTE|")) spends << l;
    if (all.isEmpty()) { err = "nothing to read"; return false; }
    return true;
}
QString rawtxLink(const QString &serverUrl, const QStringList &lines) {
    QString base = serverUrl; base.remove(QRegularExpression("[?#].*$"));
    return base + "#rawtx=" + QString::fromLatin1(QUrl::toPercentEncoding(lines.join('\n')));
}

// ---------------------------------------------------------------- API
bool Api::call(const QString &action, const QJsonObject &body, QJsonObject &out) {
    QNetworkAccessManager nam;
    QUrl url(base); { QString q = url.query(); url.setQuery((q.isEmpty() ? "" : q + "&") + "action=" + action); }
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) req.setRawHeader(it.key(), it.value());
    QNetworkReply *r = nam.post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    QEventLoop loop; QTimer timer; timer.setSingleShot(true);
    QObject::connect(r, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(timeoutMs); loop.exec();
    if (!r->isFinished()) { r->abort(); r->deleteLater(); lastError = "server did not answer in time"; return false; }
    const QByteArray data = r->readAll();
    const int code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QString netErr = r->error() != QNetworkReply::NoError ? r->errorString() : QString();
    r->deleteLater();
    out = QJsonDocument::fromJson(data).object();
    if (out.isEmpty()) { lastError = netErr.isEmpty() ? QString("unexpected reply (HTTP %1)").arg(code) : netErr; return false; }
    if (!out.value("ok").toBool()) { lastError = out.value("err").toString(QString("HTTP %1").arg(code)); return false; }
    lastError.clear();
    return true;
}

// ---------------------------------------------------------------- exact weight pick
QVector<int> pickByWeight(const QVector<qint64> &amounts, qint64 target, qint64 *below, qint64 *above) {
    if (below) *below = 0; if (above) *above = 0;
    qint64 total = 0; for (qint64 a : amounts) total += a;
    if (target < 1 || amounts.isEmpty()) return {};
    QMap<qint64, QVector<int>> groups; for (int i = 0; i < amounts.size(); i++) groups[amounts[i]].append(i);
    QVector<qint64> amts = groups.keys().toVector(); std::sort(amts.begin(), amts.end(), std::greater<qint64>());
    qint64 lim = qMin(total, target + amts[0]);
    if (qint64(amts.size()) * (lim + 1) > 4000000) {        // huge: largest-first greedy
        QVector<int> order(amounts.size()); for (int i = 0; i < order.size(); i++) order[i] = i;
        std::sort(order.begin(), order.end(), [&](int a, int b) { return amounts[a] > amounts[b]; });
        QVector<int> pick; qint64 sum = 0;
        for (int i : order) if (sum + amounts[i] <= target) { pick << i; sum += amounts[i]; }
        if (sum == target) return pick;
        if (below) *below = sum; return {};
    }
    QVector<char> reach(int(lim) + 1, 0); reach[0] = 1;
    QVector<QVector<int>> layers;
    for (qint64 a : amts) {
        const int cnt = groups[a].size(); QVector<char> nr = reach; QVector<int> u(int(lim) + 1, 0);
        for (qint64 s = a; s <= lim; s++) if (!reach[int(s)] && nr[int(s - a)] && u[int(s - a)] < cnt) { nr[int(s)] = 1; u[int(s)] = u[int(s - a)] + 1; }
        layers << u; reach = nr;
    }
    auto build = [&](qint64 s) { QVector<int> out; for (int k = amts.size() - 1; k >= 0; k--) { const int n = layers[k][int(s)]; out += groups[amts[k]].mid(0, n); s -= n * amts[k]; } return out; };
    if (target <= lim && reach[int(target)]) return build(target);
    qint64 lo = qMin(target, lim); while (lo > 0 && !reach[int(lo)]) lo--;
    qint64 hi = target + 1; while (hi <= lim && !reach[int(hi)]) hi++;
    if (below) *below = lo; if (above) *above = hi <= lim ? hi : 0;
    return {};
}

} // namespace evote
