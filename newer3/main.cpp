// Secure decentralized PEX/DEX voting + currency prototype
// Qt 5.12 compatible
//
// Features:
// - TLS transport
// - certificate pinning
// - long-term Ed25519 node identity
// - signed HELLO authentication
// - signed token issuance
// - signed votes
// - signed transfers
// - nonce/timestamp replay protection
// - peer gossip
//
// Requires:
// - Qt 5.12
// - OpenSSL 1.1.1 or newer for Ed25519
// - Qt modules: core gui network sql widgets

/* still need todo
better issuance policy,
consensus/ordering for double-spend conflicts,
wallet separation from node identity,
key encryption/passphrase protection,
certificate rotation,
peer reputation,
Sybil resistance,
optional private voting commitments,
optional UTXO/balance model for divisible currency.
*/

#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>
#include <QPlainTextEdit>
#include <QMessageBox>
#include <QTcpServer>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslError>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QTimer>
#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QObject>
#include <QMap>
#include <QSet>
#include <QList>
#include <QPointer>
#include <QHostAddress>
#include <QProcess>
#include <QFileInfo>
#include <QFileDevice>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static const int PORT = 5555;

// ------------------------------------------------------------
// Utility helpers
// ------------------------------------------------------------

QString randomBase64(int byteCount) {
    QByteArray buffer(byteCount, 0);

    if (RAND_bytes(reinterpret_cast<unsigned char*>(buffer.data()), byteCount) != 1) {
        for (int i = 0; i < byteCount; ++i) {
            buffer[i] = static_cast<char>(QRandomGenerator::global()->bounded(256));
        }
    }

    return QString(buffer.toBase64());
}

QString hashToken(const QString &token) {
    return QString(
        QCryptographicHash::hash(token.toUtf8(), QCryptographicHash::Sha256).toHex()
    );
}

QString certificateFingerprint(const QSslCertificate &cert) {
    if (cert.isNull()) return QString();

    QByteArray der = cert.toDer();
    if (der.isEmpty()) return QString();

    QByteArray digest = QCryptographicHash::hash(der, QCryptographicHash::Sha256);
    return QString(digest.toHex());
}

// ------------------------------------------------------------
// Ed25519 node identity using OpenSSL
// ------------------------------------------------------------

class NodeIdentity {
public:
    NodeIdentity() = default;

    ~NodeIdentity() {
        freeKeys();
    }

    NodeIdentity(const NodeIdentity&) = delete;
    NodeIdentity& operator=(const NodeIdentity&) = delete;

    bool loadOrGenerate(const QString &privPath, const QString &pubPath) {
        if (QFileInfo::exists(privPath) && QFileInfo::exists(pubPath)) {
            QFile privFile(privPath);
            QFile pubFile(pubPath);

            if (privFile.open(QIODevice::ReadOnly) && pubFile.open(QIODevice::ReadOnly)) {
                QByteArray privPem = privFile.readAll();
                QByteArray pubPem = pubFile.readAll();

                if (loadPrivate(privPem) && loadPublic(pubPem)) {
                    m_privPem = privPem;
                    m_pubPem = pubPem;
                    return true;
                }
            }

            qWarning() << "Existing identity files invalid. Regenerating identity.";
        }

        if (!generate()) {
            return false;
        }

        QFile privFile(privPath);
        QFile pubFile(pubPath);

        if (!privFile.open(QIODevice::WriteOnly) || !pubFile.open(QIODevice::WriteOnly)) {
            qWarning() << "Could not save identity files.";
            return false;
        }

        privFile.write(m_privPem);
        pubFile.write(m_pubPem);

        privFile.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);

        return true;
    }

    bool ready() const {
        return privKey != nullptr;
    }

    QString publicKeyBase64() const {
        return QString(m_pubPem.toBase64());
    }

    QByteArray publicKeyPem() const {
        return m_pubPem;
    }

    QByteArray sign(const QByteArray &message) const {
        if (!privKey) return QByteArray();

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) return QByteArray();

        QByteArray signature;

        if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, privKey) == 1) {
            size_t sigLen = 0;

            if (EVP_DigestSign(ctx,
                               nullptr,
                               &sigLen,
                               reinterpret_cast<const unsigned char*>(message.constData()),
                               message.size()) == 1) {

                signature.resize(static_cast<int>(sigLen));

                if (EVP_DigestSign(ctx,
                                   reinterpret_cast<unsigned char*>(signature.data()),
                                   &sigLen,
                                   reinterpret_cast<const unsigned char*>(message.constData()),
                                   message.size()) == 1) {
                    signature.resize(static_cast<int>(sigLen));
                } else {
                    signature.clear();
                }
            }
        }

        EVP_MD_CTX_free(ctx);
        return signature;
    }

    static bool verify(const QByteArray &message,
                       const QByteArray &signature,
                       const QString &publicKeyBase64) {
        QByteArray pubPem = QByteArray::fromBase64(publicKeyBase64.toUtf8());
        if (pubPem.isEmpty()) return false;

        BIO *bio = BIO_new_mem_buf(pubPem.constData(), pubPem.size());
        if (!bio) return false;

        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey) return false;

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        bool ok = false;

        if (ctx) {
            if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
                int rc = EVP_DigestVerify(ctx,
                                          reinterpret_cast<const unsigned char*>(signature.constData()),
                                          signature.size(),
                                          reinterpret_cast<const unsigned char*>(message.constData()),
                                          message.size());

                ok = (rc == 1);
            }

            EVP_MD_CTX_free(ctx);
        }

        EVP_PKEY_free(pkey);
        return ok;
    }

private:
    EVP_PKEY *privKey = nullptr;
    EVP_PKEY *pubKey = nullptr;

    QByteArray m_privPem;
    QByteArray m_pubPem;

    void freeKeys() {
        if (privKey) {
            EVP_PKEY_free(privKey);
            privKey = nullptr;
        }

        if (pubKey) {
            EVP_PKEY_free(pubKey);
            pubKey = nullptr;
        }
    }

    bool generate() {
        freeKeys();

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (!ctx) {
            qWarning() << "OpenSSL does not support Ed25519.";
            return false;
        }

        bool ok = false;

        if (EVP_PKEY_keygen_init(ctx) > 0) {
            EVP_PKEY *pkey = nullptr;

            if (EVP_PKEY_keygen(ctx, &pkey) > 0) {
                m_privPem = pemPrivate(pkey);
                m_pubPem = pemPublic(pkey);

                if (!m_privPem.isEmpty() && !m_pubPem.isEmpty()) {
                    privKey = pkey;
                    loadPublic(m_pubPem);
                    ok = true;
                } else {
                    EVP_PKEY_free(pkey);
                }
            }
        }

        EVP_PKEY_CTX_free(ctx);
        return ok;
    }

    bool loadPrivate(const QByteArray &pem) {
        BIO *bio = BIO_new_mem_buf(pem.constData(), pem.size());
        if (!bio) return false;

        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey) return false;

        if (privKey) EVP_PKEY_free(privKey);

        privKey = pkey;
        m_privPem = pem;

        return true;
    }

    bool loadPublic(const QByteArray &pem) {
        BIO *bio = BIO_new_mem_buf(pem.constData(), pem.size());
        if (!bio) return false;

        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey) return false;

        if (pubKey) EVP_PKEY_free(pubKey);

        pubKey = pkey;
        m_pubPem = pem;

        return true;
    }

    QByteArray pemPrivate(EVP_PKEY *pkey) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio) return QByteArray();

        PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);

        char *data = nullptr;
        long len = BIO_get_mem_data(bio, &data);

        QByteArray out(data, static_cast<int>(len));

        BIO_free(bio);
        return out;
    }

    QByteArray pemPublic(EVP_PKEY *pkey) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio) return QByteArray();

        PEM_write_bio_PUBKEY(bio, pkey);

        char *data = nullptr;
        long len = BIO_get_mem_data(bio, &data);

        QByteArray out(data, static_cast<int>(len));

        BIO_free(bio);
        return out;
    }
};

// ------------------------------------------------------------
// Signed line verification helper
// ------------------------------------------------------------

bool verifySignedLine(const QString &line,
                      int minUnsignedParts,
                      QString &pubkey,
                      qint64 &ts,
                      QString &nonce,
                      QStringList &unsignedParts) {
    QStringList parts = line.split('|');

    if (parts.size() < minUnsignedParts + 1) {
        return false;
    }

    QString signatureBase64 = parts.takeLast();
    QByteArray signature = QByteArray::fromBase64(signatureBase64.toUtf8());

    QString payload = parts.join("|");

    if (parts.size() < 5) {
        return false;
    }

    pubkey = parts.value(2);

    bool ok = false;
    ts = parts.value(3).toLongLong(&ok);
    if (!ok) return false;

    nonce = parts.value(4);
    unsignedParts = parts;

    return NodeIdentity::verify(payload.toUtf8(), signature, pubkey);
}

// ------------------------------------------------------------
// Qt 5.12 SSL server helper
// ------------------------------------------------------------

class SslServer : public QTcpServer {
    Q_OBJECT

public:
    explicit SslServer(QObject *parent = nullptr)
        : QTcpServer(parent) {
    }

    void setSslConfiguration(const QSslConfiguration &config) {
        m_config = config;
    }

signals:
    void newSslSocket(QSslSocket *socket);

protected:
    void incomingConnection(qintptr socketDescriptor) override {
        QSslSocket *socket = new QSslSocket(this);

        if (socket->setSocketDescriptor(socketDescriptor)) {
            socket->setSslConfiguration(m_config);
            socket->setPeerVerifyMode(QSslSocket::VerifyNone); // manual pinning later

            emit newSslSocket(socket);
        } else {
            socket->deleteLater();
        }
    }

private:
    QSslConfiguration m_config;
};

// ------------------------------------------------------------
// Peer node
// ------------------------------------------------------------

class PeerNode : public QObject {
    Q_OBJECT

public:
    PeerNode(QObject *parent = nullptr)
        : QObject(parent),
          sslReady(false),
          maxPeers(8) {

        setupDatabase();

        if (!identity.loadOrGenerate("node.key", "node.pub")) {
            qWarning() << "Failed to load/generate node identity.";
        }

        loadTrustedPeers();

        // Always trust our own node key.
        if (identity.ready()) {
            trustedNodeKeys.insert(identity.publicKeyBase64());
        }

        server = new SslServer(this);

        sslReady = setupSslConfiguration();

        if (sslReady) {
            server->setSslConfiguration(sslConfig);

            if (!server->listen(QHostAddress::Any, PORT)) {
                qWarning() << "TLS server failed to listen on port" << PORT;
            } else {
                qDebug() << "TLS server listening on port" << PORT;
            }
        } else {
            qWarning() << "TLS setup failed. OpenSSL may be missing or server.crt/server.key could not be loaded.";
        }

        connect(server, &SslServer::newSslSocket,
                this, &PeerNode::handleServerSocket);

        gossipTimer = new QTimer(this);
        connect(gossipTimer, &QTimer::timeout,
                this, &PeerNode::performGossip);
        gossipTimer->start(60000);

        loadPeersFromFile();
    }

    bool sslIsReady() const {
        return sslReady;
    }

    QString localPublicKeyBase64() const {
        return identity.publicKeyBase64();
    }

    QString trustLine(const QString &advertisedAddress) const {
        if (!identity.ready()) {
            return "ERROR: node identity not ready";
        }

        if (ownCertificate.isNull()) {
            return "ERROR: TLS certificate not ready";
        }

        return QString("%1|%2|%3")
            .arg(advertisedAddress)
            .arg(certificateFingerprint(ownCertificate))
            .arg(identity.publicKeyBase64());
    }

    void setupDatabase() {
        QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
        db.setDatabaseName(QCoreApplication::applicationDirPath() + "/secure_evote.db");

        if (!db.open()) {
            qWarning() << "Could not open SQLite database.";
            return;
        }

        QSqlQuery query;

        query.exec(
            "CREATE TABLE IF NOT EXISTS tokens ("
            "token_hash TEXT PRIMARY KEY,"
            "owner_pub TEXT NOT NULL,"
            "amount INTEGER NOT NULL DEFAULT 1,"
            "spent INTEGER NOT NULL DEFAULT 0,"
            "updated INTEGER NOT NULL DEFAULT 0"
            ");"
        );

        query.exec(
            "CREATE TABLE IF NOT EXISTS votes ("
            "token_hash TEXT PRIMARY KEY,"
            "candidate TEXT,"
            "voter_pub TEXT,"
            "ts INTEGER,"
            "nonce TEXT"
            ");"
        );

        query.exec(
            "CREATE TABLE IF NOT EXISTS used_nonces ("
            "pubkey TEXT NOT NULL,"
            "nonce TEXT NOT NULL,"
            "ts INTEGER NOT NULL,"
            "PRIMARY KEY (pubkey, nonce)"
            ");"
        );

        query.exec(
            "CREATE TABLE IF NOT EXISTS signed_messages ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "type TEXT,"
            "ts INTEGER,"
            "nonce TEXT,"
            "pubkey TEXT,"
            "line TEXT UNIQUE"
            ");"
        );
    }

    bool connectToPeerString(const QString &hostPort) {
        QString clean = hostPort.trimmed();
        QStringList parts = clean.split(':');

        if (parts.size() != 2) {
            return false;
        }

        bool ok = false;
        int port = parts[1].toInt(&ok);

        if (!ok || port <= 0) {
            return false;
        }

        return connectToPeer(parts[0], port);
    }

    bool connectToPeer(const QString &host, int port = PORT) {
        QString cleanHost = host.trimmed();

        if (cleanHost.isEmpty()) return false;

        if (!sslReady) {
            qWarning() << "SSL is not ready.";
            return false;
        }

        if (!identity.ready()) {
            qWarning() << "Node identity is not ready.";
            return false;
        }

        if (peers.size() >= maxPeers) return false;

        if ((cleanHost == "127.0.0.1" || cleanHost.toLower() == "localhost") && port == PORT) {
            return false;
        }

        QString address = QString("%1:%2").arg(cleanHost).arg(port);

        if (connectedPeers.contains(address) || pendingPeers.contains(address)) {
            return false;
        }

        if (!trustedPeers.contains(address)) {
            qWarning() << "No trusted certificate pin for" << address;
            qWarning() << "Add it to trusted_peers.txt first.";
            return false;
        }

        QSslSocket *socket = new QSslSocket(this);

        socket->setSslConfiguration(sslConfig);
        socket->setProtocol(QSsl::TlsV1_2OrLater);
        socket->setPeerVerifyMode(QSslSocket::VerifyNone);

        socket->setProperty("peerAddress", address);
        socket->setProperty("expectedPub", trustedPeers.value(address).second);
        socket->setProperty("authed", false);

        pendingPeers.insert(address);

        connect(socket, QOverload<const QList<QSslError>&>::of(&QSslSocket::sslErrors),
                this, [=](const QList<QSslError> &errors) {
            Q_UNUSED(errors);
            socket->ignoreSslErrors();
        });

        connect(socket, &QSslSocket::encrypted, this, [=]() {
            handleClientEncrypted(socket, address);
        });

        connect(socket, &QSslSocket::readyRead, this, [=]() {
            if (socket->isEncrypted()) {
                handleData(socket);
            }
        });

        connect(socket, &QSslSocket::disconnected, this, [=]() {
            removeSocket(socket, address);
            socket->deleteLater();
        });

        QPointer<QSslSocket> guard = socket;

        QTimer::singleShot(10000, this, [=]() {
            if (guard.isNull()) return;

            if (!guard->property("authed").toBool()) {
                pendingPeers.remove(address);
                guard->abort();
                guard->deleteLater();
            }
        });

        socket->connectToHostEncrypted(cleanHost, port);
        return true;
    }

    void generateTokens(int count) {
        if (!identity.ready()) {
            qWarning() << "Identity not ready.";
            return;
        }

        QString owner = identity.publicKeyBase64();

        for (int i = 0; i < count; ++i) {
            QString randomSecret = randomBase64(32);
            QString tokenHash = hashToken(randomSecret);

            QString line = makeSignedLine("SIGNED_ISSUE", {
                tokenHash,
                owner,
                "1"
            });

            if (line.isEmpty()) continue;

            writeAuthenticated(line);
            handleSignedIssue(line);
        }
    }

    QStringList localTokens() {
        QStringList list;

        if (!identity.ready()) return list;

        QSqlQuery q;
        q.prepare(
            "SELECT token_hash FROM tokens "
            "WHERE owner_pub = ? AND spent = 0 "
            "ORDER BY updated DESC;"
        );
        q.addBindValue(identity.publicKeyBase64());

        if (q.exec()) {
            while (q.next()) {
                list << q.value(0).toString();
            }
        }

        return list;
    }

    bool createSignedVote(const QString &candidate, const QString &tokenHash) {
        if (!identity.ready()) return false;

        QString cleanCandidate = candidate.trimmed();
        QString cleanToken = tokenHash.trimmed();

        if (cleanCandidate.isEmpty() || cleanToken.isEmpty()) return false;

        QString owner;
        int spent = 0;
        int amount = 0;

        if (!getTokenInfo(cleanToken, owner, spent, amount)) {
            return false;
        }

        if (owner != identity.publicKeyBase64()) return false;
        if (spent != 0) return false;

        QString candidateB64 = QString(cleanCandidate.toUtf8().toBase64());

        QString line = makeSignedLine("SIGNED_VOTE", {
            candidateB64,
            cleanToken
        });

        if (line.isEmpty()) return false;

        writeAuthenticated(line);
        return handleSignedVote(line);
    }

    bool createSignedTransfer(const QString &tokenHash,
                              const QString &receiverPubkey,
                              int amount) {
        if (!identity.ready()) return false;

        QString cleanToken = tokenHash.trimmed();
        QString cleanReceiver = receiverPubkey.trimmed();

        if (cleanToken.isEmpty() || cleanReceiver.isEmpty()) return false;
        if (amount <= 0) return false;

        QString owner;
        int spent = 0;
        int dbAmount = 0;

        if (!getTokenInfo(cleanToken, owner, spent, dbAmount)) {
            return false;
        }

        if (owner != identity.publicKeyBase64()) return false;
        if (spent != 0) return false;
        if (dbAmount != amount) return false;

        qint64 expiry = QDateTime::currentSecsSinceEpoch() + 3600;

        QString line = makeSignedLine("SIGNED_TRANSFER", {
            cleanToken,
            cleanReceiver,
            QString::number(amount),
            QString::number(expiry)
        });

        if (line.isEmpty()) return false;

        writeAuthenticated(line);
        return handleSignedTransfer(line);
    }

private:
    SslServer *server = nullptr;
    QSslConfiguration sslConfig;
    QSslCertificate ownCertificate;
    bool sslReady;
    int maxPeers;

    NodeIdentity identity;

    QMap<QString, QPair<QString, QString>> trustedPeers; // address -> cert sha256, node pubkey
    QSet<QString> trustedNodeKeys;

    QList<QSslSocket *> peers;
    QSet<QString> connectedPeers;
    QSet<QString> pendingPeers;

    QTimer *gossipTimer = nullptr;

    // ------------------------------------------------------------
    // SSL setup
    // ------------------------------------------------------------

    bool generateSelfSignedCert(const QString &certPath, const QString &keyPath) {
        QString openssl = "openssl";

        if (QFileInfo::exists("/usr/bin/openssl")) {
            openssl = "/usr/bin/openssl";
        } else if (QFileInfo::exists("/opt/homebrew/bin/openssl")) {
            openssl = "/opt/homebrew/bin/openssl";
        }

        QStringList args;
        args << "req"
             << "-x509"
             << "-newkey"
             << "rsa:2048"
             << "-keyout" << keyPath
             << "-out" << certPath
             << "-days" << "365"
             << "-nodes"
             << "-subj" << "/CN=EVOTE";

        QProcess proc;
        proc.start(openssl, args);

        if (!proc.waitForStarted(5000)) return false;
        if (!proc.waitForFinished(30000)) return false;

        return proc.exitCode() == 0;
    }

    bool setupSslConfiguration() {
        if (!QSslSocket::supportsSsl()) {
            qWarning() << "OpenSSL / SSL support is not available.";
            return false;
        }

        QString appDir = QCoreApplication::applicationDirPath();
        QString certPath = appDir + "/server.crt";
        QString keyPath = appDir + "/server.key";

        if (!QFileInfo::exists(certPath) || !QFileInfo::exists(keyPath)) {
            generateSelfSignedCert(certPath, keyPath);
        }

        QFile certFile(certPath);
        QFile keyFile(keyPath);

        if (!certFile.open(QIODevice::ReadOnly) || !keyFile.open(QIODevice::ReadOnly)) {
            qWarning() << "Could not open certificate/key files:" << certPath << keyPath;
            return false;
        }

        QList<QSslCertificate> certs = QSslCertificate::fromDevice(&certFile, QSsl::Pem);

        if (certs.isEmpty()) {
            qWarning() << "No valid SSL certificate found.";
            return false;
        }

        ownCertificate = certs.first();

        QSslKey key(&keyFile, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);

        if (key.isNull()) {
            keyFile.reset();
            key = QSslKey(&keyFile, QSsl::Opaque, QSsl::Pem, QSsl::PrivateKey);
        }

        if (key.isNull()) {
            qWarning() << "Could not load private key.";
            return false;
        }

        QSslConfiguration config = QSslConfiguration::defaultConfiguration();
        config.setProtocol(QSsl::TlsV1_2OrLater);
        config.setLocalCertificate(ownCertificate);
        config.setPrivateKey(key);

        // We do manual certificate pinning after handshake.
        config.setPeerVerifyMode(QSslSocket::VerifyNone);

        sslConfig = config;
        QSslConfiguration::setDefaultConfiguration(config);

        return true;
    }

    // ------------------------------------------------------------
    // Trust / pinning
    // ------------------------------------------------------------

    void loadTrustedPeers() {
        trustedPeers.clear();
        trustedNodeKeys.clear();

        QFile file("trusted_peers.txt");

        if (!file.open(QIODevice::ReadOnly)) {
            qDebug() << "No trusted_peers.txt found.";
            return;
        }

        QTextStream in(&file);

        while (!in.atEnd()) {
            QString line = in.readLine().trimmed();

            if (line.isEmpty() || line.startsWith("#")) continue;

            QStringList parts = line.split('|');

            if (parts.size() < 3) continue;

            QString address = parts[0].trimmed();
            QString certSha256 = parts[1].trimmed().toLower();
            QString nodePub = parts[2].trimmed();

            trustedPeers.insert(address, qMakePair(certSha256, nodePub));
            trustedNodeKeys.insert(nodePub);
        }

        qDebug() << "Loaded trusted peers:" << trustedPeers.size();
    }

    bool isTrustedNode(const QString &pubkey) const {
        return trustedNodeKeys.contains(pubkey);
    }

    bool verifyTlsPin(QSslSocket *socket, const QString &address) {
        if (!trustedPeers.contains(address)) {
            qWarning() << "No trusted certificate pin for" << address;
            return false;
        }

        QSslCertificate cert = socket->peerCertificate();

        if (cert.isNull()) {
            qWarning() << "Peer certificate is null for" << address;
            return false;
        }

        QString expected = trustedPeers.value(address).first.toLower();
        QString actual = certificateFingerprint(cert).toLower();

        if (expected != actual) {
            qWarning() << "TLS certificate pin mismatch for" << address;
            qWarning() << "Expected:" << expected;
            qWarning() << "Actual:  " << actual;
            return false;
        }

        return true;
    }

    bool findTrustedPubByCert(const QString &certFingerprint, QString &pubkey) const {
        QString fp = certFingerprint.toLower();

        for (auto it = trustedPeers.constBegin(); it != trustedPeers.constEnd(); ++it) {
            if (it.value().first.toLower() == fp) {
                pubkey = it.value().second;
                return true;
            }
        }

        return false;
    }

    // ------------------------------------------------------------
    // Signed message helpers
    // ------------------------------------------------------------

    QString makeSignedLine(const QString &messageType, const QStringList &fields) {
        if (!identity.ready()) return QString();

        QString ts = QString::number(QDateTime::currentSecsSinceEpoch());
        QString nonce = randomBase64(16);

        QStringList parts;
        parts << messageType;
        parts << "1";
        parts << identity.publicKeyBase64();
        parts << ts;
        parts << nonce;
        parts << fields;

        QString payload = parts.join("|");
        QByteArray signature = identity.sign(payload.toUtf8());

        if (signature.isEmpty()) return QString();

        return payload + "|" + QString(signature.toBase64());
    }

    bool checkAndStoreNonce(const QString &pubkey,
                             const QString &nonce,
                             qint64 ts,
                             bool enforceFreshness) {
        qint64 now = QDateTime::currentSecsSinceEpoch();

        // Reject far-future timestamps.
        if (ts > now + 3600) {
            return false;
        }

        // For HELLO, require fresh timestamps.
        // For ledger messages, allow older signed history for syncing.
        if (enforceFreshness && qAbs(now - ts) > 120) {
            return false;
        }

        QSqlQuery check;
        check.prepare("SELECT 1 FROM used_nonces WHERE pubkey = ? AND nonce = ?;");
        check.addBindValue(pubkey);
        check.addBindValue(nonce);

        if (check.exec() && check.next()) {
            return false;
        }

        QSqlQuery insert;
        insert.prepare("INSERT INTO used_nonces (pubkey, nonce, ts) VALUES (?, ?, ?);");
        insert.addBindValue(pubkey);
        insert.addBindValue(nonce);
        insert.addBindValue(ts);

        return insert.exec();
    }

    bool storeSignedMessage(const QString &type,
                            const QString &pubkey,
                            qint64 ts,
                            const QString &nonce,
                            const QString &line) {
        QSqlQuery q;
        q.prepare(
            "INSERT OR IGNORE INTO signed_messages (type, ts, nonce, pubkey, line) "
            "VALUES (?, ?, ?, ?, ?);"
        );

        q.addBindValue(type);
        q.addBindValue(ts);
        q.addBindValue(nonce);
        q.addBindValue(pubkey);
        q.addBindValue(line);

        return q.exec();
    }

    // ------------------------------------------------------------
    // Token helpers
    // ------------------------------------------------------------

    bool getTokenInfo(const QString &tokenHash,
                      QString &owner,
                      int &spent,
                      int &amount) {
        QSqlQuery q;
        q.prepare("SELECT owner_pub, spent, amount FROM tokens WHERE token_hash = ?;");
        q.addBindValue(tokenHash);

        if (!q.exec() || !q.next()) {
            return false;
        }

        owner = q.value(0).toString();
        spent = q.value(1).toInt();
        amount = q.value(2).toInt();

        return true;
    }

    // ------------------------------------------------------------
    // Networking
    // ------------------------------------------------------------

    void sendHello(QSslSocket *socket) {
        if (!socket || !socket->isEncrypted()) return;
        if (!identity.ready()) return;

        QString line = makeSignedLine("HELLO", {});
        if (line.isEmpty()) return;

        socket->write(line.toUtf8() + "\n");
    }

    void writeAuthenticated(const QString &line) {
        if (line.isEmpty()) return;

        QByteArray data = line.toUtf8() + "\n";

        for (QSslSocket *peer : peers) {
            if (peer && peer->isEncrypted() && peer->property("authed").toBool()) {
                peer->write(data);
            }
        }
    }

    void sendKnownPeersTo(QSslSocket *socket) {
        if (!socket || !socket->isEncrypted()) return;
        if (!socket->property("authed").toBool()) return;

        QString self = socket->property("peerAddress").toString();
        QStringList list;

        for (const QString &peer : connectedPeers) {
            if (peer != self && trustedPeers.contains(peer)) {
                list << peer;
            }
        }

        if (list.isEmpty()) return;

        QString message = QString("PEERS|%1\n").arg(list.join(","));
        socket->write(message.toUtf8());
    }

    void broadcastKnownPeers() {
        for (QSslSocket *peer : peers) {
            sendKnownPeersTo(peer);
        }
    }

    void handlePeerList(const QString &peerList) {
        QStringList candidates = peerList.split(',');

        for (QString candidate : candidates) {
            candidate = candidate.trimmed();

            if (candidate.isEmpty()) continue;

            connectToPeerString(candidate);
        }
    }

    void savePeersToFile() {
        QFile file("peers.txt");

        if (!file.open(QIODevice::WriteOnly)) return;

        QTextStream out(&file);

        for (const QString &peer : connectedPeers) {
            // Only save known pinned addresses.
            if (trustedPeers.contains(peer)) {
                out << peer << "\n";
            }
        }
    }

    void loadPeersFromFile() {
        QFile file("peers.txt");

        if (!file.open(QIODevice::ReadOnly)) return;

        QTextStream in(&file);

        while (!in.atEnd()) {
            QString line = in.readLine().trimmed();
            if (!line.isEmpty()) {
                connectToPeerString(line);
            }
        }
    }

    void sendSyncTo(QSslSocket *socket) {
        if (!socket || !socket->isEncrypted()) return;
        if (!socket->property("authed").toBool()) return;

        QSqlQuery q("SELECT line FROM signed_messages ORDER BY id ASC;");

        while (q.next()) {
            QString line = q.value(0).toString();
            socket->write(line.toUtf8() + "\n");
        }
    }

    // ------------------------------------------------------------
    // Message handlers
    // ------------------------------------------------------------

    void handleHello(QSslSocket *socket, const QString &line) {
        if (!socket) return;

        QString pubkey;
        qint64 ts = 0;
        QString nonce;
        QStringList parts;

        // HELLO|1|pub|ts|nonce = 5 unsigned parts.
        if (!verifySignedLine(line, 5, pubkey, ts, nonce, parts)) {
            qWarning() << "Invalid HELLO signature.";
            socket->disconnectFromHost();
            return;
        }

        QString expected = socket->property("expectedPub").toString();

        if (!expected.isEmpty() && pubkey != expected) {
            qWarning() << "HELLO pubkey does not match pinned certificate pubkey.";
            socket->disconnectFromHost();
            return;
        }

        if (!isTrustedNode(pubkey)) {
            qWarning() << "HELLO from untrusted node key.";
            socket->disconnectFromHost();
            return;
        }

        if (!checkAndStoreNonce(pubkey, nonce, ts, true)) {
            qWarning() << "HELLO replay rejected.";
            socket->disconnectFromHost();
            return;
        }

        socket->setProperty("authed", true);
        socket->setProperty("nodePub", pubkey);

        QString address = socket->property("peerAddress").toString();

        pendingPeers.remove(address);

        if (!peers.contains(socket)) {
            peers.append(socket);
        }

        connectedPeers.insert(address);
        savePeersToFile();

        qDebug() << "Peer authenticated:" << address;

        sendKnownPeersTo(socket);

        // Ask peer for ledger history.
        socket->write("SYNC_REQUEST\n");
    }

    bool handleSignedIssue(const QString &line) {
        QString pubkey;
        qint64 ts = 0;
        QString nonce;
        QStringList parts;

        // SIGNED_ISSUE|1|issuer|ts|nonce|tokenHash|ownerPub|amount = 8 unsigned parts.
        if (!verifySignedLine(line, 8, pubkey, ts, nonce, parts)) {
            qWarning() << "Invalid SIGNED_ISSUE signature.";
            return false;
        }

        if (!isTrustedNode(pubkey)) {
            qWarning() << "SIGNED_ISSUE from untrusted issuer.";
            return false;
        }

        if (!checkAndStoreNonce(pubkey, nonce, ts, false)) {
            // Duplicate is normal during sync.
            return false;
        }

        QString tokenHash = parts.value(5);
        QString ownerPub = parts.value(6);
        int amount = parts.value(7).toInt();

        if (tokenHash.isEmpty() || ownerPub.isEmpty() || amount <= 0) {
            return false;
        }

        QSqlQuery insert;
        insert.prepare(
            "INSERT OR IGNORE INTO tokens (token_hash, owner_pub, amount, spent, updated) "
            "VALUES (?, ?, ?, 0, ?);"
        );

        insert.addBindValue(tokenHash);
        insert.addBindValue(ownerPub);
        insert.addBindValue(amount);
        insert.addBindValue(ts);

        if (!insert.exec()) {
            return false;
        }

        storeSignedMessage("SIGNED_ISSUE", pubkey, ts, nonce, line);
        return true;
    }

    bool handleSignedVote(const QString &line) {
        QString pubkey;
        qint64 ts = 0;
        QString nonce;
        QStringList parts;

        // SIGNED_VOTE|1|voter|ts|nonce|candidateB64|tokenHash = 7 unsigned parts.
        if (!verifySignedLine(line, 7, pubkey, ts, nonce, parts)) {
            qWarning() << "Invalid SIGNED_VOTE signature.";
            return false;
        }

        if (!isTrustedNode(pubkey)) {
            qWarning() << "SIGNED_VOTE from untrusted node.";
            return false;
        }

        if (!checkAndStoreNonce(pubkey, nonce, ts, false)) {
            return false;
        }

        QString candidateB64 = parts.value(5);
        QString tokenHash = parts.value(6);

        QString candidate = QString(QByteArray::fromBase64(candidateB64.toUtf8()));

        if (candidate.trimmed().isEmpty() || tokenHash.isEmpty()) {
            return false;
        }

        QString owner;
        int spent = 0;
        int amount = 0;

        if (!getTokenInfo(tokenHash, owner, spent, amount)) {
            qWarning() << "Vote failed: token not found.";
            return false;
        }

        if (owner != pubkey) {
            qWarning() << "Vote failed: voter does not own token.";
            return false;
        }

        if (spent != 0) {
            qWarning() << "Vote failed: token already spent.";
            return false;
        }

        QSqlQuery update;
        update.prepare(
            "UPDATE tokens "
            "SET spent = 1, updated = ? "
            "WHERE token_hash = ? AND owner_pub = ? AND spent = 0;"
        );

        update.addBindValue(ts);
        update.addBindValue(tokenHash);
        update.addBindValue(pubkey);

        if (!update.exec() || update.numRowsAffected() == 0) {
            return false;
        }

        QSqlQuery vote;
        vote.prepare(
            "INSERT OR REPLACE INTO votes (token_hash, candidate, voter_pub, ts, nonce) "
            "VALUES (?, ?, ?, ?, ?);"
        );

        vote.addBindValue(tokenHash);
        vote.addBindValue(candidate);
        vote.addBindValue(pubkey);
        vote.addBindValue(ts);
        vote.addBindValue(nonce);

        if (!vote.exec()) {
            return false;
        }

        storeSignedMessage("SIGNED_VOTE", pubkey, ts, nonce, line);
        return true;
    }

    bool handleSignedTransfer(const QString &line) {
        QString pubkey;
        qint64 ts = 0;
        QString nonce;
        QStringList parts;

        // SIGNED_TRANSFER|1|owner|ts|nonce|tokenHash|receiverPub|amount|expiry = 9 unsigned parts.
        if (!verifySignedLine(line, 9, pubkey, ts, nonce, parts)) {
            qWarning() << "Invalid SIGNED_TRANSFER signature.";
            return false;
        }

        if (!isTrustedNode(pubkey)) {
            qWarning() << "SIGNED_TRANSFER from untrusted node.";
            return false;
        }

        if (!checkAndStoreNonce(pubkey, nonce, ts, false)) {
            return false;
        }

        QString tokenHash = parts.value(5);
        QString receiverPub = parts.value(6);
        int amount = parts.value(7).toInt();
        qint64 expiry = parts.value(8).toLongLong();

        qint64 now = QDateTime::currentSecsSinceEpoch();

        if (now > expiry) {
            qWarning() << "SIGNED_TRANSFER expired.";
            return false;
        }

        if (tokenHash.isEmpty() || receiverPub.isEmpty() || amount <= 0) {
            return false;
        }

        QString owner;
        int spent = 0;
        int dbAmount = 0;

        if (!getTokenInfo(tokenHash, owner, spent, dbAmount)) {
            qWarning() << "Transfer failed: token not found.";
            return false;
        }

        if (owner != pubkey) {
            qWarning() << "Transfer failed: sender does not own token.";
            return false;
        }

        if (spent != 0) {
            qWarning() << "Transfer failed: token already spent.";
            return false;
        }

        if (dbAmount != amount) {
            qWarning() << "Transfer failed: amount mismatch.";
            return false;
        }

        QSqlQuery update;
        update.prepare(
            "UPDATE tokens "
            "SET owner_pub = ?, spent = 0, updated = ? "
            "WHERE token_hash = ? AND owner_pub = ? AND spent = 0;"
        );

        update.addBindValue(receiverPub);
        update.addBindValue(ts);
        update.addBindValue(tokenHash);
        update.addBindValue(pubkey);

        if (!update.exec() || update.numRowsAffected() == 0) {
            return false;
        }

        storeSignedMessage("SIGNED_TRANSFER", pubkey, ts, nonce, line);
        return true;
    }

    void removeSocket(QSslSocket *socket, const QString &address) {
        if (!socket) return;

        peers.removeAll(socket);

        if (!address.isEmpty()) {
            connectedPeers.remove(address);
            pendingPeers.remove(address);
        } else {
            QString prop = socket->property("peerAddress").toString();
            if (!prop.isEmpty()) {
                connectedPeers.remove(prop);
                pendingPeers.remove(prop);
            }
        }
    }

private slots:
    void handleServerSocket(QSslSocket *client) {
        if (!client) return;

        if (peers.size() >= maxPeers) {
            client->disconnectFromHost();
            client->deleteLater();
            return;
        }

        QString address = QString("%1:%2")
            .arg(client->peerAddress().toString())
            .arg(client->peerPort());

        client->setProperty("peerAddress", address);
        client->setProperty("authed", false);

        connect(client, QOverload<const QList<QSslError>&>::of(&QSslSocket::sslErrors),
                this, [=](const QList<QSslError> &errors) {
            Q_UNUSED(errors);
            client->ignoreSslErrors();
        });

        connect(client, &QSslSocket::encrypted, this, [=]() {
            handleServerEncrypted(client);
        });

        connect(client, &QSslSocket::readyRead, this, [=]() {
            if (client->isEncrypted()) {
                handleData(client);
            }
        });

        connect(client, &QSslSocket::disconnected, this, [=]() {
            removeSocket(client, address);
            client->deleteLater();
        });

        client->startServerEncryption();
    }

    void handleServerEncrypted(QSslSocket *socket) {
        if (!socket || !socket->isEncrypted()) return;

        QSslCertificate cert = socket->peerCertificate();

        if (cert.isNull()) {
            qWarning() << "Incoming peer certificate is null.";
            socket->disconnectFromHost();
            return;
        }

        QString fp = certificateFingerprint(cert);
        QString expectedPub;

        if (!findTrustedPubByCert(fp, expectedPub)) {
            qWarning() << "Incoming TLS certificate is not pinned.";
            qWarning() << "Fingerprint:" << fp;
            socket->disconnectFromHost();
            return;
        }

        socket->setProperty("expectedPub", expectedPub);

        sendHello(socket);
    }

    void handleClientEncrypted(QSslSocket *socket, const QString &address) {
        if (!socket || !socket->isEncrypted()) return;

        pendingPeers.remove(address);

        if (!verifyTlsPin(socket, address)) {
            socket->disconnectFromHost();
            return;
        }

        sendHello(socket);
    }

    void handleData(QSslSocket *socket) {
        if (!socket || !socket->isEncrypted()) return;

        while (socket->canReadLine()) {
            QString line = socket->readLine().trimmed();

            if (line.isEmpty()) continue;

            QStringList parts = line.split('|');

            if (parts.isEmpty()) continue;

            if (parts[0] == "HELLO") {
                if (!socket->property("authed").toBool()) {
                    handleHello(socket, line);
                }
                continue;
            }

            if (!socket->property("authed").toBool()) {
                qWarning() << "Message before authentication. Disconnecting.";
                socket->disconnectFromHost();
                return;
            }

            if (parts[0] == "SYNC_REQUEST") {
                sendSyncTo(socket);
            }

            else if (parts[0] == "PEERS" && parts.size() == 2) {
                handlePeerList(parts[1]);
            }

            else if (parts[0] == "SIGNED_ISSUE") {
                handleSignedIssue(line);
            }

            else if (parts[0] == "SIGNED_VOTE") {
                handleSignedVote(line);
            }

            else if (parts[0] == "SIGNED_TRANSFER") {
                handleSignedTransfer(line);
            }
        }
    }

    void performGossip() {
        broadcastKnownPeers();
    }
};

// ------------------------------------------------------------
// GUI
// ------------------------------------------------------------

class VotingApp : public QWidget {
    Q_OBJECT

public:
    VotingApp(QWidget *parent = nullptr)
        : QWidget(parent) {

        setWindowTitle("EVOTE Secure PEX/DEX Prototype");
        resize(900, 650);

        peer = new PeerNode(this);

        QVBoxLayout *layout = new QVBoxLayout(this);

        logView = new QPlainTextEdit;
        logView->setReadOnly(true);

        QLabel *pubLabel = new QLabel("Local node public key:");
        QLineEdit *localPubEdit = new QLineEdit(peer->localPublicKeyBase64());
        localPubEdit->setReadOnly(true);

        QHBoxLayout *trustRow = new QHBoxLayout;
        advertisedEdit = new QLineEdit("127.0.0.1:5555");
        QPushButton *trustBtn = new QPushButton("Show Trust Line");
        trustRow->addWidget(new QLabel("Advertised address:"));
        trustRow->addWidget(advertisedEdit);
        trustRow->addWidget(trustBtn);

        QHBoxLayout *peerRow = new QHBoxLayout;
        peerEdit = new QLineEdit("127.0.0.1:5555");
        QPushButton *connectBtn = new QPushButton("Connect");
        peerRow->addWidget(new QLabel("Peer address:"));
        peerRow->addWidget(peerEdit);
        peerRow->addWidget(connectBtn);

        QHBoxLayout *tokenRow = new QHBoxLayout;
        tokenCountEdit = new QLineEdit("5");
        QPushButton *generateBtn = new QPushButton("Generate Tokens");
        QPushButton *listBtn = new QPushButton("List My Tokens");
        tokenRow->addWidget(new QLabel("Count:"));
        tokenRow->addWidget(tokenCountEdit);
        tokenRow->addWidget(generateBtn);
        tokenRow->addWidget(listBtn);

        QHBoxLayout *voteRow = new QHBoxLayout;
        candidateEdit = new QLineEdit;
        candidateEdit->setPlaceholderText("Candidate");
        voteTokenEdit = new QLineEdit;
        voteTokenEdit->setPlaceholderText("Token hash");
        QPushButton *voteBtn = new QPushButton("Sign Vote");
        voteRow->addWidget(candidateEdit);
        voteRow->addWidget(voteTokenEdit);
        voteRow->addWidget(voteBtn);

        QHBoxLayout *transferRow = new QHBoxLayout;
        transferTokenEdit = new QLineEdit;
        transferTokenEdit->setPlaceholderText("Token hash");
        receiverEdit = new QLineEdit;
        receiverEdit->setPlaceholderText("Receiver public key");
        amountEdit = new QLineEdit("1");
        QPushButton *transferBtn = new QPushButton("Sign Transfer");
        transferRow->addWidget(transferTokenEdit);
        transferRow->addWidget(receiverEdit);
        transferRow->addWidget(amountEdit);
        transferRow->addWidget(transferBtn);

        layout->addWidget(pubLabel);
        layout->addWidget(localPubEdit);
        layout->addLayout(trustRow);
        layout->addLayout(peerRow);
        layout->addLayout(tokenRow);
        layout->addLayout(voteRow);
        layout->addLayout(transferRow);
        layout->addWidget(logView, 1);

        connect(trustBtn, &QPushButton::clicked, this, [=]() {
            log(peer->trustLine(advertisedEdit->text().trimmed()));
        });

        connect(connectBtn, &QPushButton::clicked, this, [=]() {
            QString target = peerEdit->text().trimmed();

            if (peer->connectToPeerString(target)) {
                log("Connecting to " + target + "...");
            } else {
                log("Connect failed. Is the peer pinned in trusted_peers.txt?");
            }
        });

        connect(generateBtn, &QPushButton::clicked, this, [=]() {
            int count = tokenCountEdit->text().toInt();
            if (count <= 0) count = 1;

            peer->generateTokens(count);
            log(QString("Generated %1 signed token issuance(s).").arg(count));
        });

        connect(listBtn, &QPushButton::clicked, this, [=]() {
            QStringList tokens = peer->localTokens();

            if (tokens.isEmpty()) {
                log("No unspent local tokens.");
            } else {
                log("Local tokens:\n" + tokens.join("\n"));
            }
        });

        connect(voteBtn, &QPushButton::clicked, this, [=]() {
            bool ok = peer->createSignedVote(
                candidateEdit->text(),
                voteTokenEdit->text()
            );

            if (ok) {
                log("Signed vote broadcast.");
            } else {
                log("Vote failed. Check token ownership and token hash.");
            }
        });

        connect(transferBtn, &QPushButton::clicked, this, [=]() {
            int amount = amountEdit->text().toInt();

            bool ok = peer->createSignedTransfer(
                transferTokenEdit->text(),
                receiverEdit->text(),
                amount
            );

            if (ok) {
                log("Signed transfer broadcast.");
            } else {
                log("Transfer failed. Check token ownership, amount, and receiver key.");
            }
        });

        log("Node started.");
        log("Port: " + QString::number(PORT));
        log(peer->trustLine(advertisedEdit->text().trimmed()));
    }

private:
    PeerNode *peer = nullptr;
    QPlainTextEdit *logView = nullptr;

    QLineEdit *advertisedEdit = nullptr;
    QLineEdit *peerEdit = nullptr;
    QLineEdit *tokenCountEdit = nullptr;
    QLineEdit *candidateEdit = nullptr;
    QLineEdit *voteTokenEdit = nullptr;
    QLineEdit *transferTokenEdit = nullptr;
    QLineEdit *receiverEdit = nullptr;
    QLineEdit *amountEdit = nullptr;

    void log(const QString &message) {
        QString line = QDateTime::currentDateTime().toString(Qt::ISODate) + "  " + message;
        logView->appendPlainText(line);
    }
};

// ------------------------------------------------------------
// main
// ------------------------------------------------------------

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    VotingApp window;
    window.show();

    return app.exec();
}

#include "main.moc"
