// Decentralized SSL Encrypted Voting & Currency PEX/DEX System
// Corrected Implementation - All helpers moved into PeerNode scope

#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QMessageBox>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QTimer>
#include <QDateTime>
#include <QInputDialog>
#include <QFileDialog>
#include <QCommandLineParser>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QUuid>
#include <QObject>
#include <QMap>
#include <QSet>
#include <QList>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslError>
#include <QProcess>
#include <QFileInfo>
#include <QPointer>
#include <QHostAddress>
// --- Mock Cryptography Classes (replaces missing external headers) ---

struct FastRSAKey { QByteArray key; };

class FastRSA {
public:
    FastRSAKey pub, priv;
    struct Key { QByteArray e, n; };
    Key pub2, priv2;

    void generateKeys() {
        QByteArray k = QCryptographicHash::hash("EVOTE_SECRET_KEY", QCryptographicHash::Sha256);
        pub.key = k; priv.key = k;
        pub2.e = "e"; pub2.n = "n";
        priv2.e = "d"; priv2.n = "n";
    }

    QByteArray encrypt(const QByteArray &data, const Key &) {
        QByteArray res;
        for (int i = 0; i < data.size(); ++i) res.append(data[i] ^ pub.key[i % pub.key.size()]);
        return res.toHex();
    }

    QByteArray decrypt(const QByteArray &hexData, const Key &) {
        QByteArray data = QByteArray::fromHex(hexData);
        QByteArray res;
        for (int i = 0; i < data.size(); ++i) res.append(data[i] ^ priv.key[i % priv.key.size()]);
        return res;
    }
};

namespace ModuloEncryptor {
    struct PublicKey { std::string e, n; };
    struct PrivateKey { std::string d, n; };
    void generateKeys(PublicKey&, PrivateKey&, int) {}
}

class StringHOTP {
public:
    enum Algo { SHA1, SHA256 };
    StringHOTP(const QString &secret, Algo algo, int digits) : m_secret(secret), m_algo(algo), m_digits(digits) {}
    QString generateOTP(const QString &input) {
        auto qAlgo = (m_algo == SHA256) ? QCryptographicHash::Sha256 : QCryptographicHash::Sha1;
        return QString(QCryptographicHash::hash((m_secret + input).toUtf8(), qAlgo).toHex()).left(m_digits).toUpper();
    }
private: QString m_secret; Algo m_algo; int m_digits;
};

class TOTP {
public:
    TOTP(const QString &secret, QCryptographicHash::Algorithm algo, int period) : m_secret(secret), m_algo(algo), m_period(period) {}
    bool verifyTOTP(const QString &otp) {
        qint64 timeStep = QDateTime::currentSecsSinceEpoch() / m_period;
        for (int i = 0; i >= -1; --i) { // Check current and previous step
            QString seed = m_secret + QString::number(timeStep + i);
            QString expectedOtp = QString(QCryptographicHash::hash(seed.toUtf8(), m_algo).toHex()).left(8).toUpper();
            if (expectedOtp == otp) return true;
        }
        return false;
    }
private: QString m_secret; QCryptographicHash::Algorithm m_algo; int m_period;
};

// --- Globals ---

QString walletID;
QString ewalletID;
int ctokens;
QComboBox *candidateBox;
int PORT = 5555;

QCommandLineParser parser;
QCommandLineOption voteOpt("vote", "vote");
QCommandLineOption generateOpt("generate", "generate");
QCommandLineOption transferOpt("transfer", "transfer");
QCommandLineOption getBalanceOpt("balance", "balance");
QCommandLineOption headlessOpt("headless", "Run without GUI");
QCommandLineOption walletIDOpt("walletID", "from address");
QCommandLineOption toOpt("to", "to address");

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
            socket->setPeerVerifyMode(QSslSocket::VerifyNone); // TESTING ONLY

            emit newSslSocket(socket);
        } else {
            socket->deleteLater();
        }
    }

private:
    QSslConfiguration m_config;
};



// --- PEX Node ---

class PeerNode : public QObject {
    Q_OBJECT

public:
    // ------------------------------------------------------------
    // Utility helpers
    // ------------------------------------------------------------

    QString generateRandomToken(int length) {
        const QString possibleCharacters(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        );

        QString randomString;
        for (int i = 0; i < length; ++i) {
            int index = QRandomGenerator::global()->bounded(possibleCharacters.length());
            randomString.append(possibleCharacters.at(index));
        }
        return randomString;
    }

    QString generateTokenPool2() {
        return QUuid::createUuid().toString(QUuid::WithoutBraces).remove("{").remove("}");
    }

    QString hashToken(const QString &token) {
        return QString(
            QCryptographicHash::hash(token.toUtf8(), QCryptographicHash::Sha256).toHex()
        );
    }

    QString xorStrings(const QString &a, const QString &b) {
        QByteArray baA = a.toUtf8();
        QByteArray baB = b.toUtf8();
        QByteArray result;

        for (int i = 0; i < baA.size(); ++i) {
            result.append(baA[i] ^ baB[i % baB.size()]);
        }

        return QString(result.toHex());
    }

    QString encryptCandidate(const QString &data, const QString &key) {
        return xorStrings(data, key);
    }

    QString decryptCandidate(const QString &hexData, const QString &key) {
        QByteArray data = QByteArray::fromHex(hexData.toUtf8());
        QByteArray keyBa = key.toUtf8();
        QByteArray result;

        for (int i = 0; i < data.size(); ++i) {
            result.append(data[i] ^ keyBa[i % keyBa.size()]);
        }

        return QString(result);
    }

    QString encryptOwnership(const QString &walletID, const QString &totp) {
        return hashToken(walletID + ":" + totp);
    }

    QString generateOneTimeToken(const QString &walletID, const QString &token) {
        qint64 timeStep = QDateTime::currentSecsSinceEpoch() / 30;
        QString seed = walletID + token + QString::number(timeStep);
        return hashToken(seed).left(16);
    }

    QString generateTotpForSecret(const QString &secret) {
        qint64 timeStep = QDateTime::currentSecsSinceEpoch() / 30;
        QString seed = secret + QString::number(timeStep);

        return QString(
            QCryptographicHash::hash(seed.toUtf8(), QCryptographicHash::Sha256)
                .toHex()
        ).left(8).toUpper();
    }

    QList<QByteArray> xorSplitSecret(const QByteArray &secret, int parts) {
        QList<QByteArray> slices;

        if (parts <= 0) return slices;
        if (parts == 1) {
            slices.append(secret);
            return slices;
        }

        QByteArray currentXor(secret.size(), '\0');

        for (int i = 0; i < parts - 1; ++i) {
            QByteArray randomSlice;

            for (int j = 0; j < secret.size(); ++j) {
                randomSlice.append((char)QRandomGenerator::global()->bounded(256));
            }

            slices.append(randomSlice);

            for (int j = 0; j < secret.size(); ++j) {
                currentXor[j] = currentXor[j] ^ randomSlice[j];
            }
        }

        QByteArray lastSlice;
        for (int j = 0; j < secret.size(); ++j) {
            lastSlice.append(secret[j] ^ currentXor[j]);
        }

        slices.append(lastSlice);
        return slices;
    }

    QByteArray xorJoinSecret(const QList<QByteArray> &slices) {
        if (slices.isEmpty()) return QByteArray();

        QByteArray result = slices.first();

        for (int i = 1; i < slices.size(); ++i) {
            for (int j = 0; j < result.size(); ++j) {
                if (j < slices[i].size()) {
                    result[j] = result[j] ^ slices[i][j];
                }
            }
        }

        return result;
    }

    bool isLocalHostAddress(const QString &host) const {
        return host == "127.0.0.1" ||
               host.toLower() == "localhost" ||
               host == "::1";
    }

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

    bool setupSslServer() {
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
        config.setLocalCertificate(certs.first());
        config.setPrivateKey(key);

        // TESTING ONLY.
        // This encrypts traffic, but does not authenticate peers.
        // For production, use certificate pinning or mutual TLS.
        config.setPeerVerifyMode(QSslSocket::VerifyNone);

        QSslConfiguration::setDefaultConfiguration(config);
        server->setSslConfiguration(config);

        return true;
    }

    // ------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------

    PeerNode(QObject *parent = nullptr) : QObject(parent), maxPeers(5) {
        UID = QString::number(QRandomGenerator::global()->bounded(10000));
        voteAcceptThreshold = 1; // Raise to 2 or 3 for production consensus.

        server = new SslServer(this);

        if (setupSslServer()) {
            if (!server->listen(QHostAddress::Any, PORT)) {
                qWarning() << "TLS server failed to listen on port" << PORT;
            } else {
                qDebug() << "TLS server listening on port" << PORT;
            }
        } else {
            qWarning() << "TLS setup failed. Run with OpenSSL available and/or create server.crt/server.key.";
        }

        connect(server, &SslServer::newConnection,
                this, &PeerNode::handleNewConnection);

        syncTimer = new QTimer(this);
        connect(syncTimer, &QTimer::timeout, this, &PeerNode::performSync);
        syncTimer->start(100000);

        gossipTimer = new QTimer(this);
        connect(gossipTimer, &QTimer::timeout, this, &PeerNode::broadcastKnownPeers);
        gossipTimer->start(60000); // Gossip peers every 60 seconds.

        rsa.generateKeys();
        pub2 = rsa.pub2;
        priv2 = rsa.priv2;
    }

    // ------------------------------------------------------------
    // Peer connection / peer exchange
    // ------------------------------------------------------------

    void connectToPeer(const QString &host, int port = PORT) {
        QString cleanHost = host.trimmed();

        if (cleanHost.isEmpty()) return;
        if (peers.size() >= maxPeers) return;

        QString address = QString("%1:%2").arg(cleanHost).arg(port);

        if (connectedPeers.contains(address) || pendingPeers.contains(address)) {
            return;
        }

        QSslSocket *socket = new QSslSocket(this);
        socket->setProtocol(QSsl::TlsV1_2OrLater);

        // TESTING ONLY.
        socket->setPeerVerifyMode(QSslSocket::VerifyNone);
        socket->setProperty("peerAddress", address);

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

            if (!guard->isEncrypted() && pendingPeers.contains(address)) {
                pendingPeers.remove(address);
                guard->abort();
                guard->deleteLater();
            }
        });

        socket->connectToHostEncrypted(cleanHost, port);
    }

    void handleNewConnection() {
        while (server->hasPendingConnections()) {
            QSslSocket *client = qobject_cast<QSslSocket*>(server->nextPendingConnection());

            if (!client) continue;

            if (peers.size() >= maxPeers) {
                client->disconnectFromHost();
                client->deleteLater();
                continue;
            }

            QString address = QString("%1:%2")
                .arg(client->peerAddress().toString())
                .arg(client->peerPort());

            client->setProperty("peerAddress", address);

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

            if (!client->isEncrypted()) {
                client->startServerEncryption();
            }
        }
    }

    void handleClientEncrypted(QSslSocket *socket, const QString &address) {
        if (!socket || !socket->isEncrypted()) return;

        pendingPeers.remove(address);

        if (peers.contains(socket)) return;

        socket->setProperty("peerAddress", address);

        peers.append(socket);
        connectedPeers.insert(address);
        savePeersToFile();

        sendKnownPeersTo(socket);

        socket->write(QString("SYNC_REQUEST|%1\n").arg(UID).toUtf8());

        // Let other peers know about this new reachable peer.
        broadcastKnownPeers();
    }

    void handleServerEncrypted(QSslSocket *socket) {
        if (!socket || !socket->isEncrypted()) return;
        if (peers.contains(socket)) return;

        QString address = socket->property("peerAddress").toString();

        peers.append(socket);
        connectedPeers.insert(address);

        // Incoming peers may be behind NAT, so be careful with saving/sharing them.
        // For testing, we still add them to the peer list.
        if (!isLocalHostAddress(socket->peerAddress().toString())) {
            savePeersToFile();
        }

        sendKnownPeersTo(socket);
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

    void sendKnownPeersTo(QSslSocket *socket) {
        if (!socket || !socket->isEncrypted()) return;

        QString self = socket->property("peerAddress").toString();
        QStringList list;

        for (const QString &peer : connectedPeers) {
            if (peer != self) {
                list << peer;
            }
        }

        if (list.isEmpty()) return;

        QString message = QString("PEERS|%1\n").arg(list.join(","));
        socket->write(message.toUtf8());
    }

    void broadcastKnownPeers() {
        if (connectedPeers.isEmpty()) return;

        for (QSslSocket *socket : peers) {
            sendKnownPeersTo(socket);
        }
    }

    void handlePeerList(const QString &peerList) {
        QStringList candidates = peerList.split(',');

        for (QString candidate : candidates) {
            candidate = candidate.trimmed();

            if (candidate.isEmpty()) continue;

            QStringList hostPort = candidate.split(':');
            if (hostPort.size() != 2) continue;

            QString host = hostPort[0].trimmed();
            int port = hostPort[1].toInt();

            if (host.isEmpty() || port <= 0) continue;

            // Avoid immediately connecting back to our own local listener.
            if (isLocalHostAddress(host) && port == PORT) continue;

            connectToPeer(host, port);
        }
    }

    void savePeersToFile() {
        QFile file("peers.txt");

        if (file.open(QIODevice::WriteOnly)) {
            QTextStream out(&file);

            for (const QString &peer : connectedPeers) {
                out << peer << "\n";
            }
        }
    }

    void loadPeersFromFile() {
        QFile file("peers.txt");

        if (file.open(QIODevice::ReadOnly)) {
            QTextStream in(&file);

            while (!in.atEnd()) {
                QString line = in.readLine().trimmed();
                QStringList parts = line.split(":");

                if (parts.size() == 2) {
                    connectToPeer(parts[0], parts[1].toInt());
                }
            }
        }
    }

    // ------------------------------------------------------------
    // Voting / token broadcast
    // ------------------------------------------------------------

    void broadcastVote(const QString &candidate, const QString &token) {
        QString message = QString("VOTE|%1|%2\n").arg(candidate, token);

        for (QSslSocket *peer : peers) {
            if (peer && peer->isEncrypted()) {
                peer->write(message.toUtf8());
            }
        }

        qDebug() << "Broadcasting vote...";

        handleVote(candidate, token, generateOneTimeToken(candidate, token));
    }

    void broadcastSyncVote(const QString &candidate, const QString &tokenHash) {
        QString message = QString("SYNC_VOTE|%1|%2\n").arg(candidate, tokenHash);

        for (QSslSocket *peer : peers) {
            if (peer && peer->isEncrypted()) {
                peer->write(message.toUtf8());
            }
        }

        handleSyncVote(candidate, tokenHash);
    }

    void broadcastTransfer(const QString &fromCandidate,
                           const QString &receiver,
                           const QString &tokenHash,
                           const QString &totp) {
        QString message = QString("TRANSFER|%1|%2|%3|%4|1\n")
            .arg(fromCandidate, receiver, tokenHash, totp);

        for (QSslSocket *peer : peers) {
            if (peer && peer->isEncrypted()) {
                peer->write(message.toUtf8());
            }
        }

        qDebug() << "Broadcasting transfer...";
    }

    void syncVotesToAllPeers() {
        for (QSslSocket *peer : peers) {
            syncVotes(peer);
        }
    }

    void syncVotes(QSslSocket *requestingPeer) {
        if (!requestingPeer || !requestingPeer->isEncrypted()) return;

        QSqlQuery q("SELECT candidate, token_hash FROM votes;");

        while (q.next()) {
            QString line = QString("SYNC_VOTE|%1|%2\n")
                .arg(q.value(0).toString(), q.value(1).toString());

            requestingPeer->write(line.toUtf8());
        }

        QString hash = currentVoteHash();
        QList<QByteArray> slices = xorSplitSecret(hash.toUtf8(), 3);

        QList<QSslSocket*> encryptedPeers;
        for (QSslSocket *peer : peers) {
            if (peer && peer->isEncrypted()) {
                encryptedPeers.append(peer);
            }
        }

        if (encryptedPeers.size() < 3) {
            for (int i = 0; i < slices.size(); ++i) {
                requestingPeer->write(
                    QString("HASH_SLICE|%1|%2\n")
                        .arg(i)
                        .arg(QString(slices[i].toHex()))
                        .toUtf8()
                );
            }
            return;
        }

        QSqlQuery q1("SELECT token_hash FROM votes WHERE candidate = 'GENESIS' LIMIT 1;");

        if (q1.next()) {
            QString genesisHash = q1.value(0).toString();
            requestingPeer->write(QString("GENESIS_HASH|%1\n").arg(genesisHash).toUtf8());
        }

        QList<QSslSocket*> selectedPeers;

        while (selectedPeers.size() < 3) {
            QSslSocket *peer = encryptedPeers.at(
                QRandomGenerator::global()->bounded(encryptedPeers.size())
            );

            if (!selectedPeers.contains(peer)) {
                selectedPeers << peer;
            }
        }

        for (int i = 0; i < slices.size(); ++i) {
            selectedPeers[i]->write(
                QString("HASH_SLICE|%1|%2\n")
                    .arg(i)
                    .arg(QString(slices[i].toHex()))
                    .toUtf8()
            );
        }

        requestingPeer->write(
            QString("SYNC_TIME|%1\n")
                .arg(QDateTime::currentDateTimeUtc().toString(Qt::ISODate))
                .toUtf8()
        );
    }

    // ------------------------------------------------------------
    // Token generation / database
    // ------------------------------------------------------------

    void generateTokenPool(int count) {
        const QString genesisMarker = "GENESIS";
        QString genesisTokenHash = hashToken(UID);

        QSqlQuery check("SELECT COUNT(*) FROM votes WHERE candidate = 'GENESIS';");

        if (check.next() && check.value(0).toInt() == 0) {
            QSqlQuery insert;
            insert.prepare("INSERT INTO votes (candidate, token_hash) VALUES (?, ?);");
            insert.addBindValue(genesisMarker);
            insert.addBindValue(genesisTokenHash);
            insert.exec();
        }

        QString fileName = QFileDialog::getSaveFileName(
            nullptr,
            "Save tokens CSV file",
            QCoreApplication::applicationDirPath(),
            "CSV (*.csv)"
        );

        if (!fileName.isEmpty()) {
            QFile file(fileName);

            if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                QTextStream out(&file);

                for (int i = 0; i < count; ++i) {
                    QString token = generateTokenPool2();
                    QString tokenHash = hashToken(token);

                    QSqlQuery q;
                    q.prepare("INSERT OR IGNORE INTO tokens (token_hash, used) VALUES (?, 0);");
                    q.addBindValue(tokenHash);
                    q.exec();

                    out << token << ",\n";

                    // Share only the hash with the network.
                    broadcastSyncVote("", tokenHash);
                }

                out << "GENESIS:" << UID << ",\n";
            }
        }

        broadcastSyncVote("SYNC_HASH", currentVoteHash());
    }

    bool addWallet(QString Candidate) {
        bool ok;

        QString text = QInputDialog::getText(
            nullptr,
            "Password",
            "New Password:",
            QLineEdit::Normal,
            "",
            &ok
        );

        if (ok && !text.isEmpty()) {
            QString name = encryptCandidate(Candidate, text);

            QSqlQuery q;
            q.prepare("INSERT INTO candidates (name) VALUES (?);");
            q.addBindValue(name);

            if (q.exec() && candidateBox) {
                candidateBox->addItem(name);
            }
        }

        return true;
    }

    QStringList getCandidates() {
        QStringList list;

        QSqlQuery query("SELECT DISTINCT name FROM candidates;");

        while (query.next()) {
            list << query.value(0).toString();
        }

        return list;
    }

    QStringList findMyTokens(const QString &walletID2) {
        QSqlQuery q("SELECT candidate, token_hash, TOTP FROM votes;");

        QStringList myTokens;
        ctokens = 0;

        while (q.next()) {
            QString encCandidate = q.value(0).toString();
            QString tokenHash = q.value(1).toString();

            QByteArray encrypted = rsa.encrypt(walletID2.toUtf8(), pub2);

            if (encCandidate == QString(encrypted)) {
                myTokens.append(tokenHash);
                ctokens++;
            }
        }

        return myTokens;
    }

    void setupDatabase() {
        QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
        db.setDatabaseName(QCoreApplication::applicationDirPath() + "/peer_voting.db");

        if (db.open()) {
            QSqlQuery query;

            query.exec(
                "CREATE TABLE IF NOT EXISTS candidates ("
                "name TEXT UNIQUE,"
                "tokenID TEXT UNIQUE,"
                "tokenHash TEXT UNIQUE"
                ");"
            );

            query.exec(
                "CREATE TABLE IF NOT EXISTS tokens ("
                "token_hash TEXT UNIQUE,"
                "used INTEGER"
                ");"
            );

            query.exec(
                "CREATE TABLE IF NOT EXISTS votes ("
                "candidate TEXT,"
                "token_hash TEXT UNIQUE,"
                "TOTP TEXT"
                ");"
            );
        }
    }

    bool getVoteCandidate(const QString &tokenHash, QString &candidate) {
        QSqlQuery q;
        q.prepare("SELECT candidate FROM votes WHERE token_hash = ?;");
        q.addBindValue(tokenHash);

        if (q.exec() && q.next()) {
            candidate = q.value(0).toString();
            return true;
        }

        return false;
    }

    void handleTransfer(const QString &token,
                        const QString &senderSecret,
                        const QString &receiverSecret,
                        QString totp,
                        int amount) {
        Q_UNUSED(senderSecret);
        Q_UNUSED(amount);

        QString tokenHash = hashToken(token);
        QString oldCandidate;

        if (!getVoteCandidate(tokenHash, oldCandidate)) {
            // Maybe the UI/user passed a token hash instead of plaintext token.
            tokenHash = token;

            if (!getVoteCandidate(tokenHash, oldCandidate)) {
                qDebug() << "Transfer failed: token hash not found.";
                return;
            }
        }

        if (totp.isEmpty()) {
            totp = generateTotpForSecret(tokenHash);
        }

        QString newEncryptedOwner = encryptCandidate(receiverSecret, totp);

        QSqlQuery update;
        update.prepare("UPDATE votes SET candidate = ? WHERE token_hash = ?;");
        update.addBindValue(newEncryptedOwner);
        update.addBindValue(tokenHash);
        update.exec();

        broadcastTransfer(oldCandidate, receiverSecret, tokenHash, totp);
    }

    void applyTransferHash(const QString &tokenHash,
                           const QString &receiver,
                           const QString &totp) {
        QString newEncryptedOwner = encryptCandidate(receiver, totp);

        QSqlQuery update;
        update.prepare("UPDATE votes SET candidate = ? WHERE token_hash = ?;");
        update.addBindValue(newEncryptedOwner);
        update.addBindValue(tokenHash);
        update.exec();
    }

    void handleVote(const QString &candidate,
                    const QString &token,
                    const QString &ott) {
        QString hash = hashToken(token);

        QString finalCandidate = candidate;
        if (finalCandidate.isEmpty()) {
            finalCandidate = ott;
        }

        QSqlQuery insert;
        insert.prepare("INSERT OR REPLACE INTO votes (candidate, token_hash) VALUES (?, ?);");
        insert.addBindValue(finalCandidate);
        insert.addBindValue(hash);
        insert.exec();
    }

    void handleSyncVote(const QString &candidate, const QString &tokenHash) {
        QSqlQuery insert;

        // IGNORE helps avoid overwriting local ownership during simple sync.
        insert.prepare("INSERT OR IGNORE INTO votes (candidate, token_hash) VALUES (?, ?);");
        insert.addBindValue(candidate);
        insert.addBindValue(tokenHash);
        insert.exec();
    }

    QString currentVoteHash() {
        QSqlQuery q(
            "SELECT candidate, token_hash FROM votes "
            "WHERE candidate IS NOT NULL "
            "AND candidate != '' "
            "AND candidate != 'SYNC_HASH' "
            "ORDER BY candidate, token_hash;"
        );

        QByteArray data;

        while (q.next()) {
            data.append(q.value(0).toString() + q.value(1).toString());
        }

        return QString(QCryptographicHash::hash(data, QCryptographicHash::Md5).toHex());
    }

    QString UID;
    QMap<QString, QSet<QString>> receivedVoteSources;
    QMap<int, QMap<QByteArray, int>> sliceVotes;
    int voteAcceptThreshold;

private slots:
    void handleData(QSslSocket *socket) {
        if (!socket || !socket->isEncrypted()) return;

        while (socket->canReadLine()) {
            QString line = socket->readLine().trimmed();
            QStringList parts = line.split("|");

            if (parts.size() == 2 && parts[0] == "PEER") {
                QStringList hostPort = parts[1].split(":");

                if (hostPort.size() == 2) {
                    connectToPeer(hostPort[0], hostPort[1].toInt());
                }
            }

            else if (parts.size() == 2 && parts[0] == "PEERS") {
                handlePeerList(parts[1]);
            }

            else if (parts[0] == "SYNC_REQUEST" && parts.size() == 2) {
                qDebug() << "Received SYNC request from peer UID:" << parts[1];
                syncVotes(socket);
            }

            else if (parts.size() == 3 && parts[0] == "SYNC_HASH") {
                futureHashes[parts[1]].insert(parts[2]);
                invalidHashCounts[parts[2]]++;
            }

            else if (parts.size() == 3 && parts[0] == "SYNC_VOTE") {
                handleSyncVote(parts[1], parts[2]);
            }

            else if (parts[0] == "VOTE" && parts.size() == 3) {
                QString tokenHash = hashToken(parts[2]);
                QString key = parts[1] + "|" + tokenHash;

                receivedVoteSources[key].insert(socket->peerAddress().toString());

                if (receivedVoteSources[key].size() >= voteAcceptThreshold) {
                    handleVote(parts[1], parts[2], "");
                }
            }

            else if (parts[0] == "HASH_SLICE" && parts.size() == 3) {
                int index = parts[1].toInt();
                QByteArray slice = QByteArray::fromHex(parts[2].toUtf8());

                sliceVotes[index][slice]++;

                if (sliceVotes[index][slice] >= 2) {
                    hashSlices[index] = slice;
                }
            }

            else if (parts[0] == "GENESIS_HASH" && parts.size() == 2) {
                QString incomingHash = parts[1];

                QSqlQuery q("SELECT token_hash FROM votes WHERE candidate = 'GENESIS' LIMIT 1;");

                if (q.next()) {
                    QString localHash = q.value(0).toString();

                    if (localHash != incomingHash) {
                        qDebug() << "Genesis hash mismatch. Possible fork.";
                        socket->disconnectFromHost();
                    }
                }
            }

            else if (parts[0] == "TRANSFER" && parts.size() == 6) {
                QString from = parts[1];
                QString to = parts[2];
                QString tokenHash = parts[3];
                QString totp = parts[4];
                int amount = parts[5].toInt();

                Q_UNUSED(from);
                Q_UNUSED(amount);

                TOTP verifier(tokenHash, QCryptographicHash::Sha256, 30);
                bool isValid = verifier.verifyTOTP(totp);

                qDebug() << "TOTP verification result:" << (isValid ? "Valid" : "Invalid");

                if (isValid) {
                    applyTransferHash(tokenHash, to, totp);
                }
            }
        }
    }

    void performSync() {
        if (hashSlices.size() == 3) {
            QList<QByteArray> slices = {
                hashSlices[0],
                hashSlices[1],
                hashSlices[2]
            };

            QByteArray reconstructed = xorJoinSecret(slices);

            if (reconstructed == currentVoteHash().toUtf8()) {
                qDebug() << "Sync verification passed.";
            } else {
                qDebug() << "WARNING: Sync hash mismatch.";
            }

            hashSlices.clear();
        }
    }

private:
    SslServer *server;
    QSslConfiguration sslConfig;
    bool sslReady;
    QList<QSslSocket *> peers;
    QSet<QString> connectedPeers;
    QSet<QString> pendingPeers;
    int maxPeers;

    QMap<QString, QSet<QString>> futureHashes;
    QMap<QString, int> invalidHashCounts;
    QMap<int, QByteArray> hashSlices;

    QTimer *syncTimer;
    QTimer *gossipTimer;

    FastRSA rsa;
    FastRSA::Key pub2;
    FastRSA::Key priv2;

    ModuloEncryptor::PublicKey pub;
    ModuloEncryptor::PrivateKey priv;
};

// --- GUI ---

class VotingApp : public QWidget {
    Q_OBJECT
public:
    VotingApp(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("Decentralized Voting & Currency");
        resize(400, 600);

        peer = new PeerNode(this);
        peer->setupDatabase();
        peer->loadPeersFromFile();

        QVBoxLayout *layout = new QVBoxLayout(this);
        candidateBox = new QComboBox;
        candidateBox->addItems(peer->getCandidates());

        QPushButton *addCandidate = new QPushButton("Add Wallet");
        QPushButton *generateTokens = new QPushButton("Generate Tokens");
        QPushButton *voteButton = new QPushButton("Vote");
        QPushButton *connectBtn = new QPushButton("Connect to Peer");
        QPushButton *Generatewalletbtn = new QPushButton("Generate WalletName");
        QPushButton *FindTokensbtn = new QPushButton("Search Wallet");
        QPushButton *transferBtn = new QPushButton("Transfer");

        newCandidateInput = new QLineEdit;
        newCandidateInput->setPlaceholderText("New Candidate Name / Wallet");

        QLineEdit *Toaddressedit = new QLineEdit;
        QLineEdit *Fromaddressedit = new QLineEdit;
        QLineEdit *amountEdt = new QLineEdit;
        Toaddressedit->setPlaceholderText("To Address");
        Fromaddressedit->setPlaceholderText("From tokenID");
        amountEdt->setPlaceholderText("Amount");

        QLabel *Tolbl = new QLabel("To Address");
        QLabel *Fromlbl = new QLabel("From address");
        QLabel *amountlbl  = new QLabel("Amount");
        QLabel *walletIDlbl  = new QLabel("WalletID");
        QLabel *walletIDlbl2  = new QLabel("Generated WalletID or Name");

        tokenInput = new QLineEdit;
        tokenInput->setPlaceholderText("Vote Token");
        peerInput = new QLineEdit;
        peerInput->setPlaceholderText("Peer IP Address");

        layout->addWidget(walletIDlbl);
        layout->addWidget(candidateBox);
        layout->addWidget(walletIDlbl2);
        layout->addWidget(newCandidateInput);
        layout->addWidget(amountlbl);
        layout->addWidget(amountEdt);
        layout->addWidget(tokenInput);
        layout->addWidget(voteButton);

        QHBoxLayout *btnLayout1 = new QHBoxLayout;
        btnLayout1->addWidget(Generatewalletbtn);
        btnLayout1->addWidget(addCandidate);
        btnLayout1->addWidget(FindTokensbtn);
        layout->addLayout(btnLayout1);

        QFrame *line = new QFrame();
        line->setFrameShape(QFrame::HLine);
        line->setFrameShadow(QFrame::Sunken);
        layout->addWidget(line);

        layout->addWidget(Fromlbl);
        layout->addWidget(Fromaddressedit);
        layout->addWidget(Tolbl);
        layout->addWidget(Toaddressedit);
        layout->addWidget(transferBtn);
        layout->addWidget(connectBtn);
        layout->addWidget(peerInput);

        QFrame *line2 = new QFrame();
        line2->setFrameShape(QFrame::HLine);
        line2->setFrameShadow(QFrame::Sunken);
        layout->addWidget(line2);

        layout->addWidget(generateTokens);
        layout->addStretch();

        QObject::connect(candidateBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [=](int index){
            QString selected = candidateBox->itemText(index);
            newCandidateInput->setText(selected);
            walletID = selected;
            ewalletID = peer->encryptCandidate(selected, walletID); // Now works!
        });

        connect(Generatewalletbtn, &QPushButton::clicked, this, [=]() { newCandidateInput->setText(peer->generateRandomToken(12)); }); // Now works!

        QTimer *cleanupTimer = new QTimer(this);
        connect(cleanupTimer, &QTimer::timeout, this, [=]() {
            peer->receivedVoteSources.clear();
            peer->sliceVotes.clear();
            candidateBox->clear();
            candidateBox->addItems(peer->getCandidates());
        });
        cleanupTimer->start(300000);

        if (candidateBox->count() > 0) candidateBox->setCurrentIndex(0);

        connect(transferBtn, &QPushButton::clicked, this, [=]() {
            QMessageBox::StandardButton reply = QMessageBox::question(this, "Confirm Transfer", "Transfer?", QMessageBox::Yes|QMessageBox::No);
            if (reply == QMessageBox::Yes) peer->handleTransfer(tokenInput->text(), Fromaddressedit->text(), Toaddressedit->text(), "", amountEdt->text().toInt());
        });

        connect(addCandidate, &QPushButton::clicked, this, [=]() { peer->addWallet(newCandidateInput->text()); });
        connect(generateTokens, &QPushButton::clicked, this, [=]() { peer->generateTokenPool(10); });
        connect(voteButton, &QPushButton::clicked, this, [=]() { peer->broadcastVote(candidateBox->currentText(), tokenInput->text()); });
        connect(connectBtn, &QPushButton::clicked, this, [=]() { peer->connectToPeer(peerInput->text()); });
        connect(FindTokensbtn, &QPushButton::clicked, this, [=]() { peer->findMyTokens(ewalletID); });
    }

private:
    PeerNode *peer;
    QLineEdit *newCandidateInput, *tokenInput, *peerInput;
};

// --- Entry Point ---
#include "main.moc"
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    parser.setApplicationDescription("Decentralized SSL Encrypted Voting & Currency PEX/DEX");
    parser.addHelpOption();
    parser.addVersionOption();

    parser.addOption(voteOpt);
    parser.addOption(generateOpt);
    parser.addOption(transferOpt);
    parser.addOption(getBalanceOpt);
    parser.addOption(headlessOpt);
    parser.addOption(walletIDOpt);
    parser.addOption(toOpt);

    parser.process(app);

    VotingApp window;

    if (parser.isSet(headlessOpt)) {
         qDebug() << "Headless Mode.";
         return 0;
    }

    window.show();
    return app.exec();
}


