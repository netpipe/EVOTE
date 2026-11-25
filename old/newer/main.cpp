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

// --- PEX Node ---

class PeerNode : public QObject {
    Q_OBJECT
public:
    // --- Helper Methods (Moved inside class to allow peer-> calls) ---
    QString generateRandomToken(int length) {
        const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
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
        return QString(QCryptographicHash::hash(token.toUtf8(), QCryptographicHash::Sha256).toHex());
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
        qint64 timeStep = QDateTime::currentSecsSinceEpoch() / 30; // 30-second TOTP step
        QString seed = walletID + token + QString::number(timeStep);
        return hashToken(seed).left(16);
    }

    QList<QByteArray> xorSplitSecret(const QByteArray &secret, int parts) {
        QList<QByteArray> slices;
        if (parts <= 0) return slices;
        if (parts == 1) { slices.append(secret); return slices; }

        QByteArray currentXor(secret.size(), '\0');
        for (int i = 0; i < parts - 1; ++i) {
            QByteArray randomSlice;
            for (int j = 0; j < secret.size(); ++j) {
                randomSlice.append((char)QRandomGenerator::global()->bounded(256));
            }
            slices.append(randomSlice);
            for (int j = 0; j < secret.size(); ++j) currentXor[j] = currentXor[j] ^ randomSlice[j];
        }
        QByteArray lastSlice;
        for (int j = 0; j < secret.size(); ++j) lastSlice.append(secret[j] ^ currentXor[j]);
        slices.append(lastSlice);
        return slices;
    }

    QByteArray xorJoinSecret(const QList<QByteArray> &slices) {
        if (slices.isEmpty()) return QByteArray();
        QByteArray result = slices.first();
        for (int i = 1; i < slices.size(); ++i) {
            for (int j = 0; j < result.size(); ++j) {
                if (j < slices[i].size()) result[j] = result[j] ^ slices[i][j];
            }
        }
        return result;
    }

    // --- Core Networking & DB ---
    PeerNode(QObject *parent = nullptr) : QObject(parent), maxPeers(5) {
        UID = QString::number(QRandomGenerator::global()->bounded(10000));
        server = new QTcpServer(this);
        connect(server, &QTcpServer::newConnection, this, &PeerNode::handleConnection);
        server->listen(QHostAddress::Any, PORT);

        syncTimer = new QTimer(this);
        connect(syncTimer, &QTimer::timeout, this, &PeerNode::performSync);
        syncTimer->start(100000);

        rsa.generateKeys();
        pub2 = rsa.pub2; priv2 = rsa.priv2;
    }

    void connectToPeer(const QString &host, int port = PORT) {
        if (peers.size() >= maxPeers) return;
        QString address = QString("%1:%2").arg(host).arg(port);
        if (connectedPeers.contains(address)) return;

        QTcpSocket *socket = new QTcpSocket(this);
        socket->connectToHost(host, port);
        connect(socket, &QTcpSocket::readyRead, this, [=]() { handleData(socket); });
        connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
        peers.append(socket);
        connectedPeers.insert(address);
        savePeersToFile();

        for (const QString &peer : connectedPeers) socket->write(QString("PEER|%1\n").arg(peer).toUtf8());
        socket->write(QString("SYNC_REQUEST|%1\n").arg(UID).toUtf8());
    }

    void broadcastVote(const QString &candidate, const QString &token) {
        QString message = QString("VOTE|%1|%2\n").arg(candidate, token);
        for (QTcpSocket *peer : peers) peer->write(message.toUtf8());
        qDebug() << "Broadcasting vote...";
        handleVote(candidate, token, generateOneTimeToken(candidate, token));
    }

    void broadcastTransfer(const QString &candidate, QString receiver, const QString &token, QString &totp) {
        QString message = QString("TRANSFER|%1|%2|%3|%4|1\n").arg(candidate, receiver, token, totp);
        for (QTcpSocket *peer : peers) peer->write(message.toUtf8());
        qDebug() << "Broadcasting transfer...";
    }

    void syncVotesToAllPeers() { for (QTcpSocket* peer : peers) syncVotes(peer); }

    void syncVotes(QTcpSocket *requestingPeer) {
        QSqlQuery q("SELECT candidate, token_hash FROM votes;");
        while (q.next()) requestingPeer->write(QString("VOTE|%1|%2\n").arg(q.value(0).toString(), q.value(1).toString()).toUtf8());

        QString hash = currentVoteHash();
        QList<QByteArray> slices = xorSplitSecret(hash.toUtf8(), 3);

        if (peers.size() < 3) {
            for (int i = 0; i < slices.size(); ++i)
                requestingPeer->write(QString("HASH_SLICE|%1|%2\n").arg(i).arg(QString(slices[i].toHex())).toUtf8());
            return;
        }

        QSqlQuery q1("SELECT token_hash FROM votes WHERE candidate = 'GENESIS' LIMIT 1;");
        if (q1.next()) requestingPeer->write(QString("GENESIS_HASH|%1\n").arg(q1.value(0).toString()).toUtf8());

        QList<QTcpSocket*> selectedPeers;
        while (selectedPeers.size() < 3) {
            QTcpSocket *peer = peers.at(QRandomGenerator::global()->bounded(peers.size()));
            if (!selectedPeers.contains(peer)) selectedPeers << peer;
        }

        for (int i = 0; i < slices.size(); ++i)
            selectedPeers[i]->write(QString("HASH_SLICE|%1|%2\n").arg(i).arg(QString(slices[i].toHex())).toUtf8());

        requestingPeer->write(QString("SYNC_TIME|%1\n").arg(QDateTime::currentDateTimeUtc().toString(Qt::ISODate)).toUtf8());
    }

    bool isValidTokenHash(const QString &token) {
        QSqlQuery q;
        q.prepare("SELECT token_hash FROM votes WHERE token_hash = ?;");
        q.addBindValue(token);
        return q.exec() && q.next() && q.value(0).toString().isEmpty();
    }

    void generateTokenPool(int count) {
        QSqlQuery clear;
        clear.exec("DELETE FROM tokens");

        const QString genesisMarker = "GENESIS";
        QString tokenHash = hashToken(UID);

        QSqlQuery check("SELECT COUNT(*) FROM votes WHERE candidate = 'GENESIS';");
        if (check.next() && check.value(0).toInt() == 0) {
            QSqlQuery insert;
            insert.prepare("INSERT INTO votes (candidate, token_hash) VALUES (?, ?);");
            insert.addBindValue(genesisMarker);
            insert.addBindValue(tokenHash);
            insert.exec();
        }

        QString fileName = QFileDialog::getSaveFileName(nullptr, "Save tokens CSV file", QCoreApplication::applicationDirPath(), "CSV (*.csv)");
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
                    broadcastVote("", tokenHash);
                }
                out << "GENESIS:" << UID << ",\n";
            }
        }
        broadcastVote("SYNC_HASH", currentVoteHash());
    }

    bool addWallet(QString Candidate){
        bool ok;
        QString text = QInputDialog::getText(nullptr, "Password", "New Password:", QLineEdit::Normal, "", &ok);
        if (ok && !text.isEmpty()) {
            QString name = encryptCandidate(Candidate, text);
            QSqlQuery q;
            q.prepare("INSERT INTO candidates (name) VALUES (?);");
            q.addBindValue(name);
            if (q.exec() && candidateBox) candidateBox->addItem(name);
        }
        return true;
    }

    QStringList getCandidates() {
        QStringList list;
        QSqlQuery query("SELECT DISTINCT name FROM candidates;");
        while (query.next()) list << query.value(0).toString();
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
            query.exec("CREATE TABLE IF NOT EXISTS candidates (name TEXT UNIQUE, tokenID TEXT UNIQUE, tokenHash TEXT UNIQUE);");
            query.exec("CREATE TABLE IF NOT EXISTS tokens (token_hash TEXT UNIQUE, used INTEGER);");
            query.exec("CREATE TABLE IF NOT EXISTS votes (candidate TEXT, token_hash TEXT UNIQUE, TOTP TEXT);");
        }
    }

    void savePeersToFile() {
        QFile file("peers.txt");
        if (file.open(QIODevice::WriteOnly)) {
            QTextStream out(&file);
            for (const QString &peer : connectedPeers) out << peer << "\n";
        }
    }

    void loadPeersFromFile() {
        QFile file("peers.txt");
        if (file.open(QIODevice::ReadOnly)) {
            QTextStream in(&file);
            while (!in.atEnd()) {
                QString line = in.readLine().trimmed();
                QStringList parts = line.split(":");
                if (parts.size() == 2) connectToPeer(parts[0], parts[1].toInt());
            }
        }
    }

    bool verifyOwnership(const QString &name, const QString &tokenID, const QString &walletID2) { Q_UNUSED(name); Q_UNUSED(tokenID); Q_UNUSED(walletID2); return true; }

    void handleTransfer(const QString &token, const QString &senderSecret, const QString &receiverSecret, QString totp, int amount) {
        Q_UNUSED(senderSecret); Q_UNUSED(amount);
        QString tokenHash = hashToken(token);

        QSqlQuery check;
        check.prepare("SELECT candidate FROM votes WHERE token_hash = ?;");
        check.addBindValue(tokenHash);
        if (!check.exec() || !check.next()) return;

        QString newEncryptedOwner = encryptCandidate(receiverSecret, totp);
        QSqlQuery update;
        update.prepare("UPDATE votes SET candidate = ? WHERE token_hash = ?;");
        update.addBindValue(newEncryptedOwner);
        update.addBindValue(tokenHash);
        update.exec();

        broadcastTransfer(check.value(0).toString(), receiverSecret, tokenHash, totp);
    }

    void handleVote(const QString candidate, const QString token, QString ott) {
        QString hash = token;
        QString finalCandidate;

        if (!candidate.isEmpty()){
            finalCandidate = ott.isEmpty() ? candidate : ott;
        } else {
            hash = hashToken(token);
            QString message = ewalletID + ott;
            finalCandidate = QString(rsa.encrypt(message.toUtf8(), pub2));
            if (!isValidTokenHash(hash) && !candidate.isEmpty()) return;
        }

        QSqlQuery insert;
        insert.prepare("INSERT OR REPLACE INTO votes (candidate, token_hash) VALUES (?, ?);");
        insert.addBindValue(finalCandidate);
        insert.addBindValue(hash);
        insert.exec();
    }

    QString currentVoteHash() {
        QSqlQuery q("SELECT candidate, token_hash FROM votes WHERE candidate IS NOT NULL AND candidate != '' AND candidate != 'SYNC_HASH' ORDER BY candidate, token_hash;");
        QByteArray data;
        while (q.next()) data.append(q.value(0).toString() + q.value(1).toString());
        return QString(QCryptographicHash::hash(data, QCryptographicHash::Md5).toHex());
    }

    QString UID;
    QMap<QString, QSet<QString>> receivedVoteSources;
    QMap<int, QMap<QByteArray, int>> sliceVotes;

private slots:
    void handleConnection() {
        QTcpSocket *client = server->nextPendingConnection();
        connect(client, &QTcpSocket::readyRead, this, [=]() { handleData(client); });
        connect(client, &QTcpSocket::disconnected, client, &QTcpSocket::deleteLater);
        peers.append(client);
    }

    void handleData(QTcpSocket *socket) {
        while (socket->canReadLine()) {
            QString line = socket->readLine().trimmed();
            QStringList parts = line.split("|");

            if (parts.size() == 2 && parts[0] == "PEER") {
                QStringList hostPort = parts[1].split(":");
                if (hostPort.size() == 2) connectToPeer(hostPort[0], hostPort[1].toInt());
            }
            else if (parts[0] == "SYNC_REQUEST" && parts.size() == 2) {
                qDebug() << "Received SYNC request from peer UID:" << parts[1];
                syncVotes(socket);
            }
            else if (parts.size() == 3 && parts[0] == "SYNC_HASH") {
                futureHashes[parts[1]].insert(parts[2]);
                invalidHashCounts[parts[2]]++;
            }
            else if (parts[0] == "VOTE" && parts.size() == 3) {
                QString key = parts[1] + "|" + parts[2];
                receivedVoteSources[key].insert(socket->peerAddress().toString());
                if (receivedVoteSources[key].size() >= 3) handleVote(parts[1], parts[2], "");
            }
            else if (parts[0] == "HASH_SLICE" && parts.size() == 3) {
                int index = parts[1].toInt();
                QByteArray slice = QByteArray::fromHex(parts[2].toUtf8());
                sliceVotes[index][slice]++;
                if (sliceVotes[index][slice] >= 2) hashSlices[index] = slice;
            }
            else if (parts[0] == "GENESIS_HASH" && parts.size() == 2) {
                QSqlQuery q("SELECT token_hash FROM votes WHERE candidate = 'GENESIS' LIMIT 1;");
                if (q.next() && q.value(0).toString() != parts[1]) {
                    qDebug() << "Genesis hash mismatch. Possible fork.";
                    socket->disconnectFromHost();
                }
            }
            else if (parts[0] == "TRANSFER" && parts.size() >= 5) {
                QString from = parts[1], to = parts[2], token = parts[3];
                int amount = (parts.size() == 6) ? parts[5].toInt() : 1;

                TOTP totp(token, QCryptographicHash::Sha256, 30);
                bool isValid = totp.verifyTOTP(parts[4]);
                qDebug() << "TOTP verification result: " << (isValid ? "Valid" : "Invalid");
                if (isValid) handleTransfer(token, from, to, parts[4], amount);
            }
        }
    }

    void performSync() {
        if (hashSlices.size() == 3) {
            QList<QByteArray> slices = { hashSlices[0], hashSlices[1], hashSlices[2] };
            QByteArray reconstructed = xorJoinSecret(slices);
            if (reconstructed == currentVoteHash().toUtf8()) qDebug() << "Sync verification passed.";
            else qDebug() << "WARNING: Sync hash mismatch.";
            hashSlices.clear();
        }
    }

private:
    QTcpServer *server;
    QList<QTcpSocket *> peers;
    QSet<QString> connectedPeers;
    int maxPeers;
    QMap<QString, QSet<QString>> futureHashes;
    QMap<QString, int> invalidHashCounts;
    QMap<int, QByteArray> hashSlices;
    QTimer *syncTimer;
    FastRSA rsa;
    FastRSA::Key pub2, priv2;
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


