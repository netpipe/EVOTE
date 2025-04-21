// Decentralized Voting App with Candidate Selector, Peer Limit, Vote Sync, Peer Verification, and Future Hash Check + Hash Warning System
#include <QApplication>
#include <QtWidgets>
#include <QtNetwork>
#include <QtSql>
#include <QCryptographicHash>
#include <QSet>
#include <QRandomGenerator>
#include <QTimer>
#include <QDateTime>
#include <qaesencryption.h>
#include "totp.h"

    QString sharedSecret = "JBSWY3DPEHPK3PXP"; // Example shared secret (Base32 encoded) OTP

class PeerNode : public QObject {
    Q_OBJECT

public:
    PeerNode(QObject *parent = nullptr) : QObject(parent), maxPeers(5) {
        UID="1234";
        server = new QTcpServer(this);
        connect(server, &QTcpServer::newConnection, this, &PeerNode::handleConnection);
        server->listen(QHostAddress::Any, 5555);
        syncTimer = new QTimer(this);
        connect(syncTimer, &QTimer::timeout, this, &PeerNode::performSync);
        syncTimer->start(10000); // Synchronize every 10 seconds
    }

    void connectToPeer(const QString &host, int port = 5555) {
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
        for (const QString &peer : connectedPeers) {
            socket->write(QString("PEER|%1\n").arg(peer).toUtf8());
        }
      //  socket->write("SYNC_REQUEST\n");
        socket->write(QString("SYNC_REQUEST|%1\n").arg(UID).toUtf8());

    }

    void broadcastVote(const QString &candidate, const QString &token) {
        QString message = QString("VOTE|%1|%2\n").arg(candidate, token);
        for (QTcpSocket *peer : peers) {
            peer->write(message.toUtf8());
        }
        qDebug() << "voting";
        handleVote(candidate, token,generateOneTimeToken(candidate,token));
    }

    void syncVotesToAllPeers() {
        for (QTcpSocket* peer : peers) {
            syncVotes(peer);
        }
    }

    void syncVotes(QTcpSocket *requestingPeer) {

        QSqlQuery q("SELECT candidate, token FROM votes;");
        while (q.next()) {
            QString line = QString("VOTE|%1|%2\n").arg(q.value(0).toString(), q.value(1).toString());
            requestingPeer->write(line.toUtf8());
        }

        QString hash = currentVoteHash();
        QList<QByteArray> slices = xorSplitSecret(hash.toUtf8(), 3);

        if (peers.size() < 3) {
            qWarning() << "Not enough peers to distribute hash slices securely.";
            // fallback: send all slices to the same peer (or skip)
            for (int i = 0; i < slices.size(); ++i)
                requestingPeer->write(QString("HASH_SLICE|%1|%2\n").arg(i).arg(QString(slices[i].toHex())).toUtf8());
            return;
        }

        QSqlQuery q1("SELECT token_hash FROM votes WHERE candidate = 'GENESIS' LIMIT 1;");
        if (q1.next()) {
            QString genesisHash = q1.value(0).toString();
            requestingPeer->write(QString("GENESIS_HASH|%1\n").arg(genesisHash).toUtf8());
        }

        // Randomly assign each slice to a different peer
        QList<QTcpSocket*> selectedPeers;
        while (selectedPeers.size() < 3) {
            QTcpSocket *peer = peers.at(QRandomGenerator::global()->bounded(peers.size()));
            if (!selectedPeers.contains(peer)) selectedPeers << peer;
        }

        for (int i = 0; i < slices.size(); ++i) {
            selectedPeers[i]->write(QString("HASH_SLICE|%1|%2\n").arg(i).arg(QString(slices[i].toHex())).toUtf8());
        }

        // Inform the requesting peer of sync time
        requestingPeer->write(QString("SYNC_TIME|%1\n").arg(QDateTime::currentDateTimeUtc().toString(Qt::ISODate)).toUtf8());
    }

    QString generateRandomToken(int length = 12) {
        const QString chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        QString token;
        for (int i = 0; i < length; ++i) {
            int index = QRandomGenerator::global()->bounded(chars.length());
            token += chars.at(index);
        }
        return token;
    }

    QString generateTokenPool2() {
      //  QSqlQuery query;
       // for (int i = 0; i < count; ++i) {
            QString raw = QString::number(QRandomGenerator::global()->generate64());
            QString hash = QString(QCryptographicHash::hash(raw.toUtf8(), QCryptographicHash::Sha256).toHex());
         //   query.prepare("INSERT INTO tokens (token, used) VALUES (?, 0);");
          //  query.addBindValue(hash);
       //     query.exec();
      //  }
            return hash;
    }

    bool isValidToken(const QString &token) {
        QString hash = hashToken(token);
        QSqlQuery q;
        q.prepare("SELECT used FROM tokens WHERE token_hash = ?;");
        q.addBindValue(hash);
        return q.exec() && q.next() && q.value(0).toInt() == 0;
    }

    void generateTokenPool(int count) {


        QSqlQuery clear;
        clear.exec("DELETE FROM tokens");
        clear.exec("DELETE FROM votes");

        //UID=generateRandomToken(10);// set then save
        const QString genesisMarker = UID; //"GENESIS";

        QString tokenHash = hashToken("genesis_seed_token");

        QSqlQuery check("SELECT COUNT(*) FROM votes;");
        if (check.next() && check.value(0).toInt() == 0) {
            QSqlQuery insert;
            insert.prepare("INSERT INTO votes (candidate, token_hash) VALUES (?, ?);");
            insert.addBindValue(genesisMarker);
            insert.addBindValue(tokenHash);
            insert.exec();
        }

        QString  fileName= QFileDialog::getSaveFileName(0, "Save tokens CSV file", QCoreApplication::applicationDirPath(), "CSV (*.csv);" );
        QFile file(fileName);
        // QFile file("tokens.csv");
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            QTextStream out(&file);
            for (int i = 0; i < count; ++i) {
                QString token = generateTokenPool2();//QUuid::createUuid().toString(QUuid::WithoutBraces);
                QString tokenHash = hashToken(token);
                QSqlQuery q;
                q.prepare("INSERT OR IGNORE INTO tokens (token_hash, used) VALUES (?, 0);");
                q.addBindValue(tokenHash);
                q.exec();
                out << token << ",\n";
                broadcastVote("",tokenHash);
            }
            out << "GENESIS:" << genesisMarker << ",\n";
        }

    }

    QString encryptCandidate(const QString &candidate, const QString &walletID) {
        QByteArray key = QCryptographicHash::hash(walletID.toUtf8(), QCryptographicHash::Sha256).left(16); // AES-128
        QByteArray iv = QCryptographicHash::hash("some-static-or-random-IV", QCryptographicHash::Sha256).left(16);

        QByteArray plain = candidate.toUtf8();
        QByteArray cipher;

        QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::CBC);
        cipher = encryption.encode(plain, key, iv);
        return cipher.toBase64();
    }

    QString decryptCandidate(const QString &encrypted, const QString &walletID) {
        QByteArray key = QCryptographicHash::hash(walletID.toUtf8(), QCryptographicHash::Sha256).left(16);
        QByteArray iv = QCryptographicHash::hash("some-static-or-random-IV", QCryptographicHash::Sha256).left(16);

        QByteArray cipher = QByteArray::fromBase64(encrypted.toUtf8());
        QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::CBC);
        QByteArray plain = encryption.decode(cipher, key, iv);
        return QString::fromUtf8(plain).trimmed();
    }


    QString encryptOwnership(const QString &walletSecret) {
        return QString(QCryptographicHash::hash(("owned" + walletSecret).toUtf8(), QCryptographicHash::Sha256).toHex());
    }

    bool verifyOwnership(const QString &candidateField, const QString &walletSecret) {
        return candidateField == encryptOwnership(walletSecret);
    }


    QString generateOneTimeToken(const QString &walletID, const QString &tokenHash) {
        //decrypt the one time token from the token later
        QString sharedSecret = tokenHash; // Example shared secret (Base32 encoded)
        TOTP totp(sharedSecret,SHA256);

        QString generatedCode = totp.generateTOTP();
       // qDebug() << "Generated TOTP Code: " << generatedCode;

        generatedCode = encryptCandidate (walletID +":" + generatedCode,tokenHash);
        return generatedCode;
    }

    void handleTransfer(const QString &token, const QString &senderSecret, const QString &receiverSecret) {
        //secret = walletid + TOTP
        QString tokenHash = token;//hashToken(token);

        QSqlQuery check;
        check.prepare("SELECT candidate FROM votes WHERE token_hash = ?;");
        check.addBindValue(tokenHash);
        if (!check.exec() || !check.next()) return;

        QString currentEncryptedOwner = check.value(0).toString();
       // if (!verifyOwnership(currentEncryptedOwner, senderSecret)) return;

     //   QString computedOwnership = QString(QCryptographicHash::hash((senderSecret + token).toUtf8(), QCryptographicHash::Sha256).toHex());
        QString computedOwnership = encryptCandidate(senderSecret,token);

        if (computedOwnership != currentEncryptedOwner) {
            qDebug() << " Ownership verification failed.";
            return;
        }

        QString newEncryptedOwner = encryptCandidate(receiverSecret,token);
        QSqlQuery update;
        update.prepare("UPDATE votes SET candidate = ? WHERE token_hash = ?;");
        update.addBindValue(newEncryptedOwner);
        update.addBindValue(tokenHash);
        update.exec();

        syncVotesToAllPeers();
    }


    QString hashToken(const QString &token) {
        return QString(QCryptographicHash::hash(token.toUtf8(), QCryptographicHash::Sha256).toHex());
    }

    void setupDatabase() {
        QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    #ifdef __APPLE__s
        db.setDatabaseName("/Applications/EVOTE.app/Contents/MacOS/peer_voting.db");
    #else
        db.setDatabaseName("peer_voting.db");
    #endif
        db.open();
        QSqlQuery query;
        query.exec("CREATE TABLE IF NOT EXISTS candidates (name TEXT UNIQUE);");
        query.exec("CREATE TABLE IF NOT EXISTS tokens (token_hash TEXT UNIQUE, used INTEGER);");
        query.exec("CREATE TABLE IF NOT EXISTS votes (candidate TEXT, token_hash TEXT UNIQUE);");
    }

    QStringList getCandidates() {
        QStringList list;
        QSqlQuery query("SELECT name FROM candidates;");
        while (query.next()) {
            list << query.value(0).toString();
        }
        return list;
    }

    QStringList exportVotesToCSV(const QString &filename) {
        QStringList lines;
        QFile file(filename);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << "candidate,token\n";

            QSqlQuery query("SELECT candidate, token FROM votes;");
            while (query.next()) {
                QString line = QString("%1,%2").arg(query.value(0).toString(), query.value(1).toString());
                out << line << "\n";
                lines << line;
            }

            file.close();
        }
        return lines;
    }

    QString getUnusedToken() {
        QSqlQuery query("SELECT tokens FROM tokens WHERE used = 0 LIMIT 1;");
        if (query.next()) {
            QString token = query.value(0).toString();

            QSqlQuery update;
            update.prepare("UPDATE tokens SET used = 1 WHERE token = ?;");
            update.addBindValue(token);
            update.exec();

            return token;
        }
        return QString(); // no available token
    }

    void savePeersToFile() {
        #ifdef __APPLE__
            QFile file("/Applications/EVOTE.app/Contents/MacOS/peers.txt");
        #else
            QFile file("peers.txt");
        #endif
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            QTextStream out(&file);
            for (const QString &addr : connectedPeers)
                out << addr << "\n";
        }
    }

    void loadPeersFromFile() {
        #ifdef __APPLE__
            QFile file("/Applications/EVOTE.app/Contents/MacOS/peers.txt");
        #else
            QFile file("peers.txt");
        #endif
        if (file.open(QIODevice::ReadOnly)) {
            QStringList lines;
            QTextStream in(&file);
            while (!in.atEnd()) {
                QString line = in.readLine().trimmed();
                if (!line.isEmpty() && !connectedPeers.contains(line)) {
                    lines.append(line);
                }
            }

            // Shuffle to avoid same peer order on every startup
            auto rng = QRandomGenerator::global(); // This is the engine
            std::shuffle(lines.begin(), lines.end(), *rng);

            for (const QString &line : lines) {
                QStringList hostPort = line.split(":");
                if (hostPort.size() == 2)
                    connectToPeer(hostPort[0], hostPort[1].toInt());
            }
        }
    }

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
           // if (parts.size() == 3 && parts[0] == "VOTE") {
           //     receivedVotes.insert(line);
           // } else
            if (parts.size() == 2 && parts[0] == "PEER") {
                QStringList hostPort = parts[1].split(":");
                if (hostPort.size() == 2) connectToPeer(hostPort[0], hostPort[1].toInt());
            } else if (parts[0] == "SYNC_REQUEST" && parts.size() == 2) {
                QString peerUid = parts[1];
                qDebug() << "Received SYNC request from peer UID:" << peerUid;
                syncVotes(socket);
            } else if (parts.size() == 3 && parts[0] == "SYNC_HASH") {
                futureHashes[parts[1]].insert(parts[2]);
                invalidHashCounts[parts[2]]++;
            } else if (parts[0] == "VOTE" && parts.size() == 3) {
                QString key = parts[1] + "|" + parts[2]; // candidate|token
                receivedVoteSources[key].insert(socket->peerAddress().toString());
                if (receivedVoteSources[key].size() >= 3) {
                    handleVote(parts[1], parts[2],generateOneTimeToken(parts[1]+parts[2],parts[2])); // Only accept after 3 peers agree could be higher
                }
            } else if (parts[0] == "HASH_SLICE" && parts.size() == 3) {
                int index = parts[1].toInt();
                QByteArray slice = QByteArray::fromHex(parts[2].toUtf8());
                sliceVotes[index][slice]++;
                if (sliceVotes[index][slice] >= 2) { // e.g., 2+ peers agree on this slice
                    hashSlices[index] = slice;
                }
            } else if (parts[0] == "GENESIS_HASH" && parts.size() == 2) {
                QString incomingHash = parts[1];
                QSqlQuery q("SELECT token_hash FROM votes WHERE candidate = 'GENESIS' LIMIT 1;");
                if (q.next()) {
                    QString localHash = q.value(0).toString();
                    if (localHash != incomingHash) {
                        qDebug() << " Genesis hash mismatch. Possible fork or unauthorized database.";
                        socket->disconnectFromHost();  // or flag the peer
                    }
                }
            } else if (parts[0] == "TRANSFER" && parts.size() == 5) {
                QString from = parts[1];
                QString to = parts[2];
                QString token = parts[3];
                TOTP totp(sharedSecret,SHA256,30);

                bool isValid = totp.verifyTOTP(parts[4]);
                qDebug() << "TOTP verification result: " << (isValid ? "Valid" : "Invalid");
                if (isValid){
                    //handleVote();//
                    //transferVote(from, to, token);
                }
            }


        }
    }

    QStringList findMyVotes(const QString &walletID) {
        QSqlQuery q("SELECT candidate, token_hash FROM votes;");
        QStringList myTokens;

        while (q.next()) {
            QString encCandidate = q.value(0).toString();
            QString tokenHash = q.value(1).toString();

            // Decrypt candidate field
           QString decrypted = decryptCandidate(encCandidate, tokenHash); // You’ll define this

            // Check if it matches walletID
            if (decrypted.startsWith(walletID + ":")) {
                myTokens.append(tokenHash); // or store whole record
            }
        }

        return myTokens;
    }

    void handleVote(const QString candidate, const QString token,QString ott) { // maybe use qstringlist for multiple tokens
        QString hash = hashToken(token);
        if (!isValidToken(token) && candidate != "") return;

        QString finalCandidate;
         if (candidate != ""){
            finalCandidate = ott;//candidate;
         }else{
            finalCandidate = candidate;
         }
           // if (!ott.isEmpty()) {
             //   finalCandidate = encryptCandidate(candidate + ":" + ott, token);
          //  }

        QSqlQuery insert;
        insert.prepare("INSERT INTO votes (candidate, token_hash) VALUES (?, ?);");
        insert.addBindValue(finalCandidate);
        insert.addBindValue(hash);
        if (insert.exec()) {
            QSqlQuery mark;
            mark.prepare("UPDATE tokens SET used = 1 WHERE token_hash = ?;");
            mark.addBindValue(hash);
            mark.exec();
        }
        syncVotesToAllPeers();
    }


    void performSync() {
        if (hashSlices.size() == 3) {
            QList<QByteArray> slices = { hashSlices[0], hashSlices[1], hashSlices[2] };
            QByteArray reconstructed = xorJoinSecret(slices);
            if (reconstructed == currentVoteHash().toUtf8()) {
                qDebug() << "Sync verification passed.";
            } else {
                qDebug() << "WARNING: Sync hash mismatch.";
            }
            hashSlices.clear();
        }
    }

    QList<QByteArray> xorSplitSecret(const QByteArray &secret, int n) {
        QList<QByteArray> parts;
        int len = secret.size();
        for (int i = 0; i < n - 1; ++i) {
            QByteArray randPart;
            for (int j = 0; j < len; ++j)
                randPart.append(QRandomGenerator::global()->generate() & 0xFF);
            parts.append(randPart);
        }
        QByteArray last = secret;
        for (const QByteArray &p : parts)
            for (int i = 0; i < len; ++i)
                last[i] = last[i] ^ p[i];
        parts.append(last);
        return parts;
    }

    QByteArray xorJoinSecret(const QList<QByteArray> &parts) {
        if (parts.isEmpty()) return {};
        QByteArray result = parts[0];
        for (int i = 1; i < parts.size(); ++i)
            for (int j = 0; j < result.size(); ++j)
                result[j] = result[j] ^ parts[i][j];
        return result;
    }

    QString currentVoteHash() {
        QSqlQuery q("SELECT candidate, token_hash FROM votes ORDER BY candidate, token_hash;");
        QByteArray data;
        while (q.next()) {
            data.append(q.value(0).toString() + q.value(1).toString());
        }
        return QString(QCryptographicHash::hash(data, QCryptographicHash::Md5).toHex());
    }

public:
    QMap<QString, QSet<QString>> receivedVoteSources;
    QMap<int, QMap<QByteArray, int>> sliceVotes; // slice index -> hash -> count
    QString UID;
private:
    QTcpServer *server;
    QList<QTcpSocket *> peers;
    QSet<QString> connectedPeers;
    int maxPeers;
    QSet<QString> receivedVotes;
    QMap<QString, QSet<QString>> futureHashes;
    QMap<QString, int> invalidHashCounts;
    QMap<int, QByteArray> hashSlices;

    QTimer *syncTimer;

};

class VotingApp : public QWidget {
    Q_OBJECT

public:
    VotingApp(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("Decentralized");
        resize(400, 300);

        peer = new PeerNode(this);
        peer->UID = qrand() % 1000; //"5555";
        peer->setupDatabase();
        peer->loadPeersFromFile();
        QVBoxLayout *layout = new QVBoxLayout(this);

        candidateBox = new QComboBox;
        candidateBox->addItems(peer->getCandidates());

        QPushButton *refreshCandidates = new QPushButton("Refresh Candidates");
        QPushButton *addCandidate = new QPushButton("Add Candidate");
        QPushButton *generateTokens = new QPushButton("Generate Tokens");
        QPushButton *voteButton = new QPushButton("Vote");
        QPushButton *connectBtn = new QPushButton("Connect to Peer");
        QPushButton *Generatewalletbtn = new QPushButton("Generate Wallet");

        QPushButton *transferBtn = new QPushButton("Transfer");

        newCandidateInput = new QLineEdit;
        newCandidateInput->setPlaceholderText("New Candidate Name");

        QSplitter *splitter = new QSplitter;
        QSplitter *splitter2 = new QSplitter;
        QSplitter *splitter3 = new QSplitter;
        QSplitter *splitter4 = new QSplitter;
        QSplitter *splitter5 = new QSplitter;
        QSplitter *splitter6 = new QSplitter;

        QLineEdit *Toaddressedit = new QLineEdit;
        QLineEdit *Fromaddressedit = new QLineEdit;
        Toaddressedit->setPlaceholderText("To Address");
        Fromaddressedit->setPlaceholderText("From tokenID");

        QLabel *Tolbl = new QLabel;
        QLabel *Fromlbl = new QLabel;
        Tolbl->setText("To Address");
        Fromlbl->setText("From tokenID");

        tokenInput = new QLineEdit;
        tokenInput->setPlaceholderText("Vote Token");

        peerInput = new QLineEdit;
        peerInput->setPlaceholderText("Peer IP Address");

        layout->addWidget(candidateBox);

        splitter6->addWidget(newCandidateInput);
        splitter6->addWidget(Generatewalletbtn);
        layout->addWidget(splitter6);

        layout->addWidget(tokenInput);

        splitter2->addWidget(Fromlbl);
        splitter2->addWidget(Fromaddressedit);
        layout->addWidget(splitter2);

        splitter->addWidget(Tolbl);
        splitter->addWidget(Toaddressedit);
        layout->addWidget(splitter);

        splitter4->addWidget(transferBtn);
        splitter4->addWidget(voteButton);
        layout->addWidget(splitter4);

        splitter5->addWidget(refreshCandidates);
        splitter5->addWidget(addCandidate);
        layout->addWidget(splitter5);

        splitter3->addWidget(connectBtn);
        splitter3->addWidget(peerInput);
        layout->addWidget(splitter3);



        layout->addWidget(generateTokens);



        connect(Generatewalletbtn, &QPushButton::clicked, this, [=]() {
           newCandidateInput->setText(peer->generateRandomToken(12));
        });





        QTimer *cleanupTimer = new QTimer(this);
        connect(cleanupTimer, &QTimer::timeout, this, [=]() {
            peer->receivedVoteSources.clear();
            peer->sliceVotes.clear();
        });
        cleanupTimer->start(300000); // Clear every 5 minutes


        connect(generateTokens, &QPushButton::clicked, this, [=]() {
             peer->handleTransfer(tokenInput->text(), Fromaddressedit->text(), peer->generateOneTimeToken(Toaddressedit->text(),tokenInput->text()) );; //
        });


        connect(refreshCandidates, &QPushButton::clicked, this, [=]() {
            candidateBox->clear();
            candidateBox->addItems(peer->getCandidates());
        });

        connect(addCandidate, &QPushButton::clicked, this, [=]() {
            QString name = newCandidateInput->text();
            QSqlQuery q;
            q.prepare("INSERT INTO candidates (name) VALUES (?);");
            q.addBindValue(name);
            if (q.exec()) candidateBox->addItem(name);
        });

        connect(generateTokens, &QPushButton::clicked, this, [=]() {
            peer->generateTokenPool(10);
        });

        connect(voteButton, &QPushButton::clicked, this, [=]() {
            peer->broadcastVote(candidateBox->currentText(), tokenInput->text());
        });

        connect(connectBtn, &QPushButton::clicked, this, [=]() {
            peer->connectToPeer(peerInput->text());
        });
    }

private:
    PeerNode *peer;
    QComboBox *candidateBox;
    QLineEdit *newCandidateInput, *tokenInput, *peerInput;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    VotingApp window;
    window.show();
    return app.exec();
}

#include "main.moc"
