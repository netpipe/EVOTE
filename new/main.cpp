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
#include "HTOP.h"

//todo
//? otp:encrypted(otp),token with walletID for challange string they keep otp and find own coins by decrypting and comparing
//? maybe TOTP verification can be randomized and sent perodically between connected peers
//? 2 passwords sender secret and walletID + password. password can decrypt the sender secret or walletId:token hash compare to find all votes
//
//1 handleTransfer needs amount feature working
//2 peers sync need testing refinement
//3
// maybe use 2 otp's one for storing and keeping the other topt for sending and verifying
//first to spend token on network basically gets the TOTP into the blockchain first to prevent double spend attacks. prove that you have wallet id with deposit address from it. maybe use shared public key openssl.

QString walletID;
QString ewalletID;
int ctokens;
QComboBox *candidateBox;

QString sharedSecret = "TESTING1234"; // Example shared secret (Base32 encoded) 2FA
QString secret = "MY_SHARED_SECRET";
QString input = "MySecondaryPassword";

int PORT = 5555;

QCommandLineParser parser;
QCommandLineOption voteOpt("vote", "vote");
QCommandLineOption generateOpt("generate", "generate");
QCommandLineOption transferOpt("transfer", "transfer");
QCommandLineOption getBalanceOpt("balance", "balance");
QCommandLineOption headlessOpt("headless", "Run without GUI");
QCommandLineOption walletIDOpt("walletID", "from address");
QCommandLineOption toOpt("to", "to address");

class PeerNode : public QObject {
    Q_OBJECT

public:
    PeerNode(QObject *parent = nullptr) : QObject(parent), maxPeers(5) {
        UID="1234";
        server = new QTcpServer(this);
        connect(server, &QTcpServer::newConnection, this, &PeerNode::handleConnection);
        server->listen(QHostAddress::Any, PORT);
       // QSslSocket::supportsSsl();
        syncTimer = new QTimer(this);
        connect(syncTimer, &QTimer::timeout, this, &PeerNode::performSync);
        syncTimer->start(100000); // Synchronize every 100 seconds
    }
#include "encrypt.h" // has encryption stuff + save/load peerslist

    void connectToPeer(const QString &host, int port = PORT) {
        if (peers.size() >= maxPeers) return;
        QString address = QString("%1:%2").arg(host).arg(port);
        if (connectedPeers.contains(address)) return;

        QTcpSocket *socket = new QTcpSocket(this);
        socket->connectToHost(host, port);
        connect(socket, &QTcpSocket::readyRead, this, [=]() { handleData(socket); });
        connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
        peers.append(socket);
        connectedPeers.insert(address); //check if peers still connected later
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

        // check weather syncVotes or to do your own SYNC_HASH here
        handleVote(candidate, token,generateOneTimeToken(candidate,token));

    }

    void broadcastTransfer(const QString &candidate, QString receiver,const QString &token,QString &totp) {
        QString message = QString("TRANSFER|%1|%2|%3|%4\n").arg(candidate,receiver, token,totp);
        for (QTcpSocket *peer : peers) {
            peer->write(message.toUtf8());
        }
        qDebug() << "Transfering";

        // check weather syncVotes or to do your own SYNC_HASH here
      //  handleVote(candidate, token,generateOneTimeToken(candidate,token));

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

    bool isValidToken(const QString &token) {
        QString hash = hashToken(token);
        QSqlQuery q;
        q.prepare("SELECT used FROM tokens WHERE token_hash = ?;");
        q.addBindValue(hash);
        return q.exec() && q.next() && q.value(0).toInt() == 0;
    }

    bool isValidCandidate(const QString &token) { //check if is used too
      //  QString hash = hashToken(token);
        QSqlQuery q;
        q.prepare("SELECT candidate FROM votes WHERE candidate = ?;");
        q.addBindValue(token);
        return q.exec() && q.next() && q.value(0) == "";
    }

    bool isValidTokenHash(const QString &token) {
      //  QString hash = hashToken(token);
        QSqlQuery q;
        q.prepare("SELECT token_hash FROM votes WHERE token_hash = ?;");
        q.addBindValue(token);
        return q.exec() && q.next() && q.value(0) == "";
    }

    void generateTokenPool(int count) {


        QSqlQuery clear;
        clear.exec("DELETE FROM tokens");
        clear.exec("DELETE FROM votes");

        //UID=generateRandomToken(10);// set then save
        const QString genesisMarker = "GENESIS";

       // QString tokenHash = hashToken("genesis_seed_token");
        QString tokenHash = hashToken(UID);

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
            out << "GENESIS:" << UID.toInt() << ",\n";
        }
        broadcastVote("SYNC_HASH",currentVoteHash());// broadcast votehash
    }

    QStringList getVotes(QString walletID2) { //gets them from wallets instead of votes list
        QSqlQuery query;
        QStringList Test;
        //maybe use walletID to decrypt the secondary TOPT to claim tokens ?
        query.prepare("SELECT * FROM candidates WHERE name = :name");
        query.bindValue(":name", walletID2);

        if (query.next()) {
            Test.append(query.value(1).toString());

            //might not need this if it puts the second encrypted otp in the findmyvotes function //
          //  QString otpenc = query.value(1).toString();
           // QString decrypted = xorStrings(QString::fromUtf8(QByteArray::fromHex(otpenc.toUtf8())), walletID);  // → original
            verifyOwnership(query.value(0).toString(),query.value(1).toString(),walletID2); // name aka walletID , totp , your ewalletid
            // Check if it matches walletID
           // if (decrypted.startsWith(walletID + ":")) {
            //    .append(tokenHash); // or store whole record
                            //get second half of otp
           // }

            //return query.value(0).toInt(); // Return the number of remaining tokens
        }
    return Test;
      //  return 0; // In case no tokens are left
    }

    void handleTransfer(const QString &token, const QString &senderSecret, const QString &receiverSecret,QString totp,int amount) {

        QStringList availableTokens;
        QStringList TTokens;
        if (amount >=1 ){
            availableTokens =  getVotes(ewalletID);// get walletid tokens left in local wallet
            if (availableTokens.size() >= amount){
                for (int i=0;availableTokens.size() != amount;i++){
                    TTokens.append(availableTokens[i]);
                }
            }else {
                qDebug() << "";
            }


        }

        //secret = walletid + TOTP
        QString tokenHash;//
        if (totp==""){ // if sending just existing tokenhash
            totp = generateOneTimeToken(receiverSecret,token);
        }

        if (tokenHash==""){
            tokenHash = token;
        }else{


            tokenHash = hashToken(token); //encryptCandidate(generateOneTimeToken(senderSecret,token),senderSecret);//hashToken(token);
        }

        QSqlQuery check;
        check.prepare("SELECT candidate FROM votes WHERE token_hash = ?;");
        check.addBindValue(tokenHash);
        if (!check.exec() || !check.next()) return;

        //QString currentEncryptedOwner = check.value(0).toString();
       // if (!verifyOwnership(currentEncryptedOwner, senderSecret)) return;
       // QString computedOwnership = QString(QCryptographicHash::hash((senderSecret + token).toUtf8(), QCryptographicHash::Sha256).toHex());
       // QString computedOwnership = encryptCandidate(generateOneTimeToken(senderSecret,token),senderSecret); //xorStrings(senderSecret,token); //encryptCandidate(senderSecret,token);
        //QString computedOwnership = encryptOwnership(ewalletID,totp);
        //  if (computedOwnership != currentEncryptedOwner) {
        //      qDebug() << " Ownership verification failed.";
        //      return;
        //  }


        if ( HOTPVerify(totp,check.value(0).toString(),encryptOwnership(ewalletID,totp))) {
            qDebug() << " Ownership verification failed.";
            return;
        }


       // QString newEncryptedOwner =  xorStrings(receiverSecret,token); //encryptCandidate(receiverSecret,token);
        QString newEncryptedOwner =  encryptOwnership(receiverSecret,totp); // receiverSecret aka ewalletID //encryptCandidate(receiverSecret,token);
        QSqlQuery update;
        update.prepare("UPDATE votes SET candidate = ? WHERE token_hash = ?;");
        update.addBindValue(newEncryptedOwner);
        update.addBindValue(tokenHash);
        update.exec();

       // syncVotesToAllPeers(); // maybe just broascast vote and only sync if issues or amount is over 10 ?
        broadcastTransfer(check.value(0).toString(),receiverSecret,tokenHash,totp);
    }




    void setupDatabase() {
        QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
        db.setDatabaseName(QCoreApplication::applicationDirPath() + "/peer_voting.db");

        db.open();
        QSqlQuery query;
        query.exec("CREATE TABLE IF NOT EXISTS candidates (name TEXT UNIQUE,tokenID TEXT UNIQUE,tokenHash TEXT UNIQUE);");
        query.exec("CREATE TABLE IF NOT EXISTS tokens (token_hash TEXT UNIQUE, used INTEGER);");
        query.exec("CREATE TABLE IF NOT EXISTS votes (candidate TEXT, token_hash TEXT UNIQUE);");
    }

    QStringList getCandidates() {
        QStringList list;
        QSqlQuery query("SELECT DISTINCT name FROM candidates;");
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

    QString getUnusedToken(QString walletID) { //unfinished
        QSqlQuery query("SELECT tokenID FROM candidates WHERE ;");
        if (query.next()) {
            QString token = query.value(0).toString();
            return token;
        }
        return QString(); // no available token
    }

    QStringList findMyTokens(const QString &walletID2) {
        QSqlQuery q("SELECT candidate, token_hash,TOTP FROM votes;");//maybe add encrypted TOTP to votes so that it can verify its ownership
        QStringList myTokens;
        ctokens=0;
        while (q.next()) {
            QString encCandidate = q.value(0).toString();
            QString tokenHash = q.value(1).toString();
            QString TOTP = q.value(2).toString();
            // Decrypt candidate field walletID encrypted TOTP
         //  QString decrypted = encryptOwnership(encCandidate,walletID2);
           //QString decrypted = decryptCandidate(encCandidate, walletID); // You’ll define this maybe we'll use XOR for speed
            //QString decrypted = xorStrings(encCandidate,walletID);
           // QString decrypted = xorStrings(QString::fromUtf8(QByteArray::fromHex(encCandidate.toUtf8())), walletID);  // → original

            // Check if it matches walletID
             if(HOTPVerify(encCandidate,encryptOwnership(walletID2,TOTP),TOTP)){ // maybe use TOTP list that you redeemed and check all of them against each hash slowly narrowing them down or maybe making a map of them too.

               QSqlQuery q;
               q.prepare("INSERT INTO candidates (name) (token_hash) (TOTP) VALUES (?);");
               q.addBindValue(encCandidate);
               q.addBindValue(tokenHash);
               q.addBindValue(TOTP);

               if (q.exec()) {}
          //  if (decrypted.startsWith(walletID + ":")) {  // if OTP matches then append the token to your wallet list
                myTokens.append(tokenHash); // or store whole record
                ctokens++;
               //}
                }
        }
        return myTokens;
    }

    bool addWallet(QString Candidate){
        bool ok;
        QString text = QInputDialog::getText(0, "Password",
                                             "New Password:", QLineEdit::Normal,
                                             "", &ok);
        QString name = encryptCandidate(Candidate, text);

        if (ok && !text.isEmpty()) {
        QSqlQuery q;
        q.prepare("INSERT INTO candidates (name) VALUES (?);");
        q.addBindValue(name);
        if (q.exec()) candidateBox->addItem(name);

        }

        if (0){ //save password
            QString  fileName= QFileDialog::getSaveFileName(0, "Save userfile", QCoreApplication::applicationDirPath(), "txt (*.txt);" );
            QFile file(fileName);
            if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                QTextStream out(&file);
                out << name << ":" << text << "\n";
            }
        }
    }

    bool HOTPVerify(QString original, QString test,QString Password){
            //verify
            StringHOTP verifier(original, StringHOTP::SHA1,9);
            QString expectedOtp = verifier.generateOTP(Password);

            if (test == expectedOtp) {
                qDebug() << "OTP valid!";
                return 1;
            } else {
                qDebug() << "Invalid OTP!";
                return 0;
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
                    handleVote(parts[1], parts[2],""); // Only accept after 3 peers agree could be higher
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
            } else if (parts[0] == "TRANSFER" && parts.size() == 6) { // from , to , token
                QString from = parts[1];
                QString to = parts[2];
                QString token = parts[3];
                int amount = parts[5].toInt();

                TOTP totp(parts[3],SHA256,30);

                // from unlock code compare to old token

                bool isValid = totp.verifyTOTP(parts[4]);
                qDebug() << "TOTP verification result: " << (isValid ? "Valid" : "Invalid");
                if (isValid){
                    handleTransfer(token,from, to,parts[4],amount);
                }
            }

        }
    }

    void handleVote(const QString candidate, const QString token,QString ott) { // maybe use qstringlist for multiple tokens
        QString hash;
        QString walletID3;
        QString finalCandidate;

        hash=token;
        //if ott is blank then candidate is the walletID encrypted OTP
         if (candidate != ""){
             if (ott == ""){   //SYNC_HASH
               finalCandidate = candidate;
               //finalCandidate = encryptCandidate(ott, walletID);
             }else{ // check ott for candidate if candidate blank. for used
                 finalCandidate = ott;
                 //if (!isValidCandidate(finalCandidate) && candidate != "") return;
             }
         }else{ // if candidate blank use ott with your ewalletid
            hash = hashToken(token);

            StringHOTP hotpSha256(ott, StringHOTP::SHA1,9);
            finalCandidate = hotpSha256.generateOTP(encryptOwnership(candidate,ott)); //ewalletID:TOPT provides user and protection for more security it could be hashed

            // check if token valid
            if (!isValidTokenHash(hash) && candidate != "") return;
         }




        QSqlQuery insert;
        insert.prepare("INSERT INTO votes (candidate, token_hash) VALUES (?, ?);");
        insert.addBindValue(finalCandidate);
        insert.addBindValue(hash);
        if (insert.exec()) {
      //      QSqlQuery mark;
      //      mark.prepare("UPDATE tokens SET used = 1 WHERE token_hash = ?;");
      //      mark.addBindValue(hash);
      //      mark.exec();
        }

        //it already broadcasted so just do our own addition + hashchecking and new SYNC_HASH compare
       // syncVotesToAllPeers(); // overkill for simple vote broadcasting
        ///maybe xor the ewalletid by the otp to make searching faster.
    }

    void performSync() {
        if (hashSlices.size() == 3) {
            QList<QByteArray> slices = { hashSlices[0], hashSlices[1], hashSlices[2] };
            QByteArray reconstructed = xorJoinSecret(slices);
            if (reconstructed == currentVoteHash().toUtf8()) {
                qDebug() << "Sync verification passed.";
            } else {
               // QMessageBox::information (0, "Test",  QString("Test %1").arg(QString::number(test1)));
                qDebug() << "WARNING: Sync hash mismatch.";
            }
            hashSlices.clear();
        }
    }

    QString currentVoteHash() {
       // QSqlQuery q("SELECT candidate, token_hash FROM votes ORDER BY candidate, token_hash");
        QSqlQuery q("SELECT candidate, token_hash FROM votes WHERE candidate IS NOT NULL AND candidate != '' AND candidate != 'SYNC_HASH' ORDER BY candidate, token_hash;");

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
        peer->UID = QString::number(qrand() % 10000);;
        peer->setupDatabase();
        peer->loadPeersFromFile();
        QVBoxLayout *layout = new QVBoxLayout(this);

        candidateBox = new QComboBox;
        candidateBox->addItems(peer->getCandidates());

        QPushButton *refreshCandidates = new QPushButton("Refresh Wallets");
        QPushButton *addCandidate = new QPushButton("Add Wallet");
        QPushButton *generateTokens = new QPushButton("Generate Tokens");
        QPushButton *voteButton = new QPushButton("Vote");
        QPushButton *connectBtn = new QPushButton("Connect to Peer");
        QPushButton *Generatewalletbtn = new QPushButton("Generate WalletName");
        QPushButton *FindTokensbtn = new QPushButton("Search Wallet");

        QPushButton *transferBtn = new QPushButton("Transfer");

        newCandidateInput = new QLineEdit;
        newCandidateInput->setPlaceholderText("New Candidate Name");

        QSplitter *splitter = new QSplitter;
        QSplitter *splitter2 = new QSplitter;
        QSplitter *splitter3 = new QSplitter;
        QSplitter *splitter4 = new QSplitter;
        QSplitter *splitter5 = new QSplitter;
        QSplitter *splitter6 = new QSplitter;
        QSplitter *splitter7 = new QSplitter;
        QSplitter *splitter8 = new QSplitter;
        QSplitter *splitter9 = new QSplitter;

        QLineEdit *Toaddressedit = new QLineEdit;
        QLineEdit *Fromaddressedit = new QLineEdit;
        QLineEdit *amountEdt = new QLineEdit;
        Toaddressedit->setPlaceholderText("To Address");
        Fromaddressedit->setPlaceholderText("From tokenID");

        QLabel *Tolbl = new QLabel;
        QLabel *Fromlbl = new QLabel;
        QLabel *amountlbl  = new QLabel;
        QLabel *walletIDlbl  = new QLabel;
        QLabel *walletIDlbl2  = new QLabel;
        amountlbl->setText("amount");
        walletIDlbl->setText("WalletID");
        walletIDlbl2->setText("Generated WalletID or Name");

        QFrame *line = new QFrame();
        line->setFrameShape(QFrame::HLine);
        line->setFrameShadow(QFrame::Sunken);

        QFrame *line2 = new QFrame();
        line2->setFrameShape(QFrame::HLine);
        line2->setFrameShadow(QFrame::Sunken);

        Tolbl->setText("To Address");
        Fromlbl->setText("From address");

        tokenInput = new QLineEdit;
        tokenInput->setPlaceholderText("Vote Token");

        peerInput = new QLineEdit;
        peerInput->setPlaceholderText("Peer IP Address");

        splitter9->addWidget(walletIDlbl);
        splitter9->addWidget(candidateBox);

         layout->addWidget(splitter9);

        splitter6->addWidget(walletIDlbl2);
        splitter6->addWidget(newCandidateInput);
        layout->addWidget(splitter6);   //

        splitter7->addWidget(amountlbl);
        splitter7->addWidget(amountEdt);
        splitter4->addWidget(splitter7);    //ammount

        splitter8->addWidget(tokenInput);
        splitter8->addWidget(voteButton);
        layout->addWidget(splitter8);   // Vote

        splitter5->addWidget(Generatewalletbtn);
                //splitter5->addWidget(refreshCandidates);
        splitter5->addWidget(addCandidate);
        splitter5->addWidget(FindTokensbtn);
        layout->addWidget(splitter5);   // wallet functions

        layout->addWidget(line);

        splitter2->addWidget(Fromlbl);
        splitter2->addWidget(Fromaddressedit);
        layout->addWidget(splitter2);   //from address

        splitter->addWidget(Tolbl);
        splitter->addWidget(Toaddressedit);
        layout->addWidget(splitter);    //to address

        splitter4->addWidget(transferBtn);
        layout->addWidget(splitter4);   //transfer

        splitter3->addWidget(connectBtn);
        splitter3->addWidget(peerInput);
        layout->addWidget(splitter3); // peer connect

        layout->addWidget(line2); //line

        layout->addWidget(generateTokens);

        if (parser.isSet(voteOpt)) {
            qDebug() << "vote.";   }

        if (parser.isSet(generateOpt)) {
            qDebug() << "generateOpt.";   }

        if (parser.isSet(getBalanceOpt) && parser.isSet(walletIDOpt)) {
            qDebug() << "getBalanceOpt.";   }

        if (parser.isSet(transferOpt) && parser.isSet(toOpt) && parser.isSet(walletIDOpt)) {
            qDebug() << "transferOpt.";   }


        QObject::connect(candidateBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [=](int index){
                QString selected = candidateBox->itemText(index);
               newCandidateInput->setText(selected) ; // You can call with actual selected text
               walletID= selected;
               ewalletID= peer->encryptCandidate(selected,walletID);
            });

        connect(Generatewalletbtn, &QPushButton::clicked, this, [=]() {
           newCandidateInput->setText(peer->generateRandomToken(12));
        });

        QTimer *cleanupTimer = new QTimer(this);
        connect(cleanupTimer, &QTimer::timeout, this, [=]() {
            peer->receivedVoteSources.clear();
            peer->sliceVotes.clear();

            candidateBox->clear();
            candidateBox->addItems(peer->getCandidates());
        });
        cleanupTimer->start(300000); // Clear every 5 minutes

       // candidateBox->addItems(peer->getCandidates());
        if (!candidateBox->size().isEmpty() ){
        candidateBox->setCurrentIndex(1);
        candidateBox->setCurrentIndex(0);
       // candidateBox->setCurrentIndex(0);
        }

        connect(transferBtn, &QPushButton::clicked, this, [=]() {
            QMessageBox::StandardButton reply;
            reply = QMessageBox::question(0, "Question Are You Sure", "Transfer?",
                                          QMessageBox::Yes|QMessageBox::No);
            if (reply == QMessageBox::Yes) {
             peer->handleTransfer(tokenInput->text(), Fromaddressedit->text(), Toaddressedit->text() ,"",amountEdt->text().toInt());
            }
        });

       // connect(refreshCandidates, &QPushButton::clicked, this, [=]() {
       //     candidateBox->clear();
       //     candidateBox->addItems(peer->getCandidates());
       // });

        connect(addCandidate, &QPushButton::clicked, this, [=]() {
            peer->addWallet(newCandidateInput->text());
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

        connect(FindTokensbtn, &QPushButton::clicked, this, [=]() {
            peer->findMyTokens(ewalletID);//candidateBox->currentText());
        });
    }

private:
    PeerNode *peer;
    QLineEdit *newCandidateInput, *tokenInput, *peerInput;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);


    parser.setApplicationDescription("Decentralized");
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
        return 0;   }

    window.show();
    return app.exec();
}

#include "main.moc"
