#include <QCoreApplication>
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QSslSocket>
#include <QTcpServer>
#include <QDebug>
#include <QDateTime>
#include <QHostInfo>
#include <QCryptographicHash>
#include <QFile>
#include <qlist.h>

QTcpServer *server;
QList<QTcpSocket *> peers;

//when broadcasting vote it might need time limit also a way to see if it got updated to a master list ?

struct Peers2 {
    QString ip;
    int port;
    QString hash;

    Peers2(const QString& ipAddress, int p) : ip(ipAddress), port(p) {
        hash = generatePeerHash(ip, port);
    }

    QString generatePeerHash(const QString& ip, int port) {
        return QString(QCryptographicHash::hash((ip + QString::number(port)).toUtf8(), QCryptographicHash::Sha256).toHex());
    }
};

QList<Peers2> peers2 = {
    Peers2("192.168.1.1", 5555),
    Peers2("192.168.1.2", 5556),
    Peers2("192.168.1.3", 5557),
    Peers2("192.168.1.4", 5558)
};



QString generateHash(const QString &data) {
    return QString(QCryptographicHash::hash(data.toUtf8(), QCryptographicHash::Sha256).toHex());
}

void setupDatabase() {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("voting_platform.db");

    if (!db.open()) {
        qDebug() << "Database error: " << db.lastError().text();
        return;
    }

    QSqlQuery query;
    query.exec("CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE);");
    query.exec("CREATE TABLE IF NOT EXISTS topics (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, category_id INTEGER, description TEXT, status TEXT, end_date TEXT, vote_limit INTEGER, FOREIGN KEY(category_id) REFERENCES categories(id));");
    query.exec("CREATE TABLE IF NOT EXISTS votes (id INTEGER PRIMARY KEY AUTOINCREMENT, topic_id INTEGER, user TEXT, ip_address TEXT, vote INTEGER, hash TEXT, FOREIGN KEY(topic_id) REFERENCES topics(id));");
    query.exec("CREATE TABLE IF NOT EXISTS moderators (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT);");
    query.exec("CREATE TABLE IF NOT EXISTS ip_list (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT UNIQUE);");
    query.exec("CREATE TABLE IF NOT EXISTS peers (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT UNIQUE, port INTEGER, hash TEXT);");
}

void addPeer(const QString &ip, int port) {
    QString peerHash = generateHash(ip + QString::number(port));
    QSqlQuery query;
    query.prepare("INSERT OR IGNORE INTO peers (ip_address, port, hash) VALUES (?, ?, ?);");
    query.addBindValue(ip);
    query.addBindValue(port);
    query.addBindValue(peerHash);
    query.exec();
}

bool validatePeer(const QString &ip, int port, const QString &peerHash) {
    QSqlQuery query;
    query.prepare("SELECT hash FROM peers WHERE ip_address = ? AND port = ?;");
    query.addBindValue(ip);
    query.addBindValue(port);
    if (query.exec() && query.next()) {
        return query.value(0).toString() == peerHash;
    }
    return false;
}

void broadcastVote(int topic_id, const QString &user, int vote, const QString &voteHash) {
    for (QTcpSocket *peer : peers) {
        if (peer->state() == QAbstractSocket::ConnectedState) {
            QString message = QString("VOTE|%1|%2|%3|%4\n").arg(topic_id).arg(user).arg(vote).arg(voteHash);
            peer->write(message.toUtf8());
        }
    }
}

void voteOnTopic(int topic_id, const QString &user, int vote) {
    QSqlQuery query;
    QString ip_address = QHostInfo::localHostName();

    QSqlQuery ipQuery;
    ipQuery.prepare("SELECT COUNT(*) FROM ip_list WHERE ip_address = ?;");
    ipQuery.addBindValue(ip_address);
    if (!ipQuery.exec() || !ipQuery.next() || ipQuery.value(0).toInt() == 0) {
        qDebug() << "IP address not authorized.";
        return;
    }

    QSqlQuery checkQuery;
    checkQuery.prepare("SELECT end_date, vote_limit, (SELECT COUNT(*) FROM votes WHERE topic_id = ?) FROM topics WHERE id = ?;");
    checkQuery.addBindValue(topic_id);
    checkQuery.addBindValue(topic_id);
    if (!checkQuery.exec() || !checkQuery.next()) {
        qDebug() << "Topic not found.";
        return;
    }

    QDateTime now = QDateTime::currentDateTime();
    QDateTime endDate = QDateTime::fromString(checkQuery.value(0).toString(), Qt::ISODate);
    int voteLimit = checkQuery.value(1).toInt();
    int currentVotes = checkQuery.value(2).toInt();

    if (now > endDate || (voteLimit > 0 && currentVotes >= voteLimit)) {
        qDebug() << "Voting closed for this topic.";
        return;
    }

    QString voteHash = generateHash(QString::number(topic_id) + user + QString::number(vote));
    query.prepare("INSERT INTO votes (topic_id, user, ip_address, vote, hash) VALUES (?, ?, ?, ?, ?);");
    query.addBindValue(topic_id);
    query.addBindValue(user);
    query.addBindValue(ip_address);
    query.addBindValue(vote);
    query.addBindValue(voteHash);
    if (!query.exec()) {
        qDebug() << "Failed to vote:" << query.lastError().text();
    } else {
        qDebug() << "Vote recorded with hash:" << voteHash;
        broadcastVote(topic_id, user, vote, voteHash);
    }
}

// New functions for backup and recovery
void createBackup() {
    QSqlDatabase db = QSqlDatabase::database();
    QString backupPath = "voting_platform_backup.db";
    if (!db.open()) {
        qDebug() << "Error opening database for backup:" << db.lastError().text();
        return;
    }

    QFile::remove(backupPath); // Remove existing backup
    QFile::copy(db.databaseName(), backupPath); // Create new backup
    qDebug() << "Backup created at" << backupPath;
}

bool restoreBackup() {
    QString backupPath = "voting_platform_backup.db";
    if (!QFile::exists(backupPath)) {
        qDebug() << "Backup file not found!";
        return false;
    }

    QFile::remove("voting_platform.db"); // Remove current database
    if (!QFile::copy(backupPath, "voting_platform.db")) {
        qDebug() << "Failed to restore backup.";
        return false;
    }
    qDebug() << "Backup restored from" << backupPath;
    return true;
}

QString generateHashFromDatabase() {
    QString hashData;
    QSqlQuery query("SELECT * FROM votes;");
    while (query.next()) {
        hashData += query.value(0).toString() + query.value(1).toString() + query.value(2).toString() + query.value(3).toString();
    }
    return generateHash(hashData);
}

QString getLastKnownHashFromPeers() {
    if (peers.isEmpty()) {
        qDebug() << "No peers available for hash verification.";
        return "";
    }

    // Randomly select a subset of peers
    int sampleSize = qMin(5, peers.size()); // Select up to 5 peers or as many as available
    QList<QString> peerHashes;

    for (int i = 0; i < sampleSize; ++i) {
        // Select a random peer
        QTcpSocket *peer = peers[qrand() % peers.size()];

        // Send a request for the peer's hash (You would need a protocol to ask for this hash)
        QString request = "HASH_REQUEST\n";
        peer->write(request.toUtf8());

        // Read response from peer
        if (peer->waitForReadyRead(5000)) {  // 5 seconds timeout
            QString peerHash = QString::fromUtf8(peer->readAll()).trimmed();
            peerHashes.append(peerHash);
        } else {
            qDebug() << "Failed to get hash from peer.";
        }
    }

    // Compare the hashes (average or majority)
    if (peerHashes.isEmpty()) {
        qDebug() << "No valid hashes retrieved from peers.";
        return "";
    }

    // For simplicity, let's take the most common hash
    QMap<QString, int> hashCount;
    for (const QString &hash : peerHashes) {
        hashCount[hash]++;
    }

    QString mostCommonHash = 0;// hashCount.key(hashCount.values().maxKey());
    return mostCommonHash;
}

void checkDatabaseHash() {
    QString currentHash = generateHashFromDatabase();
    QString expectedHash = getLastKnownHashFromPeers(); // Get the average hash from peers

    if (currentHash != expectedHash) {
        qDebug() << "Database integrity compromised. Restoring backup.";
        if (!restoreBackup()) {
            qDebug() << "Failed to restore database. Manual intervention required.";
        }
    } else {
        qDebug() << "Database integrity verified.";
    }
}

QString getLastKnownHash() {
    // Retrieve the last known valid hash from a secure location (e.g., an admin server or peer network)
    return "last_known_good_hash"; // Placeholder for the actual hash from trusted source
}

// Call these functions periodically
void backupAndVerifyDatabase() {
    createBackup();
    checkDatabaseHash();
}

void voteOnTopicWithRecovery(int topic_id, const QString &user, int vote) {
    // Before allowing vote, verify integrity
    checkDatabaseHash();

    // Proceed with the vote if no integrity issues
    voteOnTopic(topic_id, user, vote);
}

void setupPeerServer() {
    server = new QTcpServer();
    server->connect(server, &QTcpServer::newConnection, []() {
        QTcpSocket *client = server->nextPendingConnection();
        server->connect(client, &QTcpSocket::readyRead, [client]() {
            while (client->canReadLine()) {
                QString line = QString::fromUtf8(client->readLine()).trimmed();
                QStringList parts = line.split("|");
                if (parts.size() == 6 && parts[0] == "PEER") {
                    if (validatePeer(parts[1], parts[2].toInt(), parts[3])) {
                        peers.append(client);
                        qDebug() << "Peer verified:" << parts[1] << ":" << parts[2];
                    } else {
                        client->disconnectFromHost();
                        qDebug() << "Invalid peer rejected.";
                    }
                } else if (parts.size() == 5 && parts[0] == "VOTE") {
                    voteOnTopic(parts[1].toInt(), parts[2], parts[3].toInt());
                }
            }
        });
    });

    if (!server->listen(QHostAddress::Any, 5555)) {
        qDebug() << "Failed to start peer server:" << server->errorString();
    } else {
        qDebug() << "Peer server listening on port 5555.";
    }
}

    QList<Peers2> selectRandomPeers(const QList<Peers2>& allPeers, int sampleSize) {
    QList<Peers2> selectedPeers;
    if (allPeers.isEmpty()) return selectedPeers;

    // Generate a secure random index list
    srand(static_cast<unsigned int>(time(0)));  // Initialize random seed

    for (int i = 0; i < sampleSize && !allPeers.isEmpty(); ++i) {
        int randomIndex = rand() % allPeers.size();
        selectedPeers.append(allPeers[randomIndex]);
    ///    allPeers.removeAt(randomIndex);  // Remove selected peer to avoid repetition
    }

    return selectedPeers;
}

QString getPeerVerificationHash(const QList<Peers2>& selectedPeers) {
    QStringList peerHashes;

    for (const Peers2& peers2 : selectedPeers) {
        peerHashes.append(peers2.hash);
    }

    //put selectedPeers into peers ?

   //old
    // Randomly select a subset of peers
    int sampleSize = qMin(5, peers.size()); // Select up to 5 peers or as many as available
   // QList<QString> peerHashes;

    for (int i = 0; i < sampleSize; ++i) {
        // Select a random peer
        QTcpSocket *peer = peers[qrand() % peers.size()];

        // Send a request for the peer's hash (You would need a protocol to ask for this hash)
        QString request = "HASH_REQUEST\n";
        peer->write(request.toUtf8());

        // Read response from peer
        if (peer->waitForReadyRead(5000)) {  // 5 seconds timeout
            QString peerHash = QString::fromUtf8(peer->readAll()).trimmed();
            peerHashes.append(peerHash);
        } else {
            qDebug() << "Failed to get hash from peer.";
        }
    }

    // Compare the hashes (average or majority)
    if (peerHashes.isEmpty()) {
        qDebug() << "No valid hashes retrieved from peers.";
        return "";
    }

    // For simplicity, let's take the most common hash
    QMap<QString, int> hashCount;
    for (const QString &hash : peerHashes) {
        hashCount[hash]++;
    }

    QString mostCommonHash = 0;//hashCount.key(hashCount.values().maxKey());



   // QString combinedHashes = peerHashes.join("|");  // Join all hashes
    return mostCommonHash;
}

void setupSsl() {
    if (!QSslSocket::supportsSsl()) {
        qDebug() << "SSL is not supported!";
        return;
    }
    qDebug() << "SSL is enabled.";
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    
    setupDatabase();
    setupSsl();
    setupPeerServer();



//testing this code
// grab peer list from random people then select some of those peers at random to increase security, also it could be country and non lan based to get even more random.

//while change lists grab 3 peers from each till you get like 50 or however many you can find based on expected popularity or weather fallback mode with only one or 2 can still do the job and reintegrate changes later ?
    QList<Peers2> selectedPeers = selectRandomPeers(peers2, 3);

    qDebug() << "Selected Peers for Verification:";
    for (const Peers2& peers2 : selectedPeers) {
        qDebug() << peers2.ip << peers2.port;
    }

    // Get a combined verification hash from the selected peers
    QString verificationHash = getPeerVerificationHash(selectedPeers);

    qDebug() << "Verification Hash:" << verificationHash;
// Test



    
    addPeer("127.0.0.1",5555);
voteOnTopicWithRecovery(1,"user1",1);
return app.exec();
}
