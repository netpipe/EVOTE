// Decentralized Voting App with Peer Exchange (PEX)
#include <QApplication>
#include <QtWidgets>
#include <QtNetwork>
#include <QtSql>
#include <QCryptographicHash>
#include <QSet>

class PeerNode : public QObject {
    Q_OBJECT

public:
    PeerNode(QObject *parent = nullptr) : QObject(parent) {
        server = new QTcpServer(this);
        connect(server, &QTcpServer::newConnection, this, &PeerNode::handleConnection);
        server->listen(QHostAddress::Any, 5555);
    }

    void connectToPeer(const QString &host, int port = 5555) {
        QString address = QString("%1:%2").arg(host).arg(port);
        if (connectedPeers.contains(address)) return;

        QTcpSocket *socket = new QTcpSocket(this);
        socket->connectToHost(host, port);
        connect(socket, &QTcpSocket::readyRead, this, [=]() { handleData(socket); });
        connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
        peers.append(socket);
        connectedPeers.insert(address);

        // Send our known peers
        for (const QString &peer : connectedPeers) {
            socket->write(QString("PEER|%1\n").arg(peer).toUtf8());
        }
    }

    void broadcastVote(const QString &candidate, const QString &token) {
        QString message = QString("VOTE|%1|%2\n").arg(candidate, token);
        for (QTcpSocket *peer : peers) {
            peer->write(message.toUtf8());
        }
        handleVote(candidate, token); // Also store locally
    }

    void generateTokenPool(int count) {
        QSqlQuery query;
        for (int i = 0; i < count; ++i) {
            QString raw = QString::number(QRandomGenerator::global()->generate64());
            QString hash = QString(QCryptographicHash::hash(raw.toUtf8(), QCryptographicHash::Sha256).toHex());
            query.prepare("INSERT INTO tokens (token, used) VALUES (?, 0);");
            query.addBindValue(hash);
            query.exec();
        }
    }

    void setupDatabase() {
        QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
        db.setDatabaseName("peer_voting.db");
        db.open();
        QSqlQuery query;
        query.exec("CREATE TABLE IF NOT EXISTS candidates (name TEXT UNIQUE);");
        query.exec("CREATE TABLE IF NOT EXISTS tokens (token TEXT UNIQUE, used INTEGER);");
        query.exec("CREATE TABLE IF NOT EXISTS votes (candidate TEXT, token TEXT UNIQUE);");
    }

    QStringList getCandidates() {
        QStringList list;
        QSqlQuery query("SELECT name FROM candidates;");
        while (query.next()) {
            list << query.value(0).toString();
        }
        return list;
    }

    bool isValidToken(const QString &token) {
        QSqlQuery q;
        q.prepare("SELECT used FROM tokens WHERE token = ?;");
        q.addBindValue(token);
        return q.exec() && q.next() && q.value(0).toInt() == 0;
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
            if (parts.size() == 3 && parts[0] == "VOTE") {
                handleVote(parts[1], parts[2]);
            } else if (parts.size() == 2 && parts[0] == "PEER") {
                QStringList hostPort = parts[1].split(":");
                if (hostPort.size() == 2) {
                    QString host = hostPort[0];
                    int port = hostPort[1].toInt();
                    connectToPeer(host, port);
                }
            }
        }
    }

    void handleVote(const QString &candidate, const QString &token) {
        if (!isValidToken(token)) return;

        QSqlQuery insert;
        insert.prepare("INSERT INTO votes (candidate, token) VALUES (?, ?);");
        insert.addBindValue(candidate);
        insert.addBindValue(token);
        if (insert.exec()) {
            QSqlQuery mark;
            mark.prepare("UPDATE tokens SET used = 1 WHERE token = ?;");
            mark.addBindValue(token);
            mark.exec();
        }
    }

private:
    QTcpServer *server;
    QList<QTcpSocket *> peers;
    QSet<QString> connectedPeers;
};

class VotingApp : public QWidget {
    Q_OBJECT

public:
    VotingApp(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("Decentralized Voting");
        resize(400, 300);

        peer = new PeerNode(this);
        peer->setupDatabase();

        QVBoxLayout *layout = new QVBoxLayout(this);

        QPushButton *addCandidate = new QPushButton("Add Candidate");
        QPushButton *generateTokens = new QPushButton("Generate Tokens");
        QPushButton *voteButton = new QPushButton("Vote");
        QPushButton *connectBtn = new QPushButton("Connect to Peer");

        candidateInput = new QLineEdit;
        candidateInput->setPlaceholderText("Candidate Name");

        tokenInput = new QLineEdit;
        tokenInput->setPlaceholderText("Vote Token");

        peerInput = new QLineEdit;
        peerInput->setPlaceholderText("Peer IP Address");

        layout->addWidget(candidateInput);
        layout->addWidget(tokenInput);
        layout->addWidget(peerInput);
        layout->addWidget(addCandidate);
        layout->addWidget(generateTokens);
        layout->addWidget(voteButton);
        layout->addWidget(connectBtn);

        connect(addCandidate, &QPushButton::clicked, this, [=]() {
            QString name = candidateInput->text();
            QSqlQuery q;
            q.prepare("INSERT INTO candidates (name) VALUES (?);");
            q.addBindValue(name);
            q.exec();
        });

        connect(generateTokens, &QPushButton::clicked, this, [=]() {
            peer->generateTokenPool(10);
        });

        connect(voteButton, &QPushButton::clicked, this, [=]() {
            peer->broadcastVote(candidateInput->text(), tokenInput->text());
        });

        connect(connectBtn, &QPushButton::clicked, this, [=]() {
            peer->connectToPeer(peerInput->text());
        });
    }

private:
    PeerNode *peer;
    QLineEdit *candidateInput, *tokenInput, *peerInput;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    VotingApp window;
    window.show();
    return app.exec();
}

#include "main.moc"
