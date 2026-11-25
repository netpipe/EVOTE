#include <QApplication>
#include <QtWidgets>
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QTcpSocket>
#include <QTcpServer>
#include <QCryptographicHash>

class VotingServer : public QTcpServer {
    Q_OBJECT

public:
    VotingServer(QObject *parent = nullptr) : QTcpServer(parent) {
        setupDatabase();
        if (listen(QHostAddress::Any, 5555)) {
            qDebug() << "Server running on port 5555.";
        } else {
            qDebug() << "Server failed to start:" << errorString();
        }
    }

protected:
    void incomingConnection(qintptr socketDescriptor) override {
        QTcpSocket *client = new QTcpSocket(this);
        client->setSocketDescriptor(socketDescriptor);
        connect(client, &QTcpSocket::readyRead, this, &VotingServer::readClient);
        connect(client, &QTcpSocket::disconnected, client, &QTcpSocket::deleteLater);
    }

private:
    void setupDatabase() {
        QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
        db.setDatabaseName("voting_platform.db");
        if (!db.open()) {
            qDebug() << "Database error:" << db.lastError().text();
            return;
        }
        QSqlQuery query;
        query.exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT);");
        query.exec("CREATE TABLE IF NOT EXISTS votes (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, candidate TEXT, token TEXT);");
        query.exec("CREATE TABLE IF NOT EXISTS candidates (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE);");
    }

    void readClient() {
        QTcpSocket *client = qobject_cast<QTcpSocket *>(sender());
        if (!client) return;

        while (client->canReadLine()) {
            QString line = QString::fromUtf8(client->readLine()).trimmed();
            QStringList parts = line.split("|");
            if (parts.size() == 3 && parts[0] == "LOGIN") {
                handleLogin(client, parts[1], parts[2]);
            } else if (parts.size() == 3 && parts[0] == "VOTE") {
                handleVote(client, parts[1], parts[2]);
            } else if (parts.size() == 3 && parts[0] == "ADD_CANDIDATE") {
                handleAddCandidate(client, parts[1], parts[2]);
            } else if (parts.size() == 3 && parts[0] == "REMOVE_CANDIDATE") {
                handleRemoveCandidate(client, parts[1], parts[2]);
            }
        }
    }

    void handleLogin(QTcpSocket *client, const QString &username, const QString &password) {
        QSqlQuery query;
        query.prepare("SELECT password, role FROM users WHERE username = ?;");
        query.addBindValue(username);
        if (query.exec() && query.next() && query.value(0).toString() == generateHash(password)) {
            client->write(QString("LOGIN_SUCCESS|%1\n").arg(query.value(1).toString()).toUtf8());
        } else {
            client->write("LOGIN_FAIL\n");
        }
    }

    void handleVote(QTcpSocket *client, const QString &candidate, const QString &username) {
        QString token = generateHash(username + candidate);
        QSqlQuery query;
        query.prepare("INSERT INTO votes (user, candidate, token) VALUES (?, ?, ?);");
        query.addBindValue(username);
        query.addBindValue(candidate);
        query.addBindValue(token);
        if (query.exec()) {
            client->write(QString("VOTE_RECORDED|%1\n").arg(token).toUtf8());
        }
    }

    void handleAddCandidate(QTcpSocket *client, const QString &candidate, const QString &username) {
        QSqlQuery query;
        query.prepare("INSERT INTO candidates (name) VALUES (?);");
        query.addBindValue(candidate);
        if (query.exec()) {
            client->write("CANDIDATE_ADDED\n");
        }
    }

    void handleRemoveCandidate(QTcpSocket *client, const QString &candidate, const QString &username) {
        QSqlQuery query;
        query.prepare("DELETE FROM candidates WHERE name = ?;");
        query.addBindValue(candidate);
        if (query.exec()) {
            client->write("CANDIDATE_REMOVED\n");
        }
    }

    QString generateHash(const QString &data) {
        return QString(QCryptographicHash::hash(data.toUtf8(), QCryptographicHash::Sha256).toHex());
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    VotingServer server;
    return app.exec();
}
