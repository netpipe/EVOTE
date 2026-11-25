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
        query.exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT);");
        query.exec("CREATE TABLE IF NOT EXISTS votes (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, candidate TEXT, token TEXT);");
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
            }
        }
    }

    void handleLogin(QTcpSocket *client, const QString &username, const QString &password) {
        QSqlQuery query;
        query.prepare("SELECT password FROM users WHERE username = ?;");
        query.addBindValue(username);
        if (query.exec() && query.next() && query.value(0).toString() == generateHash(password)) {
            client->write("LOGIN_SUCCESS\n");
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

    QString generateHash(const QString &data) {
        return QString(QCryptographicHash::hash(data.toUtf8(), QCryptographicHash::Sha256).toHex());
    }
};

class VotingClient : public QWidget {
    Q_OBJECT

public:
    VotingClient(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("Voting System");
        resize(400, 300);

        QVBoxLayout *layout = new QVBoxLayout(this);
        usernameEdit = new QLineEdit(this);
        passwordEdit = new QLineEdit(this);
        passwordEdit->setEchoMode(QLineEdit::Password);
        loginButton = new QPushButton("Login", this);
        candidateList = new QListWidget(this);
        voteButton = new QPushButton("Vote", this);
        tokenLabel = new QLabel("", this);
        statusLabel = new QLabel("Not connected", this);

        layout->addWidget(new QLabel("Username:"));
        layout->addWidget(usernameEdit);
        layout->addWidget(new QLabel("Password:"));
        layout->addWidget(passwordEdit);
        layout->addWidget(loginButton);
        layout->addWidget(new QLabel("Candidates:"));
        layout->addWidget(candidateList);
        layout->addWidget(voteButton);
        layout->addWidget(new QLabel("Vote Token:"));
        layout->addWidget(tokenLabel);
        layout->addWidget(statusLabel);

        socket = new QTcpSocket(this);
        connect(loginButton, &QPushButton::clicked, this, &VotingClient::attemptLogin);
        connect(voteButton, &QPushButton::clicked, this, &VotingClient::castVote);
        connect(socket, &QTcpSocket::readyRead, this, &VotingClient::readServerResponse);
        connect(socket, &QTcpSocket::connected, this, &VotingClient::onConnected);
        connect(socket, &QTcpSocket::disconnected, this, &VotingClient::onDisconnected);

        socket->connectToHost("127.0.0.1", 5555);
    }

private slots:
    void attemptLogin() {
        QString username = usernameEdit->text();
        QString password = passwordEdit->text();
        socket->write(QString("LOGIN|%1|%2\n").arg(username).arg(password).toUtf8());
    }

    void castVote() {
        if (candidateList->currentItem()) {
            QString candidate = candidateList->currentItem()->text();
            socket->write(QString("VOTE|%1|%2\n").arg(candidate).arg(usernameEdit->text()).toUtf8());
        }
    }

    void readServerResponse() {
        while (socket->canReadLine()) {
            QString response = QString::fromUtf8(socket->readLine()).trimmed();
            if (response.startsWith("LOGIN_SUCCESS")) {
                statusLabel->setText("Login successful");
            } else if (response.startsWith("LOGIN_FAIL")) {
                statusLabel->setText("Login failed");
            } else if (response.startsWith("VOTE_RECORDED")) {
                tokenLabel->setText(response.split("|").last());
                statusLabel->setText("Vote recorded");
            }
        }
    }

    void onConnected() {
        statusLabel->setText("Connected to server");
    }

    void onDisconnected() {
        statusLabel->setText("Disconnected");
    }

private:
    QTcpSocket *socket;
    QLineEdit *usernameEdit;
    QLineEdit *passwordEdit;
    QPushButton *loginButton;
    QListWidget *candidateList;
    QPushButton *voteButton;
    QLabel *tokenLabel;
    QLabel *statusLabel;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    VotingServer server;
    VotingClient client;
    client.show();
    return app.exec();
}
