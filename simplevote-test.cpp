#include <QApplication>
#include <QtWidgets>
#include <QtSql>
#include <QTcpSocket>
#include <QTcpServer>
#include <QCryptographicHash>
#include <QFile>
#include <QTextStream>
#include <QRandomGenerator>

class VotingServer : public QTcpServer {
    Q_OBJECT

public:
    VotingServer(QObject *parent = nullptr) : QTcpServer(parent) {
        setupDatabase();
    }

    bool startServer() {
        return listen(QHostAddress::Any, 5555);
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
        query.exec("CREATE TABLE IF NOT EXISTS candidates (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE);");
        query.exec("CREATE TABLE IF NOT EXISTS tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE, used INTEGER DEFAULT 0);");
        query.exec("CREATE TABLE IF NOT EXISTS votes (id INTEGER PRIMARY KEY AUTOINCREMENT, candidate TEXT, token TEXT);");
    }

    void readClient() {
        QTcpSocket *client = qobject_cast<QTcpSocket *>(sender());
        if (!client) return;

        while (client->canReadLine()) {
            QString line = QString::fromUtf8(client->readLine()).trimmed();
            QStringList parts = line.split("|");
            if (parts.size() == 2 && parts[0] == "GET_CANDIDATES") {
                sendCandidates(client);
            } else if (parts.size() == 3 && parts[0] == "VOTE") {
                handleVote(client, parts[1], parts[2]);
            }
        }
    }

    void sendCandidates(QTcpSocket *client) {
        QSqlQuery query("SELECT name FROM candidates;");
        QStringList names;
        while (query.next()) {
            names << query.value(0).toString();
        }
        client->write("CANDIDATES|" + names.join(",").toUtf8() + "\n");
    }

    void handleVote(QTcpSocket *client, const QString &candidate, const QString &token) {
        QSqlQuery checkToken;
        checkToken.prepare("SELECT used FROM tokens WHERE token = ?;");
        checkToken.addBindValue(token);
        if (checkToken.exec() && checkToken.next() && checkToken.value(0).toInt() == 0) {
            QSqlQuery insertVote;
            insertVote.prepare("INSERT INTO votes (candidate, token) VALUES (?, ?);");
            insertVote.addBindValue(candidate);
            insertVote.addBindValue(token);
            if (insertVote.exec()) {
                QSqlQuery markUsed("UPDATE tokens SET used = 1 WHERE token = '" + token + "';");
                markUsed.exec();
                client->write("VOTE_ACCEPTED\n");
            }
        } else {
            client->write("VOTE_REJECTED\n");
        }
    }
};

class VotingApp : public QWidget {
    Q_OBJECT

public:
    VotingApp(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("Voting Platform");
        resize(400, 300);

        QVBoxLayout *layout = new QVBoxLayout(this);
        tabWidget = new QTabWidget(this);
        layout->addWidget(tabWidget);

        setupAdminTab();
        setupClientTab();
    }

private slots:
    void startServer() {
        if (server.startServer()) {
            QMessageBox::information(this, "Server", "Server started on port 5555.");
        } else {
            QMessageBox::critical(this, "Server Error", server.errorString());
        }
    }

    void addCandidate() {
        QString name = candidateInput->text().trimmed();
        if (!name.isEmpty()) {
            QSqlQuery query;
            query.prepare("INSERT INTO candidates (name) VALUES (?);");
            query.addBindValue(name);
            if (query.exec()) {
                QMessageBox::information(this, "Success", "Candidate added.");
                candidateInput->clear();
            } else {
                QMessageBox::warning(this, "Error", query.lastError().text());
            }
        }
    }

    void generateTokens() {
        int count = tokenSpin->value();
        QFile file("tokens.txt");
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            for (int i = 0; i < count; ++i) {
                QString raw = QString::number(QRandomGenerator::global()->generate64());
                QString hash = QString(QCryptographicHash::hash(raw.toUtf8(), QCryptographicHash::Sha256).toHex());
                QSqlQuery query;
                query.prepare("INSERT INTO tokens (token) VALUES (?);");
                query.addBindValue(hash);
                query.exec();
                out << hash << "\n";
            }
            file.close();
            QMessageBox::information(this, "Done", "Tokens saved to tokens.txt");
        }
    }

    void submitVote() {
        QString host = hostInput->text();
        QString candidate = candidateInputClient->text();
        QString token = tokenInput->text();

        QTcpSocket socket;
        socket.connectToHost(host, 5555);
        if (!socket.waitForConnected(2000)) {
            QMessageBox::critical(this, "Error", "Cannot connect to server.");
            return;
        }

        socket.write("VOTE|" + candidate.toUtf8() + "|" + token.toUtf8() + "\n");
        socket.waitForBytesWritten();
        socket.waitForReadyRead();
        QString response = socket.readLine().trimmed();
        if (response == "VOTE_ACCEPTED") {
            QMessageBox::information(this, "Success", "Your vote has been recorded.");
        } else {
            QMessageBox::warning(this, "Failed", "Invalid or used token.");
        }
    }

private:
    VotingServer server;
    QTabWidget *tabWidget;
    QLineEdit *candidateInput;
    QSpinBox *tokenSpin;
    QLineEdit *hostInput, *candidateInputClient, *tokenInput;

    void setupAdminTab() {
        QWidget *adminTab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(adminTab);

        QPushButton *startServerBtn = new QPushButton("Start Server");
        connect(startServerBtn, &QPushButton::clicked, this, &VotingApp::startServer);
        layout->addWidget(startServerBtn);

        candidateInput = new QLineEdit;
        candidateInput->setPlaceholderText("Candidate Name");
        layout->addWidget(candidateInput);

        QPushButton *addCandidateBtn = new QPushButton("Add Candidate");
        connect(addCandidateBtn, &QPushButton::clicked, this, &VotingApp::addCandidate);
        layout->addWidget(addCandidateBtn);

        tokenSpin = new QSpinBox;
        tokenSpin->setRange(1, 1000);
        layout->addWidget(tokenSpin);

        QPushButton *generateTokensBtn = new QPushButton("Generate Vote Tokens");
        connect(generateTokensBtn, &QPushButton::clicked, this, &VotingApp::generateTokens);
        layout->addWidget(generateTokensBtn);

        tabWidget->addTab(adminTab, "Admin");
    }

    void setupClientTab() {
        QWidget *clientTab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(clientTab);

        hostInput = new QLineEdit("127.0.0.1");
        hostInput->setPlaceholderText("Server Address");
        layout->addWidget(hostInput);

        candidateInputClient = new QLineEdit;
        candidateInputClient->setPlaceholderText("Candidate Name");
        layout->addWidget(candidateInputClient);

        tokenInput = new QLineEdit;
        tokenInput->setPlaceholderText("Your Vote Token");
        layout->addWidget(tokenInput);

        QPushButton *voteBtn = new QPushButton("Submit Vote");
        connect(voteBtn, &QPushButton::clicked, this, &VotingApp::submitVote);
        layout->addWidget(voteBtn);

        tabWidget->addTab(clientTab, "Client");
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    VotingApp votingApp;
    votingApp.show();
    return app.exec();
}

#include "main.moc"
