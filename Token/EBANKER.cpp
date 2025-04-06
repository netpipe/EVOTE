#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QLabel>
#include <QFileDialog>
#include <QDateTime>
#include <QCryptographicHash>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QRandomGenerator>

QString generateRandomToken(int length = 12) {
    const QString chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    QString token;
    for (int i = 0; i < length; ++i) {
        int index = QRandomGenerator::global()->bounded(chars.length());
        token += chars.at(index);
    }
    return token;
}

void bruteForceTokenPool(int total = 100000) {
    QSqlQuery clear;
    clear.exec("DELETE FROM all_tokens");

    QSqlQuery insert;
    insert.prepare("INSERT OR IGNORE INTO all_tokens (token) VALUES (:token)");

    int inserted = 0;
    while (inserted < total) {
        QString token = generateRandomToken(12);
        insert.bindValue(":token", token);
        insert.exec();

        if (insert.numRowsAffected() > 0) {
            inserted++;
        }
    }
}

void selectValidTokens(int count = 1000) {
    QSqlQuery q;
    q.exec("DELETE FROM valid_tokens");
    QSqlQuery insert;
    insert.prepare("INSERT INTO valid_tokens (token) SELECT token FROM all_tokens ORDER BY RANDOM() LIMIT :count");
    insert.bindValue(":count", count);
    insert.exec();
}

QString validateTokenRedemption(const QString &token) {
    QSqlQuery check;
    check.prepare("SELECT 1 FROM all_tokens WHERE token = :token");
    check.bindValue(":token", token);
    if (!check.exec() || !check.next()) {
        return "Invalid Token: Not recognized (forged).";
    }

    QSqlQuery valid;
    valid.prepare("SELECT redeemed FROM valid_tokens WHERE token = :token");
    valid.bindValue(":token", token);
    if (!valid.exec() || !valid.next()) {
        return "Invalid Token: Not part of active set.";
    }

    if (valid.value(0).toBool()) {
        return "Token already redeemed.";
    }

    QSqlQuery update;
    update.prepare("UPDATE valid_tokens SET redeemed = 1 WHERE token = :token");
    update.bindValue(":token", token);
    update.exec();
    return "Token successfully redeemed.";
}

QString generateTokenFile(int count = 10, int hoursToExpire = 24) {
    QSqlQuery query;
    query.prepare("SELECT token FROM valid_tokens WHERE redeemed = 0 LIMIT :count");
    query.bindValue(":count", count);
    query.exec();

    QStringList tokens;
    while (query.next()) {
        tokens << query.value(0).toString();
    }

    QString timestamp = QDateTime::currentDateTime().toString(Qt::ISODate);
    QString expiry = QDateTime::currentDateTime().addSecs(hoursToExpire * 3600).toString(Qt::ISODate);

    QStringList lines;
    lines << "# IOU Export File";
    lines << "Timestamp: " + timestamp;
    lines << "Expires: " + expiry;
    lines << "Tokens:";
    for (const QString &t : tokens) lines << t;

    QString rawData = lines.join("\n");
    QByteArray md5 = QCryptographicHash::hash(rawData.toUtf8(), QCryptographicHash::Md5).toHex();
    lines << "MD5: " + QString(md5);

    QString filePath = QFileDialog::getSaveFileName(nullptr, "Export Token File", "", "Token File (*.iou)");
    if (!filePath.isEmpty()) {
        QFile file(filePath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << lines.join("\n");
            file.close();
            return QString("Exported %1 tokens to %2").arg(tokens.size()).arg(filePath);
        }
    }
    return "Export cancelled or failed.";
}

QString importTokenFile() {
    QString filePath = QFileDialog::getOpenFileName(nullptr, "Import Token File", "", "Token File (*.iou)");
    if (filePath.isEmpty()) return "Import cancelled.";

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return "Failed to open file.";

    QStringList lines;
    while (!file.atEnd()) lines << file.readLine().trimmed();

    int md5Index = lines.lastIndexOf(QRegExp("^MD5: .*"));
    if (md5Index == -1) return "Invalid file format: No MD5 found.";

    QString originalMD5 = lines[md5Index].mid(5).trimmed();
    QString rawData = lines.mid(0, md5Index).join("\n");
    QByteArray calculatedMD5 = QCryptographicHash::hash(rawData.toUtf8(), QCryptographicHash::Md5).toHex();
    if (originalMD5 != calculatedMD5) return "MD5 mismatch: File integrity compromised.";

    QString expiryLine = lines.filter(QRegExp("^Expires:")).value(0);
    QDateTime expiry = QDateTime::fromString(expiryLine.mid(8).trimmed(), Qt::ISODate);
    if (expiry.isValid() && expiry < QDateTime::currentDateTime()) {
        return "Token file expired on " + expiry.toString();
    }

    int tokenStart = lines.indexOf("Tokens:") + 1;
    int tokenEnd = md5Index;
    QStringList importedTokens = lines.mid(tokenStart, tokenEnd - tokenStart);

    int redeemed = 0;
    for (const QString &token : importedTokens) {
        QSqlQuery q;
        q.prepare("UPDATE valid_tokens SET redeemed = 1 WHERE token = :token AND redeemed = 0");
        q.bindValue(":token", token);
        q.exec();
        if (q.numRowsAffected() > 0) redeemed++;
    }

    return QString("Imported %1 tokens. %2 were valid and redeemed.").arg(importedTokens.size()).arg(redeemed);
}

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QWidget window;
    window.setWindowTitle("Secure IOU Token System");
    auto *layout = new QVBoxLayout(&window);

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("tokens.db");
    db.open();

    QSqlQuery init;
    init.exec("CREATE TABLE IF NOT EXISTS all_tokens (token TEXT PRIMARY KEY)");
    init.exec("CREATE TABLE IF NOT EXISTS valid_tokens (token TEXT PRIMARY KEY, redeemed INTEGER DEFAULT 0, FOREIGN KEY(token) REFERENCES all_tokens(token))");

    auto *output = new QPlainTextEdit;
    output->setReadOnly(true);
    auto *tokenInput = new QLineEdit;
    tokenInput->setPlaceholderText("Enter token to redeem...");

    auto *redeemBtn = new QPushButton("Redeem Token");
    auto *genAllBtn = new QPushButton("Generate All Tokens");
    auto *genValidBtn = new QPushButton("Select Valid Tokens");
    auto *exportBtn = new QPushButton("Export Tokens to File");
    auto *importBtn = new QPushButton("Import & Redeem Token File");

    layout->addWidget(tokenInput);
    layout->addWidget(redeemBtn);
    layout->addWidget(genAllBtn);
    layout->addWidget(genValidBtn);
    layout->addWidget(exportBtn);
    layout->addWidget(importBtn);
    layout->addWidget(output);

    QObject::connect(redeemBtn, &QPushButton::clicked, [&]() {
        QString result = validateTokenRedemption(tokenInput->text().trimmed());
        output->appendPlainText(result);
    });
    QObject::connect(genAllBtn, &QPushButton::clicked, [&]() {
        bruteForceTokenPool();
        output->appendPlainText("Generated all tokens.");
    });
    QObject::connect(genValidBtn, &QPushButton::clicked, [&]() {
        selectValidTokens();
        output->appendPlainText("Selected valid tokens.");
    });
    QObject::connect(exportBtn, &QPushButton::clicked, [&]() {
        output->appendPlainText(generateTokenFile());
    });
    QObject::connect(importBtn, &QPushButton::clicked, [&]() {
        output->appendPlainText(importTokenFile());
    });

    window.resize(500, 500);
    window.show();
    return app.exec();
}
