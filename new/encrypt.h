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

QString xorStrings(const QString &str1, const QString &str2) {
    QByteArray a = str1.toUtf8();
    QByteArray b = str2.toUtf8();

    int len = qMin(a.size(), b.size());
    QByteArray result;
    result.resize(len);

    for (int i = 0; i < len; ++i) {
        result[i] = a[i] ^ b[i];
    }

    return QString(result.toHex()); // return hex for readability
 //   return QString::fromUtf8(result);
   // return hexOutput ? QString(result.toHex()) : QString::fromUtf8(result);
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


QString encryptOwnership(const QString &walletSecret,QString ewalletID2) { //encrpted TOTP by ewalletID
    return QString(QCryptographicHash::hash((ewalletID2 + walletSecret).toUtf8(), QCryptographicHash::Sha256).toHex());
}

bool verifyOwnership(const QString &owner,QString ETOTP,QString ewalletID2) {
    return owner == encryptOwnership(ETOTP,ewalletID2);
}

QString generateOneTimeToken(const QString &walletID, const QString &tokenHash) {
    //decrypt the one time token from the token later
    QString sharedSecret2 = tokenHash; // Example shared secret (Base32 encoded)
    TOTP totp(sharedSecret2,SHA256);

    QString generatedCode = totp.generateTOTP();
   // qDebug() << "Generated TOTP Code: " << generatedCode;

    generatedCode = encryptCandidate (generatedCode,walletID);
   // generatedCode = xorStrings(walletID + ":" + generatedCode,sharedSecret);
    return generatedCode;
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
       int test=0;
    if (file.open(QIODevice::ReadOnly)) {
        QStringList lines;
        QTextStream in(&file);
        while (!in.atEnd()) {
            QString line = in.readLine().trimmed();
            if (!line.isEmpty() && !connectedPeers.contains(line) && test < 20) {
                lines.append(line);
                test++;
            }
        }

        // Shuffle to avoid same peer order on every startup
        //maybe connect to random peer then send their peers list or 3 from each
        auto rng = QRandomGenerator::global(); // This is the engine
        std::shuffle(lines.begin(), lines.end(), *rng);

        for (const QString &line : lines) {
            QStringList hostPort = line.split(":");
            if (hostPort.size() == 2)
                connectToPeer(hostPort[0], hostPort[1].toInt());
        }
    }
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

QString hashToken(const QString &token) {
    return QString(QCryptographicHash::hash(token.toUtf8(), QCryptographicHash::Sha256).toHex());
}

