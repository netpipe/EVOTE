#include "totp.h"
#include <QTime>
#include <QByteArray>
#include <QCryptographicHash>
#include <QtGlobal>
#include <QDebug>
HashAlgorithm m_algorithm;

TOTP::TOTP(const QString &sharedSecret, HashAlgorithm algorithm)
    : m_sharedSecret(sharedSecret), m_algorithm(algorithm)
{
}


QString TOTP::generateTOTP() const
{
    // Get the current Unix timestamp (seconds)
    qint64 timestamp = QDateTime::currentSecsSinceEpoch();
    // Calculate the number of time steps
    qint64 timeCounter = timestamp / m_timeStep;

    // Convert the time counter to a QByteArray
    QByteArray timeArray;
    timeArray.append(reinterpret_cast<const char*>(&timeCounter), sizeof(timeCounter));

    // Compute HMAC-SHA1 hash of the time counter with the secret key
    QByteArray hmac = computeHMAC(m_sharedSecret.toUtf8(), timeArray);

    // Apply dynamic truncation to get the final 6-digit code
    quint32 code = toUInt32(hmac.mid(hmac.length() - 4)) & 0x7FFFFFFF;
    code %= 1000000; // Ensure it's 6 digits

    // Return the TOTP as a 6-digit string
    return QString::number(code).rightJustified(6, '0');
}

bool TOTP::verifyTOTP(const QString &code) const
{
    // Generate the current TOTP code
    QString generatedCode = generateTOTP();

    // Compare the generated code with the provided code
    return generatedCode == code;
}
QByteArray TOTP::computeHMAC(const QByteArray &key, const QByteArray &message) const
{
    QCryptographicHash::Algorithm algo;

    switch (m_algorithm) {
        case SHA256:
            algo = QCryptographicHash::Sha256;
            break;
        case SHA512:
            algo = QCryptographicHash::Sha512;
            break;
        case SHA1:
        default:
            algo = QCryptographicHash::Sha1;
            break;
    }

    QCryptographicHash hash(algo);
    int blockSize = (algo == QCryptographicHash::Sha512) ? 128 : 64;

    QByteArray keyBytes = key;
    if (keyBytes.size() > blockSize) {
        hash.addData(keyBytes);
        keyBytes = hash.result();
        hash.reset();
    }
    if (keyBytes.size() < blockSize) {
        keyBytes.append(QByteArray(blockSize - keyBytes.size(), '\0'));
    }

    QByteArray ipad = keyBytes;
    QByteArray opad = keyBytes;

    for (int i = 0; i < blockSize; ++i) {
        ipad[i] = static_cast<char>(static_cast<quint8>(ipad[i]) ^ 0x36);
        opad[i] = static_cast<char>(static_cast<quint8>(opad[i]) ^ 0x5C);
    }

    hash.addData(ipad);
    hash.addData(message);
    QByteArray innerHash = hash.result();

    hash.reset();
    hash.addData(opad);
    hash.addData(innerHash);

    return hash.result();
}


quint32 TOTP::toUInt32(const QByteArray &data) const
{
    // Convert QByteArray to uint32 (be aware of endianess)
    quint32 result = 0;
    for (int i = 0; i < 4; ++i) {
        result = (result << 8) | (static_cast<quint8>(data[i]));
    }
    return result;
}
