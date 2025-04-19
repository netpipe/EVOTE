#ifndef TOTP_H
#define TOTP_H

#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <QCryptographicHash>
#include <QtGlobal>

class TOTP
{
public:
    // Constructor that takes the secret key (shared)
    TOTP(const QString &sharedSecret);

    // Generates the TOTP code
    QString generateTOTP() const;

    // Verifies if the provided TOTP code is correct
    bool verifyTOTP(const QString &code) const;

private:
    QString m_sharedSecret;  // The shared secret key for TOTP
    const int m_timeStep = 30;  // The time step (in seconds)

    // Helper method to compute HMAC-SHA1
    QByteArray computeHMACSHA1(const QByteArray &key, const QByteArray &message) const;

    // Helper method to convert QByteArray to integer
    quint32 toUInt32(const QByteArray &data) const;
};

#endif // TOTP_H
