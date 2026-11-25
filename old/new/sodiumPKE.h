#include <QtCore/QCoreApplication>
#include <QtCore/QByteArray>
#include <QtCore/QDebug>

extern "C" {
    #include <sodium.h>
}

class SodiumExample {
public:
    SodiumExample() {
        if (sodium_init() == -1) {
            qCritical() << "libsodium initialization failed!";
         //   exit(1);
        }
    }

    // Generate an X25519 key pair (public/private)
    void generateKeyPair(QByteArray &privateKey, QByteArray &publicKey) {
        privateKey.resize(crypto_box_SECRETKEYBYTES);
        publicKey.resize(crypto_box_PUBLICKEYBYTES);

        // Generate key pair
        crypto_box_keypair(reinterpret_cast<unsigned char*>(publicKey.data()), reinterpret_cast<unsigned char*>(privateKey.data()));
    }

    // Encrypt a message with a public key using X25519
    QByteArray encrypt(const QByteArray &message, const QByteArray &publicKey, const QByteArray &privateKey) {
        QByteArray nonce(crypto_box_NONCEBYTES, 0); // Use random nonce in real-world cases
        QByteArray ciphertext(message.size() + crypto_box_MACBYTES, 0);

        // Encrypt the message using X25519
        if (crypto_box_easy(reinterpret_cast<unsigned char*>(ciphertext.data()),
                            reinterpret_cast<const unsigned char*>(message.data()),
                            message.size(),
                            reinterpret_cast<const unsigned char*>(nonce.data()),
                            reinterpret_cast<const unsigned char*>(publicKey.data()),
                            reinterpret_cast<const unsigned char*>(privateKey.data())) != 0) {
            qCritical() << "Encryption failed!";
          //  exit(1);
        }

        return ciphertext;
    }

    // Decrypt a message with a public key using X25519
    QByteArray decrypt(const QByteArray &ciphertext, const QByteArray &publicKey, const QByteArray &privateKey) {
        QByteArray nonce(crypto_box_NONCEBYTES, 0); // Use random nonce in real-world cases
        QByteArray decryptedMessage(ciphertext.size() - crypto_box_MACBYTES, 0);

        // Decrypt the message using X25519
        if (crypto_box_open_easy(reinterpret_cast<unsigned char*>(decryptedMessage.data()),
                                 reinterpret_cast<const unsigned char*>(ciphertext.data()),
                                 ciphertext.size(),
                                 reinterpret_cast<const unsigned char*>(nonce.data()),
                                 reinterpret_cast<const unsigned char*>(publicKey.data()),
                                 reinterpret_cast<const unsigned char*>(privateKey.data())) != 0) {
            qCritical() << "Decryption failed!";
          //  exit(1);
        }

        return decryptedMessage;
    }
};

int main2(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    SodiumExample sodium;

    QByteArray privateKey, publicKey;

    // Generate Key Pair
    sodium.generateKeyPair(privateKey, publicKey);

    qDebug() << "Private Key:" << privateKey.toHex();
    qDebug() << "Public Key:" << publicKey.toHex();

    QByteArray message = "Hello, this is a secret message!";
    qDebug() << "Original Message:" << message;

    // Encrypt the message
    QByteArray encryptedMessage = sodium.encrypt(message, publicKey, privateKey);
    qDebug() << "Encrypted Message:" << encryptedMessage.toHex();

    // Decrypt the message
    QByteArray decryptedMessage = sodium.decrypt(encryptedMessage, publicKey, privateKey);
    qDebug() << "Decrypted Message:" << decryptedMessage;

    return a.exec();
}
