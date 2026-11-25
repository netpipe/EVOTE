// sphincs_light.h - Lightweight SPHINCS+ signature demo (educational purposes only)
// WARNING: Not a full implementation. Not secure for production.

#ifndef SPHINCS_LIGHT_H
#define SPHINCS_LIGHT_H

#include <QtCore>
#include <array>
#include <random>
#include <QCryptographicHash>

class SphincsLight {
public:
    static constexpr int SEED_BYTES = 32; // private key seed
    static constexpr int SIG_BYTES = 64;  // placeholder size
    static constexpr int PK_BYTES = 32;   // public key size

    struct PublicKey {
        QByteArray pubkey; // Public seed / node
    };

    struct PrivateKey {
        QByteArray sk_seed; // Private seed
        QByteArray pub_seed; // For root node
    };

    struct Signature {
        QByteArray sig;
        QByteArray embedded_seed; // Add this for demo validation
    };


    SphincsLight() {
        std::random_device rd;
        rng.seed(rd());
    }

    void keygen(PublicKey &pk, PrivateKey &sk) {
        sk.sk_seed = randomBytes(SEED_BYTES);
        sk.pub_seed = randomBytes(SEED_BYTES);

        pk.pubkey = hash(sk.pub_seed); // Simulate root calculation
    }

    Signature sign(const QByteArray &message, const PrivateKey &sk) {
        QByteArray data = sk.sk_seed + message;
        QByteArray sig = hash(data);
        return { sig, sk.sk_seed }; // Embed seed for validation
    }


    bool verify(const QByteArray &message, const Signature &sig, const PublicKey &pk) {
        Q_UNUSED(pk); // Still not using tree, just simulating

        QByteArray guess = hash(sig.embedded_seed + message);
        return sig.sig == guess;
    }


    QByteArray printHex(const QByteArray &data) {
        return data.toHex();
    }

private:
    std::mt19937 rng;
    QByteArray skEmulatedSeed = "DemoSeed"; // Used for verify simulation only

    QByteArray randomBytes(int length) {
        QByteArray result;
        std::uniform_int_distribution<int> dist(0, 255);
        for (int i = 0; i < length; ++i)
            result.append(static_cast<char>(dist(rng)));
        return result;
    }

    QByteArray hash(const QByteArray &data) {
        return QCryptographicHash::hash(data, QCryptographicHash::Sha256);
    }
};

#endif // SPHINCS_LIGHT_H
