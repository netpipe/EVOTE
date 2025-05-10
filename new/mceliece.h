// pqcrypto_light.h - Simplified, working McEliece-like KEM (for educational/demo use only)
// WARNING: This is not secure! For demonstration purposes only.

#ifndef PQCRYPTO_LIGHT_H
#define PQCRYPTO_LIGHT_H

#include <QtCore>
#include <array>
#include <random>
#include <bitset>

class PQCryptoLite {
public:
    static constexpr int K = 128; // message bits
    static constexpr int N = 256; // codeword length (simple code)

    using BitVec = std::bitset<N>;

    struct PublicKey {
        std::array<BitVec, K> G; // Generator matrix
    };

    struct PrivateKey {
        std::bitset<N> permutation; // Permuted positions (identity here)
    };

    struct CipherText {
        BitVec c;
    };

    struct SharedSecret {
        QByteArray key;
    };

    PQCryptoLite() {
        std::random_device rd;
        rng.seed(rd());
    }

    void keygen(PublicKey &pk, PrivateKey &sk) {
        for (int i = 0; i < K; ++i) {
            pk.G[i].reset();
            pk.G[i].set(i); // Identity generator (trivial code)
        }
        sk.permutation.reset();
        for (int i = 0; i < N; ++i) sk.permutation.set(i); // Identity permutation
    }

    CipherText encapsulate(const PublicKey &pk, SharedSecret &ss) {
        BitVec message = randomMessage();
        BitVec c = encode(pk, message);
        c ^= simpleErrorPattern(); // Add correctable errors

        ss.key = hash(message);
        return { c };
    }

    SharedSecret decapsulate(const CipherText &ct, const PrivateKey &sk) {
        BitVec corrected = simpleErrorCorrection(ct.c);
        BitVec message;
        for (int i = 0; i < K; ++i)
            message[i] = corrected[i];

        return { hash(message) };
    }

private:
    std::mt19937 rng;

    BitVec randomMessage() {
        BitVec m;
        std::uniform_int_distribution<int> dist(0, 1);
        for (int i = 0; i < K; ++i)
            m[i] = dist(rng);
        return m;
    }

    BitVec encode(const PublicKey &pk, const BitVec &m) {
        BitVec c;
        for (int i = 0; i < K; ++i)
            if (m[i]) c ^= pk.G[i];
        return c;
    }

    BitVec simpleErrorPattern() {
        BitVec e;
        e.set(N - 1); // Flip last bit only for simple correction
        return e;
    }

    BitVec simpleErrorCorrection(const BitVec &c) {
        BitVec corrected = c;
        corrected.flip(N - 1); // Reverse the bit flipped
        return corrected;
    }

    QByteArray hash(const BitVec &b) {
        QByteArray raw;
        for (int i = 0; i < N; i += 8) {
            uint8_t byte = 0;
            for (int j = 0; j < 8 && i + j < N; ++j) {
                if (b[i + j]) byte |= (1 << j);
            }
            raw.append(byte);
        }
        return QCryptographicHash::hash(raw, QCryptographicHash::Sha256);
    }
};

#endif // PQCRYPTO_LIGHT_H

