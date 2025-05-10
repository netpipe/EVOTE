// pqcrypto_light.h - Simplified, enhanced McEliece-like KEM (for educational/demo use only)
// WARNING: This is not secure! For demonstration purposes only.

#ifndef PQCRYPTO_LIGHT_H
#define PQCRYPTO_LIGHT_H

#include <QtCore>
#include <array>
#include <random>
#include <bitset>
#include <algorithm>

class PQCryptoLite {
public:
    static constexpr int K = 128; // message bits
    static constexpr int N = 256; // codeword length

    using BitVec = std::bitset<N>;

    struct PublicKey {
        std::array<BitVec, K> G; // Generator matrix (randomized rows)
    };

    struct PrivateKey {
        std::array<int, N> permutation; // Permutation of bit positions
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
        std::uniform_int_distribution<int> bitdist(0, 1);

        for (int i = 0; i < K; ++i) {
            pk.G[i].reset();
            for (int j = 0; j < N; ++j) {
                pk.G[i][j] = bitdist(rng);
            }
        }

        // Generate a random permutation
        for (int i = 0; i < N; ++i) sk.permutation[i] = i;
        std::shuffle(sk.permutation.begin(), sk.permutation.end(), rng);
    }

    CipherText encapsulate(const PublicKey &pk, SharedSecret &ss) {
        BitVec message = randomMessage();
        BitVec c = encode(pk, message);
        c ^= randomErrorPattern();

        ss.key = hash(message);
        return { c };
    }

    SharedSecret decapsulate(const CipherText &ct, const PrivateKey &sk) {
        BitVec permuted;
        for (int i = 0; i < N; ++i) {
            permuted[sk.permutation[i]] = ct.c[i];
        }

        BitVec corrected = simpleErrorCorrection(permuted);
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

    BitVec randomErrorPattern() {
        BitVec e;
        std::uniform_int_distribution<int> posDist(0, N - 1);
        for (int i = 0; i < 3; ++i) { // Add 3 errors
            int pos = posDist(rng);
            e.flip(pos);
        }
        return e;
    }

    BitVec simpleErrorCorrection(const BitVec &c) {
        // NOTE: No real decoding. This just returns the first K bits.
        return c;
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
