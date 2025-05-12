// pqcrypto_light.h - Minimal lattice-based key exchange (Kyber-style, educational only)
// WARNING: Not cryptographically secure. For learning/demo use only.

#ifndef PQCRYPTO_LIGHT_H
#define PQCRYPTO_LIGHT_H

#include <QtCore>
#include <random>
#include <array>

class PQCryptoLite {
public:
    static constexpr int N = 16;         // Polynomial degree (small for speed)
    static constexpr int Q = 3329;       // Modulus (like Kyber)
    static constexpr int SEED_BYTES = 32;
    using Poly = std::array<int16_t, N>;

    struct PublicKey {
        Poly a;
        Poly b;
    };

    struct PrivateKey {
        Poly s;
    };

    struct CipherText {
        Poly u;
        Poly v;
    };

    struct SharedSecret {
        QByteArray key;
    };

    PQCryptoLite() {
        std::random_device rd;
        rng.seed(rd());
    }

    void keygen(PublicKey &pk, PrivateKey &sk) {
        sk.s = sampleNoise();
        Poly e = sampleNoise();
        Poly a = sampleUniform();
        Poly b = polyAdd(polyMul(a, sk.s), e);

        pk.a = a;
        pk.b = b;
    }

    CipherText encapsulate(const PublicKey &pk, SharedSecret &ss) {
        Poly r = sampleNoise();
        Poly e1 = sampleNoise();
        Poly e2 = sampleNoise();

        Poly u = polyAdd(polyMul(pk.a, r), e1);
        Poly v = polyAdd(polyMul(pk.b, r), e2);

        ss.key = hashPoly(v);
        return { u, v };
    }

    SharedSecret decapsulate(const CipherText &ct, const PrivateKey &sk) {
        Poly t = polySub(ct.v, polyMul(ct.u, sk.s));
        SharedSecret ss;
        ss.key = hashPoly(t);
        return ss;
    }

    void printPublicKey(const PublicKey &pk) {
        qDebug() << "Public Key (Generator Matrix G):";
        for (int i = 0; i < N; ++i) {
            // Convert bitset to QString and print it
            QString str = QString::fromStdString(pk.G[i].to_string());
            qDebug() << str;
        }
    }

    void printPrivateKey(const PrivateKey &sk) {
        qDebug() << "Private Key (Permutation):";
        for (int i = 0; i < N; ++i) {
            qDebug() << sk.permutation[i];
        }
        printPublicKey(sk.pk); // Print the associated public key
    }


    // Function to print the ciphertext
    void printCipherText(const CipherText &ct) {
        qDebug()  << "Ciphertext (c): " << ct.c ;
    }

    // Function to print shared secret
    void printSharedSecret(const SharedSecret &ss) {
        qDebug()  << "Shared Secret: " << ss.key.toHex() ;
    }
private:
    std::mt19937 rng;

    Poly sampleUniform() {
        std::uniform_int_distribution<int16_t> dist(0, Q - 1);
        Poly out;
        for (int i = 0; i < N; ++i) out[i] = dist(rng);
        return out;
    }

    Poly sampleNoise(int bound = 3) {
        std::uniform_int_distribution<int16_t> dist(-bound, bound);
        Poly out;
        for (int i = 0; i < N; ++i) out[i] = modQ(dist(rng));
        return out;
    }

    Poly polyAdd(const Poly &a, const Poly &b) {
        Poly r;
        for (int i = 0; i < N; ++i) r[i] = modQ(a[i] + b[i]);
        return r;
    }

    Poly polySub(const Poly &a, const Poly &b) {
        Poly r;
        for (int i = 0; i < N; ++i) r[i] = modQ(a[i] - b[i]);
        return r;
    }

    Poly polyMul(const Poly &a, const Poly &b) {
        Poly r = {0};
        for (int i = 0; i < N; ++i) {
            for (int j = 0; j < N; ++j) {
                int k = (i + j) % N;
                r[k] = modQ(r[k] + a[i] * b[j]);
            }
        }
        return r;
    }

    int16_t modQ(int x) {
        int r = x % Q;
        return r < 0 ? r + Q : r;
    }

    QByteArray hashPoly(const Poly &p) {
        QByteArray data;
        for (int16_t v : p)
            data.append(reinterpret_cast<const char*>(&v), sizeof(int16_t));
        return QCryptographicHash::hash(data, QCryptographicHash::Sha256);
    }
};

#endif // PQCRYPTO_LIGHT_H
