#ifndef RSA_QT_H
#define RSA_QT_H

#include <QtCore>
#include <random>
#include <cmath>

class RSA {
public:
    struct Key {
        qint64 n;
        qint64 exp;
    };

    RSA(int primeBits = 16) {
        generateKeys(primeBits);
    }

    QByteArray encrypt(const QByteArray &message, const Key &publicKey) {
        QByteArray result;
        for (char ch : message) {
            qint64 m = static_cast<unsigned char>(ch);
            qint64 c = modExp(m, publicKey.exp, publicKey.n);
            result.append(reinterpret_cast<const char *>(&c), sizeof(c));
        }
        return result;
    }

    QByteArray decrypt(const QByteArray &ciphertext, const Key &privateKey) {
        QByteArray result;
        for (int i = 0; i < ciphertext.size(); i += sizeof(qint64)) {
            qint64 c;
            memcpy(&c, ciphertext.constData() + i, sizeof(qint64));
            qint64 m = modExp(c, privateKey.exp, privateKey.n);
            result.append(static_cast<char>(m));
        }
        return result;
    }

    Key getPublicKey() const { return publicKey; }
    Key getPrivateKey() const { return privateKey; }

private:
    Key publicKey, privateKey;

    void generateKeys(int bits) {
        qint64 p = generatePrime(bits);
        qint64 q = generatePrime(bits);
        while (q == p)
            q = generatePrime(bits);

        qint64 n = p * q;
        qint64 phi = (p - 1) * (q - 1);
        qint64 e = 65537; // Common choice

        if (gcd(e, phi) != 1) e = 3;
        qint64 d = modInverse(e, phi);

        publicKey = {n, e};
        privateKey = {n, d};
    }

    qint64 generatePrime(int bits) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<qint64> dist(1LL << (bits - 1), (1LL << bits) - 1);

        while (true) {
            qint64 candidate = dist(gen) | 1; // make it odd
            if (isPrime(candidate)) return candidate;
        }
    }

    bool isPrime(qint64 n, int k = 5) {
        if (n < 2) return false;
        if (n % 2 == 0) return n == 2;
        for (int i = 0; i < k; ++i) {
            qint64 a = 2 + qrand() % (n - 3);
            if (modExp(a, n - 1, n) != 1) return false;
        }
        return true;
    }

    qint64 modExp(qint64 base, qint64 exp, qint64 mod) const {
        qint64 result = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2 == 1)
                result = (result * base) % mod;
            exp = exp >> 1;
            base = (base * base) % mod;
        }
        return result;
    }

    qint64 gcd(qint64 a, qint64 b) const {
        return b == 0 ? a : gcd(b, a % b);
    }

    qint64 modInverse(qint64 a, qint64 m) {
        qint64 m0 = m, t, q;
        qint64 x0 = 0, x1 = 1;

        if (m == 1) return 0;

        while (a > 1) {
            q = a / m;
            t = m;
            m = a % m;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }

        if (x1 < 0) x1 += m0;
        return x1;
    }
};

#endif // RSA_QT_H
