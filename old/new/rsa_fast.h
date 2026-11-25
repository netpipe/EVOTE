#ifndef RSA_QT_FAST_H
#define RSA_QT_FAST_H

//✅ 64-bit primes
// Chunked message encryption (2-byte blocks)
// Small public exponent (e = 3)
// Inlined modular exponentiation
// Unsigned arithmetic for speed//

#include <QtCore>
#include <random>

class FastRSA {
public:
    using BigInt = quint64;

    struct Key {
        BigInt n;
        BigInt exp;
    };

    FastRSA(int primeBits = 64) {
        generateKeys(primeBits);
    }

    QByteArray encrypt(const QByteArray &message, const Key &publicKey) {
        QByteArray result;
        for (int i = 0; i < message.size(); i += 2) {
            BigInt m = (static_cast<quint8>(message[i]) << 8);
            if (i + 1 < message.size())
                m |= static_cast<quint8>(message[i + 1]);

            BigInt c = modExp(m, publicKey.exp, publicKey.n);
            result.append(reinterpret_cast<const char *>(&c), sizeof(BigInt));
        }
        return result;
    }

    QByteArray decrypt(const QByteArray &ciphertext, const Key &privateKey) {
        QByteArray result;
        for (int i = 0; i < ciphertext.size(); i += sizeof(BigInt)) {
            BigInt c;
            memcpy(&c, ciphertext.constData() + i, sizeof(BigInt));
            BigInt m = modExp(c, privateKey.exp, privateKey.n);
            char high = static_cast<char>((m >> 8) & 0xFF);
            char low = static_cast<char>(m & 0xFF);
            result.append(high);
            if (low != 0) result.append(low); // avoid padding byte
        }
        return result;
    }

    Key getPublicKey() const { return publicKey; }
    Key getPrivateKey() const { return privateKey; }

private:
    Key publicKey, privateKey;

    void generateKeys(int bits) {
        BigInt p = generatePrime(bits);
        BigInt q = generatePrime(bits);
        while (q == p) q = generatePrime(bits);

        BigInt n = p * q;
        BigInt phi = (p - 1) * (q - 1);
        BigInt e = 3;
        while (gcd(e, phi) != 1) e += 2;
        BigInt d = modInverse(e, phi);

        publicKey = {n, e};
        privateKey = {n, d};
    }

    BigInt generatePrime(int bits) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<BigInt> dist((1ULL << (bits - 1)), (1ULL << bits) - 1);

        while (true) {
            BigInt candidate = dist(gen) | 1; // force odd
            if (isProbablePrime(candidate)) return candidate;
        }
    }

    bool isProbablePrime(BigInt n, int k = 3) {
        if (n < 4) return n == 2 || n == 3;
        for (int i = 0; i < k; ++i) {
            BigInt a = 2 + (qrand() % (n - 3));
            if (modExp(a, n - 1, n) != 1)
                return false;
        }
        return true;
    }

    inline BigInt modExp(BigInt base, BigInt exp, BigInt mod) const {
        BigInt result = 1;
        base %= mod;
        while (exp > 0) {
            if (exp & 1) result = (result * base) % mod;
            base = (base * base) % mod;
            exp >>= 1;
        }
        return result;
    }

    BigInt gcd(BigInt a, BigInt b) const {
        while (b != 0) {
            BigInt t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    BigInt modInverse(BigInt a, BigInt m) {
        BigInt m0 = m, t, q;
        BigInt x0 = 0, x1 = 1;

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

#endif // RSA_QT_FAST_H
