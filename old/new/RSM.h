#include <gmpxx.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <random>
#include <sstream>
using namespace std;

class ModuloEncryptor {
public:
    struct PublicKey {
        mpz_class n;
        mpz_class e;
    };

    struct PrivateKey {
        mpz_class n;
        mpz_class d;
    };

    static void generateKeys(PublicKey& pub, PrivateKey& priv, int bits = 512) {
        gmp_randclass rng(gmp_randinit_mt);
        rng.seed(time(nullptr));

        mpz_class p = generatePrime(rng, bits);
        mpz_class q;
        do { q = generatePrime(rng, bits); } while (q == p);

        mpz_class n = p * q;
        mpz_class phi = (p - 1) * (q - 1);
//        mpz_class e = 65537;
        // Generate a 10-bit prime (values between 512 and 1023)
mpz_class e;
// Try until e is between 30000 and 65535 and is coprime with phi
do {
    // Generate a random number in a safer range
    e = rng.get_z_range(65536 - 30000) + 30000; // [30000, 65535]

    // Find next prime ≥ e
    mpz_nextprime(e.get_mpz_t(), e.get_mpz_t());

} while (e > 65537); // Optional: keep e small for encryption efficiency


        mpz_class d;

        mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());

        pub = {n, e};
        priv = {n, d};
    }

    static string encrypt(const string& message, const PublicKey& pub, const string& key) {
        string data = message;

        auto order = getMethodOrder(key);
        for (int method : order) applyMethod(data, key, method);

        mpz_class m(dataToInt(data));
        mpz_class c;

        // Double exponentiation and modulo
        mpz_powm(c.get_mpz_t(), m.get_mpz_t(), pub.e.get_mpz_t(), pub.n.get_mpz_t());
        mpz_powm(c.get_mpz_t(), c.get_mpz_t(), pub.e.get_mpz_t(), pub.n.get_mpz_t());

        return c.get_str();
    }

    static string decrypt(const string& ciphertext, const PrivateKey& priv, const string& key) {
        mpz_class c(ciphertext);
        mpz_class m;

        // Double decryption
        mpz_powm(m.get_mpz_t(), c.get_mpz_t(), priv.d.get_mpz_t(), priv.n.get_mpz_t());
        mpz_powm(m.get_mpz_t(), m.get_mpz_t(), priv.d.get_mpz_t(), priv.n.get_mpz_t());

        string data = intToData(m);

        auto order = getMethodOrder(key);
        reverse(order.begin(), order.end());
        for (int method : order) reverseMethod(data, key, method);

        return data;
    }
    static void customMix(std::string& data) {
        for (char& c : data) {
            uint8_t x = static_cast<uint8_t>(c);
            x = ((x << 1) | (x >> 7)) & 0xFF;  // Rotate left 1
            x ^= 0xA5;                         // XOR with constant
            c = static_cast<char>(x);
        }
    }

   static  void customUnmix(std::string& data) {
        for (char& c : data) {
            uint8_t x = static_cast<uint8_t>(c);
            x ^= 0xA5;                         // Reverse XOR
            x = ((x >> 1) | (x << 7)) & 0xFF;  // Rotate right 1
            c = static_cast<char>(x);
        }
    }

    static void flipBytePairs(std::string& data) {
        for (size_t i = 0; i + 1 < data.size(); i += 2) {
            std::swap(data[i], data[i + 1]);
        }
    }

private:
    static mpz_class generatePrime(gmp_randclass& rng, int bits) {
        mpz_class candidate;
        do {
            candidate = rng.get_z_bits(bits);
            mpz_nextprime(candidate.get_mpz_t(), candidate.get_mpz_t());
        } while (candidate < 10000); // avoid tiny primes
        return candidate;
    }

    static string intToData(const mpz_class& num) {
        string hex = num.get_str(16);
        if (hex.size() % 2 != 0) hex = "0" + hex;

        string out;
        for (size_t i = 0; i < hex.size(); i += 2) {
            int byte;
            stringstream ss;
            ss << hex.substr(i, 2);
            ss >> std::hex >> byte;
            out += static_cast<char>(byte);
        }
        return out;
    }

    static mpz_class dataToInt(const string& data) {
        string hex;
        for (char c : data) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned char>(c));
            hex += buf;
        }
        return mpz_class("0x" + hex);
    }

static std::vector<int> getMethodOrder(const std::string& key, size_t limit = 4) {
    std::vector<int> order = {0, 1, 2, 3, 4, 5};
    std::seed_seq seed(key.begin(), key.end());
    std::mt19937 rng(seed);
    std::shuffle(order.begin(), order.end(), rng);
    // Clamp the limit to avoid overflow
    if (limit > order.size()) limit = order.size();
    // Return only the first `limit` items
    return std::vector<int>(order.begin(), order.begin() + limit);
}


    // === TRANSFORMATION METHODS ===
    static void applyMethod(string& data, const string& key, int method) {
        switch (method) {
            case 0: applyXOR(data, key); break;
            case 1: applyROT(data, 13); break;
            case 2: applySubstitution(data, key); break;
            case 3: customMix(data);  break;
            case 4: flipBytePairs(data);  break;
            case 5: shuffleString(data,key);  break;
        }
    }

    static void reverseMethod(string& data, const string& key, int method) {
        switch (method) {
            case 0: applyXOR(data, key); break; // XOR is symmetric
            case 1: applyROT(data, 26 - 13); break;
            case 2: reverseSubstitution(data, key); break;
            case 3: customUnmix(data);  break;
            case 4: flipBytePairs(data);  break;
            case 5: unshuffleString(data,key);  break;
        }
    }

    static void applyXOR(string& data, const string& key) {
        for (size_t i = 0; i < data.size(); ++i)
            data[i] ^= key[i % key.size()];
    }

    static void applyROT(string& data, int shift) {
        for (char& c : data)
            if (isalpha(c))
                c = (islower(c) ? 'a' : 'A') + (c - (islower(c) ? 'a' : 'A') + shift) % 26;
    }

    static void shuffleString(std::string& data, const std::string& key) {
        std::vector<size_t> indices(data.size());
        std::iota(indices.begin(), indices.end(), 0);

        std::seed_seq seed(key.begin(), key.end());
        std::mt19937 rng(seed);
        std::shuffle(indices.begin(), indices.end(), rng);

        std::string shuffled = data;
        for (size_t i = 0; i < data.size(); ++i) {
            shuffled[i] = data[indices[i]];
        }
        data = shuffled;
    }

    static void unshuffleString(std::string& data, const std::string& key) {
        std::vector<size_t> indices(data.size());
        std::iota(indices.begin(), indices.end(), 0);

        std::seed_seq seed(key.begin(), key.end());
        std::mt19937 rng(seed);
        std::shuffle(indices.begin(), indices.end(), rng);

        std::string unshuffled = data;
        for (size_t i = 0; i < data.size(); ++i) {
            unshuffled[indices[i]] = data[i];  // ← reverse mapping
        }
        data = unshuffled;
    }

    
    static void applySubstitution(string& data, const string& key) {
        string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        string shuffled = alphabet;
        seed_seq seed(key.begin(), key.end());
        mt19937 rng(seed);
        shuffle(shuffled.begin(), shuffled.end(), rng);

        for (char& c : data) {
            size_t idx = alphabet.find(c);
            if (idx != string::npos) c = shuffled[idx];
        }
    }

    static void reverseSubstitution(string& data, const string& key) {
        string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        string shuffled = alphabet;
        seed_seq seed(key.begin(), key.end());
        mt19937 rng(seed);
        shuffle(shuffled.begin(), shuffled.end(), rng);

        for (char& c : data) {
            size_t idx = shuffled.find(c);
            if (idx != string::npos) c = alphabet[idx];
        }
    }
};
