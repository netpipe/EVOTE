#include <QCoreApplication>
#include <QDebug>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <QTime>

// -------- Settings --------
#define KYBER_512 0
#define KYBER_768 1
#define KYBER_1024 2

int kyber_mode = KYBER_512;

// Parameters based on mode
int getPolyLength() {
    switch (kyber_mode) {
    case KYBER_768: return 6;
    case KYBER_1024: return 8;
    default: return 4; // KYBER_512
    }
}

int mod_q = 17; // Small q for demo, real Kyber uses 3329

// -------- Utilities --------
void printPoly(const std::vector<int>& poly, const QString& label) {
    qDebug().noquote() << label << ": " << QVector<int>::fromStdVector(poly);
}

void modReduce(std::vector<int>& v, int mod = mod_q) {
    for (int& x : v)
        x = ((x % mod) + mod) % mod;
}

std::vector<int> addPoly(const std::vector<int>& a, const std::vector<int>& b) {
    std::vector<int> res(a.size());
    for (size_t i = 0; i < a.size(); ++i)
        res[i] = (a[i] + b[i]) % mod_q;
    return res;
}

std::vector<int> subPoly(const std::vector<int>& a, const std::vector<int>& b) {
    std::vector<int> res(a.size());
    for (size_t i = 0; i < a.size(); ++i)
        res[i] = ((a[i] - b[i]) % mod_q + mod_q) % mod_q;
    return res;
}

std::vector<int> mulPoly(const std::vector<int>& a, const std::vector<int>& b) {
    std::vector<int> res(a.size() * 2 - 1, 0);
    for (size_t i = 0; i < a.size(); ++i)
        for (size_t j = 0; j < b.size(); ++j)
            res[i + j] += a[i] * b[j];

    modReduce(res);
    res.resize(a.size()); // Poly reduction for demo
    return res;
}

// -------- Kyber Core --------
struct KeyPair {
    std::vector<std::vector<int>> A;
    std::vector<std::vector<int>> S;
    std::vector<std::vector<int>> E;
    std::vector<std::vector<int>> T; // Public t = A·S + E
};

KeyPair generateKeyPair(int polyLen) {
    KeyPair key;
    qsrand(QTime::currentTime().msec());

    for (int i = 0; i < 2; ++i) {
        key.S.push_back({});
        key.E.push_back({});
        key.T.push_back({});
        for (int j = 0; j < polyLen; ++j) {
            key.S[i].push_back(qrand() % 3 - 1); // Small: -1, 0, 1
            key.E[i].push_back(qrand() % 3 - 1);
        }
    }

    for (int i = 0; i < 4; ++i) {
        key.A.push_back({});
        for (int j = 0; j < polyLen; ++j) {
            key.A[i].push_back(qrand() % mod_q);
        }
    }

    for (int i = 0; i < 2; ++i) {
        auto prod1 = mulPoly(key.A[i], key.S[0]);
        auto prod2 = mulPoly(key.A[i + 2], key.S[1]);
        auto sum = addPoly(prod1, prod2);
        key.T[i] = addPoly(sum, key.E[i]);
    }

    return key;
}

void encrypt(const std::vector<std::vector<int>>& A, const std::vector<std::vector<int>>& T,
             const std::vector<int>& message, std::vector<std::vector<int>>& u, std::vector<int>& v) {
    int polyLen = message.size();
    std::vector<int> r0(polyLen), r1(polyLen), e1_0(polyLen), e1_1(polyLen), e2(polyLen);
    for (int i = 0; i < polyLen; ++i) {
        r0[i] = qrand() % 3 - 1;
        r1[i] = qrand() % 3 - 1;
        e1_0[i] = qrand() % 3 - 1;
        e1_1[i] = qrand() % 3 - 1;
        e2[i] = qrand() % 3 - 1;
    }

    u.resize(2);
    u[0] = addPoly(addPoly(mulPoly(A[0], r0), mulPoly(A[2], r1)), e1_0);
    u[1] = addPoly(addPoly(mulPoly(A[1], r0), mulPoly(A[3], r1)), e1_1);
    auto v_temp = addPoly(mulPoly(T[0], r0), mulPoly(T[1], r1));
    v = addPoly(addPoly(v_temp, e2), message);
}

std::vector<int> decrypt(const std::vector<std::vector<int>>& S,
                         const std::vector<std::vector<int>>& u,
                         const std::vector<int>& v) {
    auto s_u = addPoly(mulPoly(S[0], u[0]), mulPoly(S[1], u[1]));
    auto m = subPoly(v, s_u);
    for (int& x : m) {
        x = (x < mod_q / 2) ? 0 : 1;
    }
    return m;
}

// -------- Demo --------
void runDemo(bool printKeys = false) {
    int polyLen = getPolyLength();
    qDebug() << "\n[Kyber Mode]" << (kyber_mode == KYBER_768 ? "Kyber-768" :
                                      kyber_mode == KYBER_1024 ? "Kyber-1024" : "Kyber-512");

    auto keypair = generateKeyPair(polyLen);
    if (printKeys) {
        printPoly(keypair.S[0], "Private S[0]");
        printPoly(keypair.S[1], "Private S[1]");
        printPoly(keypair.T[0], "Public T[0]");
        printPoly(keypair.T[1], "Public T[1]");
    }

    std::vector<int> message(polyLen, 0);
    message[0] = 1; // Simple demo message
    qDebug() << "\nOriginal Message:";
    printPoly(message, "Msg");

    std::vector<std::vector<int>> u;
    std::vector<int> v;
    encrypt(keypair.A, keypair.T, message, u, v);

    qDebug() << "\nCiphertext:";
    printPoly(u[0], "u[0]");
    printPoly(u[1], "u[1]");
    printPoly(v, "v");

    auto recovered = decrypt(keypair.S, u, v);
    qDebug() << "\nDecrypted Message:";
    printPoly(recovered, "Recovered");
}

// -------- Main --------
int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    kyber_mode = KYBER_512;   runDemo(true);
    kyber_mode = KYBER_768;   runDemo();
    kyber_mode = KYBER_1024;  runDemo();

    return 0;
}
