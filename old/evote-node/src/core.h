// EVOTE Lite Wallet - core: crypto, wallet files, signed ledger lines, server API.
// Wire-compatible with php-new3-3 (website), the dice site / change machine, and the newer3 Qt node:
//   TYPE|1|pubId|ts|nonce|fields...|sigB64      pubId = base64(PEM SPKI Ed25519)
#pragma once
#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QJsonObject>
#include <QJsonArray>
#include <QVector>
#include <QMap>

namespace evote {

// ---------------------------------------------------------------- crypto
QByteArray sha256(const QByteArray &data);
QString sha256Hex(const QByteArray &data);
QByteArray hmacSha256(const QByteArray &key, const QByteArray &msg);
QByteArray pbkdf2Sha256(const QByteArray &pass, const QByteArray &salt, int iter, int len);
QByteArray randomBytes(int n);

struct Key {
    QByteArray seed;    // 32-byte Ed25519 private seed (empty = no key)
    QByteArray pubRaw;  // 32-byte public key
    QString id;         // base64(PEM SPKI) address
    bool valid() const { return seed.size() == 32 && pubRaw.size() == 32; }
};
Key keyFromSeed(const QByteArray &seed);
Key generateKey();
QByteArray sign(const Key &k, const QByteArray &msg);
bool verify(const QByteArray &pubRaw, const QByteArray &msg, const QByteArray &sig);
QString pubIdFromRaw(const QByteArray &raw);
QByteArray rawFromPubId(const QString &id);         // empty if not a valid Ed25519 key id
QString shortId(const QString &s, int n = 8);
QString shortAddr(const QString &id);               // readable short form of an address (raw key hex)
bool strictB64(const QByteArray &s);                // base64 alphabet only, padded to a multiple of 4

// ---------------------------------------------------------------- wallet file (evote-wallet.json)
struct WalletInfo { Key key; QString label; qint64 created = 0; int version = 0; };
// Opens v2 (legacy) and v3 files exactly like the website. Throws std::runtime_error with a readable message.
WalletInfo walletDecrypt(const QJsonObject &file, const QString &passphrase);
QJsonObject walletEncrypt(const Key &k, const QString &passphrase, const QString &label, qint64 created = 0); // always v3

// ---------------------------------------------------------------- ledger lines
struct Line {
    QString raw, type, pub, nonce, hash;
    qint64 ts = 0;
    QStringList p;      // every field except the signature (p[0]=type ... )
    QByteArray sig;
    bool sigOk = false;
    QString coin() const;                                // token hash the line is about
};
bool parseLine(const QString &raw, Line &out);           // false if malformed; sets sigOk
QString makeLine(const Key &k, const QString &type, const QStringList &fields);
QString makeTransfer(const Key &k, const QString &coin, const QString &to, qint64 amount, int hours);
QString makeVote(const Key &k, const QString &coin, const QString &option);

// ---------------------------------------------------------------- vouchers / bundles
struct Coin { QString hash; qint64 amount = 0; QString owner; bool spent = false; QStringList lines; };
QJsonObject makeVoucher(const QString &kind, const QString &signer, const QString &recipient,
                        const QStringList &provenance, const QStringList &spends);
// Accepts an evote-voucher / evote-coins JSON, raw lines, or a ...#rawtx= / #voucher= link.
// spends = the lines meant as payments (voucher tail, or every transfer/vote for raw input).
bool readTransactions(const QString &text, QStringList &allLines, QStringList &spends, QString &err);
QString rawtxLink(const QString &serverUrl, const QStringList &lines);

// ---------------------------------------------------------------- server API (blocking with timeout)
class Api {
public:
    explicit Api(const QString &url) : base(url) {}
    QString base;
    QString lastError;
    int timeoutMs = 20000;
    QMap<QByteArray, QByteArray> headers;   // extra request headers (e.g. X-Admin-Token in tests)
    bool call(const QString &action, const QJsonObject &body, QJsonObject &out);
};

// Exact-weight coin pick (bounded subset-sum per coin size, same as the website); empty if none.
QVector<int> pickByWeight(const QVector<qint64> &amounts, qint64 target, qint64 *below = nullptr, qint64 *above = nullptr);

} // namespace evote
