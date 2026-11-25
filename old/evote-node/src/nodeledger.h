// EVOTE node ledger: the website's rules, line for line.
//
//  - admit()  = php-new3-3 ingest_one_tx(): what a NEW line must pass (signature, fields, issuer list,
//               max coin weight, expiry window, ballot open + option, owner, not spent). Same checks in
//               the same order with the same error words, so a node and the site accept/reject alike.
//  - replay() = the website's replay(): the state is rebuilt from the stored lines in one fixed order -
//               lines the site confirmed (by site line id) first, then the rest in the order this node
//               accepted them -
//               with retry passes for lines that arrive before the line they depend on. Every node that
//               holds the same lines computes the same coins, owners and votes.
#pragma once
#include "core.h"
#include <QHash>
#include <QSet>
#include <QSqlDatabase>

namespace evote {

static const qint64 MAX_COIN_WEIGHT = 1000000;
static const qint64 MAX_EXPIRY_SEC = 30 * 86400;
static const int MAX_LINE_LEN = 4096;

struct Ballot {
    QString question;
    QStringList options;
    bool closed = false;
    qint64 ts = 0;          // signed ballot time (standalone mode)
    QString signer;         // issuer that signed it ("" = from the bridged website)
    QJsonObject toJson() const;
};

struct Token { QString hash, owner, issuer; qint64 amount = 0, ts = 0, updated = 0; bool spent = false; QStringList history; };
struct Vote { QString candidate, voter, hash; qint64 ts = 0, amount = 0; };
struct Conflict { QString coin, kind, first, second; };

struct Entry {
    Line l;
    qint64 siteId = -1;     // the bridged website's line id (its first-come order), -1 = not confirmed by a site
    qint64 seq = 0;         // local arrival order
    bool siteRejected = false;
    QString status;         // after replay: "" applied, otherwise why it has no effect
};

class NodeLedger {
public:
    enum Mode {
        New,        // a fresh line (wallet, peer broadcast, local API): every website rule incl. clock + ballot
        History,    // a line a trusted peer already accepted earlier: no "expired now" / ballot-state checks
        Site        // a line the bridged website accepted (with its line id): format checks, order from the site
    };
    struct Result { bool ok = false; QString err; bool dup = false, orphan = false, conflict = false; QString hash; };

    explicit NodeLedger(const QString &dbFile);
    ~NodeLedger();

    Result admit(const QString &line, Mode mode, qint64 siteId = -1);
    int retryOrphans();                       // after new lines: orphans whose coin now exists
    void markSiteRejected(const QString &hash, const QString &why);

    void beginBatch();                        // many lines (sync / pull): one transaction, one replay
    void endBatch();

    // configuration
    QSet<QString> issuers;                    // keys allowed to SIGNED_ISSUE (issuers.txt + bridged site's list)
    Ballot ballot;
    qint64 now() const;                       // clock (tests can shift it)
    qint64 clockOffset = 0;

    // state (rebuilt by replay)
    const QHash<QString, Token> &tokens() const { return m_tokens; }
    const QHash<QString, Vote> &votes() const { return m_votes; }
    const QVector<Conflict> &conflicts() const { return m_conflicts; }
    const QVector<Entry> &entries() const { return m_entries; }
    QVector<Entry> orderedEntries() const;    // in replay order
    int orphanCount() const;
    QVector<Token> coinsOf(const QString &owner) const;
    QMap<QString, qint64> tally() const;      // option -> weight
    QStringList unconfirmedLines() const;     // not yet confirmed by the site (to push)
    QString stateHash() const;                // compact fingerprint of coins + votes (nodes compare it)
    bool has(const QString &hash) const { return m_index.contains(hash); }
    qint64 siteIdOf(const QString &hash) const { auto it = m_index.constFind(hash); return it == m_index.constEnd() ? -2 : m_entries[*it].siteId; }
    QString lineOf(const QString &hash) const;

    QString meta(const QString &k, const QString &def = QString()) const;
    void setMeta(const QString &k, const QString &v);

    void replay();

private:
    QSqlDatabase db;
    QString conn;
    QVector<Entry> m_entries;
    QHash<QString, int> m_index;               // hash -> entries index
    QSet<QString> m_nonces;                    // pub + '|' + nonce
    QHash<QString, Token> m_tokens;
    QHash<QString, Vote> m_votes;
    QVector<Conflict> m_conflicts;
    qint64 m_seq = 0;
    int m_batch = 0;
    bool m_dirty = false;

    QHash<QString, QString> m_spendOf;
    QString applyOne(const Entry &e);
    Result check(const Line &v, Mode mode);
    void store(const Line &v, qint64 siteId);
    void persistSiteId(const QString &hash, qint64 siteId);
    void addOrphan(const QString &line, Mode mode);
};

// PHP ctype_digit + (int) with saturation (huge values behave like PHP_INT_MAX)
bool digits(const QString &s);
qint64 toIntSat(const QString &s);
// PHP base64_decode($s, true)
bool b64StrictDecode(const QString &s, QByteArray &out);

} // namespace evote
