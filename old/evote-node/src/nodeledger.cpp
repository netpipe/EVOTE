#include "nodeledger.h"
#include <QDateTime>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSqlQuery>
#include <QUuid>
#include <QVariant>
#include <algorithm>

namespace evote {

QJsonObject Ballot::toJson() const {
    return QJsonObject{{"question", question}, {"options", QJsonArray::fromStringList(options)}, {"closed", closed}};
}

bool digits(const QString &s) {
    if (s.isEmpty()) return false;
    for (QChar c : s) if (c < '0' || c > '9') return false;
    return true;
}
qint64 toIntSat(const QString &s) {
    QString t = s; while (t.size() > 1 && t[0] == '0') t.remove(0, 1);
    if (t.size() > 18) return std::numeric_limits<qint64>::max();
    return t.toLongLong();
}
bool b64StrictDecode(const QString &s, QByteArray &out) {
    // PHP strict mode: only the alphabet (+ '=' padding at the end), whitespace ignored
    QByteArray b; for (QChar c : s) if (!c.isSpace()) b += c.toLatin1();
    static const QRegularExpression re("^[A-Za-z0-9+/]*={0,2}$");
    if (!re.match(QString::fromLatin1(b)).hasMatch()) return false;
    const QByteArray body = QByteArray(b).replace("=", "");
    if (body.size() % 4 == 1) return false;
    out = QByteArray::fromBase64(b);
    return true;
}
static QByteArray phpTrim(const QByteArray &s) {
    const QByteArray ws(" \t\n\r\0\x0B", 6);
    int a = 0, b = s.size();
    while (a < b && ws.contains(s[a])) a++;
    while (b > a && ws.contains(s[b - 1])) b--;
    return s.mid(a, b - a);
}
static bool hex64(const QString &s) { static const QRegularExpression re("^[0-9a-f]{64}$"); return re.match(s).hasMatch(); }

NodeLedger::NodeLedger(const QString &file) {
    conn = "nodeledger-" + QUuid::createUuid().toString();
    db = QSqlDatabase::addDatabase("QSQLITE", conn);
    db.setDatabaseName(file);
    db.open();
    QSqlQuery q(db);
    q.exec("PRAGMA journal_mode=WAL");
    q.exec("CREATE TABLE IF NOT EXISTS lines (seq INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL, line TEXT NOT NULL,"
           " site_id INTEGER NOT NULL DEFAULT -1, site_rejected INTEGER NOT NULL DEFAULT 0, recv INTEGER NOT NULL)");
    q.exec("CREATE TABLE IF NOT EXISTS orphans (line TEXT PRIMARY KEY, mode INTEGER NOT NULL, ts INTEGER NOT NULL)");
    q.exec("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)");
    q.exec("SELECT seq, line, site_id, site_rejected FROM lines ORDER BY seq");
    while (q.next()) {
        Entry e;
        if (!parseLine(q.value(1).toString(), e.l)) continue;
        e.seq = q.value(0).toLongLong(); e.siteId = q.value(2).toLongLong(); e.siteRejected = q.value(3).toInt();
        m_index.insert(e.l.hash, m_entries.size());
        m_nonces.insert(e.l.pub + '|' + e.l.nonce);
        m_entries << e; m_seq = qMax(m_seq, e.seq);
    }
    const QJsonObject b = QJsonDocument::fromJson(meta("ballot", "{}").toUtf8()).object();
    ballot.question = b.value("question").toString();
    for (const QJsonValue &o : b.value("options").toArray()) ballot.options << o.toString();
    ballot.closed = b.value("closed").toBool(); ballot.ts = qint64(b.value("ts").toDouble()); ballot.signer = b.value("signer").toString();
    replay();
}
NodeLedger::~NodeLedger() { db.close(); db = QSqlDatabase(); QSqlDatabase::removeDatabase(conn); }

qint64 NodeLedger::now() const { return QDateTime::currentSecsSinceEpoch() + clockOffset; }
QString NodeLedger::meta(const QString &k, const QString &def) const {
    QSqlQuery q(db); q.prepare("SELECT v FROM meta WHERE k=?"); q.addBindValue(k);
    return q.exec() && q.next() ? q.value(0).toString() : def;
}
void NodeLedger::setMeta(const QString &k, const QString &v) {
    QSqlQuery q(db); q.prepare("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)"); q.addBindValue(k); q.addBindValue(v); q.exec();
}
void NodeLedger::beginBatch() { if (m_batch++ == 0) db.transaction(); }
void NodeLedger::endBatch() {
    if (m_batch == 0 || --m_batch > 0) return;
    db.commit();
    if (m_dirty) replay();
}

// The website's ingest_one_tx(), same order of checks, same error words.
NodeLedger::Result NodeLedger::check(const Line &v, Mode mode) {
    Result r; r.hash = v.hash;
    auto fail = [&](const QString &e) { r.err = e; return r; };
    auto note = [&](const QString &coin, const QString &kind, const QString &first) {
        r.conflict = true;
        for (const Conflict &c : m_conflicts) if (c.second == v.hash) return;
        m_conflicts << Conflict{coin, kind, first, v.hash};
    };
    const QStringList &p = v.p;
    if (m_nonces.contains(v.pub + '|' + v.nonce)) { r.dup = true; return fail("nonce replay"); }

    if (v.type == "SIGNED_ISSUE") {
        if (p.size() != 8) return fail("issue fields");
        if (mode != Site && !issuers.contains(v.pub)) return fail("not an issuer");   // the website enforces its own issuer list
        if (!digits(p[7])) return fail("issue values");
        const qint64 amt = toIntSat(p[7]);
        if (!hex64(p[5]) || rawFromPubId(p[6]).isEmpty() || amt < 1 || amt > MAX_COIN_WEIGHT) return fail("issue values");
    } else if (v.type == "SIGNED_VOTE") {
        if (p.size() != 7) return fail("vote fields");
        QByteArray cand;
        if (!b64StrictDecode(p[5], cand) || phpTrim(cand).isEmpty() || cand.size() > 200) return fail("candidate");
        if (mode == New) {
            if (ballot.closed) return fail("ballot closed");
            if (!ballot.options.contains(QString::fromUtf8(cand)) || QString::fromUtf8(cand).toUtf8() != cand) return fail("not a ballot option");
        }
        if (mode != Site) {
            auto t = m_tokens.constFind(p[6]);
            if (t == m_tokens.constEnd()) { r.orphan = true; return fail("orphan"); }
            if (t->owner != v.pub) return fail("not owner");
            if (t->spent) { note(p[6], "double-spend vote", t->history.value(t->history.size() - 1)); return fail("already spent"); }
        }
    } else if (v.type == "SIGNED_TRANSFER") {
        if (p.size() != 9) return fail("transfer fields");
        if (!digits(p[7]) || !digits(p[8])) return fail("transfer values");
        const qint64 amt = toIntSat(p[7]), exp = toIntSat(p[8]);
        if (rawFromPubId(p[6]).isEmpty() || amt < 1) return fail("transfer values");
        if (exp < v.ts || exp - v.ts > MAX_EXPIRY_SEC) return fail("bad expiry");
        if (mode == New && now() > exp) return fail("expired");
        if (mode != Site) {
            auto t = m_tokens.constFind(p[5]);
            if (t == m_tokens.constEnd()) { r.orphan = true; return fail("orphan"); }
            if (t->owner != v.pub) {
                // a previous owner signing the same coin again = double spend attempt (the site says "not owner")
                for (const QString &h : t->history) { const QString l = lineOf(h); Line x; if (parseLine(l, x) && x.type == "SIGNED_TRANSFER" && x.pub == v.pub) { note(p[5], "double-spend transfer", h); break; } }
                return fail("not owner");
            }
            if (t->spent) { note(p[5], "double-spend transfer", t->history.value(t->history.size() - 1)); return fail("already spent"); }
            if (t->amount != amt) return fail("amount mismatch");
        }
    } else {
        return fail("unknown type");
    }
    r.ok = true;
    return r;
}

NodeLedger::Result NodeLedger::admit(const QString &raw, Mode mode, qint64 siteId) {
    Result r;
    if (raw.size() > MAX_LINE_LEN) { r.err = "oversize"; return r; }
    Line v;
    if (!parseLine(raw, v) || !v.sigOk || v.sig.size() != 64 || rawFromPubId(v.pub).isEmpty()) { r.err = "bad signature"; return r; }
    r.hash = v.hash;
    auto it = m_index.constFind(v.hash);
    if (it != m_index.constEnd()) {
        // a line we hold unconfirmed that the site now confirms: take the site's position in the order
        if (mode == Site && siteId >= 0 && m_entries[*it].siteId != siteId) {
            m_entries[*it].siteId = siteId; m_entries[*it].siteRejected = false; persistSiteId(v.hash, siteId);
            if (m_batch) m_dirty = true; else replay();
        }
        r.dup = true; r.err = "duplicate"; return r;
    }
    if (v.ts > now() + 3600) { r.err = "timestamp in future"; return r; }
    if (m_dirty && mode != Site) replay();
    r = check(v, mode);
    if (!r.ok) { if (r.orphan) addOrphan(raw, mode); return r; }
    store(v, mode == Site ? siteId : -1);
    // A Site line can land anywhere in the order -> replay. New/History lines passed check() against
    // the current state, so applying them on top gives the same result as a full replay.
    if (mode == Site) { if (m_batch) m_dirty = true; else replay(); }
    else { Entry &e = m_entries.last(); e.status = applyOne(e); }
    return r;
}

void NodeLedger::store(const Line &v, qint64 siteId) {
    Entry e; e.l = v; e.siteId = siteId; e.seq = ++m_seq;
    m_index.insert(v.hash, m_entries.size());
    m_nonces.insert(v.pub + '|' + v.nonce);
    m_entries << e;
    QSqlQuery q(db);
    q.prepare("INSERT OR IGNORE INTO lines(seq,hash,line,site_id,recv) VALUES(?,?,?,?,?)");
    q.addBindValue(e.seq); q.addBindValue(v.hash); q.addBindValue(v.raw); q.addBindValue(siteId); q.addBindValue(QDateTime::currentSecsSinceEpoch());
    q.exec();
    QSqlQuery d(db); d.prepare("DELETE FROM orphans WHERE line=?"); d.addBindValue(v.raw); d.exec();
}
void NodeLedger::persistSiteId(const QString &hash, qint64 siteId) {
    QSqlQuery q(db); q.prepare("UPDATE lines SET site_id=?, site_rejected=0 WHERE hash=?"); q.addBindValue(siteId); q.addBindValue(hash); q.exec();
}
void NodeLedger::markSiteRejected(const QString &hash, const QString &why) {
    auto it = m_index.constFind(hash); if (it == m_index.constEnd()) return;
    if (m_entries[*it].siteId >= 0) return;
    m_entries[*it].siteRejected = true; m_entries[*it].status = "rejected by the website: " + why;
    QSqlQuery q(db); q.prepare("UPDATE lines SET site_rejected=1 WHERE hash=?"); q.addBindValue(hash); q.exec();
    if (m_batch) m_dirty = true; else replay();
}
void NodeLedger::addOrphan(const QString &line, Mode mode) {
    QSqlQuery q(db); q.prepare("INSERT OR IGNORE INTO orphans(line,mode,ts) VALUES(?,?,?)");
    q.addBindValue(line.trimmed()); q.addBindValue(int(mode)); q.addBindValue(QDateTime::currentSecsSinceEpoch()); q.exec();
}
int NodeLedger::orphanCount() const { QSqlQuery q(db); q.exec("SELECT COUNT(*) FROM orphans"); return q.next() ? q.value(0).toInt() : 0; }

// like push_lines(): up to 4 passes over parked lines, drop the ones that fail for good, forget after 24 h
int NodeLedger::retryOrphans() {
    int total = 0;
    for (int pass = 0; pass < 4; pass++) {
        QSqlQuery q(db); q.exec("SELECT line, mode FROM orphans ORDER BY rowid LIMIT 400");
        QVector<QPair<QString, int>> rows; while (q.next()) rows << qMakePair(q.value(0).toString(), q.value(1).toInt());
        if (rows.isEmpty()) break;
        bool progress = false;
        for (const auto &row : rows) {
            QSqlQuery d(db); d.prepare("DELETE FROM orphans WHERE line=?"); d.addBindValue(row.first); d.exec();
            const Result r = admit(row.first, Mode(row.second));
            if (r.ok) { progress = true; total++; }
        }
        if (!progress) break;
    }
    QSqlQuery old(db); old.prepare("DELETE FROM orphans WHERE ts < ?"); old.addBindValue(QDateTime::currentSecsSinceEpoch() - 86400); old.exec();
    return total;
}

QVector<Entry> NodeLedger::orderedEntries() const {
    QVector<Entry> arr;
    for (const Entry &e : m_entries) if (!e.siteRejected) arr << e;
    std::stable_sort(arr.begin(), arr.end(), [](const Entry &a, const Entry &b) {
        if (a.siteId >= 0 && b.siteId >= 0) return a.siteId < b.siteId;
        if (a.siteId >= 0) return true;
        if (b.siteId >= 0) return false;
        return a.seq < b.seq;   // not confirmed by a site: the order this node accepted them in (signer-chosen
                                // timestamps can't reorder anything; peers sync in their own accepted order)
    });
    return arr;
}

QString NodeLedger::applyOne(const Entry &e) {   // "retry", "" applied, or the reason it does nothing
    QHash<QString, QString> &spendOf = m_spendOf;
        const Line &l = e.l; const QStringList &p = l.p;
        if (l.type == "SIGNED_ISSUE" && p.size() == 8) {
            if (!issuers.contains(l.pub) && e.siteId < 0) return "issuer not on this node's issuer list";
            const qint64 amt = digits(p[7]) ? toIntSat(p[7]) : 0;
            if (!hex64(p[5]) || amt < 1 || amt > MAX_COIN_WEIGHT) return "issue values";
            if (m_tokens.contains(p[5])) return "coin already issued";
            Token t; t.hash = p[5]; t.owner = p[6]; t.amount = amt; t.issuer = l.pub; t.ts = l.ts; t.updated = l.ts; t.history << l.hash;
            m_tokens.insert(t.hash, t);
        } else if (l.type == "SIGNED_TRANSFER" && p.size() == 9) {
            auto t = m_tokens.find(p[5]);
            if (t == m_tokens.end() || t->owner != l.pub) return "retry";
            if (t->spent) { m_conflicts << Conflict{p[5], "transfer after spend", spendOf.value(p[5]), l.hash}; return "coin already spent"; }
            const qint64 amt = digits(p[7]) ? toIntSat(p[7]) : -1;
            if (t->amount != amt) return "amount mismatch";
            t->owner = p[6]; t->updated = l.ts; t->history << l.hash; spendOf.insert(p[5], l.hash);
        } else if (l.type == "SIGNED_VOTE" && p.size() == 7) {
            QByteArray cand; if (!b64StrictDecode(p[5], cand) || phpTrim(cand).isEmpty()) return "candidate";
            auto t = m_tokens.find(p[6]);
            if (t == m_tokens.end() || t->owner != l.pub) return "retry";
            if (t->spent) { m_conflicts << Conflict{p[6], "double spend", spendOf.value(p[6]), l.hash}; return "coin already spent"; }
            t->spent = true; t->updated = l.ts; t->history << l.hash; spendOf.insert(p[6], l.hash);
            m_votes.insert(p[6], Vote{QString::fromUtf8(cand), l.pub, l.hash, l.ts, t->amount});
        } else return "unknown type";
        return QString();
}

// The website's replay(): same order, same per-type rules, same retry passes.
void NodeLedger::replay() {
    m_dirty = false;
    m_tokens.clear(); m_votes.clear();
    QVector<Conflict> admissionConflicts = m_conflicts; m_conflicts.clear();
    m_spendOf.clear();
    const QVector<Entry> arr = orderedEntries();
    QHash<QString, QString> status;
    QVector<Entry> pending;
    for (const Entry &e : arr) { const QString s = applyOne(e); if (s == "retry") pending << e; else status.insert(e.l.hash, s); }
    for (int pass = 0; !pending.isEmpty() && pass < 50; pass++) {
        const int before = pending.size(); QVector<Entry> next;
        for (const Entry &e : pending) { const QString s = applyOne(e); if (s == "retry") next << e; else status.insert(e.l.hash, s); }
        pending = next;
        if (pending.size() == before) break;
    }
    for (const Entry &e : pending) {   // lost to an earlier spend in the order (e.g. the site confirmed another one)
        const Line &l = e.l; const QString coin = l.coin();
        const auto t = m_tokens.constFind(coin);
        if (t != m_tokens.constEnd()) {
            for (const QString &h : t->history) { Line x; if (parseLine(lineOf(h), x) && x.type == "SIGNED_TRANSFER" && x.pub == l.pub && x.hash != l.hash) { m_conflicts << Conflict{coin, "double spend (lost on order)", h, l.hash}; break; } }
            status.insert(l.hash, "signer is not the owner in the agreed order (double spend that lost)");
        } else status.insert(l.hash, "coin unknown");
    }
    for (Entry &e : m_entries) e.status = e.siteRejected ? (e.status.isEmpty() ? QString("rejected by the website") : e.status) : status.value(e.l.hash);
    // keep admission-time conflict notes (rejected lines never enter the ledger) without duplicates
    for (const Conflict &c : admissionConflicts) {
        bool seen = false; for (const Conflict &x : m_conflicts) if (x.second == c.second) { seen = true; break; }
        if (!seen && !m_index.contains(c.second)) m_conflicts << c;
    }
}

QString NodeLedger::lineOf(const QString &hash) const { auto it = m_index.constFind(hash); return it == m_index.constEnd() ? QString() : m_entries[*it].l.raw; }
QVector<Token> NodeLedger::coinsOf(const QString &owner) const {
    QVector<Token> out; for (const Token &t : m_tokens) if (t.owner == owner && !t.spent) out << t;
    std::sort(out.begin(), out.end(), [](const Token &a, const Token &b) { return a.updated != b.updated ? a.updated < b.updated : a.hash < b.hash; });
    return out;
}
QMap<QString, qint64> NodeLedger::tally() const { QMap<QString, qint64> m; for (const Vote &v : m_votes) m[v.candidate] += v.amount; return m; }
QStringList NodeLedger::unconfirmedLines() const {
    // only lines that are in effect here: a spend of a coin the site refused would only be parked there forever
    QStringList out; for (const Entry &e : orderedEntries()) if (e.siteId < 0 && !e.siteRejected && e.status.isEmpty()) out << e.l.raw; return out;
}
QString NodeLedger::stateHash() const {
    QStringList rows;
    for (const Token &t : m_tokens) rows << QString("%1:%2:%3:%4").arg(t.hash, t.owner).arg(t.amount).arg(t.spent ? 1 : 0);
    for (auto it = m_votes.constBegin(); it != m_votes.constEnd(); ++it) rows << QString("v:%1:%2:%3").arg(it.key(), it->candidate, it->voter);
    rows.sort();
    return sha256Hex(rows.join('\n').toUtf8());
}

} // namespace evote
