#include "ledger.h"
#include <QDateTime>
#include <QJsonDocument>
#include <QSqlError>
#include <QSqlQuery>
#include <QSet>
#include <QUuid>
#include <QVariant>

namespace evote {

static const qint64 MAX_EXPIRY_SEC = 30 * 86400;

OfflineLedger::OfflineLedger(const QString &file) {
    conn = "ledger-" + QUuid::createUuid().toString();
    db = QSqlDatabase::addDatabase("QSQLITE", conn);
    db.setDatabaseName(file);
    if (!db.open()) return;
    QSqlQuery q(db);
    q.exec("PRAGMA journal_mode=WAL");
    q.exec("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)");
    q.exec("CREATE TABLE IF NOT EXISTS coins (hash TEXT PRIMARY KEY, owner TEXT NOT NULL, amount INTEGER NOT NULL, spent INTEGER NOT NULL,"
           " issuer TEXT NOT NULL, updated INTEGER NOT NULL, last TEXT NOT NULL DEFAULT '')");
    q.exec("CREATE INDEX IF NOT EXISTS idx_coins_owner ON coins(owner)");
    q.exec("CREATE TABLE IF NOT EXISTS lines (id INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL, coin TEXT, line TEXT NOT NULL)");
    q.exec("CREATE INDEX IF NOT EXISTS idx_lines_coin ON lines(coin)");
    q.exec("CREATE TABLE IF NOT EXISTS seen (coin TEXT NOT NULL, line_hash TEXT NOT NULL, recipient TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(coin, line_hash))");
}
OfflineLedger::~OfflineLedger() { db.close(); db = QSqlDatabase(); QSqlDatabase::removeDatabase(conn); }

QString OfflineLedger::meta(const QString &k, const QString &def) const {
    QSqlQuery q(db); q.prepare("SELECT v FROM meta WHERE k=?"); q.addBindValue(k);
    return q.exec() && q.next() ? q.value(0).toString() : def;
}
void OfflineLedger::setMeta(const QString &k, const QString &v) {
    QSqlQuery q(db); q.prepare("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)"); q.addBindValue(k); q.addBindValue(v); q.exec();
}
void OfflineLedger::reset() {
    QSqlQuery q(db);
    for (const char *t : {"DELETE FROM meta", "DELETE FROM coins", "DELETE FROM lines", "DELETE FROM seen"}) q.exec(t);
}
qint64 OfflineLedger::lineCount() const { return meta("total_lines", "0").toLongLong(); }
QDateTime OfflineLedger::syncedAt() const {
    const qint64 t = meta("synced_at", "0").toLongLong();
    return t ? QDateTime::fromSecsSinceEpoch(t) : QDateTime();
}
QString OfflineLedger::ageText() const {
    const QDateTime t = syncedAt();
    if (!t.isValid()) return "No offline ledger yet - press \"Download / update ledger\" while online.";
    const qint64 mins = t.secsTo(QDateTime::currentDateTime()) / 60;
    const QString ago = mins < 60 ? QString("%1 min ago").arg(mins) : mins < 2880 ? QString("%1 h ago").arg(mins / 60) : QString("%1 days ago").arg(mins / 1440);
    return QString("Ledger as of %1 (%2), %3 lines. Spends made after that can't be seen offline.")
        .arg(t.toString("yyyy-MM-dd HH:mm"), ago).arg(lineCount());
}
QJsonObject OfflineLedger::ballot() const { return QJsonDocument::fromJson(meta("ballot", "{}").toUtf8()).object(); }

QVector<Coin> OfflineLedger::coinsOf(const QString &owner) const {
    QVector<Coin> out; QSqlQuery q(db);
    q.prepare("SELECT hash, amount FROM coins WHERE owner=? AND spent=0 ORDER BY updated"); q.addBindValue(owner); q.exec();
    while (q.next()) { Coin c; c.hash = q.value(0).toString(); c.amount = q.value(1).toLongLong(); c.owner = owner; out << c; }
    return out;
}
QStringList OfflineLedger::historyOf(const QString &coin) const {
    QStringList out; QSqlQuery q(db);
    q.prepare("SELECT line FROM lines WHERE coin=? ORDER BY id"); q.addBindValue(coin); q.exec();
    while (q.next()) out << q.value(0).toString();
    return out;
}
int OfflineLedger::seenCount() const { QSqlQuery q(db); q.exec("SELECT COUNT(*) FROM seen"); return q.next() ? q.value(0).toInt() : 0; }
void OfflineLedger::clearSeen() { QSqlQuery q(db); q.exec("DELETE FROM seen"); }

// Lines come from the server in its own accepted order, so applying them in id order rebuilds
// exactly the server's state. Signatures are still checked here, never trusted blindly.
bool OfflineLedger::applyLine(const Line &l, qint64 id, QString &why) {
    QSqlQuery q(db);
    const QSet<QString> issuers = [&] { QSet<QString> s; for (const QJsonValue &v : QJsonDocument::fromJson(meta("issuers", "[]").toUtf8()).array()) s << v.toString(); return s; }();
    bool applied = false;
    if (!l.sigOk) why = "bad signature";
    else if (l.type == "SIGNED_ISSUE" && l.p.size() == 8) {
        if (!issuers.contains(l.pub)) why = "issuer not on the server's issuer list";
        else {
            q.prepare("INSERT OR IGNORE INTO coins(hash,owner,amount,spent,issuer,updated,last) VALUES(?,?,?,0,?,?,?)");
            for (const QVariant &v : {QVariant(l.p[5]), QVariant(l.p[6]), QVariant(l.p[7].toLongLong()), QVariant(l.pub), QVariant(l.ts), QVariant(l.hash)}) q.addBindValue(v);
            applied = q.exec();
        }
    } else if ((l.type == "SIGNED_TRANSFER" && l.p.size() == 9) || (l.type == "SIGNED_VOTE" && l.p.size() == 7)) {
        q.prepare("SELECT owner, spent, amount FROM coins WHERE hash=?"); q.addBindValue(l.coin()); q.exec();
        if (!q.next()) why = "unknown coin";
        else if (q.value(0).toString() != l.pub) why = "signer is not the owner";
        else if (q.value(1).toInt()) why = "coin already spent";
        else if (l.type == "SIGNED_TRANSFER" && q.value(2).toLongLong() != l.p[7].toLongLong()) why = "amount mismatch";
        else {
            QSqlQuery u(db);
            if (l.type == "SIGNED_TRANSFER") { u.prepare("UPDATE coins SET owner=?, updated=?, last=? WHERE hash=?"); u.addBindValue(l.p[6]); }
            else u.prepare("UPDATE coins SET spent=1, updated=?, last=? WHERE hash=?");
            u.addBindValue(l.ts); u.addBindValue(l.hash); u.addBindValue(l.coin());
            applied = u.exec();
        }
    } else why = "unknown line type";
    QSqlQuery ins(db);
    ins.prepare("INSERT OR IGNORE INTO lines(id,hash,coin,line) VALUES(?,?,?,?)");
    ins.addBindValue(id); ins.addBindValue(l.hash); ins.addBindValue(l.coin()); ins.addBindValue(l.raw);
    ins.exec();
    return applied;
}

bool OfflineLedger::loadSnapshot(Api &api, const QJsonObject &boot, QString &msg) {
    QJsonObject r;
    if (!api.call("snapshot", {}, r)) { msg = "snapshot: " + api.lastError; return false; }
    const QJsonObject c = r.value("checkpoint").toObject();
    if (c.isEmpty()) return true;                            // server has no checkpoint yet: pull everything
    const QString data = r.value("data").toString();
    const QString m = QStringList{"EVOTE-CHECKPOINT", "1", QString::number(qint64(c.value("line_id").toDouble())), QString::number(qint64(c.value("count").toDouble())),
                                  c.value("head").toString(), c.value("state_hash").toString(), QString::number(qint64(c.value("created").toDouble()))}.join('|');
    if (!evote::verify(rawFromPubId(boot.value("serverPub").toString()), m.toUtf8(), QByteArray::fromBase64(c.value("sig").toString().toLatin1()))) {
        msg = "checkpoint signature is not valid for this server - refused"; return false;
    }
    if (sha256Hex(data.toUtf8()) != c.value("state_hash").toString()) { msg = "checkpoint data does not match its signed hash - refused"; return false; }
    const QJsonObject d = QJsonDocument::fromJson(data.toUtf8()).object();
    const QJsonArray owners = d.value("owners").toArray();
    QSqlQuery q(db);
    q.prepare("INSERT OR REPLACE INTO coins(hash,owner,amount,spent,issuer,updated,last) VALUES(?,?,?,?,?,?,?)");
    for (const QJsonValue &tv : d.value("tokens").toArray()) {
        const QJsonArray t = tv.toArray();   // [hash, ownerIdx, amount, spent, issuerIdx, ts, updated, lastHash, received]
        q.addBindValue(t[0].toString()); q.addBindValue(owners[t[1].toInt()].toString()); q.addBindValue(qint64(t[2].toDouble()));
        q.addBindValue(t[3].toInt()); q.addBindValue(owners[t[4].toInt()].toString()); q.addBindValue(qint64(t[6].toDouble())); q.addBindValue(t[7].toString());
        q.exec();
    }
    setMeta("cursor", QString::number(qint64(c.value("line_id").toDouble())));
    setMeta("checkpoint", QString::number(qint64(c.value("line_id").toDouble())));
    setMeta("total_lines", QString::number(qint64(c.value("count").toDouble())));
    setMeta("checkpoint_count", QString::number(qint64(c.value("count").toDouble())));
    return true;
}

bool OfflineLedger::sync(Api &api, const std::function<bool(qint64, qint64)> &progress, QString &msg) {
    QJsonObject boot;
    if (!api.call("boot", {}, boot)) { msg = "server unreachable: " + api.lastError; return false; }
    const QString pub = boot.value("serverPub").toString();
    const QString pinned = meta("server_pub");
    if (!pinned.isEmpty() && pinned != pub) { msg = "this server's key is different from the one this ledger was downloaded from - refused (use Reset to start over with another server)"; return false; }
    QJsonArray iss; for (const QJsonValue &v : boot.value("issuers").toArray()) iss.append(v.toObject().value("pub"));
    setMeta("server_pub", pub); setMeta("server_url", api.base);
    setMeta("issuers", QString::fromUtf8(QJsonDocument(iss).toJson(QJsonDocument::Compact)));
    setMeta("ballot", QString::fromUtf8(QJsonDocument(boot.value("ballot").toObject()).toJson(QJsonDocument::Compact)));
    const qint64 serverTotal = qint64(boot.value("counts").toObject().value("lines").toDouble());

    // The server may delete lines older than a newer checkpoint (ledger trimming). If its checkpoint is
    // past where this copy stopped, the missing lines may be gone: rebuild from the new signed checkpoint.
    const QJsonObject cp = boot.value("checkpoint").toObject();
    const qint64 cpLine = qint64(cp.value("line_id").toDouble()), cpCount = qint64(cp.value("count").toDouble());
    if (cpCount && cpCount < meta("checkpoint_count", "0").toLongLong()) { msg = "the server offers an older checkpoint than one already verified - refused"; return false; }
    if (!meta("cursor").isEmpty() && cpLine > meta("cursor").toLongLong()) {
        QSqlQuery q(db); q.exec("DELETE FROM coins"); q.exec("DELETE FROM lines");
        for (const char *k : {"cursor", "checkpoint", "total_lines"}) { QSqlQuery d(db); d.prepare("DELETE FROM meta WHERE k=?"); d.addBindValue(k); d.exec(); }
    }
    if (meta("cursor").isEmpty()) {                          // first download: start from the signed checkpoint
        db.transaction();
        if (!loadSnapshot(api, boot, msg)) { db.rollback(); return false; }
        if (meta("cursor").isEmpty()) setMeta("cursor", "0");
        db.commit();
    }
    qint64 cursor = meta("cursor").toLongLong(), done = lineCount(), added = 0, skipped = 0;
    for (;;) {
        if (!progress(done, serverTotal)) { msg = QString("paused at %1 of %2 lines - press again to continue").arg(done).arg(serverTotal); return true; }
        QJsonObject r;
        if (!api.call("pull", QJsonObject{{"since", double(cursor)}}, r)) { msg = "download stopped: " + api.lastError + " - press again to continue"; return false; }
        const QJsonArray lines = r.value("lines").toArray();
        if (lines.isEmpty()) break;
        db.transaction();
        for (const QJsonValue &v : lines) {
            const QJsonObject o = v.toObject(); Line l; QString why;
            if (!parseLine(o.value("line").toString(), l)) { skipped++; continue; }
            if (!applyLine(l, qint64(o.value("id").toDouble()), why)) skipped++;
            cursor = qint64(o.value("id").toDouble()); done++; added++;
        }
        setMeta("cursor", QString::number(cursor)); setMeta("total_lines", QString::number(done));
        db.commit();
        if (lines.size() < 400) break;
    }
    setMeta("synced_at", QString::number(QDateTime::currentSecsSinceEpoch()));
    progress(done, serverTotal);
    msg = QString("Ledger up to date: %1 lines (%2 new%3).").arg(done).arg(added).arg(skipped ? QString(", %1 skipped").arg(skipped) : QString());
    return true;
}

// ---------------------------------------------------------------- offline voucher check
VerifyReport OfflineLedger::verify(const QStringList &all, const QStringList &spends, bool remember) {
    VerifyReport rep; rep.ledgerAge = ageText();
    const QSet<QString> issuers = [&] { QSet<QString> s; for (const QJsonValue &v : QJsonDocument::fromJson(meta("issuers", "[]").toUtf8()).array()) s << v.toString(); return s; }();
    const QJsonObject bal = ballot();
    QSet<QString> options; for (const QJsonValue &v : bal.value("options").toArray()) options << v.toString();
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    QMap<QString, QVector<Line>> prov;                       // coin -> voucher lines about it (history)
    for (const QString &raw : all) { Line l; if (parseLine(raw, l) && l.sigOk) prov[l.coin()] << l; }

    QSet<QString> inThisVoucher;
    for (const QString &raw : spends) {
        VerifyItem it; Line l;
        if (!parseLine(raw, l)) { it.message = "not a valid signed line"; rep.items << it; continue; }
        it.kind = l.type == "SIGNED_VOTE" ? "vote" : "transfer"; it.coin = l.coin(); it.from = l.pub;
        if (l.type == "SIGNED_TRANSFER") { it.to = l.p.value(6); it.amount = l.p.value(7).toLongLong(); }
        else it.option = QString::fromUtf8(QByteArray::fromBase64(l.p.value(5).toLatin1()));
        auto fail = [&](const QString &m) { it.state = VerifyItem::Invalid; it.message = m; rep.items << it; };
        if (!l.sigOk) { fail("INVALID SIGNATURE - this line was not signed by the coin's owner key"); continue; }
        if (l.type == "SIGNED_TRANSFER") {
            const qint64 exp = l.p.value(8).toLongLong();
            if (exp < l.ts || exp - l.ts > MAX_EXPIRY_SEC) { fail("bad expiry"); continue; }
            if (now > exp) { fail(QString("EXPIRED at %1").arg(QDateTime::fromSecsSinceEpoch(exp).toString("yyyy-MM-dd HH:mm"))); continue; }
        } else {
            if (bal.value("closed").toBool()) { fail("the ballot was closed when the ledger was downloaded"); continue; }
            if (!options.isEmpty() && !options.contains(it.option)) { fail("\"" + it.option + "\" is not an option on the ballot"); continue; }
        }
        if (inThisVoucher.contains(it.coin)) { fail("DOUBLE SPEND inside this voucher - the same coin appears twice"); continue; }
        inThisVoucher << it.coin;

        QSqlQuery q(db); q.prepare("SELECT owner, spent, amount, last FROM coins WHERE hash=?"); q.addBindValue(it.coin); q.exec();
        if (q.next()) {
            const QString owner = q.value(0).toString(), last = q.value(3).toString();
            if (last == l.hash) { fail("ALREADY REDEEMED - this exact spend is already in the ledger"); continue; }
            if (q.value(1).toInt()) { fail("ALREADY SPENT - the coin was used for a vote"); continue; }
            if (owner != l.pub) { fail("NOT THE OWNER - at the time of the ledger the coin belongs to " + shortAddr(owner)); continue; }
            if (l.type == "SIGNED_TRANSFER" && q.value(2).toLongLong() != it.amount) { fail("amount does not match the coin's weight"); continue; }
            it.state = VerifyItem::Valid; it.message = "OK - signed by the owner, unspent in your ledger copy";
            if (l.type == "SIGNED_VOTE") it.amount = q.value(2).toLongLong();
        } else {
            // coin newer than the ledger copy: accept it only if the voucher carries its full history
            QString owner; qint64 amount = 0; bool chain = false;
            QVector<Line> h = prov.value(it.coin);
            std::sort(h.begin(), h.end(), [](const Line &a, const Line &b) { return a.ts < b.ts; });
            for (const Line &x : h) {
                if (x.type == "SIGNED_ISSUE" && x.p.size() == 8 && issuers.contains(x.pub) && owner.isEmpty()) { owner = x.p[6]; amount = x.p[7].toLongLong(); chain = true; }
                else if (chain && x.type == "SIGNED_TRANSFER" && x.hash != l.hash && x.pub == owner && x.p.value(7).toLongLong() == amount) owner = x.p[6];
            }
            if (!chain) { fail("UNKNOWN COIN - not in your ledger copy and the voucher has no history for it (update the ledger when online)"); continue; }
            if (owner != l.pub) { fail("NOT THE OWNER according to the coin's own history"); continue; }
            if (l.type == "SIGNED_TRANSFER" && amount != it.amount) { fail("amount does not match the coin's weight"); continue; }
            it.state = VerifyItem::ValidByHistory; it.amount = amount;
            it.message = "OK by its own history - the coin is newer than your ledger copy, so a later spend can't be ruled out";
        }
        // remembered for the rest of the meet: the same coin shown again in a different spend is a double spend
        QSqlQuery s(db); s.prepare("SELECT line_hash, recipient, ts FROM seen WHERE coin=?"); s.addBindValue(it.coin); s.exec();
        bool dup = false;
        while (s.next()) {
            if (s.value(0).toString() == l.hash) { it.state = VerifyItem::Warning; it.message = "ALREADY CHECKED - the same voucher was shown earlier (" + QDateTime::fromSecsSinceEpoch(s.value(2).toLongLong()).toString("HH:mm") + ")"; }
            else { dup = true; it.state = VerifyItem::Invalid;
                   it.message = "DOUBLE PRESENTATION - this coin was already presented at " + QDateTime::fromSecsSinceEpoch(s.value(2).toLongLong()).toString("HH:mm") + " in a different spend (to " + (s.value(1).toString().startsWith("vote: ") ? s.value(1).toString() : shortAddr(s.value(1).toString())) + ")"; }
        }
        if (remember && !dup && it.state != VerifyItem::Warning) {
            QSqlQuery ins(db); ins.prepare("INSERT OR IGNORE INTO seen(coin,line_hash,recipient,ts) VALUES(?,?,?,?)");
            ins.addBindValue(it.coin); ins.addBindValue(l.hash); ins.addBindValue(it.kind == "vote" ? QString("vote: ") + it.option : it.to); ins.addBindValue(now); ins.exec();
        }
        if (it.state == VerifyItem::Valid || it.state == VerifyItem::ValidByHistory) rep.validWeightTo[it.kind == "vote" ? "vote: " + it.option : it.to] += it.amount;
        rep.items << it;
    }
    return rep;
}

} // namespace evote
