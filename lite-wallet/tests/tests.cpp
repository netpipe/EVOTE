// EVOTE Lite Wallet - core + offline ledger tests against a real php-new3-3 server.
// usage: evote-lite-tests <evote index.php url> <admin token> <fixtures dir> <work dir> [second server url]
#include "../src/core.h"
#include "../src/ledger.h"
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <cstdio>
#include <stdexcept>

using namespace evote;
static int passed = 0, failed = 0;
static void check(const QString &name, bool ok) { printf("%s %s\n", ok ? "PASS" : "FAIL", qPrintable(name)); (ok ? passed : failed)++; }
static QJsonObject readJson(const QString &f) { QFile x(f); x.open(QIODevice::ReadOnly); return QJsonDocument::fromJson(x.readAll()).object(); }
static QString readText(const QString &f) { QFile x(f); x.open(QIODevice::ReadOnly); return QString::fromUtf8(x.readAll()).trimmed(); }

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    if (argc < 5) { fprintf(stderr, "usage: %s url admintoken fixtures workdir [url2]\n", argv[0]); return 2; }
    const QString url = argv[1], token = argv[2], fx = argv[3], work = argv[4], url2 = argc > 5 ? argv[5] : "";
    QDir().mkpath(work);
    Api api(url), admin(url); admin.headers.insert("X-Admin-Token", token.toUtf8());

    // ---- 1. key ids and wallet files, cross-checked with files made by the website (JS)
    const QJsonObject v2 = readJson(fx + "/wallet-test.json"), v3 = readJson(fx + "/wallet-v3.json");
    const QByteArray seed2 = QByteArray::fromHex(readText(fx + "/wallet-test.json.seed").toLatin1());
    const QByteArray seed3 = QByteArray::fromHex(readText(fx + "/wallet-v3.json.seed").toLatin1());
    check("address from seed == address the website wrote (PEM format identical)", keyFromSeed(seed3).id == v3.value("pub").toString());
    try { check("open website v2 wallet (legacy) -> right seed", walletDecrypt(v2, "correct horse battery").key.seed == seed2); } catch (std::exception &e) { check(QString("open v2: ") + e.what(), false); }
    try { check("open website v3 wallet -> right seed", walletDecrypt(v3, "correct horse battery").key.seed == seed3); } catch (std::exception &e) { check(QString("open v3: ") + e.what(), false); }
    bool threw = false; try { walletDecrypt(v3, "wrong"); } catch (std::exception &e) { threw = QString(e.what()) == "wrong passphrase"; }
    check("wrong passphrase refused", threw);
    const Key me = generateKey();
    const QJsonObject mine = walletEncrypt(me, "pass-1234", "qt wallet");
    { QFile f(work + "/qt-wallet.json"); f.open(QIODevice::WriteOnly); f.write(QJsonDocument(mine).toJson()); }
    { QFile f(work + "/qt-wallet.json.seed"); f.open(QIODevice::WriteOnly); f.write(me.seed.toHex()); }
    try { check("Qt-made v3 wallet re-opens in Qt", walletDecrypt(mine, "pass-1234").key.seed == me.seed && mine.value("version").toInt() == 3); } catch (...) { check("Qt-made v3 wallet re-opens", false); }
    const QByteArray ct = QByteArray::fromBase64(mine.value("ct").toString().toLatin1());
    check("Qt-made v3 wallet has no plain seed bytes", !ct.contains(me.seed.toHex().left(8)) && !ct.contains(me.seed.toHex().mid(32, 8)));

    // ---- 2. signed lines accepted by the server
    QJsonObject r, boot; api.call("boot", {}, boot);
    const QString option = boot.value("ballot").toObject().value("options").toArray().first().toString();
    check("admin mint 6 coins to the Qt wallet", admin.call("admin", QJsonObject{{"op", "issue"}, {"to", me.id}, {"count", 6}, {"amount", 1}}, r));
    QStringList coins; for (const QJsonValue &l : r.value("lines").toArray()) { Line x; parseLine(l.toString(), x); coins << x.coin(); }
    const Key bob = generateKey(), carol = generateKey();
    const QString t1 = makeTransfer(me, coins[0], bob.id, 1, 24);
    Line pl; check("Qt line parses + signature verifies locally", parseLine(t1, pl) && pl.sigOk && pl.coin() == coins[0]);
    api.call("redeem", QJsonObject{{"lines", QJsonArray{t1}}, {"to", bob.id}}, r);
    check("server accepts a Qt-signed transfer (deposited 1)", r.value("to").toObject().value("weight").toInt() == 1);
    api.call("redeem", QJsonObject{{"lines", QJsonArray{makeVote(me, coins[1], option)}}}, r);
    check("server accepts a Qt-signed vote (voted)", r.value("items").toArray().first().toObject().value("status").toString() == "voted");
    api.call("balance", QJsonObject{{"pub", me.id}}, r);
    check("balance API shows 4 coins left", r.value("weight").toInt() == 4);
    QStringList all, sp; QString err;
    const QString link = rawtxLink(url + "?x=1", {t1});
    check("#rawtx link round-trips", readTransactions(link, all, sp, err) && sp == QStringList{t1} && link.contains("#rawtx="));

    // ---- 3. offline ledger: chunked download with cancel + resume, from the signed checkpoint
    QFile::remove(work + "/ledger.sqlite");
    OfflineLedger led(work + "/ledger.sqlite");
    QString msg; int calls = 0;
    led.sync(api, [&](qint64, qint64) { return ++calls < 2; }, msg);           // cancel after the first chunk
    const qint64 partial = led.lineCount();
    check("download can be cancelled part-way (" + msg + ")", msg.startsWith("paused") && partial > 0);
    bool ok = led.sync(api, [](qint64, qint64) { return true; }, msg);
    api.call("boot", {}, boot);
    const qint64 serverLines = qint64(boot.value("counts").toObject().value("lines").toDouble());
    check(QString("resume finishes: %1 lines = server %2 (%3)").arg(led.lineCount()).arg(serverLines).arg(msg), ok && led.lineCount() == serverLines && led.lineCount() > partial);
    check("first download started from the signed checkpoint", led.meta("checkpoint").toLongLong() > 0);
    api.call("balance", QJsonObject{{"pub", me.id}}, r);
    qint64 offW = 0; for (const Coin &c : led.coinsOf(me.id)) offW += c.amount;
    check(QString("offline coins of the Qt wallet = server balance (%1)").arg(offW), offW == qint64(r.value("weight").toDouble()));
    api.call("balance", QJsonObject{{"pub", bob.id}}, r);
    qint64 bobW = 0; for (const Coin &c : led.coinsOf(bob.id)) bobW += c.amount;
    check("offline ledger saw the transfer to bob", bobW == 1 && qint64(r.value("weight").toDouble()) == 1);
    check("offline ballot stored", led.ballot().value("options").toArray().size() > 0);

    // ---- 4. offline voucher checks
    const QString v1 = makeTransfer(me, coins[2], carol.id, 1, 24);
    VerifyReport rep = led.verify({v1}, {v1}, true);
    check("valid voucher -> OK: " + rep.items[0].message, rep.items[0].state == VerifyItem::Valid && rep.validWeightTo.value(carol.id) == 1);
    rep = led.verify({v1}, {v1}, true);
    check("same voucher again -> ALREADY CHECKED", rep.items[0].state == VerifyItem::Warning && rep.items[0].message.startsWith("ALREADY CHECKED"));
    const QString v1b = makeTransfer(me, coins[2], bob.id, 1, 24);
    rep = led.verify({v1b}, {v1b}, true);
    check("same coin to someone else -> DOUBLE PRESENTATION", rep.items[0].state == VerifyItem::Invalid && rep.items[0].message.startsWith("DOUBLE PRESENTATION"));
    QString forged = makeTransfer(me, coins[3], carol.id, 1, 24); forged.replace(QString("|1|") + carol.id.left(5), QString("|2|") + carol.id.left(5));
    { Line a; QString x = makeTransfer(me, coins[3], carol.id, 1, 24); QStringList p = x.split('|'); p[7] = "5"; forged = p.join('|'); }
    rep = led.verify({forged}, {forged}, false);
    check("tampered amount -> INVALID SIGNATURE", rep.items[0].message.startsWith("INVALID SIGNATURE"));
    { QStringList f{"SIGNED_TRANSFER", "1", me.id, QString::number(QDateTime::currentSecsSinceEpoch() - 7200), QString::fromLatin1(randomBytes(16).toBase64()), coins[4], carol.id, "1", QString::number(QDateTime::currentSecsSinceEpoch() - 60)};
      const QString exp = f.join('|') + "|" + QString::fromLatin1(sign(me, f.join('|').toUtf8()).toBase64());
      rep = led.verify({exp}, {exp}, false);
      check("expired voucher -> EXPIRED", rep.items[0].message.startsWith("EXPIRED")); }
    const QString notMine = makeTransfer(carol, coins[5], bob.id, 1, 24);
    rep = led.verify({notMine}, {notMine}, false);
    check("someone else's coin -> NOT THE OWNER", rep.items[0].message.startsWith("NOT THE OWNER"));
    rep = led.verify({t1}, {t1}, false);
    check("a spend already in the ledger -> ALREADY REDEEMED", rep.items[0].message.startsWith("ALREADY REDEEMED"));
    const QString badVote = makeVote(me, coins[4], "NOT AN OPTION");
    rep = led.verify({badVote}, {badVote}, false);
    check("vote for a non-option -> refused", rep.items[0].state == VerifyItem::Invalid && rep.items[0].message.contains("not an option"));
    // coin minted AFTER the download: only valid if the voucher carries its history
    admin.call("admin", QJsonObject{{"op", "issue"}, {"to", me.id}, {"count", 1}, {"amount", 3}}, r);
    const QString newIssue = r.value("lines").toArray().first().toString(); Line ni; parseLine(newIssue, ni);
    const QString nt = makeTransfer(me, ni.coin(), carol.id, 3, 24);
    rep = led.verify({nt}, {nt}, false);
    check("newer coin without history -> UNKNOWN COIN", rep.items[0].message.startsWith("UNKNOWN COIN"));
    rep = led.verify({newIssue, nt}, {nt}, false);
    check("newer coin WITH its history -> OK by its own history (3 weight)", rep.items[0].state == VerifyItem::ValidByHistory && rep.validWeightTo.value(carol.id) == 3);
    const QString fakeIssue = makeLine(carol, "SIGNED_ISSUE", {sha256Hex("x"), me.id, "500"});
    Line fi; parseLine(fakeIssue, fi);
    const QString ft = makeTransfer(me, fi.coin(), carol.id, 500, 24);
    rep = led.verify({fakeIssue, ft}, {ft}, false);
    check("coin 'issued' by a non-issuer -> UNKNOWN COIN", rep.items[0].state == VerifyItem::Invalid);
    led.clearSeen(); check("clear meet list", led.seenCount() == 0);
    // update after new activity
    ok = led.sync(api, [](qint64, qint64) { return true; }, msg);
    api.call("boot", {}, boot);
    check("update fetches only what is new (" + msg + ")", ok && led.lineCount() == qint64(boot.value("counts").toObject().value("lines").toDouble()) && msg.contains("new"));
    check("age text shown", led.ageText().startsWith("Ledger as of"));
    {   // server makes a newer checkpoint (may trim older lines) -> copy rebuilds from it, meet list kept
        led.verify({v1}, {v1}, true);
        const int seenBefore = led.seenCount();
        const qint64 oldCp = led.meta("checkpoint").toLongLong();
        admin.call("admin", QJsonObject{{"op", "issue"}, {"to", me.id}, {"count", 2}, {"amount", 4}}, r);
        admin.call("admin", QJsonObject{{"op", "checkpoint"}}, r);
        ok = led.sync(api, [](qint64, qint64) { return true; }, msg);
        api.call("boot", {}, boot);
        api.call("balance", QJsonObject{{"pub", me.id}}, r);
        qint64 w2 = 0; for (const Coin &c : led.coinsOf(me.id)) w2 += c.amount;
        check(QString("newer checkpoint -> rebuilt from it (cp %1 -> %2), lines %3 = server %4, weight %5 = server %6")
              .arg(oldCp).arg(led.meta("checkpoint")).arg(led.lineCount()).arg(qint64(boot.value("counts").toObject().value("lines").toDouble())).arg(w2).arg(r.value("weight").toInt()),
              ok && led.meta("checkpoint").toLongLong() > oldCp && led.lineCount() == qint64(boot.value("counts").toObject().value("lines").toDouble()) && w2 == r.value("weight").toInt() && w2 > 0);
        check("meet list survives the rebuild", seenBefore > 0 && led.seenCount() == seenBefore);
        VerifyReport rr = led.verify({v1}, {v1}, true);
        check("after rebuild, the meet still remembers the voucher", rr.items[0].state == VerifyItem::Warning);
    }
    if (!url2.isEmpty()) {
        Api other(url2);
        ok = led.sync(other, [](qint64, qint64) { return true; }, msg);
        check("a different server's key is refused (" + msg.left(60) + ")", !ok && msg.contains("different"));
    }

    // ---- 5. exact weight pick
    qint64 lo = 0, hi = 0;
    QVector<int> p = pickByWeight({1, 1, 1, 5, 5}, 12);
    qint64 s = 0; for (int i : p) s += QVector<qint64>{1, 1, 1, 5, 5}[i];
    check("pick 12 from 1,1,1,5,5 exact", s == 12);
    check("pick 9 -> closest 8 / 10", pickByWeight({1, 1, 1, 5, 5}, 9, &lo, &hi).isEmpty() && lo == 8 && hi == 10);

    printf("%s\n", failed ? qPrintable(QString("FAILURES: %1").arg(failed)) : qPrintable(QString("ALL PASS (%1)").arg(passed)));
    return failed ? 1 : 0;
}
