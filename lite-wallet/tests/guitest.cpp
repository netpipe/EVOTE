// Drives the real MainWindow (offscreen) through every flow against a live EVOTE server.
#include "../src/mainwindow.h"
#include <QApplication>
#include <QFile>
#include <QJsonDocument>
#include <QLabel>
#include <QPlainTextEdit>
#include <QSettings>
#include <QTabWidget>
#include <QTableWidget>
#include <QDir>
#include <cstdio>
using namespace evote;
static int passed = 0, failed = 0;
static void check(const QString &n, bool ok) { printf("%s %s\n", ok ? "PASS" : "FAIL", qPrintable(n)); (ok ? passed : failed)++; }
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("EVOTE-test"); QCoreApplication::setApplicationName("guitest");
    const QString url = argv[1], token = argv[2], fx = argv[3], work = argv[4];
    QDir().mkpath(work); QFile::remove(work + "/offline-ledger.sqlite");
    MainWindow w(work); w.resize(1100, 720); w.show(); app.processEvents();
    w.setServerUrl(url);
    auto shot = [&](int tab, const QString &name) { w.tabs->setCurrentIndex(tab); app.processEvents(); w.grab().save(work + "/" + name); };

    QFile f(fx + "/wallet-v3.json"); f.open(QIODevice::ReadOnly); const QByteArray v3 = f.readAll();
    check("wrong passphrase shows a message", !w.openWalletJson(v3, "nope") && w.walletStatus->text().contains("wrong passphrase"));
    const QByteArray file = w.createWallet("meet wallet", "pass-1234");
    QJsonObject wj = QJsonDocument::fromJson(file).object();
    const QString me = wj.value("pub").toString();
    check("create wallet -> v3 file", wj.value("version").toInt() == 3);
    check("re-open created file", w.openWalletJson(file, "pass-1234"));
    shot(0, "1-wallet.png");

    Api admin(url); admin.headers.insert("X-Admin-Token", token.toUtf8()); QJsonObject r;
    admin.call("admin", QJsonObject{{"op", "issue"}, {"to", me}, {"count", 3}, {"amount", 1}}, r);
    admin.call("admin", QJsonObject{{"op", "issue"}, {"to", me}, {"count", 2}, {"amount", 5}}, r);
    admin.call("admin", QJsonObject{{"op", "issue"}, {"to", me}, {"count", 1}, {"amount", 10}}, r);
    check("refresh from server: 6 coins", w.refreshCoinsFromServer() && w.coinTable->rowCount() == 6 && w.coinsStatus->text().contains("23 weight"));
    const Key bob = generateKey(), shop = generateKey();
    w.setRecipient(bob.id);
    check("pick 9 refused with closest", !w.pickWeight(9) && w.coinsStatus->text().contains("Closest: 8 or 10"));
    check("pick 12 exact", w.pickWeight(12));
    shot(1, "2-coins.png");
    check("send 12 to server", w.sendToServer() && w.sendLog->toPlainText().contains("12 weight deposited"));
    Api api(url); api.call("balance", QJsonObject{{"pub", bob.id}}, r);
    check("bob has 12 on the server", r.value("weight").toInt() == 12);
    check("my coins refreshed: 11 left", w.coinsStatus->text().contains("11 weight"));

    // voucher -> redeemed by the server's voucher API (what the dice site / change machine call)
    w.setRecipient(shop.id); w.pickWeight(5);
    const QByteArray vch = w.voucherJson("transfer");
    const QJsonObject vo = QJsonDocument::fromJson(vch).object();
    check("voucher has provenance + 1 spend", vo.value("spends").toInt() == 1 && vo.value("lines").toArray().size() >= 2);
    // offline ledger + verify BEFORE redeeming (the meet)
    check("download ledger", w.syncLedger() && w.ledgerAge->text().contains("Ledger as of"));
    w.verifyText(QString::fromUtf8(vch));
    check("verify voucher: VALID 5 to shop", w.verifyTable->item(0, 0)->text() == "VALID" && w.verifySummary->text().contains("5 weight to"));
    shot(3, "4-verify-ok.png");
    w.verifyText(QString::fromUtf8(vch));
    check("shown again: SEEN", w.verifyTable->item(0, 0)->text() == "SEEN");
    w.setRecipient(bob.id); w.pickWeight(5);
    const QString link = w.rawtxLinkText();   // same coin (first 5) to someone else
    w.verifyText(link);
    check("same coin to bob via #rawtx: REJECT double presentation", w.verifyTable->item(0, 0)->text() == "REJECT" && w.verifyTable->item(0, 4)->text().startsWith("DOUBLE PRESENTATION"));
    shot(3, "5-verify-double.png");
    api.call("redeem", QJsonObject{{"voucher", vo}}, r);
    check("server redeems the Qt voucher (5 to shop)", r.value("deposited").toObject().value(shop.id).toInt() == 5);

    // ballot
    check("load ballot", w.loadBallot());
    w.refreshCoinsFromServer(); w.tickCoins(1);
    QJsonObject boot; api.call("boot", {}, boot);
    const QString opt = boot.value("ballot").toObject().value("options").toArray().at(1).toString();
    w.chooseOption(opt);
    shot(2, "3-ballot.png");
    check("vote submitted and counted", w.submitVotes() && w.ballotLog->toPlainText().contains("1 of 1 vote line(s) counted"));
    w.tickCoins(1);
    const QJsonObject vv = QJsonDocument::fromJson(w.voucherJson("vote")).object();
    check("vote voucher (kind vote, 1 spend)", vv.value("kind") == "vote" && vv.value("spends").toInt() == 1);
    api.call("redeem", QJsonObject{{"voucher", vv}}, r);
    check("server counts the vote voucher", r.value("items").toArray().last().toObject().value("status") == "voted");

    // update ledger then offline coin list matches server
    admin.call("admin", QJsonObject{{"op", "issue"}, {"to", me}, {"count", 4}, {"amount", 7}}, r);
    check("update ledger", w.syncLedger());
    check("offline coin list", w.useOfflineLedgerCoins());
    api.call("balance", QJsonObject{{"pub", me}}, r);
    check("offline weight == server weight (" + w.coinsStatus->text().left(40) + ")", r.value("weight").toInt() == 28 && w.coinsStatus->text().contains(QString("%1 weight").arg(r.value("weight").toInt())));
    shot(3, "6-ledger.png");
    w.setServerUrl("http://127.0.0.1:9/index.php");
    check("server down: send fails cleanly", !w.refreshCoinsFromServer() && w.coinsStatus->text().contains("offline"));
    check("server down: ballot from offline ledger", w.loadBallot() && w.ballotQuestion->text().contains("offline ledger"));
    QSettings().clear();
    printf("%s\n", failed ? qPrintable(QString("FAILURES: %1").arg(failed)) : qPrintable(QString("ALL PASS (%1)").arg(passed)));
    return failed;
}
