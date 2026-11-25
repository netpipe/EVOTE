#include "mainwindow.h"
#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRadioButton>
#include <QSettings>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableWidget>
#include <QVBoxLayout>
#include <stdexcept>

using namespace evote;

static QLabel *note(const QString &t) { auto *l = new QLabel(t); l->setWordWrap(true); l->setStyleSheet("color:#666"); return l; }

MainWindow::MainWindow(const QString &dir, QWidget *parent) : QMainWindow(parent), dataDir(dir) {
    setWindowTitle("EVOTE Lite Wallet");
    resize(980, 680);
    ledger.reset(new OfflineLedger(dataDir + "/offline-ledger.sqlite"));
    tabs = new QTabWidget;
    tabs->addTab(buildWalletTab(), "Wallet");
    tabs->addTab(buildCoinsTab(), "Coins && Send");
    tabs->addTab(buildBallotTab(), "Ballot");
    tabs->addTab(buildLedgerTab(), "Offline ledger && Verify");
    setCentralWidget(tabs);
    updateLedgerLabel();
}
MainWindow::~MainWindow() = default;

// ---------------------------------------------------------------- wallet tab
QWidget *MainWindow::buildWalletTab() {
    auto *w = new QWidget; auto *v = new QVBoxLayout(w);
    auto *srv = new QGroupBox("Server"); auto *sf = new QFormLayout(srv);
    serverEdit = new QLineEdit(QSettings().value("server", "http://localhost/php-new3-3/index.php").toString());
    connect(serverEdit, &QLineEdit::editingFinished, this, [this] { QSettings().setValue("server", serverEdit->text().trimmed()); });
    sf->addRow("EVOTE index.php URL", serverEdit);
    v->addWidget(srv);
    auto *wal = new QGroupBox("Wallet"); auto *wf = new QVBoxLayout(wal);
    auto *row = new QHBoxLayout;
    passEdit = new QLineEdit; passEdit->setEchoMode(QLineEdit::Password); passEdit->setPlaceholderText("passphrase");
    auto *openBtn = new QPushButton("Open wallet file..."), *newBtn = new QPushButton("Create new wallet...");
    connect(openBtn, &QPushButton::clicked, this, &MainWindow::onOpenWallet);
    connect(newBtn, &QPushButton::clicked, this, &MainWindow::onCreateWallet);
    row->addWidget(passEdit, 1); row->addWidget(openBtn); row->addWidget(newBtn);
    wf->addLayout(row);
    auto *ar = new QHBoxLayout; addrEdit = new QLineEdit; addrEdit->setReadOnly(true); addrEdit->setPlaceholderText("no wallet open");
    auto *copyBtn = new QPushButton("Copy address");
    connect(copyBtn, &QPushButton::clicked, this, [this] { QApplication::clipboard()->setText(key.id); walletStatus->setText("Address copied."); });
    ar->addWidget(new QLabel("Address")); ar->addWidget(addrEdit, 1); ar->addWidget(copyBtn);
    wf->addLayout(ar);
    walletStatus = new QLabel("Open an evote-wallet.json (old v2 or new v3 files both work) or create a new one.");
    walletStatus->setWordWrap(true); wf->addWidget(walletStatus);
    wf->addWidget(note("Your key never leaves this app: transfers and votes are signed here and only the signed lines are sent."));
    v->addWidget(wal); v->addStretch();
    return w;
}
QString MainWindow::serverUrl() const { return serverEdit->text().trimmed(); }
void MainWindow::setServerUrl(const QString &url) { serverEdit->setText(url); QSettings().setValue("server", url); }

bool MainWindow::openWalletJson(const QByteArray &json, const QString &pass) {
    try {
        const WalletInfo w = walletDecrypt(QJsonDocument::fromJson(json).object(), pass);
        key = w.key; label = w.label; addrEdit->setText(key.id); addrEdit->setCursorPosition(0); addrEdit->setToolTip(shortAddr(key.id));
        walletStatus->setText(QString("Unlocked \"%1\" (wallet file v%2).%3").arg(label).arg(w.version)
            .arg(w.version == 2 ? " This is an old v2 file: use \"Create new wallet\" style saving below to re-save it as v3." : ""));
        coins.clear(); showCoins("");
        return true;
    } catch (const std::exception &e) { walletStatus->setText(QString("Could not open the wallet: ") + e.what()); return false; }
}
QByteArray MainWindow::createWallet(const QString &lbl, const QString &pass) {
    const Key k = generateKey();
    const QByteArray file = QJsonDocument(walletEncrypt(k, pass, lbl)).toJson();
    key = k; label = lbl; addrEdit->setText(key.id); addrEdit->setCursorPosition(0);
    walletStatus->setText(QString("New wallet \"%1\" created and saved (v3). Keep a backup of the file - there is no other copy of the key.").arg(lbl));
    coins.clear(); showCoins("");
    return file;
}
void MainWindow::onOpenWallet() {
    const QString f = QFileDialog::getOpenFileName(this, "Open wallet", QString(), "EVOTE wallet (*.json)");
    if (f.isEmpty()) return;
    QFile x(f); x.open(QIODevice::ReadOnly);
    const QByteArray json = x.readAll();
    if (openWalletJson(json, passEdit->text()) && QJsonDocument::fromJson(json).object().value("version").toInt(2) != 3 &&
        QMessageBox::question(this, "Old wallet file", "This is an old v2 wallet file, which leaves half of the key unencrypted. Save a fixed v3 copy now?") == QMessageBox::Yes) {
        const QString out = QFileDialog::getSaveFileName(this, "Save v3 wallet", "evote-wallet-v3.json", "EVOTE wallet (*.json)");
        if (!out.isEmpty()) { QFile o(out); o.open(QIODevice::WriteOnly); o.write(QJsonDocument(walletEncrypt(key, passEdit->text(), label)).toJson());
            walletStatus->setText("Saved a v3 copy. Delete the old file and any copies of it."); }
    }
    passEdit->clear();
}
void MainWindow::onCreateWallet() {
    bool ok = false;
    const QString lbl = QInputDialog::getText(this, "New wallet", "Label", QLineEdit::Normal, "my wallet", &ok); if (!ok) return;
    const QString p1 = QInputDialog::getText(this, "New wallet", "Passphrase (8+ characters)", QLineEdit::Password, "", &ok); if (!ok) return;
    const QString p2 = QInputDialog::getText(this, "New wallet", "Repeat passphrase", QLineEdit::Password, "", &ok); if (!ok) return;
    if (p1.size() < 8 || p1 != p2) { walletStatus->setText("Passphrases must match and be at least 8 characters."); return; }
    const QString out = QFileDialog::getSaveFileName(this, "Save wallet", "evote-wallet.json", "EVOTE wallet (*.json)"); if (out.isEmpty()) return;
    QFile o(out); o.open(QIODevice::WriteOnly); o.write(createWallet(lbl, p1));
}

// ---------------------------------------------------------------- coins tab
QWidget *MainWindow::buildCoinsTab() {
    auto *w = new QWidget; auto *v = new QVBoxLayout(w);
    auto *src = new QHBoxLayout;
    auto *b1 = new QPushButton("Refresh from server"), *b2 = new QPushButton("Load \"Export coins\" file..."), *b3 = new QPushButton("Use offline ledger");
    connect(b1, &QPushButton::clicked, this, [this] { refreshCoinsFromServer(); });
    connect(b2, &QPushButton::clicked, this, &MainWindow::onLoadBundle);
    connect(b3, &QPushButton::clicked, this, [this] { useOfflineLedgerCoins(); });
    src->addWidget(b1); src->addWidget(b2); src->addWidget(b3); src->addStretch();
    v->addLayout(src);
    coinTable = new QTableWidget(0, 3); coinTable->setHorizontalHeaderLabels({"", "Coin", "Weight"});
    coinTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch); coinTable->verticalHeader()->hide();
    coinTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    v->addWidget(coinTable, 1);
    coinsStatus = new QLabel("Open a wallet, then load your coins."); v->addWidget(coinsStatus);
    auto *pick = new QHBoxLayout; weightSpin = new QSpinBox; weightSpin->setRange(1, 1000000000);
    auto *pickBtn = new QPushButton("Pick coins for this weight");
    connect(pickBtn, &QPushButton::clicked, this, [this] { pickWeight(weightSpin->value()); });
    pick->addWidget(new QLabel("Send weight")); pick->addWidget(weightSpin); pick->addWidget(pickBtn); pick->addStretch();
    v->addLayout(pick);
    auto *dest = new QFormLayout; toEdit = new QLineEdit; toEdit->setPlaceholderText("recipient address (base64 PEM public key id)");
    hoursSpin = new QSpinBox; hoursSpin->setRange(1, 720); hoursSpin->setValue(24); hoursSpin->setSuffix(" h");
    dest->addRow("To", toEdit); dest->addRow("Expires in", hoursSpin);
    v->addLayout(dest);
    auto *acts = new QHBoxLayout;
    auto *sendBtn = new QPushButton("Send to server"), *vBtn = new QPushButton("Save voucher..."), *lBtn = new QPushButton("Copy #rawtx link");
    connect(sendBtn, &QPushButton::clicked, this, [this] { sendToServer(); });
    connect(vBtn, &QPushButton::clicked, this, &MainWindow::onSaveVoucher);
    connect(lBtn, &QPushButton::clicked, this, &MainWindow::onCopyLink);
    acts->addWidget(sendBtn); acts->addWidget(vBtn); acts->addWidget(lBtn); acts->addStretch();
    v->addLayout(acts);
    sendLog = new QPlainTextEdit; sendLog->setReadOnly(true); sendLog->setMaximumHeight(140);
    v->addWidget(sendLog);
    return w;
}
bool MainWindow::needKey(QPlainTextEdit *log) { if (key.valid()) return true; log->appendPlainText("Open a wallet first (Wallet tab)."); return false; }
void MainWindow::showCoins(const QString &source) {
    coinTable->setRowCount(coins.size());
    qint64 total = 0;
    for (int i = 0; i < coins.size(); i++) {
        auto *c = new QTableWidgetItem; c->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled); c->setCheckState(Qt::Unchecked);
        coinTable->setItem(i, 0, c);
        coinTable->setItem(i, 1, new QTableWidgetItem(shortId(coins[i].hash, 12)));
        coinTable->setItem(i, 2, new QTableWidgetItem(QString::number(coins[i].amount)));
        total += coins[i].amount;
    }
    coinTable->resizeColumnToContents(0);
    if (!source.isEmpty()) coinsStatus->setText(QString("%1 unspent coin(s), %2 weight - from %3.").arg(coins.size()).arg(total).arg(source));
}
bool MainWindow::refreshCoinsFromServer() {
    if (!needKey(sendLog)) return false;
    Api api(serverUrl()); QJsonObject r;
    if (!api.call("balance", QJsonObject{{"pub", key.id}}, r)) { coinsStatus->setText("Server: " + api.lastError + " (offline? use the offline ledger)"); return false; }
    coins.clear();
    for (const QJsonValue &v : r.value("coins").toArray()) { Coin c; c.hash = v.toObject().value("hash").toString(); c.amount = qint64(v.toObject().value("amount").toDouble()); c.owner = key.id; coins << c; }
    showCoins("the server");
    return true;
}
bool MainWindow::loadCoinsBundle(const QByteArray &json) {
    if (!needKey(sendLog)) return false;
    const QJsonObject j = QJsonDocument::fromJson(json).object();
    if (j.value("format") != "evote-coins") { coinsStatus->setText("Not an \"Export coins\" file."); return false; }
    coins.clear();
    for (const QJsonValue &v : j.value("coins").toArray()) {
        const QJsonObject o = v.toObject();
        if (o.value("spent").toBool() || o.value("owner").toString() != key.id) continue;
        Coin c; c.hash = o.value("token_hash").toString(); c.amount = qint64(o.value("amount").toDouble()); c.owner = key.id;
        for (const QJsonValue &l : o.value("lines").toArray()) c.lines << l.toString();
        coins << c;
    }
    showCoins("the export file (may be out of date - the server has the final say)");
    return true;
}
bool MainWindow::useOfflineLedgerCoins() {
    if (!needKey(sendLog)) return false;
    if (!ledger->syncedAt().isValid()) { coinsStatus->setText("No offline ledger yet - download it on the last tab while online."); return false; }
    coins = ledger->coinsOf(key.id);
    for (Coin &c : coins) c.lines = ledger->historyOf(c.hash);
    showCoins("the offline ledger (" + ledger->syncedAt().toString("yyyy-MM-dd HH:mm") + ")");
    return true;
}
void MainWindow::tickCoins(int n) { for (int i = 0; i < coinTable->rowCount(); i++) coinTable->item(i, 0)->setCheckState(i < n ? Qt::Checked : Qt::Unchecked); }
QVector<Coin> MainWindow::checkedCoins() const {
    QVector<Coin> out; for (int i = 0; i < coinTable->rowCount() && i < coins.size(); i++) if (coinTable->item(i, 0)->checkState() == Qt::Checked) out << coins[i];
    return out;
}
bool MainWindow::pickWeight(qint64 w) {
    QVector<qint64> a; for (const Coin &c : coins) a << c.amount;
    qint64 lo = 0, hi = 0; const QVector<int> pick = pickByWeight(a, w, &lo, &hi);
    for (int i = 0; i < coinTable->rowCount(); i++) coinTable->item(i, 0)->setCheckState(Qt::Unchecked);
    if (pick.isEmpty()) { coinsStatus->setText(QString("No exact set of coins adds up to %1 (coins can't be split). Closest: %2%3").arg(w)
        .arg(lo ? QString::number(lo) : "-").arg(hi ? QString(" or %1").arg(hi) : "")); return false; }
    for (int i : pick) coinTable->item(i, 0)->setCheckState(Qt::Checked);
    coinsStatus->setText(QString("Picked %1 coin(s) = exactly %2 weight.").arg(pick.size()).arg(w));
    return true;
}
void MainWindow::setRecipient(const QString &to) { toEdit->setText(to); }
QStringList MainWindow::signTransfers() {
    lastSpends.clear();
    if (!needKey(sendLog)) return {};
    const QString to = toEdit->text().trimmed();
    if (rawFromPubId(to).isEmpty()) { sendLog->appendPlainText("Recipient is not a valid EVOTE address."); return {}; }
    if (to == key.id) { sendLog->appendPlainText("That is your own address."); return {}; }
    const QVector<Coin> cs = checkedCoins();
    if (cs.isEmpty()) { sendLog->appendPlainText("Tick at least one coin (or use \"Pick coins\")."); return {}; }
    for (const Coin &c : cs) lastSpends << makeTransfer(key, c.hash, to, c.amount, hoursSpin->value());
    return lastSpends;
}
void MainWindow::renderRedeem(const QJsonObject &r, QPlainTextEdit *log) {
    for (const QJsonValue &v : r.value("items").toArray()) {
        const QJsonObject o = v.toObject();
        log->appendPlainText(QString("%1  %2  %3%4").arg(o.value("status").toString().toUpper(), -16).arg(shortId(o.value("coin").toString(), 8))
            .arg(o.value("type").toString()).arg(o.value("err").toString().isEmpty() ? "" : "  - " + o.value("err").toString()));
    }
}
bool MainWindow::sendToServer() {
    const QStringList lines = signTransfers(); if (lines.isEmpty()) return false;
    Api api(serverUrl()); QJsonObject r;
    if (!api.call("redeem", QJsonObject{{"lines", QJsonArray::fromStringList(lines)}, {"to", toEdit->text().trimmed()}}, r)) {
        sendLog->appendPlainText("Server: " + api.lastError + " - nothing was sent. You can save a voucher instead."); return false; }
    sendLog->appendPlainText(QString("Sent: %1 weight deposited to %2").arg(qint64(r.value("to").toObject().value("weight").toDouble())).arg(shortAddr(toEdit->text().trimmed())));
    renderRedeem(r, sendLog);
    refreshCoinsFromServer();
    return qint64(r.value("to").toObject().value("weight").toDouble()) > 0;
}
QStringList MainWindow::provenanceFor(const QVector<Coin> &cs) {
    QStringList prov, need;
    for (const Coin &c : cs) need << c.hash;
    Api api(serverUrl()); QJsonObject r;
    if (api.call("history", QJsonObject{{"tokens", QJsonArray::fromStringList(need)}}, r)) {
        for (const QJsonValue &v : r.value("lines").toArray()) prov << v.toString();
        return prov;
    }
    for (const Coin &c : cs) prov += c.lines.isEmpty() ? ledger->historyOf(c.hash) : c.lines;   // offline fallback
    return prov;
}
QByteArray MainWindow::voucherJson(const QString &kind) {
    const QStringList spends = kind == "vote" ? signVotes() : signTransfers();
    if (spends.isEmpty()) return {};
    QVector<Coin> cs = checkedCoins();
    return QJsonDocument(makeVoucher(kind, key.id, kind == "vote" ? QString() : toEdit->text().trimmed(), provenanceFor(cs), spends)).toJson();
}
void MainWindow::onSaveVoucher() {
    const QByteArray v = voucherJson("transfer"); if (v.isEmpty()) return;
    const QString out = QFileDialog::getSaveFileName(this, "Save voucher", "evote-voucher.json", "EVOTE voucher (*.json)"); if (out.isEmpty()) return;
    QFile o(out); o.open(QIODevice::WriteOnly); o.write(v);
    sendLog->appendPlainText("Voucher saved (not broadcast). Deliver it once - until it is redeemed you could still sign a conflicting spend.");
}
QString MainWindow::rawtxLinkText() { const QStringList l = signTransfers(); return l.isEmpty() ? QString() : rawtxLink(serverUrl(), l); }
void MainWindow::onCopyLink() {
    const QString link = rawtxLinkText(); if (link.isEmpty()) return;
    QApplication::clipboard()->setText(link);
    sendLog->appendPlainText("#rawtx link copied - opening it on the site (or the dice site / change machine) fills the redeem box.");
}
void MainWindow::onLoadBundle() {
    const QString f = QFileDialog::getOpenFileName(this, "Export coins file", QString(), "EVOTE coins (*.json)"); if (f.isEmpty()) return;
    QFile x(f); x.open(QIODevice::ReadOnly); loadCoinsBundle(x.readAll());
}

// ---------------------------------------------------------------- ballot tab
QWidget *MainWindow::buildBallotTab() {
    auto *w = new QWidget; auto *v = new QVBoxLayout(w);
    auto *load = new QPushButton("Load ballot"); connect(load, &QPushButton::clicked, this, [this] { loadBallot(); });
    v->addWidget(load, 0, Qt::AlignLeft);
    ballotQuestion = new QLabel("No ballot loaded."); ballotQuestion->setWordWrap(true); ballotQuestion->setStyleSheet("font-size:15px;font-weight:600");
    v->addWidget(ballotQuestion);
    auto *box = new QGroupBox("Options"); optionBox = new QVBoxLayout(box); optionGroup = new QButtonGroup(this);
    v->addWidget(box);
    v->addWidget(note("Each coin ticked on the \"Coins & Send\" tab casts one ballot line with its weight. A coin used for a vote is spent permanently."));
    auto *acts = new QHBoxLayout;
    auto *sub = new QPushButton("Sign && submit votes"), *vv = new QPushButton("Save vote voucher...");
    connect(sub, &QPushButton::clicked, this, [this] { submitVotes(); });
    connect(vv, &QPushButton::clicked, this, &MainWindow::onSaveVoteVoucher);
    acts->addWidget(sub); acts->addWidget(vv); acts->addStretch(); v->addLayout(acts);
    ballotLog = new QPlainTextEdit; ballotLog->setReadOnly(true); v->addWidget(ballotLog, 1);
    return w;
}
bool MainWindow::loadBallot() {
    Api api(serverUrl()); QJsonObject r; QString from = "the server";
    if (api.call("boot", {}, r)) ballot = r.value("ballot").toObject();
    else if (ledger->syncedAt().isValid()) { ballot = ledger->ballot(); from = "the offline ledger"; }
    else { ballotQuestion->setText("Server unreachable and no offline ledger: " + api.lastError); return false; }
    ballotQuestion->setText(ballot.value("question").toString() + (ballot.value("closed").toBool() ? "  (CLOSED)" : "") + "\n(from " + from + ")");
    for (QAbstractButton *b : optionGroup->buttons()) { optionGroup->removeButton(b); delete b; }
    for (const QJsonValue &o : ballot.value("options").toArray()) {
        auto *rb = new QRadioButton(o.toString()); optionGroup->addButton(rb); optionBox->addWidget(rb);
        connect(rb, &QRadioButton::toggled, this, [this, rb](bool on) { if (on) option = rb->text(); });
    }
    option.clear();
    return true;
}
void MainWindow::chooseOption(const QString &o) { for (QAbstractButton *b : optionGroup->buttons()) if (b->text() == o) b->setChecked(true); option = o; }
QStringList MainWindow::signVotes() {
    lastSpends.clear();
    if (!needKey(ballotLog)) return {};
    if (ballot.value("closed").toBool()) { ballotLog->appendPlainText("The ballot is closed."); return {}; }
    if (option.isEmpty()) { ballotLog->appendPlainText("Pick an option."); return {}; }
    const QVector<Coin> cs = checkedCoins();
    if (cs.isEmpty()) { ballotLog->appendPlainText("Tick the coins to vote with on the \"Coins & Send\" tab."); return {}; }
    for (const Coin &c : cs) lastSpends << makeVote(key, c.hash, option);
    return lastSpends;
}
bool MainWindow::submitVotes() {
    const QStringList lines = signVotes(); if (lines.isEmpty()) return false;
    Api api(serverUrl()); QJsonObject r;
    if (!api.call("redeem", QJsonObject{{"lines", QJsonArray::fromStringList(lines)}}, r)) { ballotLog->appendPlainText("Server: " + api.lastError + " - nothing was sent."); return false; }
    int voted = 0; for (const QJsonValue &v : r.value("items").toArray()) voted += v.toObject().value("status").toString() == "voted";
    ballotLog->appendPlainText(QString("%1 of %2 vote line(s) counted for \"%3\".").arg(voted).arg(lines.size()).arg(option));
    renderRedeem(r, ballotLog);
    refreshCoinsFromServer();
    return voted == lines.size();
}
void MainWindow::onSaveVoteVoucher() {
    const QByteArray v = voucherJson("vote"); if (v.isEmpty()) return;
    const QString out = QFileDialog::getSaveFileName(this, "Save vote voucher", "evote-vote-voucher.json", "EVOTE voucher (*.json)"); if (out.isEmpty()) return;
    QFile o(out); o.open(QIODevice::WriteOnly); o.write(v); ballotLog->appendPlainText("Vote voucher saved (not submitted).");
}

// ---------------------------------------------------------------- offline ledger tab
QWidget *MainWindow::buildLedgerTab() {
    auto *w = new QWidget; auto *v = new QVBoxLayout(w);
    auto *g = new QGroupBox("Offline ledger (optional)"); auto *gv = new QVBoxLayout(g);
    ledgerAge = new QLabel; ledgerAge->setWordWrap(true); gv->addWidget(ledgerAge);
    auto *row = new QHBoxLayout; syncBtn = new QPushButton("Download / update ledger"); cancelBtn = new QPushButton("Cancel"); cancelBtn->setEnabled(false);
    auto *resetBtn = new QPushButton("Reset");
    syncBar = new QProgressBar; syncBar->setRange(0, 100); syncBar->setValue(0);
    connect(syncBtn, &QPushButton::clicked, this, [this] { syncLedger(); });
    connect(cancelBtn, &QPushButton::clicked, this, [this] { cancelSync = true; });
    connect(resetBtn, &QPushButton::clicked, this, [this] {
        if (QMessageBox::question(this, "Reset", "Forget the offline ledger and the meet list?") == QMessageBox::Yes) { ledger->reset(); updateLedgerLabel(); } });
    row->addWidget(syncBtn); row->addWidget(cancelBtn); row->addWidget(syncBar, 1); row->addWidget(resetBtn);
    gv->addLayout(row);
    gv->addWidget(note("Starts from the server's signed checkpoint and then fetches newer lines in chunks; every signature is checked. Cancel any time - the next press continues where it stopped."));
    v->addWidget(g);
    auto *vg = new QGroupBox("Verify a voucher (works offline)"); auto *vv = new QVBoxLayout(vg);
    voucherInput = new QPlainTextEdit; voucherInput->setPlaceholderText("Paste a voucher, signed lines or a #rawtx link - or load the file"); voucherInput->setMaximumHeight(90);
    vv->addWidget(voucherInput);
    auto *vr = new QHBoxLayout; auto *lf = new QPushButton("Load file..."), *vb = new QPushButton("Verify voucher");
    rememberBox = new QCheckBox("Remember for this meet (flags the same coin shown twice)"); rememberBox->setChecked(true);
    auto *clr = new QPushButton("Clear meet list");
    connect(lf, &QPushButton::clicked, this, &MainWindow::onLoadVoucherFile);
    connect(vb, &QPushButton::clicked, this, [this] { verifyText(voucherInput->toPlainText()); });
    connect(clr, &QPushButton::clicked, this, &MainWindow::clearMeet);
    vr->addWidget(lf); vr->addWidget(vb); vr->addWidget(rememberBox); vr->addStretch(); vr->addWidget(clr);
    vv->addLayout(vr);
    verifyTable = new QTableWidget(0, 5); verifyTable->setHorizontalHeaderLabels({"Result", "Kind", "Coin", "Weight", "Details"});
    verifyTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch); verifyTable->verticalHeader()->hide();
    verifyTable->setEditTriggers(QAbstractItemView::NoEditTriggers); verifyTable->setWordWrap(true);
    vv->addWidget(verifyTable, 1);
    verifySummary = new QLabel; verifySummary->setWordWrap(true); vv->addWidget(verifySummary);
    v->addWidget(vg, 1);
    return w;
}
void MainWindow::updateLedgerLabel() {
    ledgerAge->setText(ledger->ageText() + QString("  Meet list: %1 coin(s) checked.").arg(ledger->seenCount()));
}
bool MainWindow::syncLedger() {
    Api api(serverUrl()); QString msg; cancelSync = false;
    syncBtn->setEnabled(false); cancelBtn->setEnabled(true);
    const bool ok = ledger->sync(api, [this](qint64 done, qint64 total) {
        syncBar->setValue(total > 0 ? int(qMin<qint64>(100, done * 100 / total)) : 0);
        syncBar->setFormat(QString("%1 / %2 lines").arg(done).arg(total));
        QApplication::processEvents();
        return !cancelSync;
    }, msg);
    syncBtn->setEnabled(true); cancelBtn->setEnabled(false);
    updateLedgerLabel();
    ledgerAge->setText(msg + "\n" + ledgerAge->text());
    return ok;
}
void MainWindow::verifyText(const QString &text) {
    QStringList all, spends; QString err;
    verifyTable->setRowCount(0);
    if (!readTransactions(text, all, spends, err)) { verifySummary->setText("Could not read it: " + err); return; }
    if (spends.isEmpty()) { verifySummary->setText("No transfer or vote lines found."); return; }
    const VerifyReport rep = ledger->verify(all, spends, rememberBox->isChecked());
    verifyTable->setRowCount(rep.items.size());
    for (int i = 0; i < rep.items.size(); i++) {
        const VerifyItem &it = rep.items[i];
        const char *word = it.state == VerifyItem::Valid ? "VALID" : it.state == VerifyItem::ValidByHistory ? "VALID*" : it.state == VerifyItem::Warning ? "SEEN" : "REJECT";
        auto *r = new QTableWidgetItem(word);
        r->setBackground(it.state == VerifyItem::Valid ? QColor("#c8f7c5") : it.state == VerifyItem::ValidByHistory ? QColor("#fff1b8") : it.state == VerifyItem::Warning ? QColor("#ffe0b2") : QColor("#ffcdd2"));
        verifyTable->setItem(i, 0, r);
        verifyTable->setItem(i, 1, new QTableWidgetItem(it.kind == "vote" ? "vote: " + it.option : "to " + shortAddr(it.to)));
        verifyTable->setItem(i, 2, new QTableWidgetItem(shortId(it.coin, 8)));
        verifyTable->setItem(i, 3, new QTableWidgetItem(it.amount ? QString::number(it.amount) : "-"));
        auto *d = new QTableWidgetItem(it.message); d->setToolTip(it.message);
        verifyTable->setItem(i, 4, d);
    }
    for (int c = 0; c < 4; c++) verifyTable->resizeColumnToContents(c);
    verifyTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    verifyTable->resizeRowsToContents();
    QStringList sum;
    for (auto it = rep.validWeightTo.constBegin(); it != rep.validWeightTo.constEnd(); ++it)
        sum << QString("%1 weight %2").arg(it.value()).arg(it.key().startsWith("vote:") ? "for " + it.key().mid(6) : "to " + shortAddr(it.key()));
    verifySummary->setText((sum.isEmpty() ? QString("Nothing in this voucher checks out.") : "Checks out: " + sum.join(", ") + ".") + "\n" + rep.ledgerAge);
    updateLedgerLabel();
}
void MainWindow::clearMeet() { ledger->clearSeen(); updateLedgerLabel(); }
void MainWindow::onLoadVoucherFile() {
    const QString f = QFileDialog::getOpenFileName(this, "Voucher", QString(), "Vouchers (*.json *.txt)"); if (f.isEmpty()) return;
    QFile x(f); x.open(QIODevice::ReadOnly); voucherInput->setPlainText(QString::fromUtf8(x.readAll()));
}
