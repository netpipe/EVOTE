#include "nodewindow.h"
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
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableWidget>
#include <QVBoxLayout>
#include <stdexcept>

using namespace evote;

static QLabel *note(const QString &t) { auto *l = new QLabel(t); l->setWordWrap(true); l->setStyleSheet("color:#666"); return l; }
static QTableWidget *table(const QStringList &h, int stretch) {
    auto *t = new QTableWidget(0, h.size()); t->setHorizontalHeaderLabels(h); t->verticalHeader()->hide();
    t->setEditTriggers(QAbstractItemView::NoEditTriggers); t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->horizontalHeader()->setSectionResizeMode(stretch, QHeaderView::Stretch);
    return t;
}
static void setRow(QTableWidget *t, int r, const QStringList &cells) { for (int c = 0; c < cells.size(); c++) t->setItem(r, c, new QTableWidgetItem(cells[c])); }

NodeWindow::NodeWindow(Node *n, QWidget *parent) : QMainWindow(parent), node(n) {
    setWindowTitle(QString("EVOTE Node - port %1").arg(node->port()));
    resize(1100, 720);
    tabs = new QTabWidget;
    tabs->addTab(buildPeersTab(), "Node && Peers");
    tabs->addTab(buildLedgerTab(), "Ledger");
    tabs->addTab(buildWalletTab(), "Wallet");
    tabs->addTab(buildBallotTab(), "Ballot");
    tabs->addTab(buildAdminTab(), "Admin");
    setCentralWidget(tabs);
    connect(node, &Node::log, this, &NodeWindow::log);
    connect(node, &Node::changed, this, &NodeWindow::refresh);
    refresh();
}
void NodeWindow::log(const QString &m) { logView->appendPlainText(QDateTime::currentDateTime().toString("HH:mm:ss  ") + m); }

// ---------------------------------------------------------------- peers
QWidget *NodeWindow::buildPeersTab() {
    auto *w = new QWidget; auto *v = new QVBoxLayout(w);
    auto *idBox = new QGroupBox("This node"); auto *iv = new QVBoxLayout(idBox);
    nodeStatus = new QLabel; nodeStatus->setWordWrap(true); nodeStatus->setTextInteractionFlags(Qt::TextSelectableByMouse); iv->addWidget(nodeStatus);
    auto *tr = new QHBoxLayout; advertEdit = new QLineEdit("127.0.0.1");
    auto *copy = new QPushButton("Copy my trust line");
    connect(copy, &QPushButton::clicked, this, [this] { QApplication::clipboard()->setText(node->trustLine(advertEdit->text().trimmed())); log("Trust line copied - give it to the other node operators."); });
    tr->addWidget(new QLabel("Address others reach me at")); tr->addWidget(advertEdit); tr->addWidget(copy); tr->addStretch(); iv->addLayout(tr);
    v->addWidget(idBox);
    auto *tb = new QGroupBox("Trusted peers (trusted_peers.txt)"); auto *tv = new QVBoxLayout(tb);
    auto *ar = new QHBoxLayout; trustEdit = new QLineEdit; trustEdit->setPlaceholderText("paste a trust line:  host:port|certificate sha256|node key");
    auto *add = new QPushButton("Trust && connect");
    connect(add, &QPushButton::clicked, this, [this] {
        QString err; if (!node->addTrustLine(trustEdit->text(), err)) { log("Not added: " + err); return; }
        node->connectTo(trustEdit->text().split('|').first()); trustEdit->clear(); });
    ar->addWidget(trustEdit, 1); ar->addWidget(add); tv->addLayout(ar);
    peerTable = table({"Address", "Node key", "Link", "Status", "Msgs in/out", "Score"}, 1); tv->addWidget(peerTable);
    tv->addWidget(note("Every peer is pinned by its TLS certificate and node key; anything else is refused. Pinned peers are reconnected automatically."));
    v->addWidget(tb, 1);
    logView = new QPlainTextEdit; logView->setReadOnly(true); logView->setMaximumHeight(170); logView->setMaximumBlockCount(2000);
    v->addWidget(logView);
    return w;
}

// ---------------------------------------------------------------- ledger + bridge
QWidget *NodeWindow::buildLedgerTab() {
    auto *w = new QWidget; auto *v = new QVBoxLayout(w);
    auto *bb = new QGroupBox("Website bridge (optional)"); auto *bv = new QVBoxLayout(bb);
    auto *br = new QHBoxLayout; bridgeEdit = new QLineEdit(node->bridgeUrl()); bridgeEdit->setPlaceholderText("https://your-site/php-new3-3/index.php");
    bridgeBox = new QCheckBox("Mirror this website"); bridgeBox->setChecked(node->bridgeEnabled());
    auto *apply = new QPushButton("Apply");
    connect(apply, &QPushButton::clicked, this, [this] { node->setBridge(bridgeEdit->text(), bridgeBox->isChecked()); });
    br->addWidget(bridgeEdit, 1); br->addWidget(bridgeBox); br->addWidget(apply); bv->addLayout(br);
    bridgeStatus = new QLabel; bridgeStatus->setWordWrap(true); bv->addWidget(bridgeStatus);
    bv->addWidget(note("On: the node copies the website's ledger (the site's order is final for what it confirmed), sends the site every line it gets from wallets and peers, and uses the site's issuer list and ballot. Off: the node runs on its peers only."));
    v->addWidget(bb);
    auto *ir = new QHBoxLayout; auto *issEdit = new QLineEdit; issEdit->setPlaceholderText("issuer key to add to issuers.txt (allowed to issue coins / publish the ballot)");
    auto *issBtn = new QPushButton("Add issuer");
    connect(issBtn, &QPushButton::clicked, this, [this, issEdit] { QString err; if (node->addIssuer(issEdit->text(), err)) issEdit->clear(); else log("Issuer not added: " + err); });
    ir->addWidget(issEdit, 1); ir->addWidget(issBtn); v->addLayout(ir);
    ledgerStatus = new QLabel; ledgerStatus->setWordWrap(true); v->addWidget(ledgerStatus);
    lineTable = table({"#", "Type", "Coin", "From", "To / option", "Weight", "Confirmed", "Status"}, 7);
    v->addWidget(lineTable, 3);
    v->addWidget(new QLabel("Conflicts (double-spend attempts)"));
    conflictTable = table({"Coin", "Kind", "Kept", "Refused"}, 1); conflictTable->setMaximumHeight(130);
    v->addWidget(conflictTable, 1);
    return w;
}

// ---------------------------------------------------------------- wallet
QWidget *NodeWindow::buildWalletTab() {
    auto *w = new QWidget; auto *v = new QVBoxLayout(w);
    auto *wb = new QGroupBox("Wallet (separate from the node key)"); auto *wv = new QVBoxLayout(wb);
    auto *row = new QHBoxLayout; passEdit = new QLineEdit; passEdit->setEchoMode(QLineEdit::Password); passEdit->setPlaceholderText("wallet passphrase");
    auto *open = new QPushButton("Open wallet file..."), *create = new QPushButton("Create new wallet...");
    connect(open, &QPushButton::clicked, this, [this] {
        const QString f = QFileDialog::getOpenFileName(this, "Open wallet", QString(), "EVOTE wallet (*.json)"); if (f.isEmpty()) return;
        QFile x(f); x.open(QIODevice::ReadOnly); openWalletJson(x.readAll(), passEdit->text()); passEdit->clear(); });
    connect(create, &QPushButton::clicked, this, [this] {
        bool ok = false;
        const QString p1 = QInputDialog::getText(this, "New wallet", "Passphrase (8+ characters)", QLineEdit::Password, "", &ok); if (!ok) return;
        const QString p2 = QInputDialog::getText(this, "New wallet", "Repeat passphrase", QLineEdit::Password, "", &ok); if (!ok) return;
        if (p1.size() < 8 || p1 != p2) { walletStatus->setText("Passphrases must match and be at least 8 characters."); return; }
        const QString out = QFileDialog::getSaveFileName(this, "Save wallet", "evote-wallet.json", "EVOTE wallet (*.json)"); if (out.isEmpty()) return;
        QFile o(out); o.open(QIODevice::WriteOnly); o.write(createWallet("node wallet", p1)); });
    row->addWidget(passEdit, 1); row->addWidget(open); row->addWidget(create); wv->addLayout(row);
    auto *ar = new QHBoxLayout; addrEdit = new QLineEdit; addrEdit->setReadOnly(true); addrEdit->setPlaceholderText("no wallet open");
    auto *cp = new QPushButton("Copy address"); connect(cp, &QPushButton::clicked, this, [this] { QApplication::clipboard()->setText(wallet.id); });
    ar->addWidget(new QLabel("Address")); ar->addWidget(addrEdit, 1); ar->addWidget(cp); wv->addLayout(ar);
    walletStatus = new QLabel("Open an evote-wallet.json (v2 or v3) - the same files the website and the Lite Wallet use."); walletStatus->setWordWrap(true); wv->addWidget(walletStatus);
    v->addWidget(wb);
    coinTable = table({"", "Coin", "Weight"}, 1); v->addWidget(coinTable, 1);
    coinsLabel = new QLabel; v->addWidget(coinsLabel);
    auto *pk = new QHBoxLayout; weightSpin = new QSpinBox; weightSpin->setRange(1, 1000000000);
    auto *pb = new QPushButton("Pick coins for this weight"); connect(pb, &QPushButton::clicked, this, [this] { pickWeight(weightSpin->value()); });
    pk->addWidget(new QLabel("Weight")); pk->addWidget(weightSpin); pk->addWidget(pb); pk->addStretch(); v->addLayout(pk);
    auto *sf = new QHBoxLayout; toEdit = new QLineEdit; toEdit->setPlaceholderText("recipient address");
    hoursSpin = new QSpinBox; hoursSpin->setRange(1, 720); hoursSpin->setValue(24); hoursSpin->setSuffix(" h");
    auto *send = new QPushButton("Sign && send ticked coins");
    connect(send, &QPushButton::clicked, this, [this] { sendTicked(toEdit->text().trimmed(), hoursSpin->value()); });
    sf->addWidget(new QLabel("To")); sf->addWidget(toEdit, 1); sf->addWidget(new QLabel("expires in")); sf->addWidget(hoursSpin); sf->addWidget(send); v->addLayout(sf);
    return w;
}
bool NodeWindow::openWalletJson(const QByteArray &json, const QString &pass) {
    try {
        const WalletInfo wi = walletDecrypt(QJsonDocument::fromJson(json).object(), pass);
        wallet = wi.key; walletLabel = wi.label; addrEdit->setText(wallet.id); addrEdit->setCursorPosition(0);
        walletStatus->setText(QString("Unlocked \"%1\" (v%2) - %3").arg(walletLabel).arg(wi.version).arg(shortAddr(wallet.id)));
        refresh(); return true;
    } catch (const std::exception &e) { walletStatus->setText(QString("Could not open the wallet: ") + e.what()); return false; }
}
QByteArray NodeWindow::createWallet(const QString &label, const QString &pass) {
    wallet = generateKey(); walletLabel = label; addrEdit->setText(wallet.id); addrEdit->setCursorPosition(0);
    walletStatus->setText("New wallet created (v3) - keep a backup of the file.");
    refresh();
    return QJsonDocument(walletEncrypt(wallet, pass, label)).toJson();
}
QStringList NodeWindow::tickedCoins() const {
    QStringList out; for (int i = 0; i < coinTable->rowCount() && i < coinHashes.size(); i++) if (coinTable->item(i, 0)->checkState() == Qt::Checked) out << coinHashes[i];
    return out;
}
void NodeWindow::tickCoins(int n) { for (int i = 0; i < coinTable->rowCount(); i++) coinTable->item(i, 0)->setCheckState(i < n ? Qt::Checked : Qt::Unchecked); }
bool NodeWindow::pickWeight(qint64 w) {
    QVector<qint64> a; for (const QString &h : coinHashes) a << node->ledger().tokens().value(h).amount;
    qint64 lo = 0, hi = 0; const QVector<int> pick = pickByWeight(a, w, &lo, &hi);
    tickCoins(0);
    if (pick.isEmpty()) { walletStatus->setText(QString("No exact set adds up to %1. Closest: %2%3").arg(w).arg(lo).arg(hi ? QString(" or %1").arg(hi) : "")); return false; }
    for (int i : pick) coinTable->item(i, 0)->setCheckState(Qt::Checked);
    walletStatus->setText(QString("Picked %1 coin(s) = %2").arg(pick.size()).arg(w));
    return true;
}
int NodeWindow::sendTicked(const QString &to, int hours) {
    if (!wallet.valid()) { walletStatus->setText("Open a wallet first."); return 0; }
    if (rawFromPubId(to).isEmpty() || to == wallet.id) { walletStatus->setText("Recipient is not a valid other address."); return 0; }
    int ok = 0; QStringList errs;
    for (const QString &h : tickedCoins()) {
        const NodeLedger::Result r = node->submit(makeTransfer(wallet, h, to, node->ledger().tokens().value(h).amount, hours));
        if (r.ok) ok++; else errs << r.err;
    }
    walletStatus->setText(QString("Sent %1 coin(s) to %2%3").arg(ok).arg(shortAddr(to)).arg(errs.isEmpty() ? "" : " - refused: " + errs.join(", ")));
    refresh(); return ok;
}
int NodeWindow::mint(const QString &toIn, int count, qint64 amount) {
    const QString to = toIn.isEmpty() ? wallet.id : toIn;
    if (!wallet.valid() || !node->ledger().issuers.contains(wallet.id)) { walletStatus->setText("This wallet is not an issuer."); return 0; }
    int ok = 0;
    for (int i = 0; i < count; i++) ok += node->submit(makeLine(wallet, "SIGNED_ISSUE", {sha256Hex(randomBytes(32)), to, QString::number(amount)})).ok;
    walletStatus->setText(QString("Issued %1 coin(s) of weight %2 to %3").arg(ok).arg(amount).arg(shortAddr(to)));
    refresh(); return ok;
}

// ---------------------------------------------------------------- ballot
QWidget *NodeWindow::buildBallotTab() {
    auto *w = new QWidget; auto *v = new QVBoxLayout(w);
    ballotQuestion = new QLabel; ballotQuestion->setWordWrap(true); ballotQuestion->setStyleSheet("font-size:15px;font-weight:600"); v->addWidget(ballotQuestion);
    auto *ob = new QGroupBox("Vote with the coins ticked on the Wallet tab"); optionBox = new QVBoxLayout(ob); optionGroup = new QButtonGroup(this);
    v->addWidget(ob);
    auto *vb = new QPushButton("Sign && submit votes"); connect(vb, &QPushButton::clicked, this, [this] { voteTicked(option); });
    v->addWidget(vb, 0, Qt::AlignLeft);
    tallyTable = table({"Option", "Weight"}, 0); v->addWidget(tallyTable, 1);
    v->addWidget(note("Issuers change the ballot on the Admin tab."));
    return w;
}
int NodeWindow::voteTicked(const QString &opt) {
    if (!wallet.valid()) { walletStatus->setText("Open a wallet first."); return 0; }
    if (opt.isEmpty()) { ballotQuestion->setText(ballotQuestion->text().split('\n').first() + "\nPick an option."); return 0; }
    int ok = 0; QStringList errs;
    for (const QString &h : tickedCoins()) { const NodeLedger::Result r = node->submit(makeVote(wallet, h, opt)); if (r.ok) ok++; else errs << r.err; }
    log(QString("Voted \"%1\" with %2 coin(s)%3").arg(opt).arg(ok).arg(errs.isEmpty() ? "" : " - refused: " + errs.join(", ")));
    refresh(); return ok;
}
bool NodeWindow::publishBallot(const QString &q, const QStringList &opts, bool closed) {
    QString err;
    if (!node->publishBallot(wallet, q, opts, closed, err)) { log("Ballot not published: " + err); return false; }
    return true;
}

// ---------------------------------------------------------------- refresh
void NodeWindow::refresh() {
    NodeLedger &L = node->ledger();
    nodeStatus->setText(QString("Node key %1  |  port %2  |  TLS certificate %3...  |  %4 peer(s) connected")
        .arg(shortAddr(node->nodeKey().id)).arg(node->port()).arg(node->certFingerprint().left(16)).arg(node->authedCount()));
    // peers: every trusted one, with its live state
    const QVector<PeerInfo> live = node->peers(); const QVector<TrustedPeer> tr = node->trusted();
    peerTable->setRowCount(tr.size());
    for (int i = 0; i < tr.size(); i++) {
        QString link = "-", st = "not connected", msgs = "";
        for (const PeerInfo &p : live) if (p.nodePub == tr[i].nodePub || p.address == tr[i].address) {
            link = p.outbound ? "outgoing" : "incoming"; st = p.authed ? "authenticated" : "connecting..."; msgs = QString("%1 / %2").arg(p.rx).arg(p.tx);
            if (p.authed) break;
        }
        const qint64 ban = node->bannedUntil(tr[i].nodePub) - QDateTime::currentSecsSinceEpoch();
        if (ban > 0) st = QString("banned %1 min").arg((ban + 59) / 60);
        QString role; if (L.anchors.contains(tr[i].nodePub)) role = "  (anchor)";
        setRow(peerTable, i, {tr[i].address, shortAddr(tr[i].nodePub) + role, link, st, msgs, QString::number(node->scoreOf(tr[i].nodePub))});
        peerTable->item(i, 3)->setBackground(st == "authenticated" ? QColor("#c8f7c5") : ban > 0 ? QColor("#ffcdd2") : QColor("#eeeeee"));
    }
    peerTable->resizeColumnsToContents(); peerTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    // ledger
    bridgeStatus->setText(QString("Bridge: ") + (node->bridgeEnabled() ? node->bridgeStatus() : "off - the node runs on its peers only"));
    int confirmed = 0, ignored = 0, anchoredN = 0; for (const Entry &e : L.entries()) { if (e.siteId >= 0) confirmed++; if (e.anchored) anchoredN++; if (!e.status.isEmpty()) ignored++; }
    const QMap<QString, qint64> tally = L.tally();
    const QString anchorText = L.anchors.isEmpty() ? QString("Anchors: none (double spends are only settled by a bridged website).")
        : QString("Anchors: %1, a line is confirmed at %2 signatures%3; %4 lines anchor-confirmed.").arg(L.anchors.size()).arg(L.effectiveThreshold())
              .arg(node->isAnchor() ? " - this node is an anchor" : "").arg(anchoredN);
    ledgerStatus->setText(QString("%1 lines (%2 confirmed by the website, %3 without effect), %4 coins, %5 votes, %6 waiting for their coin. Issuers: %7.  State fingerprint %8 (equal on nodes that agree)\n%9")
        .arg(L.entries().size()).arg(confirmed).arg(ignored).arg(L.tokens().size()).arg(L.votes().size()).arg(L.orphanCount()).arg(L.issuers.size()).arg(L.stateHash().left(16)).arg(anchorText));
    QVector<Entry> ord = L.orderedEntries();
    for (const Entry &e : L.entries()) if (e.siteRejected) ord << e;   // refused by the website: still listed, with the reason
    const int show = qMin(ord.size(), 500);
    lineTable->setRowCount(show);
    for (int i = 0; i < show; i++) {
        const Entry &e = ord[ord.size() - 1 - i]; const QStringList &p = e.l.p;
        QString to, weight;
        if (e.l.type == "SIGNED_ISSUE") { to = shortAddr(p.value(6)); weight = p.value(7); }
        else if (e.l.type == "SIGNED_TRANSFER") { to = shortAddr(p.value(6)); weight = p.value(7); }
        else if (e.l.type == "SIGNED_VOTE") { to = "vote: " + QString::fromUtf8(QByteArray::fromBase64(p.value(5).toLatin1())); weight = QString::number(L.votes().value(p.value(6)).amount); }
        setRow(lineTable, i, {QString::number(ord.size() - i), QString(e.l.type).remove("SIGNED_"), shortId(e.l.coin(), 6), shortAddr(e.l.pub), to, weight,
                              e.siteId >= 0 ? QString("site #%1").arg(e.siteId) : e.anchored ? QString(e.endorsements >= L.effectiveThreshold() ? "anchors %1/%2" : "tie-break %1/%2").arg(e.endorsements).arg(L.anchors.size())
                              : L.anchors.isEmpty() ? QString("unconfirmed") : QString("waiting %1/%2").arg(e.endorsements).arg(L.effectiveThreshold()), e.status.isEmpty() ? "ok" : e.status});
        if (!e.status.isEmpty()) lineTable->item(i, 7)->setBackground(QColor("#ffcdd2"));
    }
    lineTable->resizeColumnsToContents(); lineTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Stretch);
    conflictTable->setRowCount(L.conflicts().size());
    for (int i = 0; i < L.conflicts().size(); i++) { const Conflict &c = L.conflicts()[i]; setRow(conflictTable, i, {shortId(c.coin, 6), c.kind, shortId(c.first, 6), shortId(c.second, 6)}); }
    // wallet coins (keep ticks)
    const QStringList ticked = tickedCoins();
    coinHashes.clear();
    const QVector<Token> mine = wallet.valid() ? L.coinsOf(wallet.id) : QVector<Token>();
    coinTable->setRowCount(mine.size());
    qint64 total = 0;
    for (int i = 0; i < mine.size(); i++) {
        coinHashes << mine[i].hash; total += mine[i].amount;
        auto *c = new QTableWidgetItem; c->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled); c->setCheckState(ticked.contains(mine[i].hash) ? Qt::Checked : Qt::Unchecked);
        coinTable->setItem(i, 0, c); coinTable->setItem(i, 1, new QTableWidgetItem(shortId(mine[i].hash, 12))); coinTable->setItem(i, 2, new QTableWidgetItem(QString::number(mine[i].amount)));
    }
    coinTable->resizeColumnToContents(0);
    coinsLabel->setText(wallet.valid() ? QString("%1 unspent coin(s), %2 weight on this node's ledger").arg(mine.size()).arg(total) : QString());
    // ballot
    const Ballot &b = L.ballot;
    ballotQuestion->setText(b.options.isEmpty() ? QString("No ballot yet (bridge a website, or an issuer publishes one below).")
        : b.question + (b.closed ? "  (CLOSED)" : "") + "\n" + (b.signer.isEmpty() ? QString("from the website") : "signed by issuer " + shortAddr(b.signer)));
    QStringList current; for (QAbstractButton *x : optionGroup->buttons()) current << x->text();
    if (current != b.options) {
        for (QAbstractButton *x : optionGroup->buttons()) { optionGroup->removeButton(x); delete x; }
        for (const QString &o : b.options) { auto *rb = new QRadioButton(o); optionGroup->addButton(rb); optionBox->addWidget(rb);
            connect(rb, &QRadioButton::toggled, this, [this, rb](bool on) { if (on) option = rb->text(); }); if (o == option) rb->setChecked(true); }
    }
    tallyTable->setRowCount(b.options.size());
    for (int i = 0; i < b.options.size(); i++) setRow(tallyTable, i, {b.options[i], QString::number(tally.value(b.options[i]))});
    refreshAdmin();
}

// ---------------------------------------------------------------- admin: issuers, issuing, ballot
QWidget *NodeWindow::buildAdminTab() {
    auto *w = new QWidget; auto *v = new QVBoxLayout(w);
    adminMode = new QLabel; adminMode->setWordWrap(true); adminMode->setStyleSheet("font-weight:600"); v->addWidget(adminMode);
    auto *tr = new QHBoxLayout; adminToken = new QLineEdit; adminToken->setEchoMode(QLineEdit::Password);
    adminToken->setPlaceholderText("website admin token (only used for the button you press, never saved)");
    tokenRow = new QWidget; tokenRow->setLayout(tr); tr->setContentsMargins(0, 0, 0, 0);
    tr->addWidget(new QLabel("Admin token")); tr->addWidget(adminToken, 1); v->addWidget(tokenRow);

    auto *top = new QHBoxLayout;
    // issuers
    auto *ib = new QGroupBox("Issuers"); auto *iv = new QVBoxLayout(ib);
    issuerTable = table({"Issuer key", "From"}, 0); issuerTable->setMaximumHeight(110); iv->addWidget(issuerTable, 1);
    auto *ir = new QHBoxLayout; issuerEdit = new QLineEdit; issuerEdit->setPlaceholderText("issuer key");
    auto *ia = new QPushButton("Add"), *id = new QPushButton("Remove selected");
    connect(ia, &QPushButton::clicked, this, [this] { QString err; if (node->addIssuer(issuerEdit->text(), err)) issuerEdit->clear(); else adminLog->appendPlainText("Issuer not added: " + err); });
    connect(id, &QPushButton::clicked, this, [this] {
        const int r = issuerTable->currentRow(); if (r < 0) return;
        QString err; if (!node->removeIssuer(issuerTable->item(r, 0)->data(Qt::UserRole).toString(), err)) adminLog->appendPlainText("Not removed: " + err); });
    ir->addWidget(issuerEdit, 1); ir->addWidget(ia); ir->addWidget(id); iv->addLayout(ir);
    top->addWidget(ib, 1);
    // issue coins
    auto *mb = new QGroupBox("Issue coins"); auto *mf = new QFormLayout(mb);
    mintTo = new QLineEdit; mintTo->setPlaceholderText("recipient address (empty = the open wallet)");
    mintCount = new QSpinBox; mintCount->setRange(1, 50); mintCount->setValue(5);
    mintAmount = new QSpinBox; mintAmount->setRange(1, int(MAX_COIN_WEIGHT)); mintAmount->setValue(1);
    mintBtn = new QPushButton("Issue");
    connect(mintBtn, &QPushButton::clicked, this, [this] { adminIssue(mintTo->text().trimmed(), mintCount->value(), mintAmount->value()); });
    mf->addRow("To", mintTo); mf->addRow("Coins", mintCount); mf->addRow("Weight each", mintAmount); mf->addRow(mintBtn);
    top->addWidget(mb, 1);
    auto *ab = new QGroupBox("Anchors (same list on every node)"); auto *av = new QVBoxLayout(ab);
    anchorTable = table({"Anchor node key"}, 0); anchorTable->setMaximumHeight(90); av->addWidget(anchorTable, 1);
    auto *ar = new QHBoxLayout; anchorEdit = new QLineEdit; anchorEdit->setPlaceholderText("anchor node key");
    auto *aa = new QPushButton("Add"), *ad = new QPushButton("Remove"), *me = new QPushButton("Copy my node key");
    connect(aa, &QPushButton::clicked, this, [this] { QString err; if (node->addAnchor(anchorEdit->text(), err)) anchorEdit->clear(); else adminLog->appendPlainText("Anchor not added: " + err); });
    connect(ad, &QPushButton::clicked, this, [this] { const int r = anchorTable->currentRow(); if (r < 0) return;
        QString err; if (!node->removeAnchor(anchorTable->item(r, 0)->data(Qt::UserRole).toString(), err)) adminLog->appendPlainText(err); });
    connect(me, &QPushButton::clicked, this, [this] { QApplication::clipboard()->setText(node->nodeKey().id); adminLog->appendPlainText("This node's key copied."); });
    ar->addWidget(anchorEdit, 1); ar->addWidget(aa); ar->addWidget(ad); av->addLayout(ar);
    auto *tr2 = new QHBoxLayout; thresholdSpin = new QSpinBox; thresholdSpin->setRange(0, 50); thresholdSpin->setSpecialValueText("majority");
    thresholdSpin->setValue(node->ledger().threshold);
    connect(thresholdSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int t) { if (t != node->ledger().threshold) node->setThreshold(t); });
    tr2->addWidget(new QLabel("Signatures needed")); tr2->addWidget(thresholdSpin); tr2->addStretch(); tr2->addWidget(me); av->addLayout(tr2);
    v->addLayout(top, 0);
    v->addWidget(ab, 0);
    // ballot editor
    auto *bb = new QGroupBox(QString("Ballot (up to %1 options, the website's limit)").arg(MAX_OPTIONS)); auto *bv = new QVBoxLayout(bb);
    auto *qf = new QHBoxLayout; ballotQ = new QLineEdit; ballotQ->setPlaceholderText("question"); qf->addWidget(new QLabel("Question")); qf->addWidget(ballotQ, 1); bv->addLayout(qf);
    optTable = new QTableWidget(0, 1); optTable->setHorizontalHeaderLabels({"Options"}); optTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    optTable->verticalHeader()->setVisible(true); bv->addWidget(optTable, 1);
    auto *orow = new QHBoxLayout;
    auto *add = new QPushButton("Add option"), *del = new QPushButton("Remove"), *up = new QPushButton("Up"), *down = new QPushButton("Down"), *load = new QPushButton("Load current ballot");
    ballotClosed = new QCheckBox("Closed (no more votes)");
    publishBtn = new QPushButton("Publish");
    connect(add, &QPushButton::clicked, this, [this] { if (optTable->rowCount() >= MAX_OPTIONS) { adminLog->appendPlainText(QString("At most %1 options.").arg(MAX_OPTIONS)); return; }
        optTable->insertRow(optTable->rowCount()); optTable->setItem(optTable->rowCount() - 1, 0, new QTableWidgetItem("")); optTable->editItem(optTable->item(optTable->rowCount() - 1, 0)); });
    connect(del, &QPushButton::clicked, this, [this] { if (optTable->currentRow() >= 0) optTable->removeRow(optTable->currentRow()); });
    auto move = [this](int d) { const int r = optTable->currentRow(), t = r + d; if (r < 0 || t < 0 || t >= optTable->rowCount()) return;
        const QString a = optTable->item(r, 0)->text(), b = optTable->item(t, 0)->text(); optTable->item(r, 0)->setText(b); optTable->item(t, 0)->setText(a); optTable->setCurrentCell(t, 0); };
    connect(up, &QPushButton::clicked, this, [move] { move(-1); });
    connect(down, &QPushButton::clicked, this, [move] { move(1); });
    connect(load, &QPushButton::clicked, this, [this] { loadBallotEditor(); });
    connect(publishBtn, &QPushButton::clicked, this, [this] { adminBallot(ballotQ->text(), editorOptions(), ballotClosed->isChecked()); });
    orow->addWidget(add); orow->addWidget(del); orow->addWidget(up); orow->addWidget(down); orow->addWidget(load); orow->addStretch(); orow->addWidget(ballotClosed); orow->addWidget(publishBtn);
    bv->addLayout(orow);
    optTable->setMinimumHeight(220);
    v->addWidget(bb, 1);
    adminLog = new QPlainTextEdit; adminLog->setReadOnly(true); adminLog->setMaximumHeight(64); v->addWidget(adminLog);
    auto *scroll = new QScrollArea; scroll->setWidgetResizable(true); scroll->setFrameShape(QFrame::NoFrame); scroll->setWidget(w);
    return scroll;
}
QStringList NodeWindow::editorOptions() const {
    QStringList o; for (int i = 0; i < optTable->rowCount(); i++) if (optTable->item(i, 0) && !optTable->item(i, 0)->text().trimmed().isEmpty()) o << optTable->item(i, 0)->text().trimmed();
    return o;
}
void NodeWindow::setEditorOptions(const QStringList &opts) {
    optTable->setRowCount(0);
    for (const QString &o : opts) { optTable->insertRow(optTable->rowCount()); optTable->setItem(optTable->rowCount() - 1, 0, new QTableWidgetItem(o)); }
}
void NodeWindow::loadBallotEditor() {
    const Ballot &b = node->ledger().ballot;
    ballotQ->setText(b.question); setEditorOptions(b.options); ballotClosed->setChecked(b.closed);
}
void NodeWindow::refreshAdmin() {
    const bool bridged = node->bridgeEnabled();
    const bool walletIssuer = wallet.valid() && node->ledger().issuers.contains(wallet.id);
    adminMode->setText(bridged
        ? "Website bridged: coins are issued and the ballot is changed on the website itself (its issuer key), using the website's admin token. The website's lockout after 5 wrong tokens applies."
        : walletIssuer ? "No website: the open wallet is an issuer - it signs new coins and the ballot, and every peer takes them."
                       : "No website: open an issuer wallet on the Wallet tab (its key must be in the issuer list) to issue coins or publish the ballot.");
    tokenRow->setVisible(bridged);
    mintBtn->setEnabled(bridged || walletIssuer);
    publishBtn->setEnabled(bridged || walletIssuer);
    publishBtn->setText(bridged ? "Save on the website" : "Sign && publish to all peers");
    QStringList rows; QMap<QString, QString> src;
    for (const QString &k : node->fileIssuers) src[k] = "issuers.txt";
    for (const QString &k : node->siteIssuers()) if (bridged) src[k] = src.contains(k) ? "issuers.txt + website" : "website";
    issuerTable->setRowCount(src.size()); int i = 0;
    for (auto it = src.constBegin(); it != src.constEnd(); ++it, ++i) {
        auto *k = new QTableWidgetItem(shortAddr(it.key()) + (wallet.valid() && it.key() == wallet.id ? "  (open wallet)" : "")); k->setData(Qt::UserRole, it.key()); k->setToolTip(it.key());
        issuerTable->setItem(i, 0, k); issuerTable->setItem(i, 1, new QTableWidgetItem(it.value()));
    }
    issuerTable->resizeColumnToContents(1);
    const QStringList an = node->ledger().anchors;
    anchorTable->setRowCount(an.size());
    for (int j = 0; j < an.size(); j++) {
        auto *k = new QTableWidgetItem(shortAddr(an[j]) + (an[j] == node->nodeKey().id ? "  (this node)" : "")); k->setData(Qt::UserRole, an[j]); k->setToolTip(an[j]);
        anchorTable->setItem(j, 0, k);
    }
    if (ballotQ->text().isEmpty() && optTable->rowCount() == 0) loadBallotEditor();
}
int NodeWindow::adminIssue(const QString &to, int count, qint64 amount) {
    if (node->bridgeEnabled()) {
        const QString dest = to.isEmpty() ? wallet.id : to;
        if (rawFromPubId(dest).isEmpty()) { adminLog->appendPlainText("Enter a recipient address (or open a wallet)."); return 0; }
        node->siteAdmin(QJsonObject{{"op", "issue"}, {"to", dest}, {"count", count}, {"amount", double(amount)}}, adminToken->text(), [this, dest](bool ok, const QJsonObject &r) {
            adminLog->appendPlainText(ok ? QString("Website issued %1 coin(s) to %2 - they arrive with the next pull.").arg(r.value("lines").toArray().size()).arg(shortAddr(dest))
                                         : "Website refused: " + r.value("err").toString());
        });
        return -1;   // asynchronous
    }
    const int n = mint(to, count, amount);
    adminLog->appendPlainText(QString("Issued %1 coin(s) of weight %2, signed by the open issuer wallet.").arg(n).arg(amount));
    return n;
}
bool NodeWindow::adminBallot(const QString &q, const QStringList &opts, bool closed) {
    if (opts.isEmpty()) { adminLog->appendPlainText("Add at least one option."); return false; }
    if (opts.size() > MAX_OPTIONS) { adminLog->appendPlainText(QString("At most %1 options.").arg(MAX_OPTIONS)); return false; }
    if (opts.toSet().size() != opts.size()) { adminLog->appendPlainText("Two options have the same text."); return false; }
    if (node->bridgeEnabled()) {
        node->siteAdmin(QJsonObject{{"op", "ballot"}, {"question", q}, {"options", QJsonArray::fromStringList(opts)}, {"closed", closed}}, adminToken->text(), [this](bool ok, const QJsonObject &r) {
            adminLog->appendPlainText(ok ? "Ballot saved on the website - every node and browser picks it up." : "Website refused: " + r.value("err").toString());
        });
        return true;
    }
    QString err;
    if (!node->publishBallot(wallet, q, opts, closed, err)) { adminLog->appendPlainText("Not published: " + err); return false; }
    adminLog->appendPlainText(QString("Ballot signed and sent to all peers (%1 options%2).").arg(opts.size()).arg(closed ? ", closed" : ""));
    return true;
}
