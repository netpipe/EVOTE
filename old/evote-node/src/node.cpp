#include "node.h"
#include "identity.h"
#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QHostAddress>
#include <QJsonDocument>
#include <QNetworkReply>
#include <QSslKey>
#include <QTextStream>
#include <QUrl>

namespace evote {

static const int HELLO_WINDOW = 120;          // seconds a HELLO timestamp may differ from our clock
static const qint64 MAX_BUFFER = 4 * 1024 * 1024;

void SslServer::incomingConnection(qintptr d) {
    auto *s = new QSslSocket(this);
    if (!s->setSocketDescriptor(d)) { s->deleteLater(); return; }
    s->setSslConfiguration(config);
    s->setPeerVerifyMode(QSslSocket::QueryPeer);   // ask for the client's certificate (newer3 used VerifyNone,
                                                   // so the server never saw one and refused every peer)
    emit newSslSocket(s);
}

Node::Node(const QString &dir, const Key &nodeKey, int port, QObject *parent)
    : QObject(parent), m_dir(dir), m_nodeKey(nodeKey), m_port(port) {
    m_ledger = new NodeLedger(dir + "/node-ledger.sqlite");
    m_nam = new QNetworkAccessManager(this);
    QFile f(dir + "/issuers.txt");
    if (f.open(QIODevice::ReadOnly)) { QTextStream in(&f); while (!in.atEnd()) { const QString l = in.readLine().trimmed(); if (!l.isEmpty() && !l.startsWith('#')) fileIssuers << l; } }
    m_bridgeUrl = m_ledger->meta("bridge_url"); m_bridgeOn = m_ledger->meta("bridge_on") == "1";
    for (const QString &p : m_ledger->meta("site_issuers").split(',', QString::SkipEmptyParts)) m_siteIssuers << p;
    refreshIssuers();
    reloadTrust();
    connect(&m_timer, &QTimer::timeout, this, &Node::housekeeping);
}
Node::~Node() {
    for (auto &s : m_sockets) if (s) { s->disconnect(this); s->abort(); }
    delete m_ledger;
}

bool Node::addIssuer(const QString &pubIn, QString &err) {
    const QString pub = pubIn.trimmed();
    if (rawFromPubId(pub).isEmpty()) { err = "not a valid key"; return false; }
    if (fileIssuers.contains(pub)) { err = "already an issuer"; return false; }
    QFile f(m_dir + "/issuers.txt");
    if (!f.open(QIODevice::Append)) { err = "cannot write issuers.txt"; return false; }
    f.write((pub + "\n").toUtf8()); f.close();
    fileIssuers << pub; refreshIssuers();
    emit log("Issuer added: " + shortAddr(pub)); emit changed();
    return true;
}
bool Node::removeIssuer(const QString &pub, QString &err) {
    if (!fileIssuers.contains(pub)) { err = m_siteIssuers.contains(pub) ? "that issuer comes from the website - remove it on the website" : "not in issuers.txt"; return false; }
    fileIssuers.remove(pub);
    QFile f(m_dir + "/issuers.txt");
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) { err = "cannot write issuers.txt"; return false; }
    for (const QString &k : fileIssuers) f.write((k + "\n").toUtf8());
    f.close();
    refreshIssuers();
    emit log("Issuer removed: " + shortAddr(pub)); emit changed();
    return true;
}
void Node::siteAdmin(const QJsonObject &body, const QString &token, std::function<void(bool, const QJsonObject &)> done) {
    if (!m_bridgeOn) { done(false, QJsonObject{{"err", "no website bridged"}}); return; }
    apiPost("admin", body, [this, done](bool ok, const QJsonObject &r) {
        done(ok, r);
        if (ok) { m_lastBoot = 0; if (!m_bridgeBusy) bridgeTick(); }   // fetch the new coins / ballot right away
    }, token.toUtf8());
}
void Node::refreshIssuers() {
    m_ledger->issuers = fileIssuers;
    if (m_bridgeOn) m_ledger->issuers.unite(m_siteIssuers);
    m_ledger->replay();
}

bool Node::start(QString &err) {
    if (!QSslSocket::supportsSsl()) { err = "TLS is not available (OpenSSL 1.1 missing?)"; return false; }
#if QT_VERSION < QT_VERSION_CHECK(5, 15, 0)
    // Qt 5.12 was made for OpenSSL 1.1: with 3.x it can't read peer certificates, so no peer could be pinned
    if (QSslSocket::sslLibraryVersionNumber() >= 0x30000000L) {
        err = "Qt " QT_VERSION_STR " loaded " + QSslSocket::sslLibraryVersionString() + ", but it needs OpenSSL 1.1 for TLS. "
              "Install OpenSSL 1.1 (macOS: brew install openssl@1.1) and make it the one Qt finds - see the README.";
        return false;
    }
#endif
    if (!ensureTlsCert(m_dir, err)) return false;
    QFile cf(m_dir + "/server.crt"), kf(m_dir + "/server.key");
    if (!cf.open(QIODevice::ReadOnly) || !kf.open(QIODevice::ReadOnly)) { err = "cannot read server.crt / server.key"; return false; }
    const QList<QSslCertificate> certs = QSslCertificate::fromDevice(&cf, QSsl::Pem);
    QSslKey key(&kf, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    if (key.isNull()) { kf.reset(); key = QSslKey(&kf, QSsl::Opaque, QSsl::Pem, QSsl::PrivateKey); }
    if (certs.isEmpty() || key.isNull()) { err = "server.crt / server.key unreadable"; return false; }
    m_certFp = QString::fromLatin1(QCryptographicHash::hash(certs.first().toDer(), QCryptographicHash::Sha256).toHex());
    m_ssl = QSslConfiguration::defaultConfiguration();
    m_ssl.setProtocol(QSsl::TlsV1_2OrLater);
    m_ssl.setLocalCertificate(certs.first());
    m_ssl.setPrivateKey(key);
    m_ssl.setPeerVerifyMode(QSslSocket::VerifyNone);   // pinning is done by hand after the handshake
    m_server = new SslServer;
    m_server->setParent(this);
    m_server->config = m_ssl;
    connect(m_server, &SslServer::newSslSocket, this, [this](QSslSocket *s) {
        if (authedCount() >= maxPeers) { s->abort(); s->deleteLater(); return; }
        setupSocket(s, false, QString("%1:%2").arg(s->peerAddress().toString()).arg(s->peerPort()));
        s->startServerEncryption();
    });
    if (!m_server->listen(QHostAddress::Any, quint16(m_port))) { err = QString("cannot listen on port %1: %2").arg(m_port).arg(m_server->errorString()); return false; }
    emit log(QString("Listening on port %1. Node key %2").arg(m_port).arg(shortAddr(m_nodeKey.id)));
    m_timer.start(5000);
    QTimer::singleShot(200, this, &Node::housekeeping);
    return true;
}

QString Node::trustLine(const QString &host) const {
    return QString("%1:%2|%3|%4").arg(host).arg(m_port).arg(m_certFp, m_nodeKey.id);
}

// ---------------------------------------------------------------- trust
void Node::reloadTrust() {
    m_trusted.clear();
    QFile f(m_dir + "/trusted_peers.txt");
    if (!f.open(QIODevice::ReadOnly)) return;
    QTextStream in(&f);
    while (!in.atEnd()) {
        const QString l = in.readLine().trimmed();
        if (l.isEmpty() || l.startsWith('#')) continue;
        const QStringList p = l.split('|');
        if (p.size() < 3 || rawFromPubId(p[2].trimmed()).isEmpty()) continue;
        m_trusted << TrustedPeer{p[0].trimmed(), p[1].trimmed().toLower(), p[2].trimmed()};
    }
}
bool Node::addTrustLine(const QString &lineIn, QString &err) {
    const QString line = lineIn.trimmed(); const QStringList p = line.split('|');
    if (p.size() != 3 || !p[0].contains(':') || p[1].size() != 64 || rawFromPubId(p[2]).isEmpty()) { err = "expected  host:port|cert sha256|node key"; return false; }
    if (p[2] == m_nodeKey.id) { err = "that is this node's own trust line"; return false; }
    for (const TrustedPeer &t : m_trusted) if (t.address == p[0] && t.nodePub == p[2]) { err = "already trusted"; return false; }
    QFile f(m_dir + "/trusted_peers.txt");
    if (!f.open(QIODevice::Append)) { err = "cannot write trusted_peers.txt"; return false; }
    f.write((line + "\n").toUtf8()); f.close();
    reloadTrust();
    emit log("Trusted " + p[0] + " (" + shortAddr(p[2]) + ")");
    emit changed();
    return true;
}

// ---------------------------------------------------------------- connections
QVector<PeerInfo> Node::peers() const {
    QVector<PeerInfo> out;
    for (const auto &s : m_sockets) {
        if (!s) continue;
        PeerInfo i; i.address = s->property("advertised").toString(); if (i.address.isEmpty()) i.address = s->property("address").toString();
        i.nodePub = s->property("nodePub").toString(); i.outbound = s->property("outbound").toBool(); i.authed = s->property("authed").toBool();
        i.since = s->property("since").toLongLong(); i.rx = s->property("rx").toLongLong(); i.tx = s->property("tx").toLongLong();
        out << i;
    }
    return out;
}
int Node::authedCount() const { int n = 0; for (const auto &s : m_sockets) if (s && s->property("authed").toBool()) n++; return n; }
bool Node::isConnectedTo(const QString &address, const QString &pub) const {
    for (const auto &s : m_sockets) if (s && ((!address.isEmpty() && (s->property("address") == address || s->property("advertised") == address)) || (!pub.isEmpty() && s->property("nodePub") == pub))) return true;
    return false;
}
bool Node::connectTo(const QString &hostPort) {
    const QString address = hostPort.trimmed();
    const int colon = address.lastIndexOf(':');
    if (colon < 1) return false;
    const QString host = address.left(colon); const int port = address.mid(colon + 1).toInt();
    if (port <= 0 || !m_server) return false;
    const TrustedPeer *tp = nullptr;
    for (const TrustedPeer &t : m_trusted) if (t.address == address) { tp = &t; break; }
    if (!tp) { emit log("Not connecting to " + address + ": no pin for it in trusted_peers.txt"); return false; }
    if (tp->nodePub == m_nodeKey.id || isConnectedTo(address, tp->nodePub) || authedCount() >= maxPeers) return false;
    auto *s = new QSslSocket(this);
    s->setSslConfiguration(m_ssl);
    s->setPeerVerifyMode(QSslSocket::VerifyNone);
    s->setProperty("expectedPub", tp->nodePub);
    s->setProperty("expectedCert", tp->certSha256);
    setupSocket(s, true, address);
    s->connectToHostEncrypted(host, quint16(port));
    return true;
}
void Node::setupSocket(QSslSocket *s, bool outbound, const QString &address) {
    s->setProperty("outbound", outbound); s->setProperty("address", address); s->setProperty("authed", false);
    s->setProperty("since", QDateTime::currentSecsSinceEpoch()); s->setProperty("rx", 0); s->setProperty("tx", 0);
    m_sockets << s;
    connect(s, QOverload<const QList<QSslError> &>::of(&QSslSocket::sslErrors), s, [s](const QList<QSslError> &) { s->ignoreSslErrors(); });
    connect(s, &QSslSocket::encrypted, this, [this, s] { onEncrypted(s); });
    connect(s, &QSslSocket::readyRead, this, [this, s] { if (s->isEncrypted()) onData(s); });
    connect(s, &QSslSocket::disconnected, this, [this, s] {
        if (s->property("authed").toBool()) emit log("Peer left: " + shortAddr(s->property("nodePub").toString()));
        finishSync(s);
        m_sockets.removeAll(s); s->deleteLater(); emit changed();
    });
    QPointer<QSslSocket> g = s;
    QTimer::singleShot(15000, this, [this, g] { if (g && !g->property("authed").toBool()) { m_sockets.removeAll(g); g->abort(); g->deleteLater(); } });
}

// Certificate pin first (outbound: by address, inbound: by fingerprint), then the signed HELLO.
void Node::onEncrypted(QSslSocket *s) {
    const QSslCertificate cert = s->peerCertificate();
    if (cert.isNull()) {
        emit log("Refused " + s->property("address").toString() + ": no peer certificate (TLS library must be OpenSSL 1.1 for Qt 5.12)");
        s->disconnectFromHost(); return;
    }
    const QString fp = QString::fromLatin1(QCryptographicHash::hash(cert.toDer(), QCryptographicHash::Sha256).toHex());
    if (s->property("outbound").toBool()) {
        if (fp != s->property("expectedCert").toString()) { emit log("Refused " + s->property("address").toString() + ": certificate does not match the pin"); s->disconnectFromHost(); return; }
    } else {
        QString pub; for (const TrustedPeer &t : m_trusted) if (t.certSha256 == fp) { pub = t.nodePub; break; }
        if (pub.isEmpty()) { emit log("Refused incoming " + s->property("address").toString() + ": certificate not pinned (" + fp.left(16) + ")"); s->disconnectFromHost(); return; }
        s->setProperty("expectedPub", pub);
    }
    sendTo(s, makeLine(m_nodeKey, "HELLO", {QString::number(m_port)}));
}

void Node::onData(QSslSocket *s) {
    if (s->bytesAvailable() > MAX_BUFFER && !s->canReadLine()) { emit log("Dropped a peer sending an oversized message"); s->abort(); return; }
    while (s->canReadLine()) {
        const QString line = QString::fromUtf8(s->readLine(MAX_LINE_LEN + 64)).trimmed();
        if (line.isEmpty()) continue;
        s->setProperty("rx", s->property("rx").toLongLong() + 1);
        if (!s->property("authed").toBool()) {
            if (line.startsWith("HELLO|")) handleHello(s, line);
            else { emit log("Dropped a peer that talked before HELLO"); s->disconnectFromHost(); return; }
            continue;
        }
        handleMessage(s, line);
        if (!s || s->state() != QAbstractSocket::ConnectedState) return;
    }
}

void Node::handleHello(QSslSocket *s, const QString &line) {
    Line h;
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    if (!parseLine(line, h) || !h.sigOk || h.type != "HELLO" || h.p.size() != 6) { emit log("Bad HELLO signature"); s->disconnectFromHost(); return; }
    if (h.pub != s->property("expectedPub").toString()) { emit log("HELLO key does not match the pinned key"); s->disconnectFromHost(); return; }
    if (qAbs(now - h.ts) > HELLO_WINDOW) { emit log("HELLO too old / clock off by more than 2 minutes"); s->disconnectFromHost(); return; }
    if (m_helloNonces.contains(h.pub + '|' + h.nonce)) { emit log("HELLO replay refused"); s->disconnectFromHost(); return; }
    m_helloNonces.insert(h.pub + '|' + h.nonce, h.ts);
    s->setProperty("authed", true); s->setProperty("nodePub", h.pub);
    // inbound peers connect from a random port: record the address they listen on
    if (!s->property("outbound").toBool()) {
        const QString adv = QString("%1:%2").arg(QHostAddress(s->peerAddress().toIPv4Address()).toString()).arg(h.p[5].toInt());
        for (const TrustedPeer &t : m_trusted) if (t.nodePub == h.pub) { s->setProperty("advertised", t.address); break; }
        if (s->property("advertised").toString().isEmpty()) s->setProperty("advertised", adv);
    }
    dropDuplicate(s);
    if (!s->property("authed").toBool()) return;
    emit log("Peer authenticated: " + shortAddr(h.pub) + " (" + (s->property("outbound").toBool() ? "outgoing" : "incoming") + ")");
    sendTo(s, "SYNC_REQUEST");
    sendPeers(s);
    sendBallot(s);
    savePeers();
    emit changed();
}
// Two nodes dialing each other at once end up with two links: both keep the one dialed by the lower key.
void Node::dropDuplicate(QSslSocket *s) {
    const QString pub = s->property("nodePub").toString();
    for (const auto &o : m_sockets) {
        if (!o || o == s || !o->property("authed").toBool() || o->property("nodePub") != pub) continue;
        const bool keepOutbound = m_nodeKey.id < pub;
        QSslSocket *drop = (s->property("outbound").toBool() == keepOutbound) ? o.data() : s;
        drop->setProperty("authed", false);
        drop->disconnectFromHost();
        return;
    }
}

void Node::handleMessage(QSslSocket *s, const QString &line) {
    if (line == "SYNC_REQUEST") {
        int n = 0;
        for (const Entry &e : m_ledger->orderedEntries()) if (e.status.isEmpty()) { sendTo(s, QString("HIST\t%1\t%2").arg(e.siteId).arg(e.l.raw)); n++; }
        sendTo(s, "SYNC_DONE");
        return;
    }
    if (line.startsWith("HIST\t") && !s->property("syncing").toBool() && s->property("synced").toBool()) {
        QStringList one{line.mid(5)}; s->setProperty("histBuf", one); finishSync(s);   // live site line from a bridged peer
        return;
    }
    if (line.startsWith("HIST\t")) {
        s->setProperty("syncing", true);
        QStringList buf = s->property("histBuf").toStringList();
        if (buf.size() > 2000000) { s->abort(); return; }
        buf << line.mid(5); s->setProperty("histBuf", buf);
        return;
    }
    if (line == "SYNC_DONE") { s->setProperty("syncing", false); s->setProperty("synced", true); finishSync(s); return; }
    if (line.startsWith("TX\t") || line.startsWith("SIGNED_")) {
        const QString raw = line.startsWith("TX\t") ? line.mid(3) : line;
        const NodeLedger::Result r = m_ledger->admit(raw, NodeLedger::New);
        if (r.ok) {
            m_ledger->retryOrphans();
            if (!m_seenTx.contains(r.hash)) { m_seenTx.insert(r.hash); broadcast("TX\t" + raw, s); }
            emit changed();
        } else if (r.conflict && !r.dup && !m_seenTx.contains(r.hash)) {
            // a double spend: refused here, but passed on once so every node records the attempt
            m_seenTx.insert(r.hash); broadcast("TX\t" + raw, s);
            emit log("Double spend refused (recorded in Conflicts)");
            emit changed();
        }
        return;
    }
    if (line.startsWith("BALLOT\t")) { acceptBallotLine(line.mid(7), s); return; }
    if (line.startsWith("PEERS|")) {
        for (const QString &a : line.mid(6).split(',', QString::SkipEmptyParts)) if (!isConnectedTo(a.trimmed(), QString())) connectTo(a.trimmed());
        return;
    }
}
// a whole ledger from a peer, applied in its order in one batch
void Node::finishSync(QSslSocket *s) {
    const QStringList buf = s->property("histBuf").toStringList();
    if (buf.isEmpty()) return;
    s->setProperty("histBuf", QStringList());
    int added = 0;
    m_ledger->beginBatch();
    for (const QString &h : buf) {
        const int t = h.indexOf('\t'); if (t < 0) continue;
        const qint64 siteId = h.left(t).toLongLong(); const QString raw = h.mid(t + 1);
        // a peer's site order is only taken when this node is not bridged itself (then its own pull decides)
        const NodeLedger::Result r = (siteId >= 0 && !m_bridgeOn) ? m_ledger->admit(raw, NodeLedger::Site, siteId) : m_ledger->admit(raw, NodeLedger::History);
        if (r.ok) added++;
    }
    m_ledger->endBatch();
    added += m_ledger->retryOrphans();
    if (added) { emit log(QString("Synced %1 new line(s) from %2").arg(added).arg(shortAddr(s->property("nodePub").toString()))); emit changed(); }
}

void Node::sendTo(QSslSocket *s, const QString &msg) {
    if (!s || !s->isEncrypted()) return;
    s->write(msg.toUtf8() + "\n");
    s->setProperty("tx", s->property("tx").toLongLong() + 1);
}
void Node::broadcast(const QString &msg, QSslSocket *except) {
    for (const auto &s : m_sockets) if (s && s != except && s->property("authed").toBool()) sendTo(s, msg);
}
void Node::sendPeers(QSslSocket *s) {
    QStringList list;
    for (const auto &o : m_sockets) if (o && o != s && o->property("authed").toBool()) { const QString a = o->property("advertised").toString().isEmpty() ? o->property("address").toString() : o->property("advertised").toString(); list << a; }
    if (!list.isEmpty()) sendTo(s, "PEERS|" + list.join(','));
}
void Node::sendBallot(QSslSocket *s) {
    const QString b = m_ledger->meta("ballot_line");
    if (!b.isEmpty()) sendTo(s, "BALLOT\t" + b);
}
void Node::savePeers() {
    QFile f(m_dir + "/peers.txt");
    if (!f.open(QIODevice::WriteOnly)) return;
    for (const auto &s : m_sockets) if (s && s->property("authed").toBool()) {
        const QString a = s->property("outbound").toBool() ? s->property("address").toString() : s->property("advertised").toString();
        f.write((a + "\n").toUtf8());
    }
}
void Node::housekeeping() {
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    for (auto it = m_helloNonces.begin(); it != m_helloNonces.end();) it = (now - it.value() > 2 * HELLO_WINDOW) ? m_helloNonces.erase(it) : it + 1;
    if (m_seenTx.size() > 200000) m_seenTx.clear();
    for (const TrustedPeer &t : m_trusted) if (!isConnectedTo(t.address, t.nodePub)) connectTo(t.address);   // keep every pinned peer connected
    if (m_bridgeOn) bridgeTick();
}

// ---------------------------------------------------------------- local lines
NodeLedger::Result Node::submit(const QString &line) {
    const NodeLedger::Result r = m_ledger->admit(line, NodeLedger::New);
    if (r.ok) {
        m_seenTx.insert(r.hash);
        broadcast("TX\t" + line.trimmed());
        m_ledger->retryOrphans();
        if (m_bridgeOn) bridgePush();
        emit changed();
    }
    return r;
}

// Standalone ballot: signed by an issuer key, newest wins. When a website is bridged its ballot rules.
bool Node::publishBallot(const Key &issuer, const QString &question, const QStringList &options, bool closed, QString &err) {
    if (m_bridgeOn) { err = "a website is bridged - change the ballot on the website's admin page"; return false; }
    if (!m_ledger->issuers.contains(issuer.id)) { err = "only an issuer key can publish the ballot (add it to issuers.txt)"; return false; }
    QStringList opts; for (const QString &o : options) if (!o.trimmed().isEmpty()) opts << o.trimmed();
    if (opts.isEmpty()) { err = "at least one option"; return false; }
    const QString line = makeLine(issuer, "BALLOT", {QString::fromLatin1(question.toUtf8().toBase64()),
        QString::fromLatin1(QJsonDocument(QJsonArray::fromStringList(opts.mid(0, 12))).toJson(QJsonDocument::Compact).toBase64()), closed ? "1" : "0"});
    acceptBallotLine(line, nullptr);
    return true;
}
void Node::acceptBallotLine(const QString &line, QSslSocket *from) {
    if (m_bridgeOn) return;
    Line b;
    if (!parseLine(line, b) || !b.sigOk || b.type != "BALLOT" || b.p.size() != 8) return;
    if (!m_ledger->issuers.contains(b.pub) || b.ts > m_ledger->now() + 3600) return;
    if (b.ts < m_ledger->ballot.ts || (b.ts == m_ledger->ballot.ts && line <= m_ledger->meta("ballot_line"))) return;   // newest wins (ties: larger line)
    Ballot nb; nb.question = QString::fromUtf8(QByteArray::fromBase64(b.p[5].toLatin1()));
    for (const QJsonValue &v : QJsonDocument::fromJson(QByteArray::fromBase64(b.p[6].toLatin1())).array()) nb.options << v.toString();
    nb.closed = b.p[7] == "1"; nb.ts = b.ts; nb.signer = b.pub;
    if (nb.options.isEmpty()) return;
    m_ledger->ballot = nb;
    QJsonObject j = nb.toJson(); j.insert("ts", double(nb.ts)); j.insert("signer", nb.signer);
    m_ledger->setMeta("ballot", QString::fromUtf8(QJsonDocument(j).toJson(QJsonDocument::Compact)));
    m_ledger->setMeta("ballot_line", line);
    broadcast("BALLOT\t" + line, from);
    emit log("Ballot updated by issuer " + shortAddr(b.pub) + ": " + nb.question);
    emit changed();
}

// ---------------------------------------------------------------- website bridge
void Node::setBridge(const QString &url, bool on) {
    if (url != m_bridgeUrl) { m_ledger->setMeta("site_cursor", "0"); m_ledger->setMeta("site_pub", ""); }
    m_bridgeUrl = url.trimmed(); m_bridgeOn = on && !m_bridgeUrl.isEmpty();
    m_ledger->setMeta("bridge_url", m_bridgeUrl); m_ledger->setMeta("bridge_on", m_bridgeOn ? "1" : "0");
    m_lastBoot = 0;
    refreshIssuers();
    m_bridgeStatus = m_bridgeOn ? "starting..." : "off (node runs on its peers only)";
    emit changed();
    if (m_bridgeOn) bridgeTick();
}
void Node::apiPost(const QString &action, const QJsonObject &body, std::function<void(bool, const QJsonObject &)> done, const QByteArray &adminToken) {
    QUrl url(m_bridgeUrl); { const QString q = url.query(); url.setQuery((q.isEmpty() ? "" : q + "&") + "action=" + action); }
    QNetworkRequest req(url); req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (!adminToken.isEmpty()) req.setRawHeader("X-Admin-Token", adminToken);
    req.setAttribute(QNetworkRequest::FollowRedirectsAttribute, true);
    QNetworkReply *r = m_nam->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    QTimer::singleShot(30000, r, [r] { if (r->isRunning()) r->abort(); });
    connect(r, &QNetworkReply::finished, this, [r, done] {
        const QJsonObject j = QJsonDocument::fromJson(r->readAll()).object();
        const bool ok = r->error() == QNetworkReply::NoError && j.value("ok").toBool();
        r->deleteLater();
        done(ok, j.isEmpty() ? QJsonObject{{"err", r->errorString()}} : j);
    });
}
void Node::bridgeTick() {
    if (!m_bridgeOn || m_bridgeBusy) return;
    m_bridgeBusy = true;
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    if (now - m_lastBoot < 30) { bridgePull(m_ledger->meta("site_cursor", "0").toLongLong(), 0); return; }
    apiPost("boot", {}, [this, now](bool ok, const QJsonObject &b) {
        if (!ok) { m_bridgeStatus = "website unreachable: " + b.value("err").toString(); m_bridgeBusy = false; emit changed(); return; }
        const QString pub = b.value("serverPub").toString(), pinned = m_ledger->meta("site_pub");
        if (!pinned.isEmpty() && pinned != pub) { m_bridgeStatus = "REFUSED: the website's server key changed (Reset the bridge if this is intended)"; m_bridgeBusy = false; emit changed(); return; }
        m_ledger->setMeta("site_pub", pub);
        m_siteIssuers.clear(); QStringList il;
        for (const QJsonValue &v : b.value("issuers").toArray()) { m_siteIssuers << v.toObject().value("pub").toString(); il << v.toObject().value("pub").toString(); }
        m_ledger->setMeta("site_issuers", il.join(','));
        const QJsonObject bj = b.value("ballot").toObject();
        Ballot nb; nb.question = bj.value("question").toString(); nb.closed = bj.value("closed").toBool();
        for (const QJsonValue &o : bj.value("options").toArray()) nb.options << o.toString();
        m_ledger->ballot = nb;
        m_ledger->setMeta("ballot", QString::fromUtf8(QJsonDocument(nb.toJson()).toJson(QJsonDocument::Compact)));
        refreshIssuers();
        m_lastBoot = now;
        bridgePull(m_ledger->meta("site_cursor", "0").toLongLong(), 0);
    });
}
void Node::bridgePull(qint64 since, int round) {
    apiPost("pull", QJsonObject{{"since", double(since)}}, [this, since, round](bool ok, const QJsonObject &r) {
        if (!ok) { m_bridgeStatus = "pull failed: " + r.value("err").toString(); m_bridgeBusy = false; emit changed(); return; }
        const QJsonArray lines = r.value("lines").toArray();
        qint64 cursor = since; int added = 0;
        m_ledger->beginBatch();
        for (const QJsonValue &v : lines) {
            const QJsonObject o = v.toObject(); const qint64 id = qint64(o.value("id").toDouble());
            const QString raw = o.value("line").toString();
            const qint64 before = m_ledger->siteIdOf(sha256Hex(raw.trimmed().toUtf8()));
            const NodeLedger::Result res = m_ledger->admit(raw, NodeLedger::Site, id);
            if (res.ok) added++;
            // peers without a bridge learn the site's order: new lines and lines that just got their site id
            if (res.ok || (before != id && m_ledger->siteIdOf(res.hash) == id)) broadcast(QString("HIST\t%1\t%2").arg(id).arg(raw.trimmed()));
            cursor = id;
        }
        m_ledger->endBatch();
        m_ledger->setMeta("site_cursor", QString::number(cursor));
        if (added) { m_ledger->retryOrphans(); emit changed(); }
        if (lines.size() >= 400 && round < 50) { bridgePull(cursor, round + 1); return; }
        bridgePush();
    });
}
void Node::bridgePush() {
    const QStringList pending = m_ledger->unconfirmedLines().mid(0, 250);
    const QString when = QDateTime::currentDateTime().toString("HH:mm:ss");
    if (pending.isEmpty()) {
        m_bridgeStatus = QString("in sync with the website at %1 (site line %2)").arg(when, m_ledger->meta("site_cursor", "0"));
        m_bridgeBusy = false; emit changed(); return;
    }
    m_bridgeBusy = true;
    apiPost("push", QJsonObject{{"lines", QJsonArray::fromStringList(pending)}}, [this, pending, when](bool ok, const QJsonObject &r) {
        if (!ok) { m_bridgeStatus = "push failed: " + r.value("err").toString(); m_bridgeBusy = false; emit changed(); return; }
        int rejected = 0;
        for (const QJsonValue &v : r.value("rejected").toArray()) { m_ledger->markSiteRejected(v.toObject().value("hash").toString(), v.toObject().value("err").toString()); rejected++; }
        const int accepted = r.value("accepted").toArray().size();
        m_bridgeStatus = QString("pushed %1 line(s) at %2: %3 accepted, %4 rejected").arg(pending.size()).arg(when).arg(accepted).arg(rejected);
        if (accepted) emit log(QString("Website accepted %1 line(s) from this node").arg(accepted));
        if (rejected) emit log(QString("Website rejected %1 line(s) - see the Ledger tab").arg(rejected));
        m_bridgeBusy = false;
        emit changed();
        if (accepted) QTimer::singleShot(300, this, [this] { m_bridgeBusy = false; bridgeTick(); });   // fetch their site ids
    });
}

} // namespace evote
