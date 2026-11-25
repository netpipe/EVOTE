// EVOTE P2P node (newer3, brought up to the website's rules).
//
// Peers:   TLS (default port 5555). trusted_peers.txt pins every peer:  address|cert sha256|node public key
//          Both sides check the other's certificate pin, then exchange a signed HELLO (fresh timestamp,
//          one-time nonce, listening port). Only then are ledger messages accepted.
// Wire:    one message per line
//            HELLO|1|nodePub|ts|nonce|port|sig       authentication
//            SYNC_REQUEST                            "send me your ledger"
//            HIST<TAB>siteId<TAB>line ... SYNC_DONE  your ledger, in your accepted order (siteId -1 = none)
//            TX<TAB>line                             a new transfer / vote / issue (relayed to other peers)
//            BALLOT<TAB>line                         issuer-signed ballot (only used when no website is bridged)
//            PEERS|addr,addr                         gossip of pinned peer addresses
//          Raw SIGNED_* lines from older newer3 nodes are read as TX.
// Bridge:  optional. With a website URL the node pulls the site's ledger (the site's order is final for
//          what it confirmed), pushes lines it got from wallets/peers, and takes the site's issuer list
//          and ballot. Without it the node runs on its own peers.
#pragma once
#include "nodeledger.h"
#include <QNetworkAccessManager>
#include <QObject>
#include <QPointer>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QTcpServer>
#include <QTimer>
#include <functional>

namespace evote {

class SslServer : public QTcpServer {
    Q_OBJECT
public:
    QSslConfiguration config;
signals:
    void newSslSocket(QSslSocket *s);
protected:
    void incomingConnection(qintptr d) override;
};

struct TrustedPeer { QString address, certSha256, nodePub; };
struct PeerInfo { QString address, nodePub; bool outbound = false, authed = false; qint64 since = 0, rx = 0, tx = 0; int score = 0; };

class Node : public QObject {
    Q_OBJECT
public:
    Node(const QString &dir, const Key &nodeKey, int port, QObject *parent = nullptr);
    ~Node() override;

    bool start(QString &err);                       // TLS cert + listen
    QString dir() const { return m_dir; }
    int port() const { return m_port; }
    const Key &nodeKey() const { return m_nodeKey; }
    QString certFingerprint() const { return m_certFp; }
    QString trustLine(const QString &advertisedHost) const;   // what other nodes paste into trusted_peers.txt

    // peers
    QVector<TrustedPeer> trusted() const { return m_trusted; }
    bool addTrustLine(const QString &line, QString &err);     // appends to trusted_peers.txt
    void reloadTrust();
    bool connectTo(const QString &hostPort);
    QVector<PeerInfo> peers() const;
    int authedCount() const;

    // ledger
    NodeLedger &ledger() { return *m_ledger; }
    QSet<QString> fileIssuers;                      // issuers.txt
    void refreshIssuers();
    bool addIssuer(const QString &pub, QString &err);   // appends to issuers.txt
    bool removeIssuer(const QString &pub, QString &err);
    QSet<QString> siteIssuers() const { return m_siteIssuers; }
    // website admin API (bridged): op = issue / ballot ... The admin token is used for this call only, never stored.
    void siteAdmin(const QJsonObject &body, const QString &adminToken, std::function<void(bool, const QJsonObject &)> done);
    NodeLedger::Result submit(const QString &line);  // a new line from this node's wallet: admit + broadcast
    bool publishBallot(const Key &issuer, const QString &question, const QStringList &options, bool closed, QString &err);

    // website bridge
    void setBridge(const QString &url, bool enabled);
    QString bridgeUrl() const { return m_bridgeUrl; }
    bool bridgeEnabled() const { return m_bridgeOn; }
    QString bridgeStatus() const { return m_bridgeStatus; }
    void bridgeTick();                               // one pull + push round (also runs on a timer)
    bool bridgeBusy() const { return m_bridgeBusy; }

    int maxPeers = 8;

    // anchors (Phase B): anchors.txt = anchor node keys + optional "threshold=N" (default majority)
    void reloadAnchors();
    bool addAnchor(const QString &pub, QString &err);
    bool removeAnchor(const QString &pub, QString &err);
    void setThreshold(int t);                         // 0 = majority
    bool isAnchor() const { return m_ledger->anchors.contains(m_nodeKey.id); }
    void anchorTick();                                // anchors: sign + gossip the next ORDER record (timer, every 2 s)

    // peer limits + reputation: score per peer node key; at -50 the peer is dropped and banned for 10 min
    int scoreOf(const QString &pub) const { return m_score.value(pub); }
    qint64 bannedUntil(const QString &pub) const { return m_banUntil.value(pub); }
    int maxMsgsPer10s = 5000;
    void broadcastRawForTest(const QString &msg) { broadcast(msg); }   // diagnostics / tests only

signals:
    void log(const QString &msg);
    void changed();                                  // ledger / peers changed (GUI refresh)

private:
    QString m_dir;
    Key m_nodeKey;
    int m_port;
    QString m_certFp;
    QSslConfiguration m_ssl;
    SslServer *m_server = nullptr;
    NodeLedger *m_ledger = nullptr;
    QVector<TrustedPeer> m_trusted;
    QList<QPointer<QSslSocket>> m_sockets;
    QHash<QString, qint64> m_helloNonces;            // pub|nonce -> ts (replay guard for HELLO)
    QSet<QString> m_seenTx;                          // relayed already
    QTimer m_timer, m_anchorTimer;
    QHash<QString, int> m_score;
    QHash<QString, qint64> m_banUntil;
    void rate(QSslSocket *s, int delta, const QString &why);
    void saveAnchors();

    QNetworkAccessManager *m_nam = nullptr;
    QString m_bridgeUrl, m_bridgeStatus;
    bool m_bridgeOn = false, m_bridgeBusy = false;
    QSet<QString> m_siteIssuers;
    qint64 m_lastBoot = 0;

    void setupSocket(QSslSocket *s, bool outbound, const QString &address);
    void onEncrypted(QSslSocket *s);
    void onData(QSslSocket *s);
    void handleHello(QSslSocket *s, const QString &line);
    void handleMessage(QSslSocket *s, const QString &line);
    void finishSync(QSslSocket *s);
    void sendTo(QSslSocket *s, const QString &msg);
    void broadcast(const QString &msg, QSslSocket *except = nullptr);
    void sendPeers(QSslSocket *s);
    void sendBallot(QSslSocket *s);
    void housekeeping();
    void savePeers();
    bool isConnectedTo(const QString &address, const QString &pub) const;
    void dropDuplicate(QSslSocket *s);
    void acceptBallotLine(const QString &line, QSslSocket *from);

    void apiPost(const QString &action, const QJsonObject &body, std::function<void(bool, const QJsonObject &)> done, const QByteArray &adminToken = QByteArray());
    void bridgePull(qint64 since, int round);
    void bridgePush();
};

} // namespace evote
