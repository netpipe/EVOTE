// Offline ledger: a verified local copy of the server's ledger, built from the signed checkpoint
// plus the lines after it, downloaded in chunks and resumable. Used to list coins and to verify
// vouchers with no internet (e.g. at an offline meet).
#pragma once
#include "core.h"
#include <QDateTime>
#include <QSqlDatabase>
#include <functional>

namespace evote {

struct VerifyItem {
    enum State { Valid, ValidByHistory, Invalid, Warning };
    State state = Invalid;
    QString kind;          // transfer / vote
    QString coin, from, to, option;
    qint64 amount = 0;
    QString message;       // human readable result
};
struct VerifyReport {
    QVector<VerifyItem> items;
    QMap<QString, qint64> validWeightTo;   // recipient -> weight that checks out
    QString ledgerAge;                      // "Ledger as of ..."
};

class OfflineLedger {
public:
    explicit OfflineLedger(const QString &file);
    ~OfflineLedger();
    bool ok() const { return db.isOpen(); }

    // Download / update in chunks. progress(done, total) returns false to cancel. Resumable.
    bool sync(Api &api, const std::function<bool(qint64, qint64)> &progress, QString &msg);
    void reset();                                   // forget everything (new server)

    QString meta(const QString &k, const QString &def = QString()) const;
    qint64 lineCount() const;                       // lines covered (checkpoint + newer)
    QDateTime syncedAt() const;
    QString ageText() const;
    QJsonObject ballot() const;
    QVector<Coin> coinsOf(const QString &owner) const;
    QStringList historyOf(const QString &coin) const;   // lines held locally for a coin

    VerifyReport verify(const QStringList &all, const QStringList &spends, bool remember);
    int seenCount() const;
    void clearSeen();

private:
    QSqlDatabase db;
    QString conn;
    void setMeta(const QString &k, const QString &v);
    bool applyLine(const Line &l, qint64 id, QString &why);
    bool loadSnapshot(Api &api, const QJsonObject &boot, QString &msg);
};

} // namespace evote
