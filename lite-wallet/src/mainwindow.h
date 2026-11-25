#pragma once
#include "core.h"
#include "ledger.h"
#include <QMainWindow>
#include <memory>

class QLineEdit; class QLabel; class QTableWidget; class QPlainTextEdit; class QSpinBox; class QProgressBar;
class QPushButton; class QTabWidget; class QButtonGroup; class QVBoxLayout; class QCheckBox;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(const QString &dataDir, QWidget *parent = nullptr);
    ~MainWindow() override;

    // Actions (no dialogs) - the buttons call these; the GUI test drives them directly.
    QString serverUrl() const;
    void setServerUrl(const QString &url);
    bool openWalletJson(const QByteArray &json, const QString &pass);
    QByteArray createWallet(const QString &label, const QString &pass);          // returns the v3 file
    bool refreshCoinsFromServer();
    bool loadCoinsBundle(const QByteArray &json);
    bool useOfflineLedgerCoins();
    void tickCoins(int n);
    bool pickWeight(qint64 w);
    void setRecipient(const QString &to);
    QStringList signTransfers();
    bool sendToServer();
    QByteArray voucherJson(const QString &kind);                                 // transfer / vote voucher with provenance
    QString rawtxLinkText();
    bool loadBallot();
    void chooseOption(const QString &option);
    QStringList signVotes();
    bool submitVotes();
    bool syncLedger();
    void verifyText(const QString &text);
    void clearMeet();

    QTabWidget *tabs = nullptr;
    QLabel *walletStatus = nullptr, *coinsStatus = nullptr, *ballotQuestion = nullptr, *ledgerAge = nullptr, *verifySummary = nullptr;
    QTableWidget *coinTable = nullptr, *verifyTable = nullptr;
    QPlainTextEdit *sendLog = nullptr, *ballotLog = nullptr, *voucherInput = nullptr;

private slots:
    void onOpenWallet();
    void onCreateWallet();
    void onLoadBundle();
    void onSaveVoucher();
    void onCopyLink();
    void onSaveVoteVoucher();
    void onLoadVoucherFile();

private:
    QString dataDir;
    evote::Key key;
    QString label;
    QVector<evote::Coin> coins;
    QStringList lastSpends;
    QJsonObject ballot;
    QString option;
    std::unique_ptr<evote::OfflineLedger> ledger;
    bool cancelSync = false;

    QLineEdit *serverEdit = nullptr, *addrEdit = nullptr, *passEdit = nullptr, *toEdit = nullptr;
    QSpinBox *weightSpin = nullptr, *hoursSpin = nullptr;
    QProgressBar *syncBar = nullptr;
    QPushButton *syncBtn = nullptr, *cancelBtn = nullptr;
    QVBoxLayout *optionBox = nullptr;
    QButtonGroup *optionGroup = nullptr;
    QCheckBox *rememberBox = nullptr;

    QWidget *buildWalletTab();
    QWidget *buildCoinsTab();
    QWidget *buildBallotTab();
    QWidget *buildLedgerTab();
    void showCoins(const QString &source);
    QVector<evote::Coin> checkedCoins() const;
    QStringList provenanceFor(const QVector<evote::Coin> &cs);
    void renderRedeem(const QJsonObject &r, QPlainTextEdit *log);
    void updateLedgerLabel();
    bool needKey(QPlainTextEdit *log);
};
