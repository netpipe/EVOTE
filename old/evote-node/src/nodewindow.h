#pragma once
#include "node.h"
#include <QMainWindow>

class QLineEdit; class QLabel; class QTableWidget; class QPlainTextEdit; class QSpinBox; class QCheckBox;
class QTabWidget; class QButtonGroup; class QVBoxLayout; class QPushButton;

class NodeWindow : public QMainWindow {
    Q_OBJECT
public:
    NodeWindow(evote::Node *node, QWidget *parent = nullptr);

    // actions used by the buttons (and by the GUI test)
    bool openWalletJson(const QByteArray &json, const QString &pass);
    QByteArray createWallet(const QString &label, const QString &pass);
    void tickCoins(int n);
    bool pickWeight(qint64 w);
    int sendTicked(const QString &to, int hours);
    int voteTicked(const QString &option);
    int mint(const QString &to, int count, qint64 amount);
    bool publishBallot(const QString &question, const QStringList &options, bool closed);
    int adminIssue(const QString &to, int count, qint64 amount);           // wallet-signed, or via the website admin API (-1 = sent)
    bool adminBallot(const QString &question, const QStringList &options, bool closed);
    void setEditorOptions(const QStringList &opts);
    QStringList editorOptions() const;
    void loadBallotEditor();
    static const int MAX_OPTIONS = 12;
    void refresh();

    QTabWidget *tabs = nullptr;
    QLineEdit *adminToken = nullptr;
    QPlainTextEdit *adminLog = nullptr;
    QTableWidget *issuerTable = nullptr, *optTable = nullptr;
    QLabel *adminMode = nullptr;
    QLabel *coinsLabel = nullptr, *nodeStatus = nullptr, *walletStatus = nullptr, *ledgerStatus = nullptr, *bridgeStatus = nullptr, *ballotQuestion = nullptr;
    QTableWidget *peerTable = nullptr, *lineTable = nullptr, *coinTable = nullptr, *tallyTable = nullptr, *conflictTable = nullptr;
    QPlainTextEdit *logView = nullptr;
    QLineEdit *bridgeEdit = nullptr;
    QCheckBox *bridgeBox = nullptr;

private:
    evote::Node *node;
    evote::Key wallet;
    QString walletLabel;
    QStringList coinHashes;
    QString option;

    QLineEdit *trustEdit = nullptr, *advertEdit = nullptr, *toEdit = nullptr, *addrEdit = nullptr, *passEdit = nullptr;
    QLineEdit *mintTo = nullptr, *ballotQ = nullptr, *issuerEdit = nullptr;
    QSpinBox *weightSpin = nullptr, *hoursSpin = nullptr, *mintCount = nullptr, *mintAmount = nullptr;
    QCheckBox *ballotClosed = nullptr;
    QVBoxLayout *optionBox = nullptr;
    QButtonGroup *optionGroup = nullptr;
    QWidget *tokenRow = nullptr;
    QPushButton *mintBtn = nullptr, *publishBtn = nullptr;

    QWidget *buildPeersTab();
    QWidget *buildLedgerTab();
    QWidget *buildWalletTab();
    QWidget *buildBallotTab();
    QWidget *buildAdminTab();
    void refreshAdmin();
    QStringList tickedCoins() const;
    void log(const QString &m);
};
