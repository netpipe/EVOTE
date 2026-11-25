// EVOTE Node - start-up: data folder, node passphrase, then the window (or --headless).
//   evote-node [--dir <folder>] [--port 5555] [--headless] [--pass-file <file>] [--bridge <index.php url>]
#include "identity.h"
#include "node.h"
#include "nodewindow.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QFile>
#include <QInputDialog>
#include <QMessageBox>
#include <QStandardPaths>
#include <cstdio>

using namespace evote;

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("EVOTE");
    QCoreApplication::setApplicationName("EVOTE Node");
    QCommandLineParser cl;
    cl.addHelpOption();
    cl.addOption({"dir", "data folder (node.key, trusted_peers.txt, ledger)", "folder", QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)});
    cl.addOption({"port", "TLS port", "port", "5555"});
    cl.addOption({"headless", "no window, log to the terminal"});
    cl.addOption({"pass-file", "read the node passphrase from this file (headless)", "file"});
    cl.addOption({"bridge", "mirror this website (index.php URL)", "url"});
    cl.process(app);
    const QString dir = cl.value("dir"); QDir().mkpath(dir);
    const bool headless = cl.isSet("headless");

    // node passphrase (protects node.key)
    QString pass;
    if (cl.isSet("pass-file")) { QFile f(cl.value("pass-file")); if (f.open(QIODevice::ReadOnly)) pass = QString::fromUtf8(f.readAll()).trimmed(); }
    IdentityResult id;
    for (int attempt = 0; attempt < 5; attempt++) {
        if (pass.isEmpty() && !headless && (!identityExists(dir) || identityEncrypted(dir))) {
            bool ok = false;
            const bool fresh = !identityExists(dir);
            pass = QInputDialog::getText(nullptr, "EVOTE Node", fresh ? "New node: choose a passphrase for the node key (8+ characters)" : "Node key passphrase",
                                         QLineEdit::Password, "", &ok);
            if (!ok) return 0;
            if (fresh) {
                const QString again = QInputDialog::getText(nullptr, "EVOTE Node", "Repeat the passphrase", QLineEdit::Password, "", &ok);
                if (!ok) return 0;
                if (again != pass) { QMessageBox::warning(nullptr, "EVOTE Node", "The passphrases differ."); pass.clear(); continue; }
            }
        }
        id = loadOrCreateIdentity(dir, pass);
        if (id.ok || headless) break;
        QMessageBox::warning(nullptr, "EVOTE Node", id.err); pass.clear();
    }
    if (!id.ok) { fprintf(stderr, "node key: %s\n", qPrintable(id.err)); return 1; }
    if (id.legacyUnencrypted) {
        // an old newer3 node.key (plain text): offer to protect it, same key so trust lines stay valid
        if (!headless) {
            bool ok = false;
            const QString np = QInputDialog::getText(nullptr, "EVOTE Node", "This node.key is not encrypted (old newer3 file).\nChoose a passphrase to encrypt it now (same key, peers' trust lines stay valid):",
                                                     QLineEdit::Password, "", &ok);
            QString err;
            if (ok && !np.isEmpty() && !encryptIdentity(dir, id.key, np, err)) QMessageBox::warning(nullptr, "EVOTE Node", err);
        } else fprintf(stderr, "WARNING: node.key is not encrypted - run once with the window to encrypt it.\n");
    }

    Node node(dir, id.key, cl.value("port").toInt());
    QString err;
    if (!node.start(err)) {
        if (headless) { fprintf(stderr, "%s\n", qPrintable(err)); return 1; }
        QMessageBox::critical(nullptr, "EVOTE Node", err); return 1;
    }
    if (cl.isSet("bridge")) node.setBridge(cl.value("bridge"), true);
    if (headless) {
        QObject::connect(&node, &Node::log, [](const QString &m) { printf("%s\n", qPrintable(m)); fflush(stdout); });
        printf("trust line: %s\n", qPrintable(node.trustLine("127.0.0.1"))); fflush(stdout);
        return app.exec();
    }
    NodeWindow w(&node);
    w.show();
    return app.exec();
}
