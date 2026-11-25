#include "mainwindow.h"
#include <QApplication>
#include <QDir>
#include <QStandardPaths>

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("EVOTE");
    QCoreApplication::setApplicationName("EVOTE Lite Wallet");
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    MainWindow w(dir);
    w.show();
    return app.exec();
}
