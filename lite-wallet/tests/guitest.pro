QT += core gui widgets network sql
CONFIG += c++14
TARGET = evote-lite-guitest
SOURCES += guitest.cpp ../src/mainwindow.cpp ../src/core.cpp ../src/ledger.cpp
HEADERS += ../src/mainwindow.h ../src/core.h ../src/ledger.h
LIBS += -lssl -lcrypto
