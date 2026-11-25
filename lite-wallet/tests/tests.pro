QT += core network sql
QT -= gui
CONFIG += c++14 console
CONFIG -= app_bundle
TARGET = evote-lite-tests
SOURCES += tests.cpp ../src/core.cpp ../src/ledger.cpp
HEADERS += ../src/core.h ../src/ledger.h
LIBS += -lssl -lcrypto
