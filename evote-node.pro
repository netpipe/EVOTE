# EVOTE Node (App 2) - Qt 5.12 + OpenSSL 1.1.1
# Qt 5.12 loads OpenSSL 1.1 for TLS; with OpenSSL 3 it cannot read peer certificates, so pinning fails.
QT       += core gui widgets network sql
CONFIG   += c++14
TARGET    = evote-node
SOURCES  += src/main.cpp src/core.cpp src/nodeledger.cpp src/identity.cpp src/node.cpp src/nodewindow.cpp
HEADERS  += src/core.h src/nodeledger.h src/identity.h src/node.h src/nodewindow.h

INCLUDEPATH += /Users/macbook2015/Desktop/brew/include /Users/macbook2015/Desktop/brew/lib
LIBS += -L/Users/macbook2015/Desktop/brew/lib

# OpenSSL 1.1 location: pass OPENSSL=/path on the qmake line, otherwise the usual places are tried
isEmpty(OPENSSL) {
    for(p, $$list($$(HOME)/Desktop/brew/opt/openssl@1.1 $$(HOME)/Desktop/brew /opt/homebrew/opt/openssl@1.1 /usr/local/opt/openssl@1.1)) {
        isEmpty(OPENSSL): exists($$p/include/openssl/evp.h): exists($$p/lib/libssl.1.1.dylib): OPENSSL = $$p
    }
}
!isEmpty(OPENSSL) {
    INCLUDEPATH += $$OPENSSL/include
    LIBS += -L$$OPENSSL/lib
    unix:!macx: LIBS += -Wl,-rpath,$$OPENSSL/lib
}
LIBS += -lssl -lcrypto
win32 {
    INCLUDEPATH += $$(OPENSSL_DIR)/include
    LIBS += -L$$(OPENSSL_DIR)/lib -llibssl -llibcrypto
}
