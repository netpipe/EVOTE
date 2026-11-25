# EVOTE Lite Wallet - Qt 5.12 + OpenSSL (1.1.1 or 3.x) for Ed25519 / PBKDF2 / HMAC
QT       += core gui widgets network sql
CONFIG   += c++14
TARGET    = evote-lite
SOURCES  += src/main.cpp src/mainwindow.cpp src/core.cpp src/ledger.cpp
HEADERS  += src/mainwindow.h src/core.h src/ledger.h
LIBS     += -lssl -lcrypto

# macOS with Homebrew OpenSSL. Checks the brew folder your newer3 node .pro uses (~/Desktop/brew),
# then the standard Homebrew places; OpenSSL 1.1 or 3 both work. Set OPENSSL=... on the qmake line to override.
macx {
    isEmpty(OPENSSL) {
        for(p, $$list($$(HOME)/Desktop/brew/opt/openssl@3 $$(HOME)/Desktop/brew/opt/openssl@1.1 $$(HOME)/Desktop/brew \
                     /opt/homebrew/opt/openssl@3 /opt/homebrew/opt/openssl@1.1 /usr/local/opt/openssl@3 /usr/local/opt/openssl@1.1)) {
            isEmpty(OPENSSL): exists($$p/include/openssl/evp.h): OPENSSL = $$p
        }
    }
    !isEmpty(OPENSSL) {
        INCLUDEPATH += $$OPENSSL/include
        LIBS = -L$$OPENSSL/lib $$LIBS
    }
}
win32 {
    # set OPENSSL_DIR to your OpenSSL install, e.g. C:/Program Files/OpenSSL-Win64
    INCLUDEPATH += $$(OPENSSL_DIR)/include
    LIBS += -L$$(OPENSSL_DIR)/lib -llibssl -llibcrypto
}
