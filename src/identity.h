// Node identity (signs HELLO only - the wallet that owns coins is a separate evote-wallet.json).
//   node.key  Ed25519 private key, PKCS#8 PEM encrypted with the node passphrase (AES-256 + PBKDF2)
//   node.pub  public key PEM (same files/format as newer3, so existing trust lines stay valid)
//   server.crt / server.key  TLS certificate made in-process (no openssl command needed)
#pragma once
#include "core.h"

namespace evote {

struct IdentityResult { bool ok = false; QString err; Key key; bool legacyUnencrypted = false; bool created = false; };

bool identityExists(const QString &dir);
bool identityEncrypted(const QString &dir);
// Loads node.key with the passphrase, or creates a new identity when none exists.
IdentityResult loadOrCreateIdentity(const QString &dir, const QString &passphrase);
// Re-saves the node key encrypted with a (new) passphrase - used for old newer3 plain node.key files.
bool encryptIdentity(const QString &dir, const Key &k, const QString &passphrase, QString &err);
// server.crt + server.key (self-signed, 10 years). Returns false with err on failure.
bool ensureTlsCert(const QString &dir, QString &err);
QString certFingerprintFile(const QString &certPath);   // sha256 of DER, hex (what trusted_peers.txt pins)

} // namespace evote
