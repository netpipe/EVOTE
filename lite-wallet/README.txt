EVOTE Lite Wallet (App 1) - Qt 5.12 C++
========================================

A small desktop wallet that talks only to the EVOTE server API (index.php). No node, no peers.
Your key never leaves the app: transfers and votes are signed locally and only the signed lines are sent.


BUILD
-----
Needs Qt 5.12 (modules: core gui widgets network sql) and OpenSSL 1.1.1 or 3.x.

  qmake evote-lite.pro
  make
  ./evote-lite          (macOS: open evote-lite.app)

macOS: the .pro looks for OpenSSL in the same brew folder as your newer3 node (~/Desktop/brew),
then in /opt/homebrew and /usr/local. If yours is somewhere else:
  qmake OPENSSL=/path/to/openssl evote-lite.pro
Windows: set OPENSSL_DIR to your OpenSSL folder before running qmake.

Tested here on Linux with Qt 5.12.12 and OpenSSL 3.0.


TABS
----
1. Wallet
   - Server URL (the full .../index.php address), remembered between runs.
   - Open evote-wallet.json with its passphrase. Old v2 and new v3 files both open. For a v2 file it
     offers to save a fixed v3 copy (v2 left half of the key unencrypted).
   - Create a new wallet. Saved as v3, exactly the same format the website writes. The website opens
     these files and the app opens the website's files (both directions tested).

2. Coins & Send
   - Coins from: the server (balance API), an "Export coins" file from the website, or the offline ledger.
   - Tick coins by hand, or enter a weight and press "Pick coins for this weight". It finds an exact set
     (same method as the website). If none exists it says the closest weights below and above, because
     coins can't be split.
   - To address + expiry (1 h to 30 days, the server's limit).
   - Send to server: signs and posts to the redeem API, then shows the result per coin.
   - Save voucher: an evote-voucher file with the coins' history included, not broadcast. Redeemable on
     the website, the dice site and the change machine.
   - Copy #rawtx link: opening it on the site fills the redeem box.

3. Ballot
   - Load ballot: from the server, or from the offline ledger when there's no connection.
   - Pick an option. The coins ticked on the Coins tab vote with their weight.
   - Sign & submit, or save a vote voucher.

4. Offline ledger & Verify
   - "Download / update ledger" (optional):
     - Fetches the server's signed checkpoint, checks its signature against the server key and its data
       against the signed hash, then pulls the newer lines in chunks (400 per request) with a progress bar.
     - Every line's signature is checked.
     - Cancel at any time. The next press continues where it stopped, and later updates fetch only the
       new lines.
     - If the server has made a newer checkpoint since your last update (it may have trimmed older
       lines), the copy rebuilds from that checkpoint by itself.
     - Refused: a different server key, a tampered checkpoint, or an older checkpoint than one already seen.
   - "Verify voucher" works with no internet. Paste or load a voucher, signed lines, or a #rawtx link.
     Each spend gets one of these results:
       VALID    - signed by the owner and unspent in your ledger copy
       VALID*   - coin is newer than your copy but the voucher carries its full signed history
                  (a later spend can't be ruled out)
       SEEN     - this exact voucher was already checked at this meet
       REJECT   - with the reason: invalid signature, expired, not the owner, already spent, already
                  redeemed, unknown coin, vote for a non-option, double spend inside the voucher, or
                  DOUBLE PRESENTATION (the same coin shown earlier at this meet in a different spend)
   - The summary shows the weight that checks out per recipient.
   - "Ledger as of <time> (x min ago)" is always shown. Offline it can't see spends made after the
     download, so receivers should redeem as soon as they're back online.
   - Meet list: on by default. "Clear meet list" starts a new meet.

Data is stored in the normal per-user app folder:
  Linux: ~/.local/share/EVOTE/EVOTE Lite Wallet
  macOS: ~/Library/Application Support/EVOTE/EVOTE Lite Wallet


FILES
-----
  evote-lite.pro       the app
  src/core.*           Ed25519 keys/signing (OpenSSL), wallet file v2/v3, line format, vouchers, API
  src/ledger.*         offline ledger (SQLite): chunked download, verification, meet list
  src/mainwindow.*     the GUI
  tests/tests.pro      core tests          ./evote-lite-tests <url> <admin token> <fixtures> <work dir> [2nd server url]
  tests/guitest.pro    drives the real window through every flow (QT_QPA_PLATFORM=offscreen)
  screenshots/         from the GUI test run


TESTS RUN (against a local copy of the latest index.php)
---------------------------------------------------------
Core: 38/38. GUI: 24/24. Highlights:
  - Opens wallet files made by the website (v2 + v3). The website opens wallets made by the app.
  - Server accepts transfers and votes signed by the app. Balance API matches.
  - Voucher made by the app is redeemed by the server's voucher API (the same call the dice site and
    change machine use). Vote voucher is counted.
  - Download cancelled part-way, then resumed to exactly the server's line count. Offline coin
    balances equal the server's.
  - Every verify case above, each with a passing and a failing example.
  - A tampered checkpoint (one coin's owner changed) is refused. The same proxy without tampering is
    accepted.
  - A server with a different key is refused. A newer checkpoint triggers a rebuild, and the meet list
    survives it.
