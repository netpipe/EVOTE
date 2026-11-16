#p2p cryptocoin
php evote.php setup                                        # once per node
PHP_CLI_SERVER_WORKERS=4 php -S 127.0.0.1:8080 evote.php   # open http://127.0.0.1:8080

# rendezvous for the network (same file on any reachable box — no keys there):
EVOTE_SIGNAL_ONLY=1 php -S 0.0.0.0:8081 evote.php

Two nodes: copy the file to the second machine, setup again, point both UIs' signaling field at http://BOX_A:8081/evote.php (or just :8081/ in router mode), join the same room, pin each other's pub keys. On LAN the data channels connect directly; for internet set TURN_SECRET/TURN_URLS at the top of the rendezvous copy (coturn config from before still applies). PHP_CLI_SERVER_WORKERS is Linux/macOS only — on Windows it still works single-worker since all requests are short.
What changed in the merge, beyond folding files together:
One dispatcher, three roles. Signaling actions (push/poll/ice) work in both modes; EVOTE_SIGNAL_ONLY=1 disables everything else, and the mailbox lives in its own signals.sqlite so a public rendezvous never touches ledger tables. Runtime state is just evote-data/ next to the file.
Security kept separate where it matters: CORS headers go only on signaling responses; wallet endpoints require application/json (blocks cross-site form CSRF) and a localhost Host header (blocks DNS-rebinding). EVOTE_NODE_ANY_HOST=1 overrides the latter if you deliberately expose a node.
Bonus CLI: php evote.php export > ledger.txt / php evote.php import < ledger.txt — sneakernet sync and direct interop with your Qt nodes' signed_messages, no browser needed.