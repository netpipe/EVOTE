<?php
declare(strict_types=1);
/**
 * EVOTE-PHP — single-file decentralized P2P coin/vote node.
 * Port of netpipe/EVOTE newer3/main.cpp: Ed25519 signed lines, token coin,
 * token-weighted votes, nonce replay protection, pinned-key federation.
 * Transport: WebRTC data channels (browser) + ICE/STUN/TURN; this file does
 * identity, signing, validation, encrypted SQLite storage, and signaling.
 *
 *   php evote.php setup                                  create identity
 *   php evote.php id                                     show pubkey
 *   php evote.php export / import                        ledger lines out/in
 *   PHP_CLI_SERVER_WORKERS=4 php -S 127.0.0.1:8080 evote.php   run node
 *   EVOTE_SIGNAL_ONLY=1 php -S 0.0.0.0:8081 evote.php          run rendezvous
 *
 * Requires PHP >= 8.0 with stock sodium + pdo_sqlite. Nothing else.
 */

/* ================= config ================= */
const TURN_SECRET = '';   // coturn static-auth-secret; '' = STUN only (LAN needs nothing more)
const TURN_URLS   = [];   // e.g. ['turn:turn.example.org:3478?transport=udp']
const STUN_URLS   = ['stun:stun.l.google.com:19302'];
const DATA_DIR    = __DIR__ . '/evote-data';
const KEY_FILE    = DATA_DIR . '/node.key.json';
const RING_FILE   = DATA_DIR . '/keyring.json';

/* ================= storage ================= */

function db(): PDO {                      // node ledger (never opened in signal-only mode)
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    if (!is_dir(DATA_DIR)) mkdir(DATA_DIR, 0700, true);
    $pdo = new PDO('sqlite:' . DATA_DIR . '/evote.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA busy_timeout=5000');
    $pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY, owner_pub TEXT NOT NULL,
  amount INTEGER NOT NULL DEFAULT 1, spent INTEGER NOT NULL DEFAULT 0,
  updated INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS votes (
  token_hash TEXT PRIMARY KEY, candidate_enc BLOB NOT NULL,
  voter_pub TEXT NOT NULL, ts INTEGER NOT NULL, nonce TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS used_nonces (
  pubkey TEXT NOT NULL, nonce TEXT NOT NULL, ts INTEGER NOT NULL,
  PRIMARY KEY (pubkey, nonce));
CREATE TABLE IF NOT EXISTS signed_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, ts INTEGER NOT NULL,
  nonce TEXT NOT NULL, pubkey TEXT NOT NULL, token_hash TEXT, line_enc BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS idx_msg_token ON signed_messages(token_hash);
CREATE TABLE IF NOT EXISTS conflicts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT NOT NULL,
  reason TEXT NOT NULL, line_enc BLOB NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS trusted_keys (
  pubkey TEXT PRIMARY KEY, label TEXT, added INTEGER NOT NULL);
SQL);
    return $pdo;
}

function sdb(): PDO {                     // signaling mailbox (separate DB, safe on a public box)
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    if (!is_dir(DATA_DIR)) mkdir(DATA_DIR, 0700, true);
    $pdo = new PDO('sqlite:' . DATA_DIR . '/signals.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA busy_timeout=5000');
    $pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS signals (
  id INTEGER PRIMARY KEY AUTOINCREMENT, room TEXT NOT NULL, sender TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, payload TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sig_room ON signals(room, id);
SQL);
    return $pdo;
}

/* ---------- encryption at rest: XChaCha20-Poly1305 ---------- */

function store_key(): string {
    $j = json_decode((string)@file_get_contents(RING_FILE), true);
    $k = $j ? hex2bin($j['k'] ?? '') : false;
    if ($k === false || strlen($k) !== 32) throw new RuntimeException('run: php evote.php setup');
    return $k;
}
function enc(string $plain): string {
    $n = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    return $n . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, '', $n, store_key());
}
function dec(string $blob): ?string {
    if (strlen($blob) < 40) return null;
    $p = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(substr($blob, 24), '', substr($blob, 0, 24), store_key());
    return $p === false ? null : $p;
}

/* ---------- Ed25519 identity, OpenSSL/Qt-compatible key IDs ---------- */

function keyfile(): array {
    $j = json_decode((string)@file_get_contents(KEY_FILE), true);
    if (!$j) throw new RuntimeException('run: php evote.php setup');
    return $j;
}
function pub_id(): string { return keyfile()['pub']; }

function pub_id_from_raw(string $raw): string {
    $der = hex2bin('302a300506032b6570032100') . $raw;   // Ed25519 SPKI prefix
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    return base64_encode($pem);                          // same as C++ publicKeyBase64()
}
function raw_from_pub_id(string $id): ?string {
    $pem = base64_decode($id, true);
    if ($pem === false) return null;
    $der = base64_decode((string)preg_replace('/-----(BEGIN|END)[^-]*-----|\s+/', '', $pem), true);
    if ($der === false || strlen($der) !== 44) return null;
    if (substr($der, 0, 12) !== hex2bin('302a300506032b6570032100')) return null;
    return substr($der, 12);
}
function secret_key(string $pass): string {              // Argon2id-encrypted seed
    $j = keyfile();
    $key = sodium_crypto_pwhash(32, $pass, base64_decode($j['kdf_salt']),
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,       // bump to MODERATE if you like
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
    $seed = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
        base64_decode($j['seed_ct']), '', base64_decode($j['seed_nonce']), $key);
    sodium_memzero($key);
    if ($seed === false) throw new RuntimeException('bad passphrase');
    $kp = sodium_crypto_sign_seed_keypair($seed);
    sodium_memzero($seed);
    return sodium_crypto_sign_secretkey($kp);
}

/* ---------- signed lines: TYPE|1|pub|ts|nonce|fields...|sig ---------- */

function make_line(string $sk, string $type, array $fields = []): string {
    foreach ($fields as $f) if (strpos((string)$f, '|') !== false) throw new RuntimeException('field contains |');
    $payload = implode('|', array_merge([$type, '1', pub_id(), (string)time(),
        base64_encode(random_bytes(16))], $fields));
    return $payload . '|' . base64_encode(sodium_crypto_sign_detached($payload, $sk));
}
function parse_line(string $line): ?array {
    $parts = explode('|', trim($line));
    if (count($parts) < 6 || $parts[1] !== '1' || !ctype_digit($parts[3])) return null;
    $sig = base64_decode((string)array_pop($parts), true);
    if ($sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) return null;
    $raw = raw_from_pub_id($parts[2]);
    if ($raw === null) return null;
    $payload = implode('|', $parts);
    if (!sodium_crypto_sign_verify_detached($sig, $payload, $raw)) return null;
    return ['type' => $parts[0], 'pub' => $parts[2], 'ts' => (int)$parts[3],
            'nonce' => $parts[4], 'parts' => $parts, 'line' => trim($line)];
}

/* ---------- trust / replay / storage helpers ---------- */

function is_trusted(string $pub): bool {
    $q = db()->prepare('SELECT 1 FROM trusted_keys WHERE pubkey=?');
    $q->execute([$pub]);
    return (bool)$q->fetchColumn();
}
function use_nonce(string $pub, string $nonce, int $ts): bool {
    try {
        db()->prepare('INSERT INTO used_nonces(pubkey,nonce,ts) VALUES(?,?,?)')->execute([$pub, $nonce, $ts]);
        return true;
    } catch (PDOException $e) { return false; }
}
function token_info(string $h): ?array {
    $q = db()->prepare('SELECT owner_pub,spent,amount FROM tokens WHERE token_hash=?');
    $q->execute([$h]);
    return $q->fetch(PDO::FETCH_ASSOC) ?: null;
}
function store_msg(array $v, ?string $tok): void {
    db()->prepare('INSERT INTO signed_messages(type,ts,nonce,pubkey,token_hash,line_enc) VALUES(?,?,?,?,?,?)')
        ->execute([$v['type'], $v['ts'], $v['nonce'], $v['pub'], $tok, enc($v['line'])]);
}
function log_conflict(string $tok, string $line, string $why): void {
    db()->prepare('INSERT INTO conflicts(token_hash,reason,line_enc,ts) VALUES(?,?,?,?)')
        ->execute([$tok, $why, enc($line), time()]);
}

/* ---------- protocol handlers (mirror the C++ ones) ---------- */

function verify_hello(string $line): array {
    $v = parse_line($line);
    if (!$v || $v['type'] !== 'HELLO' || count($v['parts']) !== 5) return ['ok' => false, 'err' => 'bad HELLO'];
    if (!is_trusted($v['pub']))       return ['ok' => false, 'err' => 'untrusted key'];
    if (abs(time() - $v['ts']) > 120) return ['ok' => false, 'err' => 'stale'];
    if (!use_nonce($v['pub'], $v['nonce'], $v['ts'])) return ['ok' => false, 'err' => 'replay'];
    return ['ok' => true, 'pub' => $v['pub']];
}

function ingest_line(string $line): array {
    $v = parse_line($line);
    if (!$v) return ['ok' => false, 'err' => 'signature'];
    if (!is_trusted($v['pub'])) return ['ok' => false, 'err' => 'untrusted'];
    if ($v['ts'] > time() + 3600) return ['ok' => false, 'err' => 'future'];
    $p = $v['parts']; $tok = null; $db = db();
    $db->beginTransaction();
    try {
        if (!use_nonce($v['pub'], $v['nonce'], $v['ts'])) { $db->rollBack(); return ['ok' => false, 'err' => 'dup']; }
        switch ($v['type']) {
        case 'SIGNED_ISSUE':                                   // |tokenHash|owner|amount
            if (count($p) !== 8) throw new RuntimeException('fields');
            [$tok, $owner, $amt] = [$p[5], $p[6], (int)$p[7]];
            if ($tok === '' || raw_from_pub_id($owner) === null || $amt <= 0) throw new RuntimeException('fields');
            $db->prepare('INSERT OR IGNORE INTO tokens(token_hash,owner_pub,amount,spent,updated) VALUES(?,?,?,0,?)')
               ->execute([$tok, $owner, $amt, $v['ts']]);
            store_msg($v, $tok);
            break;
        case 'SIGNED_VOTE':                                    // |candidateB64|tokenHash
            if (count($p) !== 7) throw new RuntimeException('fields');
            $cand = base64_decode($p[5], true); $tok = $p[6];
            if ($cand === false || trim($cand) === '' || $tok === '') throw new RuntimeException('fields');
            $t = token_info($tok);
            if (!$t) throw new RuntimeException('unknown token');
            if ($t['owner_pub'] !== $v['pub']) throw new RuntimeException('not owner');
            if ((int)$t['spent'] !== 0) throw new RuntimeException('spent');
            $u = $db->prepare('UPDATE tokens SET spent=1, updated=? WHERE token_hash=? AND owner_pub=? AND spent=0');
            $u->execute([$v['ts'], $tok, $v['pub']]);
            if ($u->rowCount() !== 1) throw new RuntimeException('race');
            $db->prepare('INSERT OR REPLACE INTO votes(token_hash,candidate_enc,voter_pub,ts,nonce) VALUES(?,?,?,?,?)')
               ->execute([$tok, enc($cand), $v['pub'], $v['ts'], $v['nonce']]);
            store_msg($v, $tok);
            break;
        case 'SIGNED_TRANSFER':                                // |tokenHash|receiver|amount|expiry
            if (count($p) !== 9) throw new RuntimeException('fields');
            [$tok, $rcv, $amt, $exp] = [$p[5], $p[6], (int)$p[7], (int)$p[8]];
            if ($tok === '' || raw_from_pub_id($rcv) === null || $amt <= 0) throw new RuntimeException('fields');
            if (time() > $exp) throw new RuntimeException('expired');
            $t = token_info($tok);
            if (!$t) throw new RuntimeException('unknown token');
            if ($t['owner_pub'] !== $v['pub']) throw new RuntimeException('not owner');
            if ((int)$t['spent'] !== 0) throw new RuntimeException('spent');
            if ((int)$t['amount'] !== $amt) throw new RuntimeException('amount');
            $u = $db->prepare('UPDATE tokens SET owner_pub=?, updated=? WHERE token_hash=? AND owner_pub=? AND spent=0');
            $u->execute([$rcv, $v['ts'], $tok, $v['pub']]);
            if ($u->rowCount() !== 1) throw new RuntimeException('race');
            store_msg($v, $tok);
            break;
        default: throw new RuntimeException('type');
        }
        $db->commit();
        return ['ok' => true, 'line' => $v['line']];
    } catch (Throwable $e) {
        $db->rollBack();
        if ($e->getMessage() === 'spent' && $tok !== null) log_conflict($tok, $v['line'], $v['type']);
        return ['ok' => false, 'err' => $e->getMessage()];
    }
}

function sync_lines(int $since, int $limit = 200): array {
    $q = db()->prepare('SELECT id,line_enc FROM signed_messages WHERE id>? ORDER BY id ASC LIMIT ?');
    $q->bindValue(1, $since, PDO::PARAM_INT);
    $q->bindValue(2, $limit, PDO::PARAM_INT);
    $q->execute();
    $out = []; $last = $since;
    foreach ($q as $r) {
        $l = dec($r['line_enc']);
        if ($l !== null) $out[] = ['id' => (int)$r['id'], 'line' => $l];
        $last = (int)$r['id'];
    }
    return ['lines' => $out, 'last' => $last];
}

function issue_tokens(string $sk, int $count): array {
    $lines = [];
    for ($i = 0; $i < $count; $i++) {
        $secret = base64_encode(random_bytes(32));            // matches randomBase64(32)
        $tok = hash('sha256', $secret);                       // matches hashToken()
        $line = make_line($sk, 'SIGNED_ISSUE', [$tok, pub_id(), '1']);
        if (ingest_line($line)['ok']) $lines[] = $line;
    }
    return $lines;
}

function state(): array {
    $db = db(); $me = pub_id();
    $q = $db->prepare('SELECT token_hash,amount,updated FROM tokens WHERE owner_pub=? AND spent=0 ORDER BY updated DESC');
    $q->execute([$me]);
    $tally = [];
    foreach ($db->query('SELECT candidate_enc FROM votes') as $r) {
        $c = dec($r['candidate_enc']);
        if ($c !== null) $tally[$c] = ($tally[$c] ?? 0) + 1;
    }
    arsort($tally);
    return ['pub' => $me, 'tokens' => $q->fetchAll(PDO::FETCH_ASSOC), 'tally' => $tally,
        'trusted' => $db->query('SELECT pubkey,label FROM trusted_keys')->fetchAll(PDO::FETCH_ASSOC),
        'conflicts' => (int)$db->query('SELECT COUNT(*) FROM conflicts')->fetchColumn(),
        'messages'  => (int)$db->query('SELECT COUNT(*) FROM signed_messages')->fetchColumn()];
}

/* ================= CLI mode ================= */

if (PHP_SAPI === 'cli') {
    $cmd = $argv[1] ?? 'help';
    try {
        switch ($cmd) {
        case 'setup':
            if (file_exists(KEY_FILE)) exit("Identity exists. Delete evote-data/ to start over.\n");
            echo "Passphrase for the node key: ";
            $pass = rtrim((string)fgets(STDIN), "\r\n");
            if ($pass === '') exit("Empty passphrase, aborting.\n");
            if (!is_dir(DATA_DIR)) mkdir(DATA_DIR, 0700, true);
            $kp   = sodium_crypto_sign_keypair();
            $seed = substr(sodium_crypto_sign_secretkey($kp), 0, SODIUM_CRYPTO_SIGN_SEEDBYTES);
            $raw  = sodium_crypto_sign_publickey($kp);
            $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
            $k    = sodium_crypto_pwhash(32, $pass, $salt,
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $n  = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
            $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($seed, '', $n, $k);
            sodium_memzero($k); sodium_memzero($seed);
            file_put_contents(KEY_FILE, json_encode([
                'pub' => pub_id_from_raw($raw), 'kdf' => 'argon2id-interactive',
                'kdf_salt' => base64_encode($salt), 'seed_nonce' => base64_encode($n),
                'seed_ct' => base64_encode($ct)], JSON_PRETTY_PRINT));
            chmod(KEY_FILE, 0600);
            file_put_contents(RING_FILE, json_encode(['k' => bin2hex(random_bytes(32))]));
            chmod(RING_FILE, 0600);
            db()->prepare('INSERT OR IGNORE INTO trusted_keys(pubkey,label,added) VALUES(?,?,?)')
                ->execute([pub_id(), 'self', time()]);
            echo "Node identity (your trust line / wallet address):\n", pub_id(), "\n";
            break;
        case 'id':
            echo pub_id(), "\n";
            break;
        case 'export':
            $s = 0;
            for (;;) {
                $r = sync_lines($s, 500);
                foreach ($r['lines'] as $l) echo $l['line'], "\n";
                $s = $r['last'];
                if (count($r['lines']) < 500) break;
            }
            break;
        case 'import':
            $ok = 0; $bad = 0;
            while (($l = fgets(STDIN)) !== false) {
                $l = trim($l);
                if ($l === '') continue;
                ingest_line($l)['ok'] ? $ok++ : $bad++;
            }
            fwrite(STDERR, "accepted $ok, rejected $bad\n");
            break;
        default:
            echo "EVOTE-PHP single-file node\n",
                 "  php evote.php setup     create identity (passphrase prompt)\n",
                 "  php evote.php id        show public key / wallet address\n",
                 "  php evote.php export    dump signed ledger lines to stdout\n",
                 "  php evote.php import    ingest signed lines from stdin\n",
                 "Node:       PHP_CLI_SERVER_WORKERS=4 php -S 127.0.0.1:8080 evote.php\n",
                 "Rendezvous: EVOTE_SIGNAL_ONLY=1 php -S 0.0.0.0:8081 evote.php\n";
        }
    } catch (Throwable $e) { fwrite(STDERR, 'error: ' . $e->getMessage() . "\n"); exit(1); }
    exit(0);
}

/* ================= web routing ================= */

function cors(): void {                   // ONLY for the untrusted signaling endpoints
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Headers: Content-Type');
    header('Access-Control-Allow-Methods: POST, OPTIONS');
}

$action     = (string)($_GET['action'] ?? '');
$method     = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$isSig      = in_array($action, ['push', 'poll', 'ice'], true);
$signalOnly = getenv('EVOTE_SIGNAL_ONLY') === '1';
$in         = json_decode((string)file_get_contents('php://input'), true) ?: [];

if ($method === 'OPTIONS') {              // CORS preflight (action is in the query string)
    if ($isSig || $signalOnly) { cors(); http_response_code(204); }
    else http_response_code(405);
    exit;
}

/* ---- signaling mailbox + ICE creds: available in both modes, no keys involved ---- */
if ($isSig) {
    cors();
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    try {
        switch ($action) {
        case 'ice':
            $servers = [];
            foreach (STUN_URLS as $u) $servers[] = ['urls' => $u];
            if (TURN_SECRET !== '' && TURN_URLS) {           // coturn REST API ephemeral creds
                $user = (string)(time() + 3600);
                $servers[] = ['urls' => TURN_URLS, 'username' => $user,
                    'credential' => base64_encode(hash_hmac('sha1', $user, TURN_SECRET, true))];
            }
            $out = ['iceServers' => $servers];
            break;
        case 'push':
            $room = (string)($in['room'] ?? ''); $sender = (string)($in['sender'] ?? '');
            $target = (string)($in['target'] ?? ''); $kind = (string)($in['kind'] ?? '');
            if ($room === '' || strlen($room) > 64 || strlen($sender) > 64 || strlen($target) > 64)
                throw new RuntimeException('bad room/sender');
            if (!in_array($kind, ['presence', 'offer', 'answer', 'candidate'], true))
                throw new RuntimeException('bad kind');
            $payload = json_encode($in['payload'] ?? null);
            if (strlen($payload) > 65536) throw new RuntimeException('payload too big');
            sdb()->prepare('INSERT INTO signals(room,sender,target,kind,payload,ts) VALUES(?,?,?,?,?,?)')
                 ->execute([$room, $sender, $target, $kind, $payload, time()]);
            $out = ['ok' => true];
            break;
        case 'poll':
            if (random_int(1, 100) === 1) sdb()->exec('DELETE FROM signals WHERE ts<' . (time() - 3600));
            $q = sdb()->prepare("SELECT id,sender,kind,payload FROM signals
                WHERE room=? AND id>? AND sender!=? AND (target='' OR target=?) ORDER BY id ASC LIMIT 200");
            $q->execute([(string)($in['room'] ?? ''), (int)($in['since'] ?? 0),
                (string)($in['sender'] ?? ''), (string)($in['sender'] ?? '')]);
            $msgs = [];
            foreach ($q as $r) $msgs[] = ['id' => (int)$r['id'], 'sender' => $r['sender'],
                'kind' => $r['kind'], 'payload' => json_decode($r['payload'], true)];
            $out = ['msgs' => $msgs];
            break;
        }
    } catch (Throwable $e) { http_response_code(400); $out = ['ok' => false, 'err' => $e->getMessage()]; }
    echo json_encode($out);
    exit;
}

if ($signalOnly) {                        // public rendezvous: nothing else is served
    header('Content-Type: application/json');
    if ($action !== '') { http_response_code(404); echo '{"err":"signal-only mode"}'; }
    else echo json_encode(['mode' => 'signal', 'ok' => true]);
    exit;
}

/* ---- node mode: localhost-only wallet/UI (Host check kills DNS-rebinding) ---- */
$host = strtolower((string)preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'] ?? 'localhost'));
if (!in_array($host, ['localhost', '127.0.0.1', '[::1]', '::1'], true) && getenv('EVOTE_NODE_ANY_HOST') !== '1') {
    http_response_code(403);
    exit('node API is localhost-only (set EVOTE_NODE_ANY_HOST=1 to override deliberately)');
}

if ($action !== '') {                     // node API — no CORS, JSON content-type required (CSRF guard)
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    if ($method !== 'POST') { http_response_code(405); echo '{"err":"POST only"}'; exit; }
    if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') === false) {
        http_response_code(415); echo '{"err":"application/json required"}'; exit;
    }
    try {
        switch ($action) {
        case 'state':  $out = state(); break;
        case 'unlock': secret_key((string)($in['pass'] ?? '')); $out = ['ok' => true]; break;
        case 'hello':  $out = ['line' => make_line(secret_key((string)($in['pass'] ?? '')), 'HELLO')]; break;
        case 'verify_hello': $out = verify_hello((string)($in['line'] ?? '')); break;
        case 'issue':
            $out = ['lines' => issue_tokens(secret_key((string)($in['pass'] ?? '')),
                max(1, min(50, (int)($in['count'] ?? 1))))];
            break;
        case 'vote':
            $sk = secret_key((string)($in['pass'] ?? ''));
            $cand = trim((string)($in['candidate'] ?? '')); $tok = trim((string)($in['token'] ?? ''));
            if ($cand === '') throw new RuntimeException('empty candidate');
            $t = token_info($tok);
            if (!$t || $t['owner_pub'] !== pub_id() || (int)$t['spent'] !== 0) throw new RuntimeException('token not spendable by you');
            $line = make_line($sk, 'SIGNED_VOTE', [base64_encode($cand), $tok]);
            $r = ingest_line($line);
            if (!$r['ok']) throw new RuntimeException($r['err']);
            $out = ['lines' => [$line]];
            break;
        case 'transfer':
            $sk = secret_key((string)($in['pass'] ?? ''));
            $tok = trim((string)($in['token'] ?? '')); $rcv = trim((string)($in['receiver'] ?? ''));
            $amt = (int)($in['amount'] ?? 0);
            if (raw_from_pub_id($rcv) === null) throw new RuntimeException('bad receiver key');
            if ($amt <= 0) throw new RuntimeException('bad amount');
            $t = token_info($tok);
            if (!$t || $t['owner_pub'] !== pub_id() || (int)$t['spent'] !== 0) throw new RuntimeException('token not spendable by you');
            if ((int)$t['amount'] !== $amt) throw new RuntimeException('amount must equal token amount (' . $t['amount'] . ')');
            $line = make_line($sk, 'SIGNED_TRANSFER', [$tok, $rcv, (string)$amt, (string)(time() + 3600)]);
            $r = ingest_line($line);
            if (!$r['ok']) throw new RuntimeException($r['err']);
            $out = ['lines' => [$line]];
            break;
        case 'ingest':
            $accepted = []; $rejected = 0;
            foreach (array_slice((array)($in['lines'] ?? []), 0, 1000) as $l) {
                $r = ingest_line((string)$l);
                $r['ok'] ? $accepted[] = $l : $rejected++;
            }
            $out = ['accepted' => $accepted, 'rejected' => $rejected];
            break;
        case 'sync': $out = sync_lines((int)($in['since'] ?? 0)); break;
        case 'trust_add':
            $pub = trim((string)($in['pub'] ?? ''));
            if (raw_from_pub_id($pub) === null) throw new RuntimeException('not a valid public key id');
            db()->prepare('INSERT OR IGNORE INTO trusted_keys(pubkey,label,added) VALUES(?,?,?)')
                ->execute([$pub, trim((string)($in['label'] ?? '')), time()]);
            $out = ['ok' => true];
            break;
        case 'trust_del':
            $pub = trim((string)($in['pub'] ?? ''));
            if ($pub === pub_id()) throw new RuntimeException('cannot untrust self');
            db()->prepare('DELETE FROM trusted_keys WHERE pubkey=?')->execute([$pub]);
            $out = ['ok' => true];
            break;
        default: throw new RuntimeException('unknown action');
        }
    } catch (Throwable $e) { http_response_code(400); $out = ['ok' => false, 'err' => $e->getMessage()]; }
    echo json_encode($out);
    exit;
}

/* ---- GET with no action: serve the UI (everything below is plain HTML/JS) ---- */
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
?>
<!doctype html>
<html><head><meta charset="utf-8"><title>EVOTE-PHP</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 body{font:14px/1.45 system-ui,sans-serif;background:#14161a;color:#d8dde3;margin:0 auto;padding:16px;max-width:980px}
 fieldset{border:1px solid #2c313a;border-radius:8px;margin:0 0 12px}
 legend{color:#7fb4ff;padding:0 6px}
 input,button,textarea{background:#1d2127;color:#d8dde3;border:1px solid #333a45;border-radius:5px;padding:6px 8px;margin:2px}
 button{cursor:pointer} button:hover{border-color:#7fb4ff}
 input{min-width:220px} textarea{width:95%;height:60px} #pub{width:70%}
 ul{margin:6px 0;padding-left:18px} #tokens li{cursor:pointer}
 #log{background:#0d0f12;border-radius:8px;padding:10px;height:220px;overflow:auto;white-space:pre-wrap;font:12px/1.4 monospace}
 table{border-collapse:collapse} td{border:1px solid #2c313a;padding:3px 10px}
 .row{display:flex;flex-wrap:wrap;gap:4px;align-items:center} small{color:#8a93a0}
</style></head><body>
<h2>EVOTE-PHP <small>· Ed25519 signed ledger · WebRTC gossip · encrypted SQLite · one file</small></h2>

<fieldset><legend>Identity / wallet</legend>
 <div class="row"><input id="pub" readonly><button id="copyPub">copy</button></div>
 <div class="row"><input id="pass" type="password" placeholder="passphrase"><button id="unlock">unlock</button><small id="stats"></small></div>
</fieldset>

<fieldset><legend>Network</legend>
 <div class="row">signaling <input id="signalUrl" style="min-width:340px"> room <input id="room" value="evote-test"><button id="join">join</button> <small>me: <span id="myid"></span></small></div>
 <ul id="peers"><li>none</li></ul>
</fieldset>

<fieldset><legend>Trust (pinned node keys)</legend>
 <div class="row"><input id="trustPub" placeholder="public key id (base64 PEM)"><input id="trustLabel" placeholder="label"><button id="trustAdd">pin</button></div>
 <ul id="trusted"></ul>
</fieldset>

<fieldset><legend>Coin</legend>
 <div class="row">count <input id="count" value="5" style="min-width:60px"><button id="issue">issue tokens</button></div>
 <ul id="tokens"></ul>
 <div class="row"><input id="xferToken" placeholder="token hash"><input id="xferRecv" placeholder="receiver public key"><input id="xferAmt" value="1" style="min-width:60px"><button id="transfer">sign transfer</button></div>
</fieldset>

<fieldset><legend>Vote</legend>
 <div class="row"><input id="candidate" placeholder="candidate"><input id="voteToken" placeholder="token hash"><button id="vote">sign vote</button></div>
 <table id="tally"></table>
</fieldset>

<fieldset><legend>Sneakernet import (signed lines)</legend>
 <textarea id="importBox" placeholder="paste TYPE|1|pub|ts|nonce|...|sig lines"></textarea><button id="importBtn">ingest + gossip</button>
</fieldset>

<pre id="log"></pre>
<script>
'use strict';
const $ = id => document.getElementById(id);
let pass = sessionStorage.getItem('evote_pass') || '';
let iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
let room = '', since = 0, polling = false;
const myId = [...crypto.getRandomValues(new Uint8Array(4))].map(b => b.toString(16).padStart(2, '0')).join('');
const known = new Set(), pcs = {}, chans = {}, authed = {}, makingOffer = {}, ignoreOffer = {}, candBuf = {};

function log(s) { const el = $('log'); el.textContent = `[${new Date().toLocaleTimeString()}] ${s}\n` + el.textContent.slice(0, 20000); }
async function napi(action, body = {}) {           // local node API (same file, relative URL)
  const r = await fetch('?action=' + action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return r.json();
}
async function sapi(action, body = {}) {           // signaling (this node or any remote copy)
  const base = $('signalUrl').value.trim();
  const sep = base.includes('?') ? '&' : '?';
  const r = await fetch(base + sep + 'action=' + action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return r.json();
}
const sendSig = (target, kind, payload = {}) => sapi('push', { room, sender: myId, target, kind, payload });
const esc = s => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

/* ---------- WebRTC: perfect negotiation ---------- */
function ensurePC(peer) {
  if (pcs[peer]) return pcs[peer];
  const pc = new RTCPeerConnection({ iceServers });
  pcs[peer] = pc; makingOffer[peer] = false; ignoreOffer[peer] = false;
  pc.onicecandidate = ({ candidate }) => candidate && sendSig(peer, 'candidate', { candidate });
  pc.ondatachannel = e => attach(peer, e.channel);
  pc.onnegotiationneeded = async () => {
    try { makingOffer[peer] = true; await pc.setLocalDescription(); sendSig(peer, 'offer', { sdp: pc.localDescription }); }
    catch (e) { log('neg: ' + e); } finally { makingOffer[peer] = false; }
  };
  pc.onconnectionstatechange = () => {
    log(`peer ${peer}: ${pc.connectionState}`);
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') drop(peer);
  };
  return pc;
}
function drop(peer) {
  try { pcs[peer] && pcs[peer].close(); } catch (e) {}
  for (const m of [pcs, chans, authed, makingOffer, ignoreOffer, candBuf]) delete m[peer];
  known.delete(peer); renderPeers();
}
function learn(peer) {
  if (!peer || peer === myId || known.has(peer)) return;
  known.add(peer);
  sendSig(peer, 'presence');
  if (myId < peer) attach(peer, ensurePC(peer).createDataChannel('gossip', { ordered: true })); // deterministic offerer
  renderPeers();
}
async function flushCands(peer, pc) {
  const buf = candBuf[peer] || []; candBuf[peer] = [];
  for (const c of buf) { try { await pc.addIceCandidate(c); } catch (e) {} }
}
async function handleSig(m) {
  const peer = m.sender;
  if (m.kind === 'presence') { learn(peer); return; }
  learn(peer);
  const pc = ensurePC(peer), polite = myId > peer;
  if (m.kind === 'offer') {
    const collision = makingOffer[peer] || pc.signalingState !== 'stable';
    ignoreOffer[peer] = !polite && collision;
    if (ignoreOffer[peer]) return;
    await pc.setRemoteDescription(m.payload.sdp);   // implicit rollback if polite
    await flushCands(peer, pc);
    await pc.setLocalDescription();
    sendSig(peer, 'answer', { sdp: pc.localDescription });
  } else if (m.kind === 'answer') {
    if (pc.signalingState === 'have-local-offer') { await pc.setRemoteDescription(m.payload.sdp); await flushCands(peer, pc); }
  } else if (m.kind === 'candidate') {
    if (pc.remoteDescription) { try { await pc.addIceCandidate(m.payload.candidate); } catch (e) { if (!ignoreOffer[peer]) log('ice: ' + e); } }
    else (candBuf[peer] = candBuf[peer] || []).push(m.payload.candidate);
  }
}

/* ---------- gossip protocol over the data channel ---------- */
function attach(peer, ch) {
  chans[peer] = ch;
  ch.onopen = async () => {
    log('channel open: ' + peer);
    const r = await napi('hello', { pass });
    if (r.line) ch.send(JSON.stringify({ t: 'HELLO', line: r.line }));
    else log('wallet locked - unlock to authenticate channels');
  };
  ch.onclose = () => { delete authed[peer]; delete chans[peer]; renderPeers(); };
  ch.onmessage = async ev => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.t === 'HELLO') {
      const r = await napi('verify_hello', { line: m.line || '' });
      if (!r.ok) { log(`auth failed ${peer}: ${r.err}`); ch.close(); return; }
      authed[peer] = r.pub; log('peer authed: ' + peer); renderPeers();
      ch.send(JSON.stringify({ t: 'SYNC_REQUEST' }));
      ch.send(JSON.stringify({ t: 'PEERS', ids: [myId, ...known] }));
      return;
    }
    if (!authed[peer]) return;                       // nothing before authenticated HELLO
    if (m.t === 'SYNC_REQUEST') {
      let s = 0;
      for (;;) {
        const r = await napi('sync', { since: s });
        if (!r.lines || !r.lines.length) break;
        sendLines(ch, r.lines.map(x => x.line));
        s = r.last;
        if (r.lines.length < 200) break;
      }
    } else if (m.t === 'LINES' && Array.isArray(m.lines)) {
      const r = await napi('ingest', { lines: m.lines });
      if (r.accepted && r.accepted.length) {
        log(`+${r.accepted.length} ledger lines from ${peer}`);
        broadcast(r.accepted, peer); refresh();
      }
    } else if (m.t === 'PEERS' && Array.isArray(m.ids)) m.ids.forEach(learn);
  };
}
function sendLines(ch, lines) {
  if (ch.readyState !== 'open') return;
  for (let i = 0; i < lines.length; i += 40) ch.send(JSON.stringify({ t: 'LINES', lines: lines.slice(i, i + 40) }));
}
function broadcast(lines, except) { for (const p in chans) if (p !== except && authed[p]) sendLines(chans[p], lines); }

/* ---------- UI ---------- */
async function act(action, body) {
  const r = await napi(action, { pass, ...body });
  if (r.err) { log(action + ': ' + r.err); return; }
  if (r.lines && r.lines.length) { broadcast(r.lines); log(action + ': ' + r.lines.length + ' signed line(s) gossiped'); }
  refresh();
}
async function refresh() {
  const s = await napi('state');
  if (s.err) { log(s.err); return; }
  $('pub').value = s.pub;
  $('stats').textContent = `${s.messages} ledger lines · ${s.conflicts} conflicts`;
  $('tokens').innerHTML = '';
  s.tokens.forEach(t => {
    const li = document.createElement('li');
    li.textContent = `${t.token_hash.slice(0, 16)}… ×${t.amount}`; li.title = t.token_hash;
    li.onclick = () => { $('voteToken').value = t.token_hash; $('xferToken').value = t.token_hash; };
    $('tokens').appendChild(li);
  });
  $('tally').innerHTML = Object.entries(s.tally).map(([c, n]) => `<tr><td>${esc(c)}</td><td>${n}</td></tr>`).join('') || '<tr><td>—</td><td>0</td></tr>';
  $('trusted').innerHTML = '';
  s.trusted.forEach(k => {
    const li = document.createElement('li');
    li.textContent = (k.label || 'peer') + ' · ' + k.pubkey.slice(0, 12) + '… '; li.title = k.pubkey;
    if (k.pubkey !== s.pub) {
      const b = document.createElement('button'); b.textContent = '✕';
      b.onclick = async () => { await napi('trust_del', { pub: k.pubkey }); refresh(); };
      li.appendChild(b);
    }
    $('trusted').appendChild(li);
  });
}
function renderPeers() {
  $('peers').innerHTML = [...known].map(p =>
    `<li>${p} ${authed[p] ? '🔒 authed' : (chans[p] && chans[p].readyState === 'open' ? 'open' : '…')}</li>`).join('') || '<li>none</li>';
}

$('unlock').onclick = async () => {
  const r = await napi('unlock', { pass: $('pass').value });
  if (!r.ok) { log('unlock failed: ' + (r.err || '')); return; }
  pass = $('pass').value; sessionStorage.setItem('evote_pass', pass); log('wallet unlocked');
  for (const p in chans) {
    const ch = chans[p];
    if (ch.readyState === 'open' && !authed[p]) {
      const h = await napi('hello', { pass });
      if (h.line) ch.send(JSON.stringify({ t: 'HELLO', line: h.line }));
    }
  }
};
$('join').onclick = async () => {
  localStorage.setItem('evote_signal', $('signalUrl').value.trim());
  room = $('room').value.trim(); since = 0;
  if (!room) { log('enter a room name'); return; }
  const ice = await sapi('ice');
  if (ice.iceServers) iceServers = ice.iceServers;
  log(`joined "${room}" as ${myId} (${iceServers.length} ICE servers)`);
  sendSig('', 'presence');
};
setInterval(async () => {
  if (!room || polling) return; polling = true;
  try {
    const r = await sapi('poll', { room, sender: myId, since });
    for (const m of (r.msgs || [])) { since = Math.max(since, m.id); try { await handleSig(m); } catch (e) { log('sig: ' + e); } }
  } catch (e) {} finally { polling = false; }
}, 1200);
setInterval(() => { if (room) sendSig('', 'presence'); }, 25000);

$('issue').onclick = () => act('issue', { count: parseInt($('count').value) || 1 });
$('vote').onclick = () => act('vote', { candidate: $('candidate').value, token: $('voteToken').value.trim() });
$('transfer').onclick = () => act('transfer', { token: $('xferToken').value.trim(), receiver: $('xferRecv').value.trim(), amount: parseInt($('xferAmt').value) || 1 });
$('trustAdd').onclick = async () => { const r = await napi('trust_add', { pub: $('trustPub').value.trim(), label: $('trustLabel').value.trim() }); log(r.ok ? 'trust added' : 'trust: ' + r.err); refresh(); };
$('importBtn').onclick = async () => {
  const lines = $('importBox').value.split('\n').map(s => s.trim()).filter(Boolean);
  const r = await napi('ingest', { lines });
  log(`import: ${r.accepted.length} accepted, ${r.rejected} rejected`);
  if (r.accepted.length) broadcast(r.accepted);
  refresh();
};
$('copyPub').onclick = () => navigator.clipboard.writeText($('pub').value);
$('myid').textContent = myId;
$('signalUrl').value = localStorage.getItem('evote_signal') || (location.origin + location.pathname);
if (pass) $('pass').value = pass;
refresh(); renderPeers();
</script>
</body></html>