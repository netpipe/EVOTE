<?php
declare(strict_types=1);
/**
 * EVOTE v2 — single-file decentralized coin + ballot console.
 *
 *   Server role : public bulletin board (validating replica) + admin issuer mint.
 *   Client role : the wallet lives in the browser (Ed25519, load/save wallet file),
 *                 the ledger is replayed + verified locally, coins are listed/exported.
 *
 *   Deploy: upload this one file, open it, complete the install screen. Done.
 *   CLI   : php evote.php id | export | reset-admin   (optional)
 *   Wire  : TYPE|1|pub|ts|nonce|fields...|sigB64  (identical to EVOTE newer3 / v1)
 *
 * Requires PHP >= 8.0 with sodium + pdo_sqlite (both stock). No composer, no CDN.
 */

const DATA_DIR    = __DIR__ . '/evote-data';   // best: point this OUTSIDE the web root, e.g. '/var/lib/evote'
const DB_FILE     = DATA_DIR . '/evote.sqlite';
const INSTALL_KEY = '';                       // optional: gate the first-run installer
const TURN_SECRET = '';                       // coturn static-auth-secret ('' = STUN only)
const TURN_URLS   = [];                       // ['turn:turn.example.org:3478?transport=udp']
const STUN_URLS   = ['stun:stun.l.google.com:19302', 'stun:global.stun.twilio.com:3478'];
const MAX_PUSH    = 250;
const FAUCET_COINS = 3;
const FAUCET_ON_INSTALL = false;              // faucet starts OFF; the admin can switch it on
const FAUCET_PER_IP_DAY = 1;                  // claims allowed per IP address per 24h
const FAUCET_DAY_CAP    = 200;                // claims allowed in total per 24h
const MAX_EXPIRY_SEC    = 30 * 86400;         // a transfer/voucher can live at most 30 days


/* ---------------------------------------------------------------- storage */

function db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    if (!is_dir(DATA_DIR)) @mkdir(DATA_DIR, 0700, true);
    lock_data_dir();
    $pdo = new PDO('sqlite:' . DB_FILE);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA busy_timeout=8000');
    $pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lines (
  id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT UNIQUE NOT NULL, type TEXT NOT NULL,
  pub TEXT NOT NULL, ts INTEGER NOT NULL, nonce TEXT NOT NULL, token_hash TEXT,
  line TEXT NOT NULL, recv INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY, owner_pub TEXT NOT NULL, amount INTEGER NOT NULL,
  spent INTEGER NOT NULL DEFAULT 0, issuer TEXT NOT NULL, ts INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS votes (
  token_hash TEXT PRIMARY KEY, candidate TEXT NOT NULL, voter_pub TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS nonces (pub TEXT NOT NULL, nonce TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(pub,nonce));
CREATE TABLE IF NOT EXISTS issuers (pub TEXT PRIMARY KEY, label TEXT, added INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS labels (pub TEXT PRIMARY KEY, label TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS conflicts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT NOT NULL, kind TEXT NOT NULL,
  a_line TEXT NOT NULL, b_line TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS orphans (id INTEGER PRIMARY KEY AUTOINCREMENT, line TEXT UNIQUE NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS claims (pub TEXT PRIMARY KEY, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS claim_ips (ip TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_claim_ips ON claim_ips(ip,ts);
CREATE TABLE IF NOT EXISTS signals (
  id INTEGER PRIMARY KEY AUTOINCREMENT, room TEXT NOT NULL, sender TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, payload TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sig ON signals(room,id);
CREATE INDEX IF NOT EXISTS idx_lines_token ON lines(token_hash);
SQL);
    return $pdo;
}
/* Deny web access to the data folder (Apache 2.2/2.4 + IIS). nginx ignores these files:
   add  location ~ /evote-data/ { deny all; }  to the server block. */
function lock_data_dir(): void {
    $files = [DATA_DIR . '/.htaccess'  => "Require all denied\nDeny from all\n",
              DATA_DIR . '/web.config' => "<?xml version=\"1.0\"?><configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
              DATA_DIR . '/index.html' => ''];
    foreach ($files as $f => $c) if (!is_file($f)) @file_put_contents($f, $c);
}
/* The issuer seed lives in a PHP file that prints nothing if it is ever requested over HTTP,
   never in the SQLite file. Older installs kept a plain copy in meta.seed_plain_demo: it is
   moved here on first use and deleted from the database. */
const KEY_FILE = DATA_DIR . '/issuer-key.php';
function issuer_seed_get(): ?string {
    if (is_file(KEY_FILE) && preg_match('/SEED=([A-Za-z0-9+\/=]+)/', (string)file_get_contents(KEY_FILE), $m)) {
        $seed = base64_decode($m[1], true);
        if ($seed !== false && strlen($seed) === 32) return $seed;
    }
    $old = meta_get('seed_plain_demo');
    if ($old !== null) {
        $seed = base64_decode($old, true);
        if ($seed !== false && strlen($seed) === 32 && issuer_seed_put($seed)) { db()->exec("DELETE FROM meta WHERE k='seed_plain_demo'"); return $seed; }
    }
    return null;
}
function issuer_seed_put(string $seed): bool {
    $ok = @file_put_contents(KEY_FILE, "<?php http_response_code(404); exit; ?>\nSEED=" . base64_encode($seed) . "\n", LOCK_EX) !== false;
    if ($ok) @chmod(KEY_FILE, 0600);
    return $ok;
}
function meta_get(string $k): ?string {
    $q = db()->prepare('SELECT v FROM meta WHERE k=?'); $q->execute([$k]);
    $v = $q->fetchColumn(); return $v === false ? null : (string)$v;
}
function meta_set(string $k, string $v): void {
    db()->prepare('INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v')->execute([$k, $v]);
}
function label_set(string $pub, string $label): void {
    if ($label === '') return;
    db()->prepare('INSERT INTO labels(pub,label) VALUES(?,?) ON CONFLICT(pub) DO UPDATE SET label=excluded.label')->execute([$pub, $label]);
}
function labels_all(): array {
    $o = []; foreach (db()->query('SELECT pub,label FROM labels') as $r) $o[$r['pub']] = $r['label']; return $o;
}
function ballot(): array {
    $b = json_decode(meta_get('ballot') ?: '{}', true) ?: [];
    return ['question' => $b['question'] ?? 'Community Treasury — Season 4 allocation',
            'options'  => $b['options'] ?? ['Developer grants', 'Infrastructure & relays', 'Education & docs', 'Reserve / rainy day'],
            'closed'   => (bool)($b['closed'] ?? false)];
}

/* ---------------------------------------------------------------- crypto helpers */

function pub_id_from_raw(string $raw): string {
    $der = hex2bin('302a300506032b6570032100') . $raw;
    return base64_encode("-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n");
}
function raw_from_pub_id(string $id): ?string {
    $pem = base64_decode($id, true); if ($pem === false) return null;
    $der = base64_decode((string)preg_replace('/-----(BEGIN|END)[^-]*-----|\s+/', '', $pem), true);
    if ($der === false || strlen($der) !== 44) return null;
    if (substr($der, 0, 12) !== hex2bin('302a300506032b6570032100')) return null;
    return substr($der, 12);
}
function make_line_with(string $sk, string $pubId, string $type, array $fields): string {
    $payload = implode('|', array_merge([$type, '1', $pubId, (string)time(), base64_encode(random_bytes(16))], $fields));
    return $payload . '|' . base64_encode(sodium_crypto_sign_detached($payload, $sk));
}
function parse_line(string $line): ?array {
    $line = trim($line);
    $parts = explode('|', $line);
    if (count($parts) < 6 || $parts[1] !== '1' || !ctype_digit($parts[3])) return null;
    $sig = base64_decode((string)array_pop($parts), true);
    if ($sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) return null;
    $raw = raw_from_pub_id($parts[2]); if ($raw === null) return null;
    $payload = implode('|', $parts);
    if (!sodium_crypto_sign_verify_detached($sig, $payload, $raw)) return null;
    return ['type' => $parts[0], 'pub' => $parts[2], 'ts' => (int)$parts[3], 'nonce' => $parts[4],
            'p' => $parts, 'line' => $line, 'hash' => hash('sha256', $line)];
}
function server_pub(): string { return (string)meta_get('server_pub'); }
function is_issuer(string $pub): bool {
    $q = db()->prepare('SELECT 1 FROM issuers WHERE pub=?'); $q->execute([$pub]); return (bool)$q->fetchColumn();
}
function server_sk(string $adminToken): string {
    $salt = base64_decode((string)meta_get('seed_salt'));
    $key = sodium_crypto_pwhash(32, $adminToken, $salt,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
    $seed = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
        base64_decode((string)meta_get('seed_ct')), '', base64_decode((string)meta_get('seed_nonce')), $key);
    sodium_memzero($key);
    if ($seed === false) throw new RuntimeException('admin token rejected');
    return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
}

/* ---------------------------------------------------------------- ledger */

function token_row(string $h): ?array {
    $q = db()->prepare('SELECT * FROM tokens WHERE token_hash=?'); $q->execute([$h]);
    return $q->fetch(PDO::FETCH_ASSOC) ?: null;
}
function note_conflict(string $tok, string $kind, string $a, string $b): void {
    db()->prepare('INSERT INTO conflicts(token_hash,kind,a_line,b_line,ts) VALUES(?,?,?,?,?)')
        ->execute([$tok, $kind, $a, $b, time()]);
}
function spend_line(string $tok): ?string {
    $q = db()->prepare("SELECT line FROM lines WHERE token_hash=? AND type IN ('SIGNED_VOTE','SIGNED_TRANSFER') ORDER BY id LIMIT 1");
    $q->execute([$tok]); $v = $q->fetchColumn(); return $v === false ? null : (string)$v;
}

function ingest_one(string $line): array {
    $db = db();
    $own = !$db->inTransaction();
    if ($own) $db->beginTransaction();
    try {
        $r = ingest_one_tx($line);
        if ($own) { if ($r['ok']) $db->commit(); else $db->rollBack(); }
        return $r;
    } catch (Throwable $e) { if ($own && $db->inTransaction()) $db->rollBack(); throw $e; }
}
function ingest_one_tx(string $line): array {
    $v = parse_line($line);
    if (!$v) return ['ok' => false, 'err' => 'bad signature'];
    $db = db();
    $q = $db->prepare('SELECT 1 FROM lines WHERE hash=?'); $q->execute([$v['hash']]);
    if ($q->fetchColumn()) return ['ok' => false, 'err' => 'duplicate', 'dup' => true];
    if ($v['ts'] > time() + 3600) return ['ok' => false, 'err' => 'timestamp in future'];
    $p = $v['p']; $tok = null;
    try {
        $db->prepare('INSERT INTO nonces(pub,nonce,ts) VALUES(?,?,?)')->execute([$v['pub'], $v['nonce'], $v['ts']]);
    } catch (PDOException $e) { return ['ok' => false, 'err' => 'nonce replay', 'dup' => true]; }

    if ($v['type'] === 'SIGNED_ISSUE') {
        if (count($p) !== 8) return ['ok' => false, 'err' => 'issue fields'];
        if (!is_issuer($v['pub'])) return ['ok' => false, 'err' => 'not an issuer'];
        if (!ctype_digit($p[7])) return ['ok' => false, 'err' => 'issue values'];
        [$tok, $owner, $amt] = [$p[5], $p[6], (int)$p[7]];
        if (!preg_match('/^[0-9a-f]{64}$/', $tok) || raw_from_pub_id($owner) === null || $amt < 1 || $amt > 1000000)
            return ['ok' => false, 'err' => 'issue values'];
        $db->prepare('INSERT OR IGNORE INTO tokens(token_hash,owner_pub,amount,spent,issuer,ts,updated) VALUES(?,?,?,0,?,?,?)')
           ->execute([$tok, $owner, $amt, $v['pub'], $v['ts'], $v['ts']]);
    } elseif ($v['type'] === 'SIGNED_VOTE') {
        if (count($p) !== 7) return ['ok' => false, 'err' => 'vote fields'];
        $cand = base64_decode($p[5], true); $tok = $p[6];
        if ($cand === false || trim($cand) === '' || strlen($cand) > 200) return ['ok' => false, 'err' => 'candidate'];
        $b = ballot();
        if ($b['closed']) return ['ok' => false, 'err' => 'ballot closed'];
        if (!in_array($cand, $b['options'], true)) return ['ok' => false, 'err' => 'not a ballot option'];
        $t = token_row($tok);
        if (!$t) return ['ok' => false, 'err' => 'orphan', 'orphan' => true];
        if ($t['owner_pub'] !== $v['pub']) return ['ok' => false, 'err' => 'not owner'];
        if ((int)$t['spent'] !== 0) { note_conflict($tok, 'double-spend vote', (string)spend_line($tok), $v['line']); return ['ok' => false, 'err' => 'already spent']; }
        $u = $db->prepare('UPDATE tokens SET spent=1, updated=? WHERE token_hash=? AND owner_pub=? AND spent=0');
        $u->execute([$v['ts'], $tok, $v['pub']]);
        if ($u->rowCount() !== 1) return ['ok' => false, 'err' => 'race'];
        $db->prepare('INSERT OR REPLACE INTO votes(token_hash,candidate,voter_pub,ts) VALUES(?,?,?,?)')
           ->execute([$tok, $cand, $v['pub'], $v['ts']]);
    } elseif ($v['type'] === 'SIGNED_TRANSFER') {
        if (count($p) !== 9) return ['ok' => false, 'err' => 'transfer fields'];
        if (!ctype_digit($p[7]) || !ctype_digit($p[8])) return ['ok' => false, 'err' => 'transfer values'];
        [$tok, $rcv, $amt, $exp] = [$p[5], $p[6], (int)$p[7], (int)$p[8]];
        if (raw_from_pub_id($rcv) === null || $amt < 1) return ['ok' => false, 'err' => 'transfer values'];
        if ($exp < $v['ts'] || $exp - $v['ts'] > MAX_EXPIRY_SEC) return ['ok' => false, 'err' => 'bad expiry'];
        if (time() > $exp) return ['ok' => false, 'err' => 'expired'];
        $t = token_row($tok);
        if (!$t) return ['ok' => false, 'err' => 'orphan', 'orphan' => true];
        if ($t['owner_pub'] !== $v['pub']) return ['ok' => false, 'err' => 'not owner'];
        if ((int)$t['spent'] !== 0) { note_conflict($tok, 'double-spend transfer', (string)spend_line($tok), $v['line']); return ['ok' => false, 'err' => 'already spent']; }
        if ((int)$t['amount'] !== $amt) return ['ok' => false, 'err' => 'amount mismatch'];
        $u = $db->prepare('UPDATE tokens SET owner_pub=?, updated=? WHERE token_hash=? AND owner_pub=? AND spent=0');
        $u->execute([$rcv, $v['ts'], $tok, $v['pub']]);
        if ($u->rowCount() !== 1) return ['ok' => false, 'err' => 'race'];
    } else {
        return ['ok' => false, 'err' => 'unknown type'];
    }
    $db->prepare('INSERT INTO lines(hash,type,pub,ts,nonce,token_hash,line,recv) VALUES(?,?,?,?,?,?,?,?)')
       ->execute([$v['hash'], $v['type'], $v['pub'], $v['ts'], $v['nonce'], $tok, $v['line'], time()]);
    return ['ok' => true, 'hash' => $v['hash']];
}

function push_lines(array $lines): array {
    $accepted = []; $rejected = []; $db = db();
    foreach (array_slice($lines, 0, MAX_PUSH) as $l) {
        if (!is_string($l) || strlen($l) > 4096) { $rejected[] = ['err' => 'oversize']; continue; }
        $r = ingest_one($l);
        if ($r['ok']) { $accepted[] = $r['hash']; continue; }
        if (!empty($r['orphan'])) {
            try { $db->prepare('INSERT OR IGNORE INTO orphans(line,ts) VALUES(?,?)')->execute([$l, time()]); } catch (Throwable $e) {}
            continue;
        }
        if (empty($r['dup'])) $rejected[] = ['err' => $r['err'], 'line' => substr($l, 0, 80), 'hash' => hash('sha256', trim($l))];
    }
    for ($pass = 0; $pass < 4; $pass++) {
        $rows = $db->query('SELECT id,line FROM orphans ORDER BY id LIMIT 400')->fetchAll(PDO::FETCH_ASSOC);
        if (!$rows) break;
        $progress = false;
        foreach ($rows as $row) {
            $r = ingest_one($row['line']);
            if ($r['ok']) { $accepted[] = $r['hash']; $db->prepare('DELETE FROM orphans WHERE id=?')->execute([$row['id']]); $progress = true; }
            elseif (empty($r['orphan']) && empty($r['dup'])) { $db->prepare('DELETE FROM orphans WHERE id=?')->execute([$row['id']]); }
        }
        if (!$progress) break;
    }
    $db->exec('DELETE FROM orphans WHERE ts < ' . (time() - 86400));
    return ['accepted' => $accepted, 'rejected' => $rejected];
}
/* Redeem a voucher / raw tx lines: push them, then report each spend and the weight
   that actually landed per recipient. Only spends accepted by THIS call count as
   "deposited", so redeeming the same voucher twice never credits twice. */
function redeem_lines(array $lines, int $spends = 0): array {
    $lines = array_values(array_filter(array_map(fn($l) => trim((string)$l), $lines), fn($l) => $l !== ''));
    $tail = $spends > 0 ? array_slice($lines, -$spends) : $lines;
    $before = [];
    $q = db()->prepare('SELECT 1 FROM lines WHERE hash=?');
    foreach ($tail as $l) { $q->execute([hash('sha256', $l)]); $before[hash('sha256', $l)] = (bool)$q->fetchColumn(); }
    $r = push_lines($lines);
    $acc = array_flip($r['accepted']);
    $rej = [];
    foreach ($r['rejected'] as $x) if (isset($x['hash'])) $rej[$x['hash']] = $x['err'];
    $items = []; $deposited = [];
    foreach ($tail as $l) {
        $v = parse_line($l);
        if (!$v) { $items[] = ['status' => 'rejected', 'err' => 'bad signature', 'line' => substr($l, 0, 80)]; continue; }
        if ($v['type'] !== 'SIGNED_TRANSFER' && $v['type'] !== 'SIGNED_VOTE') continue;
        $tok = $v['type'] === 'SIGNED_TRANSFER' ? $v['p'][5] : $v['p'][6];
        $it = ['hash' => $v['hash'], 'type' => $v['type'] === 'SIGNED_TRANSFER' ? 'transfer' : 'vote', 'coin' => $tok, 'from' => $v['pub']];
        if ($v['type'] === 'SIGNED_TRANSFER') { $it['to'] = $v['p'][6]; $it['amount'] = (int)$v['p'][7]; $it['expires'] = (int)$v['p'][8]; }
        if (isset($acc[$v['hash']])) {
            $t = token_row($tok);
            $it['status'] = 'deposited';
            if ($it['type'] === 'transfer') {
                if ($t && $t['owner_pub'] === $it['to'] && (int)$t['spent'] === 0) $deposited[$it['to']] = ($deposited[$it['to']] ?? 0) + (int)$t['amount'];
                else $it['status'] = 'moved';   // accepted, but the coin was passed on again in the same batch
            } else $it['status'] = 'voted';
        } elseif (!empty($before[$v['hash']])) $it['status'] = 'already_redeemed';
        elseif (isset($rej[$v['hash']])) { $it['status'] = 'rejected'; $it['err'] = $rej[$v['hash']]; }
        else {
            $q->execute([$v['hash']]);
            if ($q->fetchColumn()) $it['status'] = 'already_redeemed';
            else { $it['status'] = 'pending'; $it['err'] = 'coin history missing on this server - include the provenance lines'; }
        }
        $items[] = $it;
    }
    return ['deposited' => $deposited, 'weight' => array_sum($deposited), 'items' => $items,
            'accepted' => count($r['accepted']), 'rejected' => $r['rejected']];
}
function balance_of(string $pub): array {
    $q = db()->prepare('SELECT token_hash,amount,issuer,updated FROM tokens WHERE owner_pub=? AND spent=0 ORDER BY updated DESC');
    $q->execute([$pub]); $coins = [];
    foreach ($q as $r) $coins[] = ['hash' => $r['token_hash'], 'amount' => (int)$r['amount'], 'issuer' => $r['issuer'], 'updated' => (int)$r['updated']];
    return ['address' => $pub, 'coins' => $coins, 'count' => count($coins), 'weight' => array_sum(array_column($coins, 'amount'))];
}
function pull_lines(int $since, int $limit = 400): array {
    $q = db()->prepare('SELECT id,line FROM lines WHERE id>? ORDER BY id ASC LIMIT ?');
    $q->bindValue(1, $since, PDO::PARAM_INT); $q->bindValue(2, $limit, PDO::PARAM_INT); $q->execute();
    $out = []; $last = $since;
    foreach ($q as $r) { $out[] = ['id' => (int)$r['id'], 'line' => $r['line']]; $last = (int)$r['id']; }
    return ['lines' => $out, 'last' => $last, 'total' => (int)db()->query('SELECT COUNT(*) FROM lines')->fetchColumn()];
}
function counts(): array {
    $d = db();
    return ['lines' => (int)$d->query('SELECT COUNT(*) FROM lines')->fetchColumn(),
            'tokens' => (int)$d->query('SELECT COUNT(*) FROM tokens')->fetchColumn(),
            'votes' => (int)$d->query('SELECT COUNT(*) FROM votes')->fetchColumn(),
            'spent' => (int)$d->query('SELECT COUNT(*) FROM tokens WHERE spent=1')->fetchColumn(),
            'conflicts' => (int)$d->query('SELECT COUNT(*) FROM conflicts')->fetchColumn()];
}
function mint(string $sk, string $to, int $count, int $amount): array {
    $lines = [];
    for ($i = 0; $i < $count; $i++) {
        $tok = hash('sha256', base64_encode(random_bytes(32)));
        $lines[] = make_line_with($sk, server_pub(), 'SIGNED_ISSUE', [$tok, $to, (string)$amount]);
    }
    return $lines;
}
function seed_demo(int $voters = 6, int $coinsEach = 5): int {
    $names = ['ada.lovelace', 'grace.hopper', 'alan.turing', 'margaret.hamilton', 'katherine.j', 'satoshi.n', 'radia.perlman', 'barbara.liskov'];
    $opts = ballot()['options'];
    $sk = server_sk_raw();
    $people = []; $issueLines = [];
    for ($i = 0; $i < $voters; $i++) {
        $kp = sodium_crypto_sign_keypair();
        $pub = pub_id_from_raw(sodium_crypto_sign_publickey($kp));
        label_set($pub, $names[$i % count($names)]);
        $people[] = ['sk' => sodium_crypto_sign_secretkey($kp), 'pub' => $pub, 'tokens' => []];
        for ($c = 0; $c < $coinsEach; $c++) {
            $tok = hash('sha256', base64_encode(random_bytes(32)));
            $people[$i]['tokens'][] = $tok;
            $issueLines[] = make_line_with($sk, server_pub(), 'SIGNED_ISSUE', [$tok, $pub, '1']);
        }
    }
    push_lines($issueLines);
    $acts = [];
    foreach ($people as $i => $p) {
        $n = count($p['tokens']);
        for ($c = 0; $c < $n; $c++) {
            $roll = mt_rand(0, 99);
            if ($roll < 62) {
                $opt = $opts[mt_rand(0, count($opts) - 1)];
                $acts[] = make_line_with($p['sk'], $p['pub'], 'SIGNED_VOTE', [base64_encode($opt), $p['tokens'][$c]]);
            } elseif ($roll < 74) {
                $to = $people[($i + 1) % count($people)]['pub'];
                $acts[] = make_line_with($p['sk'], $p['pub'], 'SIGNED_TRANSFER', [$p['tokens'][$c], $to, '1', (string)(time() + 86400)]);
            }
        }
    }
    push_lines($acts);
    return count($issueLines) + count($acts);
}
function server_sk_raw(): string {
    $seed = issuer_seed_get();
    if ($seed !== null) return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
    throw new RuntimeException('issuer key unavailable');
}

/* ---------------------------------------------------------------- http plumbing */

function out(array $a, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json'); header('Cache-Control: no-store');
    echo json_encode($a); exit;
}
function body(): array { $j = json_decode((string)file_get_contents('php://input'), true); return is_array($j) ? $j : []; }
function same_origin(): bool {
    $host = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
    foreach (['HTTP_ORIGIN', 'HTTP_REFERER'] as $h) {
        if (!empty($_SERVER[$h])) {
            $p = parse_url((string)$_SERVER[$h]);
            if (($p['host'] ?? '') !== '' && strtolower($p['host'] . (isset($p['port']) ? ':' . $p['port'] : '')) !== $host) return false;
        }
    }
    return true;
}
function admin_token(): string { return (string)($_SERVER['HTTP_X_ADMIN_TOKEN'] ?? ''); }
function admin_ok(): bool {
    $h = meta_get('admin_hash'); $t = admin_token(); if (!$h || $t === '') return false;
    if (preg_match('/^[0-9a-f]{64}$/', $h)) {             // pre-fix install: plain sha256, upgrade on success
        if (!hash_equals($h, hash('sha256', $t))) return false;
        meta_set('admin_hash', sodium_crypto_pwhash_str($t, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE));
        return true;
    }
    return sodium_crypto_pwhash_str_verify($h, $t);
}

/* ---------------------------------------------------------------- CLI */

if (PHP_SAPI === 'cli') {
    $cmd = $argv[1] ?? 'help';
    try {
        if ($cmd === 'id') { echo server_pub() ?: "(not installed)\n"; }
        elseif ($cmd === 'export') { $s = 0; for (;;) { $r = pull_lines($s, 500); foreach ($r['lines'] as $l) echo $l['line'], "\n"; $s = $r['last']; if (count($r['lines']) < 500) break; } }
        elseif ($cmd === 'reset-admin') { db()->exec("DELETE FROM meta WHERE k IN ('admin_hash','seed_salt','seed_nonce','seed_ct','seed_plain_demo')"); @unlink(KEY_FILE); echo "admin cleared — reopen the page to install again\n"; }
        else echo "EVOTE v2\n  php evote.php id\n  php evote.php export > ledger.txt\n  php evote.php reset-admin\n";
    } catch (Throwable $e) { fwrite(STDERR, 'error: ' . $e->getMessage() . "\n"); exit(1); }
    exit(0);
}

/* ---------------------------------------------------------------- router */

$action = (string)($_GET['action'] ?? '');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'OPTIONS') { http_response_code(204); exit; }

if ($action === '') {                       // serve the app
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
} else {
    if ($method !== 'POST') out(['ok' => false, 'err' => 'POST required'], 405);
    if (!same_origin()) out(['ok' => false, 'err' => 'cross-origin blocked'], 403);
    if (stripos((string)($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json') === false) out(['ok' => false, 'err' => 'application/json required'], 415);
    $in = body();
    try {
        switch ($action) {

        case 'boot': {
            $installed = meta_get('admin_hash') !== null;
            $iss = []; foreach (db()->query('SELECT pub,label FROM issuers') as $r) $iss[] = ['pub' => $r['pub'], 'label' => $r['label']];
            out(['ok' => true, 'mode' => 'server', 'installed' => $installed, 'serverPub' => server_pub(),
                 'issuers' => $iss, 'labels' => labels_all(), 'ballot' => ballot(),
                 'faucet' => meta_get('faucet') !== '0', 'counts' => $installed ? counts() : ['lines' => 0, 'tokens' => 0, 'votes' => 0, 'spent' => 0, 'conflicts' => 0],
                 'installGuard' => INSTALL_KEY !== '', 'ts' => time()]);
        }

        case 'install': {
            if (meta_get('admin_hash') !== null) out(['ok' => false, 'err' => 'already installed'], 409);
            $tok = (string)($in['token'] ?? '');
            if (strlen($tok) < 8) out(['ok' => false, 'err' => 'admin token must be at least 8 characters'], 400);
            if (INSTALL_KEY !== '' && !hash_equals(INSTALL_KEY, (string)($in['installKey'] ?? ''))) out(['ok' => false, 'err' => 'install key rejected'], 403);
            $kp = sodium_crypto_sign_keypair();
            $seed = substr(sodium_crypto_sign_secretkey($kp), 0, SODIUM_CRYPTO_SIGN_SEEDBYTES);
            $pub = pub_id_from_raw(sodium_crypto_sign_publickey($kp));
            $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
            $k = sodium_crypto_pwhash(32, $tok, $salt, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $n = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
            meta_set('seed_ct', base64_encode(sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($seed, '', $n, $k)));
            meta_set('seed_salt', base64_encode($salt)); meta_set('seed_nonce', base64_encode($n));
            if (!issuer_seed_put($seed)) out(['ok' => false, 'err' => 'cannot write ' . KEY_FILE . ' - check folder permissions'], 500);
            meta_set('admin_hash', sodium_crypto_pwhash_str($tok, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE));
            meta_set('server_pub', $pub);
            meta_set('faucet', FAUCET_ON_INSTALL ? '1' : '0');
            $q = trim((string)($in['question'] ?? '')); $opts = (array)($in['options'] ?? []);
            $opts = array_values(array_filter(array_map(fn($o) => trim((string)$o), $opts), fn($o) => $o !== ''));
            meta_set('ballot', json_encode(['question' => $q !== '' ? $q : ballot()['question'],
                                            'options' => $opts ?: ballot()['options'], 'closed' => false]));
            db()->prepare('INSERT OR IGNORE INTO issuers(pub,label,added) VALUES(?,?,?)')->execute([$pub, 'treasury issuer', time()]);
            label_set($pub, 'treasury issuer');
            $seeded = !empty($in['seed']) ? seed_demo(6, 5) : 0;
            out(['ok' => true, 'serverPub' => $pub, 'seeded' => $seeded]);
        }

        case 'pull': out(['ok' => true] + pull_lines((int)($in['since'] ?? 0)));

        case 'push': {
            $lines = (array)($in['lines'] ?? []);
            if (count($lines) > MAX_PUSH) out(['ok' => false, 'err' => 'too many lines'], 413);
            $r = push_lines($lines);
            out(['ok' => true] + $r + ['last' => (int)db()->query('SELECT COALESCE(MAX(id),0) FROM lines')->fetchColumn()]);
        }

        case 'redeem': {            // API: voucher file / raw tx lines -> deposited weight per address
            $v = $in['voucher'] ?? null;
            if (is_string($v)) $v = json_decode($v, true);
            $spends = 0;
            if (is_array($v)) {
                if (($v['format'] ?? '') !== 'evote-voucher') out(['ok' => false, 'err' => 'not an evote-voucher'], 400);
                $lines = (array)($v['lines'] ?? []); $spends = max(0, (int)($v['spends'] ?? 0));
            } elseif (isset($in['lines'])) $lines = (array)$in['lines'];
            elseif (isset($in['raw'])) $lines = preg_split('/\r?\n/', (string)$in['raw']);
            else out(['ok' => false, 'err' => 'send voucher, lines or raw'], 400);
            if (count($lines) > MAX_PUSH) out(['ok' => false, 'err' => 'too many lines'], 413);
            $r = redeem_lines($lines, $spends);
            $to = trim((string)($in['to'] ?? ''));
            if ($to !== '') $r['to'] = ['address' => $to, 'weight' => (int)($r['deposited'][$to] ?? 0)];
            out(['ok' => true] + $r);
        }

        case 'balance': {           // API: unspent coins + weight held by an address
            $pub = trim((string)($in['pub'] ?? ''));
            if (raw_from_pub_id($pub) === null) out(['ok' => false, 'err' => 'invalid address'], 400);
            out(['ok' => true] + balance_of($pub));
        }

        case 'claim': {
            if (meta_get('faucet') === '0') out(['ok' => false, 'err' => 'faucet disabled by admin'], 403);
            $pub = trim((string)($in['pub'] ?? ''));
            if (raw_from_pub_id($pub) === null) out(['ok' => false, 'err' => 'invalid address'], 400);
            $q = db()->prepare('SELECT 1 FROM claims WHERE pub=?'); $q->execute([$pub]);
            if ($q->fetchColumn()) out(['ok' => false, 'err' => 'this address already claimed its allowance'], 409);
            $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
            $day = time() - 86400;
            $q = db()->prepare('SELECT COUNT(*) FROM claim_ips WHERE ip=? AND ts>?'); $q->execute([$ip, $day]);
            if ((int)$q->fetchColumn() >= FAUCET_PER_IP_DAY) out(['ok' => false, 'err' => 'faucet limit reached for your connection - try again tomorrow'], 429);
            $q = db()->prepare('SELECT COUNT(*) FROM claim_ips WHERE ts>?'); $q->execute([$day]);
            if ((int)$q->fetchColumn() >= FAUCET_DAY_CAP) out(['ok' => false, 'err' => 'faucet is empty for today'], 429);
            db()->prepare('DELETE FROM claim_ips WHERE ts<?')->execute([$day]);
            db()->prepare('INSERT INTO claims(pub,ts) VALUES(?,?)')->execute([$pub, time()]);
            db()->prepare('INSERT INTO claim_ips(ip,ts) VALUES(?,?)')->execute([$ip, time()]);
            $lines = mint(server_sk_raw(), $pub, FAUCET_COINS, 1);
            $r = push_lines($lines);
            out(['ok' => true, 'lines' => $lines, 'accepted' => $r['accepted']]);
        }

        case 'selftest': {
            $msg = (string)($in['msg'] ?? ''); $pub = (string)($in['pub'] ?? ''); $sig = (string)($in['sig'] ?? '');
            $valid = false;
            $raw = raw_from_pub_id($pub); $sb = base64_decode($sig, true);
            if ($raw !== null && $sb !== false && strlen($sb) === SODIUM_CRYPTO_SIGN_BYTES && strlen($msg) < 4096)
                $valid = sodium_crypto_sign_verify_detached($sb, $msg, $raw);
            $smsg = 'EVOTE-SELFTEST|' . hash('sha256', $msg) . ':server';   // domain-separated: can never parse as a ledger line
            out(['ok' => true, 'valid' => $valid, 'serverPub' => server_pub(),
                 'serverMsg' => $smsg, 'serverSig' => base64_encode(sodium_crypto_sign_detached($smsg, server_sk_raw()))]);
        }

        case 'admin': {
            if (!admin_ok()) out(['ok' => false, 'err' => 'admin token rejected'], 403);
            $op = (string)($in['op'] ?? '');
            if ($op === 'state') {
                $toks = db()->query('SELECT token_hash,owner_pub,amount,spent,issuer,ts FROM tokens ORDER BY ts DESC LIMIT 500')->fetchAll(PDO::FETCH_ASSOC);
                $conf = db()->query('SELECT * FROM conflicts ORDER BY id DESC LIMIT 100')->fetchAll(PDO::FETCH_ASSOC);
                $iss = []; foreach (db()->query('SELECT pub,label FROM issuers') as $r) $iss[] = ['pub' => $r['pub'], 'label' => $r['label']];
                $claims = (int)db()->query('SELECT COUNT(*) FROM claims')->fetchColumn();
                out(['ok' => true, 'counts' => counts(), 'tokens' => $toks, 'conflicts' => $conf, 'issuers' => $iss,
                     'ballot' => ballot(), 'faucet' => meta_get('faucet') !== '0', 'labels' => labels_all(), 'claims' => $claims]);
            }
            if ($op === 'issue') {
                $to = trim((string)($in['to'] ?? ''));
                if (raw_from_pub_id($to) === null) out(['ok' => false, 'err' => 'invalid recipient address'], 400);
                $count = max(1, min(50, (int)($in['count'] ?? 1)));
                $amount = max(1, min(1000, (int)($in['amount'] ?? 1)));
                $lines = mint(server_sk(admin_token()), $to, $count, $amount);
                $r = push_lines($lines);
                if (!empty($in['label'])) label_set($to, trim((string)$in['label']));
                out(['ok' => true, 'lines' => $lines, 'accepted' => $r['accepted']]);
            }
            if ($op === 'ballot') {
                $opts = array_values(array_filter(array_map(fn($o) => trim((string)$o), (array)($in['options'] ?? [])), fn($o) => $o !== ''));
                if (!$opts) out(['ok' => false, 'err' => 'at least one option required'], 400);
                meta_set('ballot', json_encode(['question' => trim((string)($in['question'] ?? '')) ?: ballot()['question'],
                                                'options' => array_slice($opts, 0, 12), 'closed' => !empty($in['closed'])]));
                out(['ok' => true, 'ballot' => ballot()]);
            }
            if ($op === 'issuer_add') {
                $pub = trim((string)($in['pub'] ?? ''));
                if (raw_from_pub_id($pub) === null) out(['ok' => false, 'err' => 'invalid key'], 400);
                db()->prepare('INSERT OR IGNORE INTO issuers(pub,label,added) VALUES(?,?,?)')->execute([$pub, trim((string)($in['label'] ?? '')), time()]);
                if (!empty($in['label'])) label_set($pub, trim((string)$in['label']));
                out(['ok' => true]);
            }
            if ($op === 'issuer_del') {
                $pub = trim((string)($in['pub'] ?? ''));
                if ($pub === server_pub()) out(['ok' => false, 'err' => 'cannot remove the treasury issuer'], 400);
                db()->prepare('DELETE FROM issuers WHERE pub=?')->execute([$pub]); out(['ok' => true]);
            }
            if ($op === 'label') { label_set(trim((string)($in['pub'] ?? '')), trim((string)($in['label'] ?? ''))); out(['ok' => true, 'labels' => labels_all()]); }
            if ($op === 'faucet') { meta_set('faucet', !empty($in['enabled']) ? '1' : '0'); out(['ok' => true, 'faucet' => !empty($in['enabled'])]); }
            if ($op === 'seed') { $n = seed_demo(max(2, min(8, (int)($in['voters'] ?? 4))), max(1, min(8, (int)($in['coins'] ?? 4)))); out(['ok' => true, 'seeded' => $n]); }
            if ($op === 'export') { $all = []; $s = 0; for (;;) { $r = pull_lines($s, 500); foreach ($r['lines'] as $l) $all[] = $l['line']; $s = $r['last']; if (count($r['lines']) < 500) break; } out(['ok' => true, 'lines' => $all]); }
            out(['ok' => false, 'err' => 'unknown admin op'], 400);
        }

        case 'sig': {
            $op = (string)($in['op'] ?? '');
            if ($op === 'ice') {
                $servers = []; foreach (STUN_URLS as $u) $servers[] = ['urls' => $u];
                if (TURN_SECRET !== '' && TURN_URLS) {
                    $user = (string)(time() + 3600);
                    $servers[] = ['urls' => TURN_URLS, 'username' => $user, 'credential' => base64_encode(hash_hmac('sha1', $user, TURN_SECRET, true))];
                }
                out(['ok' => true, 'iceServers' => $servers]);
            }
            if ($op === 'push') {
                $room = (string)($in['room'] ?? ''); $sender = (string)($in['sender'] ?? '');
                $target = (string)($in['target'] ?? ''); $kind = (string)($in['kind'] ?? '');
                if ($room === '' || strlen($room) > 64 || strlen($sender) > 64 || strlen($target) > 64) out(['ok' => false, 'err' => 'bad room/sender'], 400);
                if (!in_array($kind, ['presence', 'offer', 'answer', 'candidate'], true)) out(['ok' => false, 'err' => 'bad kind'], 400);
                $payload = json_encode($in['payload'] ?? null);
                if (strlen($payload) > 65536) out(['ok' => false, 'err' => 'payload too big'], 413);
                $c = db()->prepare('SELECT COUNT(*) FROM signals WHERE room=?'); $c->execute([$room]);
                if ((int)$c->fetchColumn() > 4000) db()->prepare('DELETE FROM signals WHERE room=? AND ts<?')->execute([$room, time() - 300]);
                db()->prepare('INSERT INTO signals(room,sender,target,kind,payload,ts) VALUES(?,?,?,?,?,?)')
                    ->execute([$room, $sender, $target, $kind, $payload, time()]);
                out(['ok' => true]);
            }
            if ($op === 'poll') {
                if (random_int(1, 60) === 1) db()->exec('DELETE FROM signals WHERE ts<' . (time() - 1800));
                $q = db()->prepare("SELECT id,sender,kind,payload FROM signals WHERE room=? AND id>? AND sender!=? AND (target='' OR target=?) ORDER BY id ASC LIMIT 200");
                $q->execute([(string)($in['room'] ?? ''), (int)($in['since'] ?? 0), (string)($in['sender'] ?? ''), (string)($in['sender'] ?? '')]);
                $msgs = []; foreach ($q as $r) $msgs[] = ['id' => (int)$r['id'], 'sender' => $r['sender'], 'kind' => $r['kind'], 'payload' => json_decode($r['payload'], true)];
                out(['ok' => true, 'msgs' => $msgs]);
            }
            out(['ok' => false, 'err' => 'unknown sig op'], 400);
        }

        default: out(['ok' => false, 'err' => 'unknown action'], 404);
        }
    } catch (Throwable $e) { out(['ok' => false, 'err' => $e->getMessage()], 400); }
    exit;
}
?>
<!doctype html>
<html lang="en" data-theme="midnight" data-density="comfortable">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>EVOTE · ledger console</title>
<meta name="color-scheme" content="dark">
<style>
/* ============================== design system ============================== */
:root{
  --bg:#060912; --bg2:#0a1020; --surface:#0f1729; --surface2:#141f37; --overlay:#1a2745; --scrim:rgba(4,7,15,.72);
  --line:#22304f; --line2:#31456e; --text:#e9edfb; --muted:#94a2c6; --faint:#65739b;
  --indigo:#4c6fff; --cyan:#22d3ee; --green:#9ae63c; --amber:#ffb020; --magenta:#e455f0; --red:#ff4d63; --violet:#8b5cf6; --teal:#2dd4bf;
  --ok:var(--green); --warn:var(--amber); --danger:var(--red); --info:var(--cyan);
  --grad-a:linear-gradient(115deg,var(--indigo),var(--cyan) 55%,var(--teal));
  --grad-b:linear-gradient(115deg,var(--magenta),var(--amber));
  --grad-c:linear-gradient(115deg,var(--violet),var(--indigo));
  --r:14px; --r-sm:9px; --pad:18px; --row:46px; --fs:14px;
  --shadow:0 18px 50px -22px rgba(0,0,0,.9),0 2px 0 rgba(255,255,255,.03) inset;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --nav:236px; --top:62px;
}
html[data-theme="ember"]{
  --bg:#0d0805; --bg2:#150d07; --surface:#1c1209; --surface2:#25180d; --overlay:#301f11; --scrim:rgba(10,5,2,.74);
  --line:#3d2716; --line2:#57381f; --text:#fdeee0; --muted:#c8a688; --faint:#96745a;
  --indigo:#ff7a18; --cyan:#ffc247; --green:#c3e63c; --amber:#ff9f1c; --magenta:#ff4d6d; --red:#ff3b30; --violet:#e0559b; --teal:#f2c14e;
  --grad-a:linear-gradient(115deg,#ff7a18,#ffc247 55%,#ffe08a);
  --grad-b:linear-gradient(115deg,#ff4d6d,#ff9f1c);
  --grad-c:linear-gradient(115deg,#e0559b,#ff7a18);
}
html[data-theme="chlorophyll"]{
  --bg:#04100c; --bg2:#071a14; --surface:#0b241c; --surface2:#103026; --overlay:#164034; --scrim:rgba(2,12,9,.74);
  --line:#1c4a3a; --line2:#2a6a53; --text:#e6fbf1; --muted:#8fc4ae; --faint:#5f9481;
  --indigo:#2dd4bf; --cyan:#67e8f9; --green:#a3e635; --amber:#facc15; --magenta:#f472b6; --red:#fb7185; --violet:#34d399; --teal:#4ade80;
  --grad-a:linear-gradient(115deg,#2dd4bf,#a3e635 55%,#facc15);
  --grad-b:linear-gradient(115deg,#f472b6,#facc15);
  --grad-c:linear-gradient(115deg,#34d399,#2dd4bf);
}
html[data-density="compact"]{ --pad:12px; --row:36px; --fs:13px; --r:11px; }
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg); color:var(--text); font:var(--fs)/1.5 var(--sans);
  -webkit-font-smoothing:antialiased; overflow-x:hidden; min-height:100vh;
}
/* layered ambient background */
.bg{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.bg .blob{position:absolute;border-radius:50%;filter:blur(90px);opacity:.30;mix-blend-mode:screen}
.bg .b1{width:52vw;height:52vw;left:-12vw;top:-14vw;background:var(--indigo);animation:drift1 34s ease-in-out infinite}
.bg .b2{width:44vw;height:44vw;right:-10vw;top:8vh;background:var(--magenta);opacity:.20;animation:drift2 41s ease-in-out infinite}
.bg .b3{width:48vw;height:48vw;left:22vw;bottom:-22vw;background:var(--cyan);opacity:.18;animation:drift3 47s ease-in-out infinite}
.bg .grid{position:absolute;inset:0;opacity:.30;
  background-image:linear-gradient(var(--line) 1px,transparent 1px),linear-gradient(90deg,var(--line) 1px,transparent 1px);
  background-size:64px 64px;mask-image:radial-gradient(ellipse at 50% 0%,#000 10%,transparent 72%)}
.bg .grain{position:absolute;inset:0;opacity:.055;
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='140' height='140'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='3'/></filter><rect width='140' height='140' filter='url(%23n)'/></svg>")}
@keyframes drift1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(8vw,6vh) scale(1.12)}}
@keyframes drift2{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-7vw,10vh) scale(1.15)}}
@keyframes drift3{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(6vw,-8vh) scale(1.08)}}
html[data-motion="off"] .bg .blob{animation:none}
@media (prefers-reduced-motion:reduce){.bg .blob{animation:none}}

::-webkit-scrollbar{width:11px;height:11px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:linear-gradient(var(--indigo),var(--cyan));border-radius:20px;border:3px solid var(--bg2)}
::-webkit-scrollbar-thumb:hover{background:linear-gradient(var(--cyan),var(--magenta))}
*{scrollbar-color:var(--indigo) var(--bg2);scrollbar-width:thin}

/* ============================== chrome ============================== */
.top{position:fixed;top:0;left:0;right:0;height:var(--top);z-index:60;display:flex;align-items:center;gap:14px;
  padding:0 16px;background:color-mix(in srgb,var(--surface) 82%,transparent);backdrop-filter:blur(16px);
  border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.brand svg{flex:none;filter:drop-shadow(0 0 10px color-mix(in srgb,var(--cyan) 60%,transparent))}
.brand b{font-size:16px;letter-spacing:.16em;font-weight:800}
.brand small{display:block;font-size:9.5px;letter-spacing:.26em;color:var(--faint);text-transform:uppercase;margin-top:-2px}
.top .spacer{flex:1}
.pill{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border-radius:999px;border:1px solid var(--line2);
  background:var(--surface2);font-size:11.5px;color:var(--muted);white-space:nowrap;font-variant-numeric:tabular-nums}
.pill b{color:var(--text);font-weight:650}
.dot{width:7px;height:7px;border-radius:50%;background:var(--faint);flex:none}
.dot.live{background:var(--green);box-shadow:0 0 0 0 color-mix(in srgb,var(--green) 70%,transparent);animation:ping 2.4s infinite}
.dot.warn{background:var(--amber)} .dot.bad{background:var(--red)} .dot.info{background:var(--cyan)}
@keyframes ping{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--green) 60%,transparent)}70%{box-shadow:0 0 0 7px transparent}100%{box-shadow:0 0 0 0 transparent}}
html[data-motion="off"] .dot.live{animation:none}
.iconbtn{width:34px;height:34px;display:grid;place-items:center;border-radius:10px;border:1px solid var(--line2);
  background:var(--surface2);color:var(--muted);cursor:pointer;transition:.16s}
.iconbtn:hover{color:var(--text);border-color:var(--cyan);transform:translateY(-1px)}
.iconbtn.on{color:var(--bg);background:var(--grad-a);border-color:transparent;font-weight:700}
.walletchip{display:flex;align-items:center;gap:9px;padding:5px 12px 5px 6px;border-radius:999px;border:1px solid var(--line2);
  background:var(--surface2);cursor:pointer;transition:.16s;max-width:230px}
.walletchip:hover{border-color:var(--indigo)}
.avatar{width:26px;height:26px;border-radius:50%;flex:none;background:var(--grad-c);display:grid;place-items:center;font-size:11px;font-weight:800;color:#fff}
.walletchip .addr{font:11.5px/1.2 var(--mono);color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.walletchip .nm{font-size:12px;font-weight:650;color:var(--text);line-height:1.2}

.nav{position:fixed;top:var(--top);bottom:0;left:0;width:var(--nav);z-index:50;padding:16px 12px;overflow-y:auto;
  background:color-mix(in srgb,var(--bg2) 88%,transparent);border-right:1px solid var(--line);backdrop-filter:blur(10px)}
.nav .eyebrow{font-size:9.5px;letter-spacing:.24em;color:var(--faint);text-transform:uppercase;padding:10px 10px 6px}
.nav a{display:flex;align-items:center;gap:11px;padding:9px 11px;border-radius:10px;color:var(--muted);text-decoration:none;
  font-size:13.5px;font-weight:550;position:relative;transition:.15s;margin-bottom:2px}
.nav a svg{flex:none;opacity:.85}
.nav a:hover{background:var(--surface);color:var(--text)}
.nav a.active{background:linear-gradient(90deg,color-mix(in srgb,var(--indigo) 26%,transparent),transparent);color:var(--text)}
.nav a.active::before{content:"";position:absolute;left:-12px;top:8px;bottom:8px;width:3px;border-radius:0 3px 3px 0;background:var(--grad-a)}
.nav a .count{margin-left:auto;font:11px/1 var(--mono);color:var(--faint);background:var(--surface2);padding:3px 6px;border-radius:6px}
.nav .netcard{margin-top:14px;padding:12px;border-radius:var(--r);border:1px solid var(--line);background:var(--surface)}
.nav .netcard h6{margin:0 0 8px;font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--faint)}
.nav .kv{display:flex;justify-content:space-between;font-size:11.5px;color:var(--muted);padding:3px 0;font-variant-numeric:tabular-nums}
.nav .kv b{color:var(--text);font-weight:600}

main{position:relative;z-index:10;margin-left:var(--nav);padding:calc(var(--top) + 22px) 26px 90px;max-width:1500px}
section{scroll-margin-top:calc(var(--top) + 16px);margin-bottom:40px;animation:rise .5s cubic-bezier(.2,.7,.3,1) both}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
html[data-motion="off"] section{animation:none}
.shead{display:flex;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:16px}
.shead .eyebrow{font-size:10px;letter-spacing:.26em;text-transform:uppercase;color:var(--cyan);font-weight:700}
.shead h2{margin:2px 0 0;font-size:26px;letter-spacing:-.02em;font-weight:750}
.shead p{margin:4px 0 0;color:var(--muted);font-size:13px;max-width:62ch}
.shead .acts{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}

.card{background:linear-gradient(180deg,color-mix(in srgb,var(--surface) 96%,transparent),var(--surface));
  border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);position:relative;overflow:hidden}
.card::after{content:"";position:absolute;inset:0 0 auto;height:1px;background:linear-gradient(90deg,transparent,color-mix(in srgb,var(--cyan) 55%,transparent),transparent);opacity:.7}
.card .hd{display:flex;align-items:center;gap:10px;padding:13px var(--pad);border-bottom:1px solid var(--line)}
.card .hd h3{margin:0;font-size:13px;font-weight:700;letter-spacing:.02em}
.card .hd .sub{font-size:11px;color:var(--faint)}
.card .hd .acts{margin-left:auto;display:flex;gap:6px;align-items:center}
.card .bd{padding:var(--pad)}
.grid{display:grid;gap:16px}
.g2{grid-template-columns:repeat(2,minmax(0,1fr))}
.g3{grid-template-columns:repeat(3,minmax(0,1fr))}
.g4{grid-template-columns:repeat(4,minmax(0,1fr))}
.hero{grid-template-columns:minmax(0,1.55fr) minmax(0,1fr)}

button,.btn{font:inherit}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:9px 15px;border-radius:10px;cursor:pointer;
  border:1px solid var(--line2);background:var(--surface2);color:var(--text);font-size:13px;font-weight:600;transition:.16s;white-space:nowrap}
.btn:hover{border-color:var(--cyan);transform:translateY(-1px);box-shadow:0 6px 18px -10px var(--cyan)}
.btn:active{transform:translateY(0)}
.btn.primary{background:var(--grad-a);color:#04070f;border-color:transparent;font-weight:750}
.btn.primary:hover{box-shadow:0 10px 26px -10px var(--cyan)}
.btn.mag{background:var(--grad-b);color:#160208;border-color:transparent;font-weight:750}
.btn.ghost{background:transparent}
.btn.danger{border-color:color-mix(in srgb,var(--red) 55%,transparent);color:var(--red)}
.btn.danger:hover{background:color-mix(in srgb,var(--red) 16%,transparent);border-color:var(--red);box-shadow:none}
.btn.sm{padding:6px 10px;font-size:12px;border-radius:8px}
.btn[disabled]{opacity:.45;pointer-events:none}
input,select,textarea{font:inherit;color:var(--text);background:var(--bg2);border:1px solid var(--line2);border-radius:9px;padding:9px 11px;width:100%;transition:.15s}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 0 3px color-mix(in srgb,var(--cyan) 18%,transparent)}
input[type=range]{padding:0;height:26px;background:transparent;border:none;-webkit-appearance:none;appearance:none}
input[type=range]::-webkit-slider-runnable-track{height:5px;border-radius:5px;background:linear-gradient(90deg,var(--indigo),var(--cyan))}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:15px;height:15px;border-radius:50%;background:var(--text);margin-top:-5px;border:2px solid var(--indigo);cursor:pointer;box-shadow:0 0 10px -2px var(--cyan)}
input[type=range]::-moz-range-track{height:5px;border-radius:5px;background:linear-gradient(90deg,var(--indigo),var(--cyan))}
input[type=range]::-moz-range-thumb{width:13px;height:13px;border-radius:50%;background:var(--text);border:2px solid var(--indigo);cursor:pointer}
input[type=checkbox]{width:16px;height:16px;accent-color:var(--cyan);cursor:pointer}
label.f{display:block;font-size:11px;letter-spacing:.13em;text-transform:uppercase;color:var(--faint);font-weight:650;margin:0 0 6px}
.field{margin-bottom:13px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
.muted{color:var(--muted)} .faint{color:var(--faint)}
.tiny{font-size:11.5px}
.switch{display:inline-flex;align-items:center;gap:9px;cursor:pointer;user-select:none;font-size:12.5px;color:var(--muted)}
.switch input{display:none}
.switch .tr{width:38px;height:21px;border-radius:999px;background:var(--overlay);border:1px solid var(--line2);position:relative;transition:.18s;flex:none}
.switch .tr::after{content:"";position:absolute;top:2px;left:2px;width:15px;height:15px;border-radius:50%;background:var(--faint);transition:.18s}
.switch input:checked + .tr{background:var(--grad-a);border-color:transparent}
.switch input:checked + .tr::after{left:19px;background:#04070f}
.chips{display:flex;gap:7px;flex-wrap:wrap}
.chip{padding:6px 12px;border-radius:999px;border:1px solid var(--line2);background:var(--surface2);color:var(--muted);
  font-size:12px;cursor:pointer;transition:.15s;font-weight:600}
.chip:hover{color:var(--text);border-color:var(--cyan)}
.chip.on{background:var(--grad-a);color:#04070f;border-color:transparent}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:7px;font-size:10.5px;font-weight:750;letter-spacing:.07em;text-transform:uppercase}
.badge.issue{background:color-mix(in srgb,var(--amber) 18%,transparent);color:var(--amber)}
.badge.vote{background:color-mix(in srgb,var(--green) 18%,transparent);color:var(--green)}
.badge.transfer{background:color-mix(in srgb,var(--cyan) 18%,transparent);color:var(--cyan)}
.badge.conflict{background:color-mix(in srgb,var(--red) 20%,transparent);color:var(--red)}
.badge.admin{background:color-mix(in srgb,var(--magenta) 20%,transparent);color:var(--magenta)}
.badge.neutral{background:var(--overlay);color:var(--muted)}
.badge.ok{background:color-mix(in srgb,var(--green) 16%,transparent);color:var(--green)}

/* stats */
.stat{padding:15px var(--pad);border-radius:var(--r);border:1px solid var(--line);background:var(--surface);position:relative;overflow:hidden}
.stat .lb{font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--faint);font-weight:700}
.stat .vl{font-size:30px;font-weight:780;letter-spacing:-.03em;font-variant-numeric:tabular-nums;margin-top:5px;line-height:1}
.stat .dl{font-size:11.5px;color:var(--muted);margin-top:6px}
.stat .spark{position:absolute;right:-6px;bottom:-6px;opacity:.20}
.stat.a{border-color:color-mix(in srgb,var(--cyan) 34%,var(--line))}
.stat.b{border-color:color-mix(in srgb,var(--amber) 34%,var(--line))}
.stat.c{border-color:color-mix(in srgb,var(--green) 34%,var(--line))}
.stat.d{border-color:color-mix(in srgb,var(--magenta) 34%,var(--line))}

/* visualizer */
.viz{position:relative;height:392px;background:radial-gradient(ellipse at 50% 45%,color-mix(in srgb,var(--indigo) 16%,transparent),transparent 65%),var(--bg2)}
.viz canvas{display:block;width:100%;height:100%}
.viz .legend{position:absolute;left:14px;bottom:12px;display:flex;gap:12px;flex-wrap:wrap;font-size:10.5px;color:var(--muted)}
.viz .legend i{width:8px;height:8px;border-radius:2px;display:inline-block;margin-right:5px}
.viz .hud{position:absolute;right:14px;top:12px;text-align:right;font:11px/1.6 var(--mono);color:var(--muted)}
.viz .hud b{color:var(--text)}
.rail{display:flex;flex-direction:column;gap:11px;padding:var(--pad);border-left:1px solid var(--line);background:var(--surface2);min-width:212px}
.rail h6{margin:0;font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--faint)}
.rail .ctl{display:grid;gap:4px}
.rail .ctl .lbl{display:flex;justify-content:space-between;font-size:11.5px;color:var(--muted)}
.rail .ctl .lbl b{color:var(--text);font-variant-numeric:tabular-nums;font-weight:600}
.vizwrap{display:grid;grid-template-columns:minmax(0,1fr) 212px}

/* tables */
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint);font-weight:700;
  padding:9px 12px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--surface);z-index:2}
.tbl td{padding:0 12px;height:var(--row);border-bottom:1px solid color-mix(in srgb,var(--line) 60%,transparent);vertical-align:middle}
.tbl tbody tr{transition:.13s;cursor:pointer}
.tbl tbody tr:hover{background:color-mix(in srgb,var(--indigo) 10%,transparent)}
.tbl tbody tr.sel{background:color-mix(in srgb,var(--cyan) 12%,transparent)}
.tbl .hash{font:12px var(--mono);color:var(--text)}
.tbl .sub{font-size:11px;color:var(--faint)}
.tbl .num{text-align:right;font-variant-numeric:tabular-nums}
.scroll{max-height:520px;overflow:auto}
.empty{padding:38px 20px;text-align:center;color:var(--faint)}
.empty svg{opacity:.4;margin-bottom:10px}
.empty b{display:block;color:var(--muted);font-size:14px;margin-bottom:5px}
.bulkbar{display:flex;align-items:center;gap:10px;padding:10px var(--pad);border-bottom:1px solid var(--line);
  background:linear-gradient(90deg,color-mix(in srgb,var(--cyan) 14%,transparent),transparent);animation:rise .22s both}
.bulkbar b{font-size:13px}

/* tally */
.opt{padding:12px 14px;border-radius:12px;border:1px solid var(--line);background:var(--surface2);margin-bottom:10px;position:relative;overflow:hidden;transition:.16s}
.opt:hover{border-color:var(--line2)}
.opt.mine{border-color:color-mix(in srgb,var(--green) 55%,transparent)}
.opt .bar{position:absolute;left:0;top:0;bottom:0;opacity:.20;transition:width .7s cubic-bezier(.2,.8,.2,1)}
.opt .bar.stripes{background-image:repeating-linear-gradient(45deg,currentColor 0 6px,transparent 6px 12px)}
.opt .top{display:flex;align-items:center;gap:10px;position:relative}
.opt .nm{font-weight:650;font-size:13.5px}
.opt .pc{margin-left:auto;font-weight:750;font-variant-numeric:tabular-nums;font-size:15px}
.opt .meta{position:relative;font-size:11.5px;color:var(--muted);margin-top:5px;display:flex;gap:12px}
.opt .swatch{width:11px;height:11px;border-radius:3px;flex:none}
.votecard{display:flex;gap:11px;align-items:flex-start;padding:12px;border-radius:11px;border:1px solid var(--line);
  background:var(--surface2);cursor:pointer;transition:.15s;margin-bottom:9px}
.votecard:hover{border-color:var(--cyan);transform:translateX(2px)}
.votecard.on{border-color:var(--cyan);background:color-mix(in srgb,var(--cyan) 10%,transparent)}
.votecard .radio{width:17px;height:17px;border-radius:50%;border:2px solid var(--line2);flex:none;margin-top:2px;transition:.15s}
.votecard.on .radio{border-color:var(--cyan);background:radial-gradient(circle,var(--cyan) 42%,transparent 46%)}

/* activity */
.feed{max-height:330px;overflow:auto}
.fitem{display:flex;gap:11px;padding:10px var(--pad);border-bottom:1px solid color-mix(in srgb,var(--line) 55%,transparent);animation:rise .3s both}
.fitem .ic{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;flex:none;font-size:13px}
.fitem .tx{min-width:0;flex:1}
.fitem .tx b{font-size:12.5px;font-weight:650;display:block}
.fitem .tx span{font-size:11px;color:var(--faint);font-family:var(--mono)}
.fitem time{font-size:10.5px;color:var(--faint);white-space:nowrap}

/* drawer + modal + toast */
.scrim{position:fixed;inset:0;background:var(--scrim);backdrop-filter:blur(4px);z-index:80;opacity:0;pointer-events:none;transition:.22s}
.scrim.on{opacity:1;pointer-events:auto}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(520px,100%);z-index:90;background:var(--surface);border-left:1px solid var(--line2);
  transform:translateX(102%);transition:transform .3s cubic-bezier(.2,.8,.2,1);display:flex;flex-direction:column;box-shadow:-30px 0 70px -30px #000}
.drawer.on{transform:none}
.drawer .dh{display:flex;align-items:center;gap:12px;padding:16px 18px;border-bottom:1px solid var(--line);background:var(--surface2)}
.drawer .dh h3{margin:0;font-size:15px}
.drawer .db{padding:18px;overflow-y:auto;flex:1}
.modal{position:fixed;z-index:95;left:50%;top:50%;transform:translate(-50%,-46%) scale(.97);opacity:0;pointer-events:none;
  width:min(600px,calc(100vw - 28px));max-height:88vh;overflow:auto;background:var(--surface);border:1px solid var(--line2);
  border-radius:18px;box-shadow:0 40px 90px -30px #000;transition:.24s cubic-bezier(.2,.8,.2,1)}
.modal.on{opacity:1;pointer-events:auto;transform:translate(-50%,-50%) scale(1)}
.modal .mh{padding:20px 22px 0} .modal .mb{padding:18px 22px 22px}
.modal h3{margin:0 0 6px;font-size:20px;letter-spacing:-.01em}
.toasts{position:fixed;right:18px;bottom:18px;z-index:120;display:flex;flex-direction:column;gap:9px;max-width:min(400px,calc(100vw - 36px))}
.toast{display:flex;gap:11px;align-items:flex-start;padding:12px 14px;border-radius:12px;border:1px solid var(--line2);
  background:var(--overlay);box-shadow:0 18px 40px -18px #000;animation:toastin .3s cubic-bezier(.2,.8,.2,1) both}
@keyframes toastin{from{opacity:0;transform:translateX(24px)}to{opacity:1;transform:none}}
.toast.out{animation:toastout .25s both}
@keyframes toastout{to{opacity:0;transform:translateX(24px)}}
.toast .bar{width:3px;border-radius:3px;align-self:stretch;flex:none}
.toast b{display:block;font-size:13px;margin-bottom:2px}
.toast p{margin:0;font-size:12px;color:var(--muted)}
.toast button{margin-left:auto;align-self:center}
.kv2{display:grid;grid-template-columns:auto 1fr;gap:7px 14px;font-size:12.5px}
.kv2 dt{color:var(--faint)} .kv2 dd{margin:0;font-family:var(--mono);word-break:break-all}
.codebox{font:11.5px/1.6 var(--mono);background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:11px;
  word-break:break-all;white-space:pre-wrap;max-height:190px;overflow:auto}
.progress{height:5px;border-radius:5px;background:var(--overlay);overflow:hidden}
.progress i{display:block;height:100%;background:var(--grad-a);transition:width .2s}
.drag{cursor:grab} .drag.over{border-color:var(--cyan);background:color-mix(in srgb,var(--cyan) 12%,transparent)}
.optrow{display:flex;align-items:center;gap:9px;padding:8px 10px;border:1px solid var(--line);border-radius:10px;background:var(--surface2);margin-bottom:7px}
.optrow .grip{color:var(--faint);cursor:grab}
.locked{padding:34px 22px;text-align:center}
.locked svg{opacity:.55;margin-bottom:12px}
.addrbook{display:flex;gap:7px;flex-wrap:wrap;margin-top:7px}
.addrbook button{font:11px var(--mono);padding:4px 9px;border-radius:7px;border:1px solid var(--line2);background:var(--bg2);color:var(--muted);cursor:pointer}
.addrbook button:hover{border-color:var(--cyan);color:var(--text)}
.banner{display:flex;gap:11px;align-items:center;padding:11px 15px;border-radius:12px;border:1px solid margin;
  border:1px solid color-mix(in srgb,var(--amber) 40%,transparent);background:color-mix(in srgb,var(--amber) 10%,transparent);margin-bottom:16px;font-size:12.5px}
.banner.info{border-color:color-mix(in srgb,var(--cyan) 40%,transparent);background:color-mix(in srgb,var(--cyan) 9%,transparent)}
.banner b{font-weight:700}
.tabs{display:flex;gap:6px;border-bottom:1px solid var(--line);padding:0 var(--pad)}
.tabs button{padding:11px 13px;background:none;border:none;color:var(--muted);cursor:pointer;font-size:12.5px;font-weight:650;border-bottom:2px solid transparent}
.tabs button.on{color:var(--text);border-bottom-color:var(--cyan)}
.mobile-nav{display:none}
@media (max-width:1180px){ .hero{grid-template-columns:1fr} .g4{grid-template-columns:repeat(2,1fr)} }
@media (max-width:900px){
  :root{--nav:0px}
  .nav{display:none}
  main{margin-left:0;padding:calc(var(--top) + 16px) 14px 96px}
  .g2,.g3,.g4{grid-template-columns:1fr}
  .vizwrap{grid-template-columns:1fr} .rail{border-left:none;border-top:1px solid var(--line)}
  .viz{height:300px}
  .top .hide-sm{display:none}
  .mobile-nav{display:flex;position:fixed;left:0;right:0;bottom:0;z-index:70;background:color-mix(in srgb,var(--surface) 94%,transparent);
    backdrop-filter:blur(14px);border-top:1px solid var(--line);padding:6px 4px;justify-content:space-around}
  .mobile-nav a{display:flex;flex-direction:column;align-items:center;gap:3px;color:var(--faint);text-decoration:none;font-size:9.5px;padding:5px 7px;border-radius:9px}
  .mobile-nav a.active{color:var(--cyan);background:color-mix(in srgb,var(--cyan) 12%,transparent)}
  .tbl thead{display:none}
  .tbl tr{display:grid;grid-template-columns:auto 1fr auto;gap:4px 10px;padding:10px 12px;border-bottom:1px solid var(--line)}
  .tbl td{border:none;height:auto;padding:0}
  .tbl td.wide{grid-column:1/-1}
  .shead h2{font-size:21px}
}
</style>
</head>
<body>
<div class="bg"><div class="blob b1"></div><div class="blob b2"></div><div class="blob b3"></div><div class="grid"></div><div class="grain"></div></div>

<header class="top">
  <div class="brand">
    <svg width="30" height="30" viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <defs><linearGradient id="bg1" x1="0" y1="0" x2="32" y2="32"><stop stop-color="var(--indigo)"/><stop offset=".55" stop-color="var(--cyan)"/><stop offset="1" stop-color="var(--magenta)"/></linearGradient></defs>
      <path d="M16 2l12 7v14l-12 7L4 23V9z" stroke="url(#bg1)" stroke-width="1.8" fill="none"/>
      <path d="M16 8l7 4v8l-7 4-7-4v-8z" fill="url(#bg1)" opacity=".22"/>
      <path d="M11.5 16.2l3.2 3.2 6-6.4" stroke="url(#bg1)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    </svg>
    <div><b>EVOTE</b><small>ledger console</small></div>
  </div>
  <div class="pill hide-sm" id="pillMode"><span class="dot" id="dotMode"></span><span id="txtMode">connecting…</span></div>
  <div class="pill hide-sm"><span class="dot info"></span>height <b id="pillHeight">0</b></div>
  <div class="pill hide-sm" id="pillPeers"><span class="dot"></span>peers <b id="pillPeerCount">0</b></div>
  <div class="spacer"></div>
  <button class="iconbtn on" id="btnSound" data-act="sound" title="Sound on — click to mute" aria-label="Toggle sound">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M11 5L6 9H2v6h4l5 4V5z"/><path d="M15.5 8.5a5 5 0 010 7" class="wave"/></svg>
  </button>
  <button class="iconbtn" data-act="theme" title="Cycle palette" aria-label="Cycle palette">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 000 18z" fill="currentColor"/></svg>
  </button>
  <button class="iconbtn" data-act="goto-admin" title="Admin area" aria-label="Admin area">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 2l8 4v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><path d="M9.5 12l1.8 1.8 3.4-3.6"/></svg>
  </button>
  <div class="walletchip" data-act="goto-vault" id="walletChip" role="button" tabindex="0">
    <div class="avatar" id="wAvatar">?</div>
    <div style="min-width:0"><div class="nm" id="wName">No wallet</div><div class="addr" id="wAddr">create or import</div></div>
  </div>
</header>

<nav class="nav" id="nav">
  <div class="eyebrow">Workspace</div>
  <a href="#overview" data-nav="overview" class="active"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>Overview</a>
  <a href="#coins" data-nav="coins"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="9" r="6"/><path d="M15.5 4.2a6 6 0 010 15.6M9 15a6 6 0 006 6"/></svg>My coins<span class="count" id="navCoins">0</span></a>
  <a href="#ballot" data-nav="ballot"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 20h16M7 16V9M12 16V4M17 16v-5"/></svg>Ballot<span class="count" id="navVotes">0</span></a>
  <a href="#ledger" data-nav="ledger"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 5h16M4 10h16M4 15h10M4 20h7"/></svg>Ledger<span class="count" id="navLines">0</span></a>
  <a href="#peers" data-nav="peers"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="18" r="2.5"/><circle cx="19" cy="18" r="2.5"/><path d="M12 7.5L6 16M12 7.5L18 16M7.5 18h9"/></svg>Network<span class="count" id="navPeers">0</span></a>
  <div class="eyebrow">Control</div>
  <a href="#admin" data-nav="admin"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 2l8 4v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/></svg>Admin<span class="count" id="navAdmin">locked</span></a>
  <a href="#vault" data-nav="vault"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="12" cy="12" r="3"/><path d="M12 9V7M12 17v-2"/></svg>Vault &amp; settings</a>
  <div class="netcard">
    <h6>Replica</h6>
    <div class="kv"><span>lines</span><b id="ncLines">0</b></div>
    <div class="kv"><span>verified</span><b id="ncVerified">0</b></div>
    <div class="kv"><span>conflicts</span><b id="ncConflicts">0</b></div>
    <div class="kv"><span>last sync</span><b id="ncSync">—</b></div>
    <div class="kv"><span>crypto</span><b id="ncCrypto">…</b></div>
  </div>
</nav>

<main id="main">
  <div id="banner"></div>

  <section id="overview">
    <div class="shead">
      <div><div class="eyebrow">Live replica</div><h2>Treasury &amp; ballot at a glance</h2>
        <p>Every coin is a signed line. Every vote spends one. Your browser verifies the whole chain itself — the server only relays.</p></div>
      <div class="acts">
        <button class="btn" data-act="sync-now"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 11-3-6.7M21 4v5h-5"/></svg>Sync now</button>
        <button class="btn primary" data-act="quick-vote">Cast a vote</button>
      </div>
    </div>
    <div class="grid g4" style="margin-bottom:16px">
      <div class="stat a"><div class="lb">Coins held</div><div class="vl" id="stCoins">0</div><div class="dl" id="stCoinsSub">unspent, owned by you</div>
        <svg class="spark" width="70" height="46" viewBox="0 0 70 46"><circle cx="46" cy="26" r="20" stroke="var(--cyan)" stroke-width="2" fill="none"/><circle cx="30" cy="20" r="14" stroke="var(--indigo)" stroke-width="2" fill="none"/></svg></div>
      <div class="stat b"><div class="lb">Coins in circulation</div><div class="vl" id="stSupply">0</div><div class="dl" id="stSupplySub">minted by allowlisted issuers</div></div>
      <div class="stat c"><div class="lb">Ballots cast</div><div class="vl" id="stVotes">0</div><div class="dl" id="stVotesSub">weight counted per coin</div></div>
      <div class="stat d"><div class="lb">Ledger lines</div><div class="vl" id="stLines">0</div><div class="dl" id="stLinesSub">append-only, signed</div></div>
    </div>
    <div class="grid hero">
      <div class="card">
        <div class="hd"><h3>Ledger constellation</h3><span class="sub">live gossip &amp; holdings</span>
          <div class="acts"><button class="btn sm ghost" data-act="viz-random">Randomize</button><button class="btn sm ghost" data-act="viz-reset">Reset</button><button class="btn sm" data-act="viz-export">Export PNG</button></div></div>
        <div class="vizwrap">
          <div class="viz"><canvas id="viz"></canvas>
            <div class="hud"><div>nodes <b id="hudNodes">0</b></div><div>in flight <b id="hudParticles">0</b></div><div>fps <b id="hudFps">0</b></div></div>
            <div class="legend"><span><i style="background:var(--amber)"></i>issue</span><span><i style="background:var(--green)"></i>vote</span><span><i style="background:var(--cyan)"></i>transfer</span><span><i style="background:var(--red)"></i>conflict</span></div>
          </div>
          <div class="rail">
            <h6>Visual controls</h6>
            <div class="ctl"><div class="lbl"><span>Orbit speed</span><b id="vSpeedV">1.0×</b></div><input type="range" id="vSpeed" min="0" max="30" value="10" data-viz="speed"></div>
            <div class="ctl"><div class="lbl"><span>Glow</span><b id="vGlowV">100%</b></div><input type="range" id="vGlow" min="0" max="20" value="10" data-viz="glow"></div>
            <div class="ctl"><div class="lbl"><span>Particles</span><b id="vPartsV">1.0×</b></div><input type="range" id="vParts" min="0" max="30" value="10" data-viz="particles"></div>
            <div class="ctl"><div class="lbl"><span>Orbit radius</span><b id="vOrbitV">100%</b></div><input type="range" id="vOrbit" min="4" max="16" value="10" data-viz="orbit"></div>
            <div class="ctl"><div class="lbl"><span>Trail length</span><b id="vTrailV">50%</b></div><input type="range" id="vTrail" min="0" max="20" value="10" data-viz="trails"></div>
            <div class="ctl"><div class="lbl"><span>Node scale</span><b id="vScaleV">1.0×</b></div><input type="range" id="vScale" min="5" max="20" value="10" data-viz="scale"></div>
            <div class="ctl"><div class="lbl"><span>Palette</span></div><select id="vTheme" data-viz="theme"><option value="midnight">Midnight</option><option value="ember">Ember</option><option value="chlorophyll">Chlorophyll</option></select></div>
            <label class="switch"><input type="checkbox" id="vGrid" data-viz="grid" checked><span class="tr"></span>Grid &amp; guides</label>
            <label class="switch"><input type="checkbox" id="vMotion" data-viz="motion" checked><span class="tr"></span>Motion</label>
          </div>
        </div>
      </div>
      <div style="display:grid;gap:16px;align-content:start">
        <div class="card"><div class="hd"><h3>Standings</h3><span class="sub" id="tallySubMini">live</span>
          <div class="acts"><button class="btn sm ghost" data-act="goto-ballot">Open ballot</button></div></div>
          <div class="bd" id="tallyMini"></div></div>
        <div class="card"><div class="hd"><h3>Activity</h3><span class="sub">newest first</span></div>
          <div class="feed" id="feed"></div></div>
      </div>
    </div>
  </section>

  <section id="coins">
    <div class="shead">
      <div><div class="eyebrow">Holdings</div><h2>My coins</h2><p>Each row is an unspent token you own, with its full provenance chain. Select any set and export it as a portable bundle.</p></div>
      <div class="acts">
        <button class="btn" data-act="claim" id="btnClaim">Claim test allowance</button>
        <button class="btn" data-act="export-coins-all">Export all coins</button>
        <button class="btn primary" data-act="receive">Receive / my address</button>
      </div>
    </div>
    <div class="card">
      <div class="hd" style="gap:12px;flex-wrap:wrap">
        <div style="position:relative;flex:1;min-width:200px;max-width:330px">
          <input id="coinQuery" placeholder="Search hash, issuer, label…  ( / )" data-act="coin-query" style="padding-left:32px">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--faint)" stroke-width="2" style="position:absolute;left:10px;top:11px"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>
        </div>
        <div class="chips" id="coinFilters">
          <button class="chip on" data-filter="unspent">Unspent</button>
          <button class="chip" data-filter="spent">Spent</button>
          <button class="chip" data-filter="incoming">Received</button>
          <button class="chip" data-filter="all">Everything</button>
        </div>
        <select id="coinSort" data-act="coin-sort" style="width:auto;min-width:150px">
          <option value="newest">Newest first</option><option value="oldest">Oldest first</option>
          <option value="amount">Largest amount</option><option value="hash">Hash A→Z</option><option value="issuer">Issuer</option>
        </select>
        <button class="btn sm ghost" data-act="save-view">Save view</button>
      </div>
      <div id="savedViews" class="bd" style="padding-top:10px;padding-bottom:0"></div>
      <div id="coinBulk"></div>
      <div class="scroll"><table class="tbl"><thead><tr>
        <th style="width:34px"><input type="checkbox" id="coinAll" data-act="coin-select-all" aria-label="Select all"></th>
        <th>Token</th><th>Amount</th><th>Issuer</th><th>Acquired</th><th>State</th><th style="width:150px"></th>
      </tr></thead><tbody id="coinRows"></tbody></table></div>
      <div id="coinEmpty"></div>
    </div>
  </section>

  <section id="ballot">
    <div class="shead">
      <div><div class="eyebrow">One coin, one ballot</div><h2 id="ballotTitle">Ballot</h2><p id="ballotDesc">Casting a vote spends the coin permanently — the signature is the ballot, the ledger is the count.</p></div>
      <div class="acts"><button class="btn" data-act="export-tally">Export results CSV</button></div>
    </div>
    <div class="grid hero">
      <div class="card"><div class="hd"><h3>Live results</h3><span class="sub" id="tallySub">counting…</span></div>
        <div class="bd" id="tallyFull"></div></div>
      <div class="card"><div class="hd"><h3>Cast your ballot</h3><span class="sub">signed in your browser</span></div>
        <div class="bd">
          <div id="voteOptions"></div>
<div class="field" style="margin-top:14px">
  <label class="f">Coins to spend <span id="voteSelCount" class="badge neutral">0</span></label>
  <div class="row" style="margin-bottom:7px">
    <button class="btn sm ghost" data-act="vote-select-all">All</button>
    <button class="btn sm ghost" data-act="vote-select-none">None</button>
    <button class="btn sm" data-act="vote-add-one">+ Add one</button>
  </div>
  <div id="voteCoinList" style="max-height:190px;overflow:auto;border:1px solid var(--line);border-radius:10px;padding:6px"></div>
  <div class="tiny faint" style="margin-top:6px" id="voteCoinHint"></div>
</div>
<button class="btn primary" style="width:100%" data-act="cast-vote" id="btnVote">Sign &amp; cast ballot</button>
          <div class="tiny faint" style="margin-top:10px">Your wallet signs <span class="mono">SIGNED_VOTE</span> locally. The coin is marked spent and can never vote twice.</div>
        </div></div>
    </div>
    <div class="card" style="margin-top:16px"><div class="hd"><h3>My ballots</h3><span class="sub" id="myVotesSub"></span></div>
      <div class="scroll" style="max-height:300px"><table class="tbl"><thead><tr><th>Choice</th><th>Coin</th><th>Weight</th><th>When</th></tr></thead><tbody id="myVoteRows"></tbody></table></div>
      <div id="myVoteEmpty"></div></div>
  </section>

  <section id="ledger">
    <div class="shead">
      <div><div class="eyebrow">Append-only history</div><h2>Ledger</h2><p>Raw signed lines, verified with Ed25519 in this tab. Import a ledger file to merge another replica's history.</p></div>
      <div class="acts">
        <button class="btn" data-act="import-ledger">Import voucher</button>
        <button class="btn" data-act="export-ledger">Export ledger</button>
        <button class="btn ghost" data-act="export-ledger-txt">Raw .txt</button>
      </div>
    </div>
    <div class="card">
      <div class="hd" style="gap:12px;flex-wrap:wrap">
        <div class="chips" id="ledgerFilters">
          <button class="chip on" data-lfilter="all">All</button><button class="chip" data-lfilter="SIGNED_ISSUE">Issues</button>
          <button class="chip" data-lfilter="SIGNED_VOTE">Votes</button><button class="chip" data-lfilter="SIGNED_TRANSFER">Transfers</button>
          <button class="chip" data-lfilter="bad">Rejected</button>
        </div>
        <input id="ledgerQuery" placeholder="Search signer, token, candidate…" data-act="ledger-query" style="flex:1;min-width:180px;max-width:320px">
        <span class="tiny faint" id="ledgerCount"></span>
      </div>
      <div class="scroll"><table class="tbl"><thead><tr><th style="width:64px">#</th><th>Type</th><th>Signer</th><th>Token / payload</th><th>When</th><th style="width:90px">Verify</th></tr></thead><tbody id="ledgerRows"></tbody></table></div>
      <div class="bd" id="ledgerMore"></div>
    </div>
  </section>

  <section id="peers">
    <div class="shead">
      <div><div class="eyebrow">Transport</div><h2>Network</h2><p>The bulletin board is always on. WebRTC adds direct browser-to-browser gossip on top — same signed lines, no server in the path.</p></div>
      <div class="acts"><button class="btn" data-act="mesh-leave" id="btnMeshLeave" style="display:none">Leave room</button></div>
    </div>
    <div class="grid g2">
      <div class="card"><div class="hd"><h3>Bulletin board</h3><span class="sub" id="bbSub">—</span></div>
        <div class="bd">
          <dl class="kv2" id="bbInfo"></dl>
          <div class="row" style="margin-top:14px">
            <label class="switch"><input type="checkbox" id="prefAuto" data-pref="autoSync" checked><span class="tr"></span>Auto-sync</label>
            <div style="flex:1;min-width:150px"><div class="lbl tiny muted" style="display:flex;justify-content:space-between"><span>Interval</span><b id="syncSecV">6s</b></div>
              <input type="range" id="prefSync" min="2" max="30" value="6" data-pref="syncSec"></div>
          </div>
          <div class="progress" style="margin-top:12px"><i id="syncBar" style="width:0%"></i></div>
        </div></div>
      <div class="card"><div class="hd"><h3>WebRTC mesh</h3><span class="sub" id="meshSub">not joined</span></div>
        <div class="bd">
          <div class="row"><input id="meshRoom" placeholder="room name" value="evote-main" style="flex:1;min-width:140px">
            <button class="btn primary" data-act="mesh-join" id="btnMeshJoin">Join</button></div>
          <div class="tiny faint" style="margin-top:8px" id="iceInfo">ICE servers load when you join.</div>
          <div id="peerList" style="margin-top:12px"></div>
        </div></div>
    </div>
    <div class="card" style="margin-top:16px"><div class="hd"><h3>Sneakernet</h3><span class="sub">paste signed lines from any replica</span>
      <div class="acts"><button class="btn sm primary" data-act="paste-ingest">Verify &amp; merge</button></div></div>
      <div class="bd"><textarea id="pasteBox" rows="4" placeholder="SIGNED_ISSUE|1|LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0…|1794806258|nonce|tokenhash|owner|1|signature"></textarea></div></div>
  </section>

  <section id="admin">
    <div class="shead">
      <div><div class="eyebrow">Restricted</div><h2>Admin &amp; treasury</h2><p>Only allowlisted issuer keys can mint. Everything here is gated by the admin token; users never need it.</p></div>
      <div class="acts" id="adminActs"></div>
    </div>
    <div id="adminBody"></div>
  </section>

  <section id="vault">
    <div class="shead">
      <div><div class="eyebrow">Keys &amp; preferences</div><h2>Vault</h2><p>Your wallet is a passphrase-encrypted file that only ever lives in this browser. Export it, carry it, import it anywhere.</p></div>
      <div class="acts"><button class="btn" data-act="wallet-export">Export wallet file</button><button class="btn" data-act="wallet-import">Import wallet</button></div>
    </div>
    <div class="grid g2">
      <div class="card"><div class="hd"><h3>Wallet</h3><span class="sub" id="vaultState">—</span></div><div class="bd" id="vaultWallet"></div></div>
      <div class="card"><div class="hd"><h3>Console preferences</h3><span class="sub">applied live</span></div>
        <div class="bd">
          <div class="field"><label class="f">Palette</label><select data-pref="theme" id="prefTheme"><option value="midnight">Midnight — indigo / cyan</option><option value="ember">Ember — amber / coral</option><option value="chlorophyll">Chlorophyll — teal / lime</option></select></div>
          <div class="field"><label class="f">Density</label><select data-pref="density" id="prefDensity"><option value="comfortable">Comfortable</option><option value="compact">Compact</option></select></div>
          <div class="row" style="gap:18px;margin-bottom:13px">
            <label class="switch"><input type="checkbox" data-pref="motion" id="prefMotion" checked><span class="tr"></span>Motion</label>
            <label class="switch"><input type="checkbox" data-pref="sound" id="prefSound" checked><span class="tr"></span>Sound</label>
            <label class="switch"><input type="checkbox" data-pref="verify" id="prefVerify" checked><span class="tr"></span>Verify on import</label>
          </div>
          <div class="field"><label class="f">Data</label>
            <div class="row"><button class="btn sm" data-act="export-all">Export everything</button>
              <button class="btn sm" data-act="import-ledger">Import voucher</button>
              <button class="btn sm danger" data-act="clear-ledger">Clear local replica</button></div></div>
        </div></div>
    </div>
    <div class="grid g2" style="margin-top:16px">
      <div class="card"><div class="hd"><h3>Protocol</h3><span class="sub">wire compatible with EVOTE newer3</span></div>
        <div class="bd"><div class="codebox">TYPE|1|pubkey|ts|nonce|fields…|signature
SIGNED_ISSUE    |tokenHash|owner|amount
SIGNED_VOTE     |candidateB64|tokenHash
SIGNED_TRANSFER |tokenHash|receiver|amount|expiry</div>
          <dl class="kv2" style="margin-top:13px">
            <dt>Signatures</dt><dd>Ed25519 (RFC 8032), pure JS in this tab</dd>
            <dt>Key id</dt><dd>base64(PEM SPKI) — same as the Qt/OpenSSL node</dd>
            <dt>Token id</dt><dd>sha256(base64(32 random bytes))</dd>
            <dt>Wallet file</dt><dd>PBKDF2-HMAC-SHA256 → HMAC stream cipher, encrypt-then-MAC</dd>
            <dt>Ordering</dt><dd>deterministic replay by (ts, hash); forks logged as conflicts</dd>
          </dl></div></div>
      <div class="card"><div class="hd"><h3>Crypto self-test</h3><span class="sub" id="selftestSub">running…</span></div>
        <div class="bd" id="selftestBody"></div></div>
    </div>
  </section>
</main>

<div class="mobile-nav" id="mnav">
  <a href="#overview" data-nav="overview" class="active"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>Home</a>
  <a href="#coins" data-nav="coins"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="9" r="6"/><path d="M15.5 4.2a6 6 0 010 15.6"/></svg>Coins</a>
  <a href="#ballot" data-nav="ballot"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 20h16M7 16V9M12 16V4M17 16v-5"/></svg>Vote</a>
  <a href="#ledger" data-nav="ledger"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 5h16M4 10h16M4 15h10M4 20h7"/></svg>Ledger</a>
  <a href="#vault" data-nav="vault"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="12" cy="12" r="3"/></svg>Vault</a>
</div>

<div class="scrim" id="scrim" data-act="close-all"></div>
<aside class="drawer" id="drawer" role="dialog" aria-modal="true" aria-label="Details">
  <div class="dh"><h3 id="drawerTitle">Details</h3><div style="flex:1"></div><button class="iconbtn" data-act="close-all" aria-label="Close">✕</button></div>
  <div class="db" id="drawerBody"></div>
</aside>
<div class="modal" id="modal" role="dialog" aria-modal="true"><div class="mh" id="modalHead"></div><div class="mb" id="modalBody"></div></div>
<div class="toasts" id="toasts"></div>
<input type="file" id="filePick" accept=".json,.txt,.evote,application/json,text/plain" style="display:none">

<script>
"use strict";
/* ==========================================================================
   EVOTE v2 client — crypto, ledger, transport, UI. No dependencies, no CDN.
   ========================================================================== */
const $ = id => document.getElementById(id);
const el = (t, c, h) => { const n = document.createElement(t); if (c) n.className = c; if (h != null) n.innerHTML = h; return n; };
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
const nowSec = () => Math.floor(Date.now() / 1000);
const tick = () => new Promise(r => setTimeout(r, 0));
const rand = n => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };
const u8 = n => new Uint8Array(n);
const concat = (...arrs) => { let n = 0; for (const a of arrs) n += a.length; const o = u8(n); let p = 0; for (const a of arrs) { o.set(a, p); p += a.length; } return o; };
const b64 = bytes => { let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); };
const unb64 = str => { const s = atob(String(str).trim()); const b = u8(s.length); for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i); return b; };
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const unhex = h => { const b = u8(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16); return b; };
const enc = s => new TextEncoder().encode(s);
const dec = b => new TextDecoder().decode(b);
const short = (s, n = 10) => !s ? '—' : (s.length <= n * 2 ? s : s.slice(0, n) + '…' + s.slice(-6));
const ago = ts => { const d = nowSec() - ts; if (d < 60) return d + 's ago'; if (d < 3600) return Math.floor(d / 60) + 'm ago'; if (d < 86400) return Math.floor(d / 3600) + 'h ago'; return Math.floor(d / 86400) + 'd ago'; };
const fmtTime = ts => new Date(ts * 1000).toLocaleString();
const be32 = n => { const b = u8(4); new DataView(b.buffer).setUint32(0, n >>> 0, false); return b; };

/* ---------------------------------------------------------------- hashing */
function firstPrimes(n) { const out = []; for (let c = 2; out.length < n; c++) { let p = true; for (let d = 2; d * d <= c; d++) if (c % d === 0) { p = false; break; } if (p) out.push(c); } return out; }
function isqrt(n) { if (n < 2n) return n; let x = 1n << BigInt(Math.ceil(n.toString(2).length / 2)); for (;;) { const y = (x + n / x) >> 1n; if (y >= x) return x; x = y; } }
function icbrt(n) { if (n < 2n) return n; let x = 1n << BigInt(Math.ceil(n.toString(2).length / 3) + 1); for (;;) { const y = (2n * x + n / (x * x)) / 3n; if (y >= x) return x; x = y; } }
const PRIMES = firstPrimes(80);
const M32 = 0xffffffffn;
const K256 = PRIMES.slice(0, 64).map(p => Number(icbrt(BigInt(p) << 96n) & M32));
const H256 = PRIMES.slice(0, 8).map(p => Number(isqrt(BigInt(p) << 64n) & M32));
const M64 = (1n << 64n) - 1n;
const K512 = PRIMES.map(p => icbrt(BigInt(p) << 192n) & M64);
const H512 = PRIMES.slice(0, 8).map(p => isqrt(BigInt(p) << 128n) & M64);

function sha256(msg) {
  const len = msg.length, pad = (56 - (len + 1) % 64 + 64) % 64, total = len + 1 + pad + 8;
  const buf = u8(total); buf.set(msg); buf[len] = 0x80;
  const dv = new DataView(buf.buffer), bits = len * 8;
  dv.setUint32(total - 8, Math.floor(bits / 4294967296), false); dv.setUint32(total - 4, bits >>> 0, false);
  const H = Uint32Array.from(H256), W = new Uint32Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let t = 0; t < 16; t++) W[t] = dv.getUint32(off + t * 4, false);
    for (let t = 16; t < 64; t++) {
      const x = W[t - 15], y = W[t - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let t = 0; t < 64; t++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K256[t] + W[t]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + mj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  const out = u8(32), odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i], false);
  return out;
}
const r64 = (x, n) => ((x >> n) | (x << (64n - n))) & M64;
function sha512(msg) {
  const len = msg.length, pad = (112 - (len + 1) % 128 + 128) % 128, total = len + 1 + pad + 16;
  const buf = u8(total); buf.set(msg); buf[len] = 0x80;
  let bits = BigInt(len) * 8n;
  for (let i = 0; i < 16; i++) { buf[total - 1 - i] = Number(bits & 255n); bits >>= 8n; }
  const H = H512.slice(), W = new Array(80);
  for (let off = 0; off < total; off += 128) {
    for (let t = 0; t < 16; t++) { let w = 0n; for (let j = 0; j < 8; j++) w = (w << 8n) | BigInt(buf[off + t * 8 + j]); W[t] = w; }
    for (let t = 16; t < 80; t++) {
      const x = W[t - 15], y = W[t - 2];
      const s0 = r64(x, 1n) ^ r64(x, 8n) ^ (x >> 7n);
      const s1 = r64(y, 19n) ^ r64(y, 61n) ^ (y >> 6n);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) & M64;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let t = 0; t < 80; t++) {
      const S1 = r64(e, 14n) ^ r64(e, 18n) ^ r64(e, 41n);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K512[t] + W[t]) & M64;
      const S0 = r64(a, 28n) ^ r64(a, 34n) ^ r64(a, 39n);
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + mj) & M64;
      h = g; g = f; f = e; e = (d + t1) & M64; d = c; c = b; b = a; a = (t1 + t2) & M64;
    }
    H[0] = (H[0] + a) & M64; H[1] = (H[1] + b) & M64; H[2] = (H[2] + c) & M64; H[3] = (H[3] + d) & M64;
    H[4] = (H[4] + e) & M64; H[5] = (H[5] + f) & M64; H[6] = (H[6] + g) & M64; H[7] = (H[7] + h) & M64;
  }
  const out = u8(64);
  for (let i = 0; i < 8; i++) { let v = H[i]; for (let j = 7; j >= 0; j--) { out[i * 8 + j] = Number(v & 255n); v >>= 8n; } }
  return out;
}
function hmac256(key, msg) {
  if (key.length > 64) key = sha256(key);
  const k = u8(64); k.set(key);
  const ip = u8(64), op = u8(64);
  for (let i = 0; i < 64; i++) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
  return sha256(concat(op, sha256(concat(ip, msg))));
}
async function pbkdf2(pass, salt, iter, dkLen, onProgress) {
  const blocks = Math.ceil(dkLen / 32), out = u8(blocks * 32);
  for (let b = 1; b <= blocks; b++) {
    let U = hmac256(pass, concat(salt, be32(b)));
    const T = U.slice();
    for (let i = 1; i < iter; i++) {
      U = hmac256(pass, U);
      for (let j = 0; j < 32; j++) T[j] ^= U[j];
      if ((i & 2047) === 0) { if (onProgress) onProgress(((b - 1) * iter + i) / (blocks * iter)); await tick(); }
    }
    out.set(T, (b - 1) * 32);
  }
  return out.slice(0, dkLen);
}
// v3 keystream: one full 32-byte HMAC block per 32 bytes of data. (The v2 stream below stepped
// 64 bytes per 32-byte block, so bytes 32-63 of every block were never encrypted.)
function streamXor3(key, nonce, data) {
  const out = u8(data.length);
  for (let i = 0; i < data.length; i += 32) {
    const ks = hmac256(key, concat(enc('ks3'), nonce, be32(i / 32)));
    for (let j = 0; j < 32 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j];
  }
  return out;
}
function streamXor(key, nonce, data) {      // legacy v2 - decrypt only
  const out = u8(data.length);
  for (let i = 0; i < data.length; i += 64) {
    const ks = hmac256(key, concat(nonce, be32(i / 64)));
    for (let j = 0; j < 64 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j];
  }
  return out;
}

/* ---------------------------------------------------------------- ed25519 */
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const md = (a, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };
function pw(b, e, m = P) { let r = 1n; b = md(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
const iv = a => pw(md(a), P - 2n);
const D = md(-121665n * iv(121666n));
const SQRT_M1 = pw(2n, (P - 1n) / 4n);
function recoverX(y, sign) {
  if (y >= P) return null;
  const y2 = y * y % P, u = md(y2 - 1n), v = md(D * y2 + 1n);
  if (v === 0n) return null;
  let x = md(u * pw(v, 3n) % P * pw(md(u * pw(v, 7n)), (P - 5n) / 8n));
  const chk = md(v * x % P * x);
  if (chk !== u) { if (chk === md(-u)) x = md(x * SQRT_M1); else return null; }
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = P - x;
  return x;
}
const GY = md(4n * iv(5n)), GX = recoverX(GY, 0);
const G = [GX, GY, 1n, md(GX * GY)];
const IDENT = [0n, 1n, 1n, 0n];
function ptAdd(p, q) {
  const A = md((p[1] - p[0]) * (q[1] - q[0]));
  const B = md((p[1] + p[0]) * (q[1] + q[0]));
  const C = md(2n * p[3] * q[3] * D);
  const E2 = md(2n * p[2] * q[2]);
  const E = md(B - A), F = md(E2 - C), Gg = md(E2 + C), H = md(B + A);
  return [md(E * F), md(Gg * H), md(F * Gg), md(E * H)];
}
function ptMul(p, s) {
  s = md(s, L); if (s === 0n) return IDENT;
  const tbl = [IDENT]; for (let i = 1; i < 16; i++) tbl.push(ptAdd(tbl[i - 1], p));
  let acc = IDENT, started = false;
  for (let i = 63; i >= 0; i--) {
    if (started) { acc = ptAdd(acc, acc); acc = ptAdd(acc, acc); acc = ptAdd(acc, acc); acc = ptAdd(acc, acc); }
    const d = Number((s >> BigInt(i * 4)) & 15n);
    if (d) { acc = ptAdd(acc, tbl[d]); started = true; }
  }
  return acc;
}
let GTBL = null;
function initG() {
  if (GTBL) return;
  GTBL = []; let base = G;
  for (let i = 0; i < 64; i++) {
    const w = [IDENT]; let acc = base;
    for (let j = 1; j < 16; j++) { w.push(acc); acc = ptAdd(acc, base); }
    GTBL.push(w); base = acc;
  }
}
function gMul(s) { initG(); let acc = IDENT; for (let i = 0; i < 64; i++) { const d = Number((s >> BigInt(i * 4)) & 15n); if (d) acc = ptAdd(acc, GTBL[i][d]); } return acc; }
function ptEncode(p) {
  const z = iv(p[2]), x = md(p[0] * z), y = md(p[1] * z);
  const out = u8(32); let v = y;
  for (let i = 0; i < 32; i++) { out[i] = Number(v & 255n); v >>= 8n; }
  if (Number(x & 1n)) out[31] |= 0x80;
  return out;
}
function ptDecode(b) {
  if (b.length !== 32) return null;
  const sign = b[31] >> 7; let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? b[i] & 0x7f : b[i]);
  const x = recoverX(y, sign); if (x === null) return null;
  return [x, y, 1n, md(x * y)];
}
const leBytes = b => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };
function le32(v) { const o = u8(32); for (let i = 0; i < 32; i++) { o[i] = Number(v & 255n); v >>= 8n; } return o; }
const ED = {
  keyFromSeed(seed) {
    if (seed.length !== 32) throw new Error('seed must be 32 bytes');
    const h = sha512(seed), a = h.slice(0, 32);
    a[0] &= 248; a[31] &= 127; a[31] |= 64;
    const scalar = leBytes(a), pub = ptEncode(gMul(scalar));
    return { seed, scalar, prefix: h.slice(32), pub, id: pubToId(pub) };
  },
  sign(msg, key) {
    const r = md(leBytes(sha512(concat(key.prefix, msg))), L);
    const R = ptEncode(gMul(r));
    const k = md(leBytes(sha512(concat(R, key.pub, msg))), L);
    const S = md(r + k * key.scalar, L);
    return concat(R, le32(S));
  },
  verify(msg, sig, pub) {
    try {
      if (sig.length !== 64) return false;
      const R = ptDecode(sig.slice(0, 32)); if (!R) return false;
      const A = ptDecode(pub); if (!A) return false;
      const S = leBytes(sig.slice(32)); if (S >= L) return false;
      const k = md(leBytes(sha512(concat(sig.slice(0, 32), pub, msg))), L);
      const lhs = gMul(S), rhs = ptAdd(R, ptMul(A, k));
      return md(lhs[0] * rhs[2]) === md(rhs[0] * lhs[2]) && md(lhs[1] * rhs[2]) === md(rhs[1] * lhs[2]);
    } catch (e) { return false; }
  }
};
const SPKI = unhex('302a300506032b6570032100');
function pubToId(pub) {
  const der = concat(SPKI, pub), b = b64(der);
  let pem = '-----BEGIN PUBLIC KEY-----\n';
  for (let i = 0; i < b.length; i += 64) pem += b.slice(i, i + 64) + '\n';
  pem += '-----END PUBLIC KEY-----\n';
  return btoa(pem);
}
function idToPub(id) {
  try {
    const pem = atob(String(id).trim());
    const der = unb64(pem.replace(/-----(BEGIN|END)[^-]*-----|\s+/g, ''));
    if (der.length !== 44) return null;
    return der.slice(12);
  } catch (e) { return null; }
}

/* ---------------------------------------------------------------- wallet file */
const WALLET_ITER = 60000;
async function walletEncrypt(key, pass, label, onProgress) {
  const salt = rand(16), nonce = rand(16);
  const dk = await pbkdf2(enc(pass), salt, WALLET_ITER, 64, onProgress);
  const kE = dk.slice(0, 32), kM = dk.slice(32);
  const plain = enc(JSON.stringify({ seed: hex(key.seed), pub: key.id, label, created: nowSec() }));
  const ct = streamXor3(kE, nonce, plain);
  const tag = hmac256(kM, concat(enc('evote-wallet-v3'), salt, nonce, ct));
  return { format: 'evote-wallet', version: 3, pub: key.id, label, created: nowSec(),
           kdf: { alg: 'pbkdf2-hmac-sha256', salt: b64(salt), iter: WALLET_ITER }, nonce: b64(nonce), ct: b64(ct), tag: b64(tag) };
}
async function walletDecrypt(file, pass, onProgress) {
  if (!file || file.format !== 'evote-wallet') throw new Error('not an EVOTE wallet file');
  const salt = unb64(file.kdf.salt), nonce = unb64(file.nonce), ct = unb64(file.ct), tag = unb64(file.tag);
  const dk = await pbkdf2(enc(pass), salt, file.kdf.iter || WALLET_ITER, 64, onProgress);
  const kE = dk.slice(0, 32), kM = dk.slice(32);
  const v3 = file.version === 3;
  const want = hmac256(kM, concat(enc(v3 ? 'evote-wallet-v3' : 'evote-wallet-v2'), salt, nonce, ct));
  let diff = 0; for (let i = 0; i < 32; i++) diff |= want[i] ^ tag[i];
  if (diff !== 0) throw new Error('wrong passphrase (authentication tag mismatch)');
  const data = JSON.parse(dec(v3 ? streamXor3(kE, nonce, ct) : streamXor(kE, nonce, ct)));
  const key = ED.keyFromSeed(unhex(data.seed));
  if (key.id !== file.pub) throw new Error('wallet public key mismatch');
  return { key, label: data.label || file.label || '', created: data.created || file.created || nowSec() };
}

/* ---------------------------------------------------------------- wire + ledger */
function makeLine(key, type, fields) {
  const payload = [type, '1', key.id, String(nowSec()), b64(rand(16)), ...fields.map(String)].join('|');
  return payload + '|' + b64(ED.sign(enc(payload), key));
}
function parseLine(line) {
  const t = String(line).trim();
  const parts = t.split('|');
  if (parts.length < 6 || parts[1] !== '1' || !/^\d+$/.test(parts[3])) return null;
  const sigB = parts.pop();
  let sig; try { sig = unb64(sigB); } catch (e) { return null; }
  const pub = idToPub(parts[2]); if (!pub || sig.length !== 64) return null;
  const payload = parts.join('|');
  return { line: t, hash: hex(sha256(enc(t))), type: parts[0], pub: parts[2], pubBytes: pub,
           ts: parseInt(parts[3], 10), nonce: parts[4], p: parts, sig, payload };
}
function verifyParsed(v) { return ED.verify(enc(v.payload), v.sig, v.pubBytes); }

const S = {
  mode: 'boot', backend: null, boot: null,
  key: null, walletFile: null, label: '', created: 0, pass: '',
  lines: [], byHash: new Map(), verified: new Set(), bad: new Set(),
  st: { tokens: new Map(), votes: new Map(), conflicts: [] },
  lastId: 0, lastSync: 0, syncing: false,
  prefs: { theme: 'midnight', density: 'comfortable', motion: false, sound: true, syncSec: 6, autoSync: true, verify: true,
           viz: { speed: 1, glow: 1, particles: 1, orbit: 1, trails: .5, scale: 1, grid: true } },
  ui: { section: 'overview', coinFilter: 'unspent', coinSort: 'newest', coinQuery: '', sel: new Set(), views: [],
        lfilter: 'all', lquery: '', llimit: 120, adminToken: '', admin: null, voteChoice: null, voteCoin: '', voteCoins: new Set() },
  mesh: { room: '', joined: false, since: 0, peers: new Map(), pcs: new Map(), chans: new Map(), authed: new Map(), making: new Map(), ignore: new Map(), buf: new Map(), myId: hex(rand(4)), ice: [], polling: false, rx: 0, tx: 0 },
  activity: [], selftest: null, undo: null, fileMode: null
};
const OPT_COLORS = ['--indigo', '--cyan', '--green', '--amber', '--magenta', '--violet', '--teal', '--red'];
const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const nameOf = pub => { const L = (S.boot && S.boot.labels) || {}; return L[pub] || (S.key && pub === S.key.id ? (S.label || 'you') : short(pub, 8)); };
const issuerSet = () => new Set(((S.boot && S.boot.issuers) || []).map(i => i.pub));

function replay() {
  const iss = issuerSet();
  const arr = S.lines.filter(l => !S.bad.has(l.hash)).slice().sort((a, b) => a.ts - b.ts || (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));
  const tokens = new Map(), votes = new Map(), conflicts = [];
  const spendOf = new Map();
  for (const l of arr) {
    const p = l.p;
    if (l.type === 'SIGNED_ISSUE' && p.length === 8) {
      if (!iss.has(l.pub)) continue;
      const tok = p[5], owner = p[6], amt = /^\d+$/.test(p[7]) ? parseInt(p[7], 10) : NaN;
      if (!/^[0-9a-f]{64}$/.test(tok) || !(amt > 0)) continue;
      if (!tokens.has(tok)) tokens.set(tok, { hash: tok, owner, amount: amt, spent: false, issuer: l.pub, ts: l.ts, updated: l.ts, history: [l.hash], received: false });
    } else if (l.type === 'SIGNED_TRANSFER' && p.length === 9) {
      const tok = p[5], rcv = p[6], amt = /^\d+$/.test(p[7]) ? parseInt(p[7], 10) : NaN, t = tokens.get(tok);
      if (!t) continue;
      if (t.owner !== l.pub) continue;
      if (t.spent) { conflicts.push({ token: tok, kind: 'transfer after spend', a: spendOf.get(tok), b: l.hash }); continue; }
      if (t.amount !== amt) continue;
      t.owner = rcv; t.updated = l.ts; t.history.push(l.hash); t.received = true; spendOf.set(tok, l.hash);
    } else if (l.type === 'SIGNED_VOTE' && p.length === 7) {
      const tok = p[6], t = tokens.get(tok);
      if (!t) continue;
      let cand = ''; try { cand = dec(unb64(p[5])); } catch (e) { continue; }
      if (!cand.trim()) continue;
      if (t.owner !== l.pub) continue;
      if (t.spent) { conflicts.push({ token: tok, kind: 'double spend', a: spendOf.get(tok), b: l.hash }); continue; }
      t.spent = true; t.updated = l.ts; t.history.push(l.hash); spendOf.set(tok, l.hash);
      votes.set(tok, { candidate: cand, voter: l.pub, ts: l.ts, amount: t.amount, hash: l.hash });
    }
  }
  S.st = { tokens, votes, conflicts };
}
function myCoins(filter) {
  if (!S.key) return [];
  const me = S.key.id, out = [];
  for (const t of S.st.tokens.values()) {
    const mine = t.owner === me, wasMine = t.history.some(h => { const l = S.byHash.get(h); return l && (l.p[6] === me || l.pub === me); });
    if (filter === 'unspent' && (!mine || t.spent)) continue;
    if (filter === 'spent' && !(wasMine && (t.spent || !mine))) continue;
    if (filter === 'incoming' && !(mine && t.received)) continue;
    if (filter === 'all' && !(mine || wasMine)) continue;
    out.push(t);
  }
  return out;
}
function tally() {
  const opts = (S.boot && S.boot.ballot && S.boot.ballot.options) || [];
  const m = new Map(opts.map(o => [o, { weight: 0, count: 0 }]));
  let total = 0;
  for (const v of S.st.votes.values()) {
    if (!m.has(v.candidate)) m.set(v.candidate, { weight: 0, count: 0 });
    const e = m.get(v.candidate); e.weight += v.amount; e.count++; total += v.amount;
  }
  const rows = [...m.entries()].map(([name, e], i) => ({ name, ...e, pct: total ? e.weight / total * 100 : 0, color: OPT_COLORS[i % OPT_COLORS.length] }));
  rows.sort((a, b) => b.weight - a.weight);
  return { rows, total, ballots: S.st.votes.size };
}
async function addLines(rawLines, opts = {}) {
  const fresh = [];
  for (const raw of rawLines) {
    if (typeof raw !== 'string' || raw.length > 4096) continue;
    const v = parseLine(raw);
    if (!v) { continue; }
    if (S.byHash.has(v.hash)) continue;
    S.byHash.set(v.hash, v); S.lines.push(v); fresh.push(v);
  }
  if (!fresh.length) return { added: 0, verified: 0 };
  let ok = 0;
  const skipVerify = opts.skipVerify || !S.prefs.verify;
  for (let i = 0; i < fresh.length; i++) {
    const v = fresh[i];
    if (S.verified.has(v.hash)) { ok++; continue; }
    if (skipVerify) { S.verified.add(v.hash); ok++; continue; }
    if (verifyParsed(v)) { S.verified.add(v.hash); ok++; } else { S.bad.add(v.hash); }
    if (i % 12 === 11) { setProgress((i + 1) / fresh.length); await tick(); }
  }
  setProgress(0);
  replay(); saveLocal(); pushActivity(fresh);
  return { added: fresh.length, verified: ok };
}
function pushActivity(list) {
  for (const v of list.slice(-40)) {
    S.activity.unshift({ type: v.type, pub: v.pub, ts: v.ts, hash: v.hash, token: v.p[5] || '', bad: S.bad.has(v.hash) });
    Viz.pulse(v.type, S.bad.has(v.hash));
  }
  S.activity = S.activity.slice(0, 120);
}

/* ---------------------------------------------------------------- persistence */
const LS = {
  get(k, d) { try { const v = localStorage.getItem('evote.' + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem('evote.' + k, JSON.stringify(v)); } catch (e) {} },
  del(k) { try { localStorage.removeItem('evote.' + k); } catch (e) {} }
};
function saveLocal() {
  LS.set('lines', S.lines.map(l => l.line).slice(-4000));
  LS.set('linesTrunc', S.lines.length > 4000);       // cache holds only the newest 4000 lines
  LS.set('verified', [...S.verified].slice(-6000));
  LS.set('lastId', S.lastId);
}
function savePrefs() { LS.set('prefs', S.prefs); }
function loadPrefs() {
  const p = LS.get('prefs', null);
  if (p) { S.prefs = Object.assign(S.prefs, p); S.prefs.viz = Object.assign({ speed: 1, glow: 1, particles: 1, orbit: 1, trails: .5, scale: 1, grid: true }, p.viz || {}); }
  if (window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches) S.prefs.motion = false;
  S.ui.views = LS.get('views', []);
}

/* ---------------------------------------------------------------- sound */
const Sound = {
  ctx: null,
  ready() { if (!S.prefs.sound) return null; if (!this.ctx) { try { this.ctx = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) { return null; } } if (this.ctx.state === 'suspended') this.ctx.resume(); return this.ctx; },
  tone(f, t0, dur, type, gain) {
    const c = this.ctx; if (!c) return;
    const o = c.createOscillator(), g = c.createGain();
    o.type = type || 'sine'; o.frequency.setValueAtTime(f, c.currentTime + t0);
    g.gain.setValueAtTime(0, c.currentTime + t0);
    g.gain.linearRampToValueAtTime(gain || .06, c.currentTime + t0 + .012);
    g.gain.exponentialRampToValueAtTime(.0001, c.currentTime + t0 + dur);
    o.connect(g); g.connect(c.destination); o.start(c.currentTime + t0); o.stop(c.currentTime + t0 + dur + .02);
  },
  play(name) {
    const c = this.ready(); if (!c) return;
    if (name === 'mint') { [523, 659, 784, 1046].forEach((f, i) => this.tone(f, i * .055, .3, 'triangle', .05)); }
    else if (name === 'vote') { this.tone(660, 0, .16, 'sine', .06); this.tone(990, .07, .26, 'sine', .045); }
    else if (name === 'transfer') { this.tone(420, 0, .14, 'sawtooth', .035); this.tone(720, .06, .2, 'sine', .04); }
    else if (name === 'peer') { this.tone(392, 0, .12, 'sine', .05); this.tone(587, .08, .18, 'sine', .04); }
    else if (name === 'error') { this.tone(180, 0, .22, 'square', .045); this.tone(120, .1, .26, 'square', .04); }
    else if (name === 'tick') { this.tone(1200, 0, .05, 'sine', .018); }
    else if (name === 'unlock') { [392, 523, 659].forEach((f, i) => this.tone(f, i * .06, .26, 'sine', .05)); }
  }
};

/* ---------------------------------------------------------------- visualizer */
const Viz = {
  cv: null, ctx: null, w: 0, h: 0, dpr: 1, raf: 0, t: 0, last: 0, fps: 0, frames: 0, fpsT: 0,
  nodes: [], parts: [], rings: [], pulses: [],
  init() {
    this.cv = $('viz'); if (!this.cv) return;
    this.ctx = this.cv.getContext('2d');
    this.resize();
    new ResizeObserver(() => this.resize()).observe(this.cv.parentElement);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) this.start(); });
    this.start();
  },
  resize() {
    const r = this.cv.parentElement.getBoundingClientRect();
    this.dpr = Math.min(2, window.devicePixelRatio || 1);
    this.w = Math.max(240, r.width); this.h = Math.max(200, r.height);
    this.cv.width = Math.floor(this.w * this.dpr); this.cv.height = Math.floor(this.h * this.dpr);
    this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    this.build();
  },
  build() {
    const pubs = [...new Set([...S.st.tokens.values()].map(t => t.owner))].slice(0, 14);
    const peers = [...S.mesh.peers.keys()];
    const list = [{ id: 'you', label: S.label || 'you', kind: 'you' }];
    if (S.boot && S.boot.serverPub) list.push({ id: S.boot.serverPub, label: 'bulletin board', kind: 'server' });
    peers.forEach(p => list.push({ id: p, label: 'peer ' + p.slice(0, 4), kind: 'peer' }));
    pubs.filter(p => !S.key || p !== S.key.id).slice(0, 10).forEach(p => list.push({ id: p, label: nameOf(p), kind: 'holder' }));
    const n = list.length;
    this.nodes = list.map((d, i) => {
      const a = (i / Math.max(1, n - 1)) * Math.PI * 2;
      const held = [...S.st.tokens.values()].filter(t => t.owner === d.id && !t.spent).length;
      return { ...d, a, r: d.kind === 'you' ? 0 : (d.kind === 'server' ? .52 : .82 + (i % 3) * .07), held,
               spin: .12 + (i % 5) * .035, ph: Math.random() * 6.28 };
    });
    this.rings = S.lines.slice(-26).map((l, i) => ({ a: (i / 26) * 6.283, type: l.type }));
  },
  pulse(type, bad) {
    const count = Math.round((bad ? 3 : 5) * S.prefs.viz.particles);
    const color = bad ? cssVar('--red') : type === 'SIGNED_ISSUE' ? cssVar('--amber') : type === 'SIGNED_VOTE' ? cssVar('--green') : cssVar('--cyan');
    for (let i = 0; i < count; i++) {
      const target = 1 + Math.floor(Math.random() * Math.max(1, this.nodes.length - 1));
      this.parts.push({ t: -Math.random() * .4, target, color, speed: .5 + Math.random() * .6, dir: Math.random() < .5 ? 1 : -1 });
    }
    this.pulses.push({ t: 0, color });
    if (this.parts.length > 420) this.parts.splice(0, this.parts.length - 420);
  },
  start() { if (!this.raf) { this.last = performance.now(); this.raf = requestAnimationFrame(ts => this.loop(ts)); } },
  loop(ts) {
    this.raf = requestAnimationFrame(t => this.loop(t));
    const dt = Math.min(.05, (ts - this.last) / 1000); this.last = ts;
    if (document.hidden) return;
    this.frames++; if (ts - this.fpsT > 500) { this.fps = Math.round(this.frames * 100 / (ts - this.fpsT)); this.frames = 0; this.fpsT = ts; const f = $('hudFps'); if (f) f.textContent = this.fps; }
    if (S.prefs.motion) this.t += dt * S.prefs.viz.speed;
    this.draw(dt);
  },
  draw(dt) {
    const c = this.ctx; if (!c) return;
    const W = this.w, H = this.h, cx = W / 2, cy = H / 2, R = Math.min(W, H) * .39 * S.prefs.viz.orbit;
    const V = S.prefs.viz;
    c.clearRect(0, 0, W, H);
    const g = c.createRadialGradient(cx, cy, 4, cx, cy, Math.max(W, H) * .7);
    g.addColorStop(0, 'rgba(255,255,255,.045)'); g.addColorStop(1, 'rgba(0,0,0,0)');
    c.fillStyle = g; c.fillRect(0, 0, W, H);
    if (V.grid) {
      c.save(); c.globalAlpha = .16; c.strokeStyle = cssVar('--line2'); c.lineWidth = 1;
      for (let i = 1; i <= 4; i++) { c.beginPath(); c.arc(cx, cy, R * i / 4, 0, 6.2832); c.stroke(); }
      for (let i = 0; i < 12; i++) { const a = i / 12 * 6.2832 + this.t * .04; c.beginPath(); c.moveTo(cx, cy); c.lineTo(cx + Math.cos(a) * R * 1.15, cy + Math.sin(a) * R * 1.15); c.stroke(); }
      c.restore();
    }
    const pos = this.nodes.map((n, i) => {
      if (n.kind === 'you') return { x: cx, y: cy, n };
      const a = n.a + this.t * n.spin * (n.kind === 'server' ? .3 : 1);
      const rr = R * n.r + Math.sin(this.t * .8 + n.ph) * 5;
      return { x: cx + Math.cos(a) * rr, y: cy + Math.sin(a) * rr * .78, n };
    });
    c.save();
    pos.forEach((p, i) => {
      if (i === 0) return;
      c.globalAlpha = .30; c.lineWidth = 1;
      const grd = c.createLinearGradient(cx, cy, p.x, p.y);
      grd.addColorStop(0, cssVar('--indigo')); grd.addColorStop(1, p.n.kind === 'server' ? cssVar('--magenta') : cssVar('--cyan'));
      c.strokeStyle = grd; c.beginPath(); c.moveTo(cx, cy); c.lineTo(p.x, p.y); c.stroke();
    });
    c.restore();
    if (S.prefs.motion) {
      for (const p of this.parts) p.t += dt * p.speed * (.4 + V.speed * .6);
      this.parts = this.parts.filter(p => p.t < 1.25);
    }
    c.save();
    for (const p of this.parts) {
      if (p.t < 0) continue;
      const tgt = pos[Math.min(p.target, pos.length - 1)] || pos[0];
      const k = clamp(p.t, 0, 1), from = p.dir > 0 ? { x: cx, y: cy } : tgt, to = p.dir > 0 ? tgt : { x: cx, y: cy };
      const x = from.x + (to.x - from.x) * k, y = from.y + (to.y - from.y) * k;
      const trail = V.trails;
      if (trail > .02) {
        const k0 = clamp(k - trail * .22, 0, 1);
        const x0 = from.x + (to.x - from.x) * k0, y0 = from.y + (to.y - from.y) * k0;
        c.globalAlpha = .35; c.strokeStyle = p.color; c.lineWidth = 1.6;
        c.beginPath(); c.moveTo(x0, y0); c.lineTo(x, y); c.stroke();
      }
      c.globalAlpha = 1; c.fillStyle = p.color;
      c.shadowBlur = 12 * V.glow; c.shadowColor = p.color;
      c.beginPath(); c.arc(x, y, 2.4, 0, 6.2832); c.fill();
    }
    c.restore();
    for (const pu of this.pulses) pu.t += dt * 1.4;
    this.pulses = this.pulses.filter(p => p.t < 1);
    for (const pu of this.pulses) {
      c.save(); c.globalAlpha = (1 - pu.t) * .5; c.strokeStyle = pu.color; c.lineWidth = 2;
      c.beginPath(); c.arc(cx, cy, 16 + pu.t * R * .9, 0, 6.2832); c.stroke(); c.restore();
    }
    pos.forEach((p, i) => {
      const isYou = i === 0, isSrv = p.n.kind === 'server';
      const base = isYou ? 13 : isSrv ? 10 : 6 + Math.min(7, p.n.held * .7);
      const r = base * V.scale * (1 + (S.prefs.motion ? Math.sin(this.t * 2 + i) * .04 : 0));
      const col = isYou ? cssVar('--cyan') : isSrv ? cssVar('--magenta') : p.n.kind === 'peer' ? cssVar('--green') : cssVar('--indigo');
      c.save(); c.shadowBlur = (isYou ? 26 : 14) * V.glow; c.shadowColor = col;
      c.fillStyle = col; c.globalAlpha = isYou ? 1 : .9;
      c.beginPath();
      if (isYou || isSrv) { for (let k = 0; k < 6; k++) { const a = k / 6 * 6.2832 - Math.PI / 2 + this.t * .2; const x = p.x + Math.cos(a) * r, y = p.y + Math.sin(a) * r; k ? c.lineTo(x, y) : c.moveTo(x, y); } c.closePath(); }
      else c.arc(p.x, p.y, r, 0, 6.2832);
      c.fill(); c.restore();
      if (isYou || isSrv || p.n.held > 0) {
        c.save(); c.globalAlpha = .85; c.fillStyle = cssVar('--muted'); c.font = '10px ui-monospace,monospace'; c.textAlign = 'center';
        c.fillText(isYou ? (S.label || 'you') : isSrv ? 'board' : p.n.label.slice(0, 14), p.x, p.y + r + 13);
        if (!isYou && p.n.held) { c.fillStyle = col; c.fillText(p.n.held + '◈', p.x, p.y - r - 6); }
        c.restore();
      }
    });
    const rn = this.rings.length;
    this.rings.forEach((rg, i) => {
      const a = rg.a + this.t * .25, rr = R * 1.16;
      const col = rg.type === 'SIGNED_ISSUE' ? cssVar('--amber') : rg.type === 'SIGNED_VOTE' ? cssVar('--green') : cssVar('--cyan');
      c.save(); c.globalAlpha = .55; c.fillStyle = col; c.shadowBlur = 8 * V.glow; c.shadowColor = col;
      c.beginPath(); c.arc(cx + Math.cos(a) * rr, cy + Math.sin(a) * rr * .78, 2, 0, 6.2832); c.fill(); c.restore();
    });
    const hn = $('hudNodes'), hp = $('hudParticles');
    if (hn) hn.textContent = this.nodes.length;
    if (hp) hp.textContent = this.parts.length;
  },
  exportPNG() {
    try {
      const a = document.createElement('a');
      a.download = 'evote-constellation.png'; a.href = this.cv.toDataURL('image/png'); a.click();
      toast('Snapshot exported', 'ok', 'PNG saved at current settings.');
    } catch (e) { toast('Export failed', 'bad', String(e.message || e)); }
  }
};

/* ---------------------------------------------------------------- backends */
function ServerBackend() {
  async function call(action, body, adminToken) {
    const h = { 'Content-Type': 'application/json' };
    if (adminToken) h['X-Admin-Token'] = adminToken;
    const r = await fetch('?action=' + action, { method: 'POST', headers: h, body: JSON.stringify(body || {}) });
    const j = await r.json().catch(() => ({ ok: false, err: 'bad server response' }));
    if (!r.ok && j.ok !== true) throw new Error(j.err || ('HTTP ' + r.status));
    return j;
  }
  return {
    kind: 'server',
    boot: () => call('boot'),
    install: b => call('install', b),
    pull: since => call('pull', { since }),
    push: lines => call('push', { lines }),
    claim: pub => call('claim', { pub }),
    selftest: b => call('selftest', b),
    admin: (op, b, tok) => call('admin', Object.assign({ op }, b || {}), tok),
    sig: b => call('sig', b)
  };
}
function LocalBackend() {
  const store = {
    installed: LS.get('local.installed', false),
    lines: LS.get('local.lines', []),
    labels: LS.get('local.labels', {}),
    ballot: LS.get('local.ballot', { question: 'Community Treasury — Season 4 allocation', options: ['Developer grants', 'Infrastructure & relays', 'Education & docs', 'Reserve / rainy day'], closed: false }),
    issuers: LS.get('local.issuers', []),
    faucet: LS.get('local.faucet', true),
    claims: LS.get('local.claims', []),
    key: null, token: 'local-demo'
  };
  const persist = () => { LS.set('local.installed', store.installed); LS.set('local.lines', store.lines.slice(-4000)); LS.set('local.labels', store.labels); LS.set('local.ballot', store.ballot); LS.set('local.issuers', store.issuers); LS.set('local.faucet', store.faucet); LS.set('local.claims', store.claims); };
  const seedKey = LS.get('local.seed', null);
  if (seedKey) store.key = ED.keyFromSeed(unhex(seedKey));
  const accepted = lines => { const set = new Set(store.lines); const add = []; for (const l of lines) if (!set.has(l)) { set.add(l); store.lines.push(l); add.push(l); } persist(); return add; };
  const validIssuer = pub => store.issuers.some(i => i.pub === pub);
  function filterValid(lines) {
    const out = [];
    for (const l of lines) { const v = parseLine(l); if (!v || !verifyParsed(v)) continue;
      if (v.type === 'SIGNED_ISSUE' && !validIssuer(v.pub)) continue; out.push(l); }
    return out;
  }
  return {
    kind: 'local', store,
    async boot() {
      return { ok: true, mode: 'local', installed: store.installed, serverPub: store.key ? store.key.id : '',
        issuers: store.issuers, labels: store.labels, ballot: store.ballot, faucet: store.faucet,
        counts: { lines: store.lines.length, tokens: 0, votes: 0, spent: 0, conflicts: 0 }, installGuard: false, ts: nowSec() };
    },
    async install(b) {
      if (store.installed) throw new Error('already installed');
      if (String(b.token || '').length < 8) throw new Error('admin token must be at least 8 characters');
      store.token = b.token;
      const key = ED.keyFromSeed(rand(32));
      store.key = key; LS.set('local.seed', hex(key.seed));
      store.issuers = [{ pub: key.id, label: 'local treasury' }];
      store.labels[key.id] = 'local treasury';
      if (b.question) store.ballot.question = b.question;
      if (b.options && b.options.length) store.ballot.options = b.options;
      store.installed = true; persist();
      let seeded = 0;
      if (b.seed) seeded = await this.admin('seed', { voters: 6, coins: 5 }, b.token).then(r => r.seeded);
      return { ok: true, serverPub: key.id, seeded };
    },
    async pull(since) { const slice = store.lines.slice(since); return { ok: true, lines: slice.map((l, i) => ({ id: since + i + 1, line: l })), last: store.lines.length, total: store.lines.length }; },
    async push(lines) { const add = accepted(filterValid(lines)); return { ok: true, accepted: add.map(l => hex(sha256(enc(l)))), rejected: [], last: store.lines.length }; },
    async claim(pub) {
      if (!store.faucet) throw new Error('faucet disabled by admin');
      if (store.claims.includes(pub)) throw new Error('this address already claimed its allowance');
      store.claims.push(pub);
      const lines = []; for (let i = 0; i < 3; i++) lines.push(makeLine(store.key, 'SIGNED_ISSUE', [hex(sha256(rand(32))), pub, '1']));
      accepted(lines); persist(); return { ok: true, lines };
    },
    async selftest(b) {
      const msg = b.msg + ':server';
      return { ok: true, valid: ED.verify(enc(b.msg), unb64(b.sig), idToPub(b.pub)), serverPub: store.key.id, serverMsg: msg, serverSig: b64(ED.sign(enc(msg), store.key)) };
    },
    async admin(op, b, tok) {
      if (tok !== store.token) throw new Error('admin token rejected');
      if (op === 'state') return { ok: true, counts: { lines: store.lines.length, tokens: S.st.tokens.size, votes: S.st.votes.size, spent: [...S.st.tokens.values()].filter(t => t.spent).length, conflicts: S.st.conflicts.length },
        tokens: [...S.st.tokens.values()].map(t => ({ token_hash: t.hash, owner_pub: t.owner, amount: t.amount, spent: t.spent ? 1 : 0, issuer: t.issuer, ts: t.ts })),
        conflicts: S.st.conflicts.map(c => ({ token_hash: c.token, kind: c.kind, a_line: (S.byHash.get(c.a) || {}).line || '', b_line: (S.byHash.get(c.b) || {}).line || '' })),
        issuers: store.issuers, ballot: store.ballot, faucet: store.faucet, labels: store.labels, claims: store.claims.length };
      if (op === 'issue') {
        if (!idToPub(b.to)) throw new Error('invalid recipient address');
        const lines = []; for (let i = 0; i < clamp(b.count | 0 || 1, 1, 50); i++) lines.push(makeLine(store.key, 'SIGNED_ISSUE', [hex(sha256(rand(32))), b.to, String(clamp(b.amount | 0 || 1, 1, 1000))]));
        accepted(lines); if (b.label) { store.labels[b.to] = b.label; } persist();
        return { ok: true, lines };
      }
      if (op === 'ballot') { store.ballot = { question: b.question || store.ballot.question, options: (b.options || []).filter(Boolean).slice(0, 12), closed: !!b.closed }; persist(); return { ok: true, ballot: store.ballot }; }
      if (op === 'issuer_add') { if (!idToPub(b.pub)) throw new Error('invalid key'); if (!validIssuer(b.pub)) store.issuers.push({ pub: b.pub, label: b.label || '' }); if (b.label) store.labels[b.pub] = b.label; persist(); return { ok: true }; }
      if (op === 'issuer_del') { if (b.pub === store.key.id) throw new Error('cannot remove the treasury issuer'); store.issuers = store.issuers.filter(i => i.pub !== b.pub); persist(); return { ok: true }; }
      if (op === 'label') { store.labels[b.pub] = b.label; persist(); return { ok: true, labels: store.labels }; }
      if (op === 'faucet') { store.faucet = !!b.enabled; persist(); return { ok: true, faucet: store.faucet }; }
      if (op === 'seed') {
        const names = ['ada.lovelace', 'grace.hopper', 'alan.turing', 'margaret.hamilton', 'katherine.j', 'satoshi.n', 'radia.perlman', 'barbara.liskov'];
        const opts = store.ballot.options, people = [], issues = [];
        const nv = clamp(b.voters | 0 || 4, 2, 8), nc = clamp(b.coins | 0 || 4, 1, 8);
        for (let i = 0; i < nv; i++) {
          const k = ED.keyFromSeed(rand(32)); store.labels[k.id] = names[i % names.length];
          const toks = [];
          for (let c = 0; c < nc; c++) { const t = hex(sha256(rand(32))); toks.push(t); issues.push(makeLine(store.key, 'SIGNED_ISSUE', [t, k.id, '1'])); }
          people.push({ k, toks });
        }
        accepted(issues);
        const acts = [];
        people.forEach((p, i) => p.toks.forEach(t => {
          const roll = Math.random();
          if (roll < .62) acts.push(makeLine(p.k, 'SIGNED_VOTE', [b64(enc(opts[Math.floor(Math.random() * opts.length)])), t]));
          else if (roll < .74) acts.push(makeLine(p.k, 'SIGNED_TRANSFER', [t, people[(i + 1) % people.length].k.id, '1', String(nowSec() + 86400)]));
        }));
        accepted(acts); persist();
        return { ok: true, seeded: issues.length + acts.length };
      }
      if (op === 'export') return { ok: true, lines: store.lines.slice() };
      throw new Error('unknown admin op');
    },
    async sig() { throw new Error('WebRTC signalling needs the PHP server'); }
  };
}

/* ---------------------------------------------------------------- toasts / modal / drawer */
function toast(title, kind, msg, actionLabel, actionFn) {
  const colors = { ok: '--green', bad: '--red', warn: '--amber', info: '--cyan' };
  const t = el('div', 'toast');
  t.innerHTML = `<div class="bar" style="background:var(${colors[kind] || '--cyan'})"></div>
    <div style="min-width:0"><b>${esc(title)}</b><p>${esc(msg || '')}</p></div>`;
  if (actionLabel) { const b = el('button', 'btn sm', esc(actionLabel)); b.onclick = () => { actionFn && actionFn(); dismiss(); }; t.appendChild(b); }
  const close = el('button', 'iconbtn', '✕'); close.style.width = '26px'; close.style.height = '26px'; close.onclick = dismiss; t.appendChild(close);
  $('toasts').appendChild(t);
  const timer = setTimeout(dismiss, actionLabel ? 9000 : 4600);
  function dismiss() { clearTimeout(timer); t.classList.add('out'); setTimeout(() => t.remove(), 240); }
  if (kind === 'bad') Sound.play('error');
  return dismiss;
}
function openModal(headHTML, bodyHTML, onMount) {
  $('modalHead').innerHTML = headHTML; $('modalBody').innerHTML = bodyHTML;
  $('modal').classList.add('on'); $('scrim').classList.add('on');
  if (onMount) onMount();
  const f = $('modalBody').querySelector('input,select,button'); if (f) setTimeout(() => f.focus(), 60);
}
function openDrawer(title, html) {
  $('drawerTitle').textContent = title; $('drawerBody').innerHTML = html;
  $('drawer').classList.add('on'); $('scrim').classList.add('on');
}
function closeAll() { $('modal').classList.remove('on'); $('drawer').classList.remove('on'); $('scrim').classList.remove('on'); }
function setProgress(f) { const b = $('syncBar'); if (b) b.style.width = (clamp(f, 0, 1) * 100).toFixed(0) + '%'; }
function download(name, text, mime) {
  const blob = new Blob([text], { type: mime || 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}
function pickFile(mode) { S.fileMode = mode; $('filePick').value = ''; $('filePick').click(); }

/* ---------------------------------------------------------------- render */
let renderQueued = false;
function render() { if (renderQueued) return; renderQueued = true; requestAnimationFrame(() => { renderQueued = false; doRender(); }); }
function doRender() {
  const me = S.key ? S.key.id : null;
  const coins = myCoins('unspent'), t = tally();
  const supply = [...S.st.tokens.values()].reduce((a, x) => a + x.amount, 0);
  $('pillHeight').textContent = S.lines.length;
  $('pillPeerCount').textContent = S.mesh.authed.size;
  $('navCoins').textContent = coins.length; $('navVotes').textContent = S.st.votes.size;
  $('navLines').textContent = S.lines.length; $('navPeers').textContent = S.mesh.authed.size;
  $('ncLines').textContent = S.lines.length; $('ncVerified').textContent = S.verified.size;
  $('ncConflicts').textContent = S.st.conflicts.length;
  $('ncSync').textContent = S.lastSync ? ago(S.lastSync) : '—';
  $('stCoins').textContent = coins.length;
  $('stCoinsSub').textContent = me ? `${coins.reduce((a, c) => a + c.amount, 0)} weight · ${nameOf(me)}` : 'create a wallet to hold coins';
  $('stSupply').textContent = supply; $('stSupplySub').textContent = `${S.st.tokens.size} tokens · ${issuerSet().size} issuer(s)`;
  $('stVotes').textContent = t.ballots; $('stVotesSub').textContent = `${t.total} weight counted`;
  $('stLines').textContent = S.lines.length; $('stLinesSub').textContent = `${S.bad.size} rejected · ${S.st.conflicts.length} conflicts`;
  $('wName').textContent = S.key ? (S.label || 'My wallet') : 'No wallet';
  $('wAddr').textContent = S.key ? short(S.key.id, 8) : 'create or import';
  $('wAvatar').textContent = S.key ? (S.label || 'ME').slice(0, 2).toUpperCase() : '?';
  $('navAdmin').textContent = S.ui.admin ? 'open' : 'locked';
  $('btnClaim').style.display = (S.key && S.boot && S.boot.faucet) ? '' : 'none';
  renderTally($('tallyMini'), t, true);
  renderTally($('tallyFull'), t, false);
  $('tallySub').textContent = `${t.ballots} ballots · ${t.total} weight`;
  $('tallySubMini').textContent = `${t.ballots} ballots`;
  $('ballotTitle').textContent = (S.boot && S.boot.ballot.question) || 'Ballot';
  renderFeed(); renderCoins(); renderVoteComposer(); renderMyVotes(); renderLedger(); renderPeers(); renderAdmin(); renderVault(); renderBanner();
  Viz.build();
}
function renderBanner() {
  const b = $('banner'); const parts = [];
  if (S.mode === 'local') parts.push(`<div class="banner"><b>Local vault mode.</b> No PHP backend reachable — everything runs in this browser with a locally generated issuer. Admin token: <span class="mono">local-demo</span>. Upload <span class="mono">evote.php</span> to a server to make it shared.</div>`);
  if (S.boot && !S.boot.installed) parts.push(`<div class="banner info"><b>Not installed yet.</b> Complete the install to create the treasury issuer.</div>`);
  if (S.st.conflicts.length) parts.push(`<div class="banner"><b>${S.st.conflicts.length} conflict(s) detected.</b> Two different spends reference the same coin — deterministic replay kept the first by (ts, hash). Review them in Admin.</div>`);
  if (S.selftest && !S.selftest.ok) parts.push(`<div class="banner"><b>Crypto self-test failed.</b> ${esc(S.selftest.detail || '')}</div>`);
  b.innerHTML = parts.join('');
}
function renderTally(host, t, mini) {
  if (!host) return;
  const rows = mini ? t.rows.slice(0, 4) : t.rows;
  if (!rows.length) { host.innerHTML = `<div class="empty"><b>No ballots yet</b>Cast the first vote to start the count.</div>`; return; }
  const mine = new Set([...S.st.votes.values()].filter(v => S.key && v.voter === S.key.id).map(v => v.candidate));
  host.innerHTML = rows.map((r, i) => {
    const col = `var(${r.color})`;
    return `<div class="opt ${mine.has(r.name) ? 'mine' : ''}">
      <div class="bar ${i % 2 ? 'stripes' : ''}" style="width:${r.pct.toFixed(1)}%;background:${col};color:${col}"></div>
      <div class="top"><span class="swatch" style="background:${col}"></span><span class="nm">${esc(r.name)}</span>
        ${mine.has(r.name) ? '<span class="badge ok">your vote</span>' : ''}
        <span class="pc" style="color:${col}">${r.pct.toFixed(1)}%</span></div>
      <div class="meta"><span>${r.weight} weight</span><span>${r.count} coin${r.count === 1 ? '' : 's'}</span>${mini ? '' : `<span>${r.count ? (r.weight / r.count).toFixed(1) : '0'} avg</span>`}</div>
    </div>`;
  }).join('');
}
function renderFeed() {
  const host = $('feed');
  if (!S.activity.length) { host.innerHTML = `<div class="empty"><b>Quiet chain</b>Activity appears as lines arrive.</div>`; return; }
  host.innerHTML = S.activity.slice(0, 26).map(a => {
    const map = { SIGNED_ISSUE: ['issue', '◈', '--amber', 'Coin minted'], SIGNED_VOTE: ['vote', '✓', '--green', 'Ballot cast'], SIGNED_TRANSFER: ['transfer', '→', '--cyan', 'Coin transferred'] };
    const m = map[a.type] || ['neutral', '•', '--muted', a.type];
    return `<div class="fitem" data-act="inspect" data-hash="${esc(a.hash)}">
      <div class="ic" style="background:color-mix(in srgb,var(${m[2]}) 18%,transparent);color:var(${m[2]})">${m[1]}</div>
      <div class="tx"><b>${m[3]}${a.bad ? ' · rejected' : ''}</b><span>${esc(nameOf(a.pub))} · ${esc(short(a.token || a.hash, 8))}</span></div>
      <time>${ago(a.ts)}</time></div>`;
  }).join('');
}
function coinList() {
  let list = myCoins(S.ui.coinFilter);
  const q = S.ui.coinQuery.trim().toLowerCase();
  if (q) list = list.filter(t => t.hash.includes(q) || nameOf(t.issuer).toLowerCase().includes(q) || t.issuer.toLowerCase().includes(q));
  const s = S.ui.coinSort;
  list.sort((a, b) => s === 'newest' ? b.updated - a.updated : s === 'oldest' ? a.updated - b.updated :
    s === 'amount' ? b.amount - a.amount : s === 'hash' ? (a.hash < b.hash ? -1 : 1) : nameOf(a.issuer).localeCompare(nameOf(b.issuer)));
  return list;
}
function renderCoins() {
  const list = coinList(), host = $('coinRows');
  $('coinEmpty').innerHTML = list.length ? '' : `<div class="empty">
    <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="9" cy="9" r="6"/><path d="M15.5 4.2a6 6 0 010 15.6"/></svg>
    <b>${S.key ? 'No coins in this view' : 'No wallet yet'}</b>
    ${S.key ? (S.boot && S.boot.faucet ? 'Claim your test allowance, or ask the admin to mint to your address.' : 'Ask the admin to mint coins to your address.') : 'Create or import a wallet in the Vault to hold coins.'}
    <div style="margin-top:12px">${S.key ? '' : '<button class="btn primary" data-act="goto-vault">Open vault</button>'}</div></div>`;
  host.innerHTML = list.slice(0, 300).map(t => {
    const sel = S.ui.sel.has(t.hash);
    const state = t.spent ? '<span class="badge vote">spent · voted</span>' : (S.key && t.owner === S.key.id ? '<span class="badge ok">unspent</span>' : '<span class="badge neutral">moved on</span>');
    return `<tr class="${sel ? 'sel' : ''}" data-act="inspect-coin" data-hash="${esc(t.hash)}">
      <td><input type="checkbox" ${sel ? 'checked' : ''} data-act="coin-sel" data-hash="${esc(t.hash)}" aria-label="select coin"></td>
      <td class="wide"><div class="hash">${esc(short(t.hash, 12))}</div><div class="sub">${t.history.length} line provenance chain</div></td>
      <td><span class="badge neutral mono">${t.amount}</span></td>
      <td><div>${esc(nameOf(t.issuer))}</div><div class="sub mono">${esc(short(t.issuer, 6))}</div></td>
      <td><div>${ago(t.updated)}</div><div class="sub">${t.received ? 'received' : 'minted to you'}</div></td>
      <td>${state}</td>
      <td><div class="row" style="gap:5px;justify-content:flex-end">
        ${!t.spent && S.key && t.owner === S.key.id ? `<button class="btn sm" data-act="vote-with" data-hash="${esc(t.hash)}">Vote</button>
        <button class="btn sm ghost" data-act="transfer" data-hash="${esc(t.hash)}">Send</button>` : ''}
        <button class="btn sm ghost" data-act="export-coin" data-hash="${esc(t.hash)}">Export</button></div></td></tr>`;
  }).join('');
  const n = S.ui.sel.size;
  $('coinBulk').innerHTML = n ? `<div class="bulkbar"><b>${n} selected</b>
    <button class="btn sm primary" data-act="export-selected">Export bundle</button>
    <button class="btn sm" data-act="vote-selected">Vote with selected</button>
    <button class="btn sm ghost" data-act="voucher-selected">Offline voucher</button>
    <button class="btn sm ghost" data-act="clear-sel">Clear</button>
    <span class="tiny faint" style="margin-left:auto">bundle = proof · voucher = signed spend</span></div>` : '';
  const views = S.ui.views;
  $('savedViews').innerHTML = views.length ? `<div class="chips">${views.map((v, i) =>
    `<button class="chip" data-act="load-view" data-i="${i}" title="filter ${esc(v.filter)} · sort ${esc(v.sort)}">${esc(v.name)} ✕</button>`).join('')}</div>` : '';
}
function renderVoteComposer() {
  const opts = (S.boot && S.boot.ballot.options) || [];
  const closed = S.boot && S.boot.ballot.closed;
  $('voteOptions').innerHTML = opts.map((o, i) => `<div class="votecard ${S.ui.voteChoice === o ? 'on' : ''}" data-act="pick-option" data-opt="${esc(o)}">
    <div class="radio"></div><div><b style="font-size:13.5px">${esc(o)}</b><div class="tiny faint">option ${i + 1}</div></div>
    <span class="swatch" style="width:11px;height:11px;border-radius:3px;background:var(${OPT_COLORS[i % OPT_COLORS.length]});margin-left:auto"></span></div>`).join('')
    || '<div class="empty"><b>No options configured</b>The admin has not set the ballot yet.</div>';
  const coins = myCoins('unspent');
  for (const h of [...S.ui.voteCoins]) if (!coins.some(c => c.hash === h)) S.ui.voteCoins.delete(h);
  //if (!S.ui.voteCoins.size && coins.length) S.ui.voteCoins.add(coins[0].hash);
  $('voteCoinList').innerHTML = coins.length ? coins.map(c => `
    <label class="optrow" style="cursor:pointer;margin-bottom:5px">
      <input type="checkbox" data-act="vote-coin" data-hash="${esc(c.hash)}" ${S.ui.voteCoins.has(c.hash) ? 'checked' : ''}>
      <div style="flex:1;min-width:0"><b class="mono" style="font-size:12px">${esc(short(c.hash, 10))}</b>
        <div class="tiny faint">${c.amount} weight · ${ago(c.updated)}</div></div>
      <span class="badge neutral">${c.amount}</span></label>`).join('')
    : '<div class="tiny faint" style="padding:8px">No unspent coins. Claim an allowance or receive a transfer.</div>';
  const weight = coins.filter(c => S.ui.voteCoins.has(c.hash)).reduce((a, c) => a + c.amount, 0);
  $('voteSelCount').textContent = `${S.ui.voteCoins.size} selected · ${weight} weight`;
  $('voteCoinHint').textContent = coins.length ? `${coins.length} unspent available · each selected coin is consumed once` : 'Acquire coins first.';
  $('btnVote').disabled = !S.key || !S.ui.voteCoins.size || !S.ui.voteChoice || closed;
  $('btnVote').textContent = closed ? 'Ballot closed by admin' : !S.key ? 'Unlock a wallet to vote' : `Cast with ${S.ui.voteCoins.size} coin(s) · ${weight} weight`;
  $('ballotDesc').textContent = closed ? 'The admin has closed this ballot. Results remain verifiable.' : 'Each selected coin signs its own ballot line and is spent permanently.';
}
function renderMyVotes() {
  const mine = [...S.st.votes.entries()].filter(([h, v]) => S.key && v.voter === S.key.id);
  $('myVotesSub').textContent = `${mine.length} ballot(s) signed by you`;
  $('myVoteRows').innerHTML = mine.map(([h, v]) => `<tr data-act="inspect" data-hash="${esc(v.hash)}">
    <td class="wide"><b>${esc(v.candidate)}</b></td><td class="mono">${esc(short(h, 10))}</td><td>${v.amount}</td><td>${ago(v.ts)}</td></tr>`).join('');
  $('myVoteEmpty').innerHTML = mine.length ? '' : '<div class="empty"><b>No ballots yet</b>Your signed votes will be listed here.</div>';
}
function renderLedger() {
  const q = S.ui.lquery.trim().toLowerCase();
  let list = S.lines.slice().sort((a, b) => b.ts - a.ts || (a.hash < b.hash ? 1 : -1));
  if (S.ui.lfilter === 'bad') list = list.filter(l => S.bad.has(l.hash));
  else if (S.ui.lfilter !== 'all') list = list.filter(l => l.type === S.ui.lfilter);
  if (q) list = list.filter(l => l.line.toLowerCase().includes(q));
  $('ledgerCount').textContent = `${list.length} line(s)`;
  const slice = list.slice(0, S.ui.llimit);
  $('ledgerRows').innerHTML = slice.map(l => {
    const badge = l.type === 'SIGNED_ISSUE' ? 'issue' : l.type === 'SIGNED_VOTE' ? 'vote' : 'transfer';
    let payload = short(l.p[5] || '', 10);
    if (l.type === 'SIGNED_VOTE') { try { payload = dec(unb64(l.p[5])); } catch (e) {} }
    if (l.type === 'SIGNED_TRANSFER') payload = short(l.p[5], 8) + ' → ' + nameOf(l.p[6]);
    const ok = S.verified.has(l.hash) && !S.bad.has(l.hash);
    return `<tr data-act="inspect" data-hash="${esc(l.hash)}">
      <td class="mono faint">${esc(short(l.hash, 4))}</td>
      <td><span class="badge ${badge}">${l.type.replace('SIGNED_', '')}</span></td>
      <td class="wide"><div>${esc(nameOf(l.pub))}</div><div class="sub mono">${esc(short(l.pub, 6))}</div></td>
      <td class="wide mono" style="font-size:12px">${esc(payload)}</td>
      <td><div>${ago(l.ts)}</div><div class="sub">${new Date(l.ts * 1000).toLocaleDateString()}</div></td>
      <td>${S.bad.has(l.hash) ? '<span class="badge conflict">bad sig</span>' : ok ? '<span class="badge ok">verified</span>' : '<span class="badge neutral">cached</span>'}</td></tr>`;
  }).join('') || '<tr><td colspan="6"><div class="empty"><b>Nothing matches</b>Adjust the filters or import a ledger.</div></td></tr>';
  $('ledgerMore').innerHTML = list.length > slice.length ? `<button class="btn sm" data-act="ledger-more">Load ${Math.min(200, list.length - slice.length)} more</button>` : '';
}
function renderPeers() {
  const bb = $('bbInfo');
  bb.innerHTML = `<dt>mode</dt><dd>${S.mode === 'server' ? 'PHP bulletin board' : 'local vault (browser only)'}</dd>
    <dt>issuer</dt><dd>${esc(short((S.boot && S.boot.serverPub) || '', 12))}</dd>
    <dt>replica height</dt><dd>${S.lines.length} lines · cursor ${S.lastId}</dd>
    <dt>verified</dt><dd>${S.verified.size} signatures · ${S.bad.size} rejected</dd>
    <dt>last sync</dt><dd>${S.lastSync ? fmtTime(S.lastSync) : 'never'}</dd>`;
  $('bbSub').textContent = S.mode === 'server' ? 'same-origin API' : 'offline';
  $('syncSecV').textContent = S.prefs.syncSec + 's';
  $('meshSub').textContent = S.mesh.joined ? `room “${S.mesh.room}” · ${S.mesh.authed.size} authenticated` : 'not joined';
  $('btnMeshLeave').style.display = S.mesh.joined ? '' : 'none';
  $('btnMeshJoin').textContent = S.mesh.joined ? 'Rejoin' : 'Join';
  $('iceInfo').textContent = S.mesh.ice.length ? `ICE: ${S.mesh.ice.map(s => Array.isArray(s.urls) ? s.urls[0] : s.urls).join(' · ')}` : 'ICE servers load when you join.';
  const peers = [...S.mesh.peers.entries()];
  $('peerList').innerHTML = peers.length ? peers.map(([id, p]) => {
    const ch = S.mesh.chans.get(id), auth = S.mesh.authed.has(id);
    return `<div class="optrow"><span class="dot ${auth ? 'live' : ch && ch.readyState === 'open' ? 'info' : 'warn'}"></span>
      <div style="flex:1"><b class="mono" style="font-size:12px">${esc(id)}</b><div class="tiny faint">${auth ? 'authenticated · ' + esc(short(S.mesh.authed.get(id), 6)) : (p.state || 'negotiating')}</div></div>
      <span class="tiny faint mono">↓${p.rx || 0} ↑${p.tx || 0}</span></div>`;
  }).join('') : '<div class="tiny faint">No peers yet. Open this page in another browser and join the same room.</div>';
}
function renderAdmin() {
  const host = $('adminBody'), acts = $('adminActs');
  if (!S.ui.admin) {
    acts.innerHTML = '';
    host.innerHTML = `<div class="card"><div class="locked">
      <svg width="46" height="46" viewBox="0 0 24 24" fill="none" stroke="var(--magenta)" stroke-width="1.6"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/></svg>
      <h3 style="margin:0 0 6px">Admin area</h3>
      <p class="muted" style="max-width:46ch;margin:0 auto 16px">Minting, ballot configuration and issuer allowlist live here. Regular voters never need this token.</p>
      <div class="row" style="max-width:420px;margin:0 auto">
        <input id="adminTok" type="password" placeholder="admin token" style="flex:1">
        <button class="btn mag" data-act="admin-unlock">Unlock</button></div>
      ${S.mode === 'local' ? '<div class="tiny faint" style="margin-top:10px">Local vault token: <span class="mono">local-demo</span> (or the one you set at install)</div>' : ''}
    </div></div>`;
    return;
  }
  const a = S.ui.admin;
  acts.innerHTML = `<button class="btn" data-act="admin-refresh">Refresh</button><button class="btn" data-act="admin-export">Export full ledger</button><button class="btn ghost" data-act="admin-lock">Lock</button>`;
  const known = [...new Set([...S.st.tokens.values()].map(t => t.owner))];
  const bal = a.ballot || (S.boot && S.boot.ballot) || { question: '', options: [] };
  host.innerHTML = `
  <div class="grid g4" style="margin-bottom:16px">
    <div class="stat b"><div class="lb">Minted</div><div class="vl">${a.counts.tokens}</div><div class="dl">${a.counts.spent} spent</div></div>
    <div class="stat c"><div class="lb">Ballots</div><div class="vl">${a.counts.votes}</div><div class="dl">on-chain votes</div></div>
    <div class="stat a"><div class="lb">Claims</div><div class="vl">${a.claims || 0}</div><div class="dl">faucet ${a.faucet ? 'enabled' : 'disabled'}</div></div>
    <div class="stat d"><div class="lb">Conflicts</div><div class="vl">${a.counts.conflicts}</div><div class="dl">equivocation evidence</div></div>
  </div>
  <div class="grid g2">
    <div class="card"><div class="hd"><h3>Mint coins</h3><span class="sub">signed by the treasury issuer</span></div>
      <div class="bd">
        <div class="field"><label class="f">Recipient address</label><input id="mintTo" placeholder="base64 PEM public key id" value="${esc(S.key ? S.key.id : '')}">
          <div class="addrbook">${known.slice(0, 8).map(p => `<button data-act="mint-pick" data-pub="${esc(p)}">${esc(nameOf(p))}</button>`).join('')}</div></div>
        <div class="row"><div style="flex:1"><label class="f">Count</label><input id="mintCount" type="number" min="1" max="50" value="5"></div>
          <div style="flex:1"><label class="f">Amount each</label><input id="mintAmount" type="number" min="1" max="1000" value="1"></div>
          <div style="flex:1"><label class="f">Label (optional)</label><input id="mintLabel" placeholder="voter name"></div></div>
        <button class="btn mag" style="width:100%;margin-top:13px" data-act="mint">Mint &amp; broadcast</button>
        <div class="row" style="margin-top:12px">
          <label class="switch"><input type="checkbox" id="faucetTgl" ${a.faucet ? 'checked' : ''} data-act="faucet"><span class="tr"></span>Public faucet (3 coins per address)</label>
          <button class="btn sm ghost" data-act="seed-demo" style="margin-left:auto">Seed demo voters</button></div>
      </div></div>
    <div class="card"><div class="hd"><h3>Ballot configuration</h3><span class="sub">drag to reorder</span></div>
      <div class="bd">
        <div class="field"><label class="f">Question</label><input id="balQ" value="${esc(bal.question)}"></div>
        <label class="f">Options</label><div id="balOpts">${bal.options.map((o, i) => `
          <div class="optrow drag" draggable="true" data-i="${i}"><span class="grip">⠿</span>
            <input value="${esc(o)}" data-act="bal-opt" data-i="${i}" style="flex:1">
            <button class="iconbtn" data-act="bal-del" data-i="${i}" aria-label="remove">✕</button></div>`).join('')}</div>
        <div class="row" style="margin-top:9px"><input id="balNew" placeholder="add an option" style="flex:1"><button class="btn sm" data-act="bal-add">Add</button></div>
        <div class="row" style="margin-top:13px"><label class="switch"><input type="checkbox" id="balClosed" ${bal.closed ? 'checked' : ''}><span class="tr"></span>Ballot closed</label>
          <button class="btn primary sm" data-act="bal-save" style="margin-left:auto">Save ballot</button></div>
      </div></div>
  </div>
  <div class="grid g2" style="margin-top:16px">
    <div class="card"><div class="hd"><h3>Issuer allowlist</h3><span class="sub">only these keys can mint</span></div>
      <div class="bd">
        ${(a.issuers || []).map(i => `<div class="optrow"><span class="dot live"></span><div style="flex:1"><b style="font-size:12.5px">${esc(i.label || 'issuer')}</b><div class="tiny faint mono">${esc(short(i.pub, 12))}</div></div>
          <button class="btn sm ghost" data-act="issuer-del" data-pub="${esc(i.pub)}">Remove</button></div>`).join('')}
        <div class="row" style="margin-top:10px"><input id="issPub" placeholder="public key id" style="flex:2"><input id="issLabel" placeholder="label" style="flex:1"><button class="btn sm" data-act="issuer-add">Add</button></div>
      </div></div>
    <div class="card"><div class="hd"><h3>Conflicts</h3><span class="sub">two spends, one coin</span></div>
      <div class="scroll" style="max-height:280px">${(a.conflicts || []).length ? a.conflicts.map(c => `
        <div class="fitem"><div class="ic" style="background:color-mix(in srgb,var(--red) 18%,transparent);color:var(--red)">!</div>
          <div class="tx"><b>${esc(c.kind)}</b><span>${esc(short(c.token_hash, 12))}</span></div>
          <button class="btn sm ghost" data-act="conflict-view" data-a="${esc(c.a_line)}" data-b="${esc(c.b_line)}">Inspect</button></div>`).join('')
        : '<div class="empty"><b>No conflicts</b>Every coin has a single spend history.</div>'}</div></div>
  </div>`;
}
function renderVault() {
  const w = $('vaultWallet');
  $('vaultState').textContent = S.key ? 'unlocked in this tab' : (S.walletFile ? 'locked' : 'empty');
  if (!S.key) {
    w.innerHTML = `<div class="empty" style="padding:22px 8px"><b>No wallet loaded</b>
      Create one here, or import an existing <span class="mono">.evote</span> wallet file.
      <div class="row" style="justify-content:center;margin-top:14px">
        <button class="btn primary" data-act="wallet-create">Create wallet</button>
        <button class="btn" data-act="wallet-import">Import file</button></div>
      ${S.walletFile ? `<div class="row" style="justify-content:center;margin-top:12px"><input id="unlockPass" type="password" placeholder="passphrase" style="max-width:220px"><button class="btn" data-act="wallet-unlock">Unlock</button></div>` : ''}</div>`;
  } else {
    w.innerHTML = `<dl class="kv2">
      <dt>Label</dt><dd><input id="wLabel" value="${esc(S.label)}" data-act="wallet-label" style="max-width:240px"></dd>
      <dt>Address</dt><dd>${esc(short(S.key.id, 18))} <button class="btn sm ghost" data-act="copy-addr">copy</button></dd>
      <dt>Created</dt><dd>${S.created ? fmtTime(S.created) : '—'}</dd>
      <dt>Holdings</dt><dd>${myCoins('unspent').length} unspent · ${myCoins('all').length} touched</dd>
      <dt>Storage</dt><dd>encrypted file in this browser only</dd></dl>
      <div class="row" style="margin-top:14px">
        <button class="btn" data-act="wallet-export">Export wallet</button>
        <button class="btn" data-act="receive">Receive</button>
        <button class="btn ghost" data-act="wallet-lock">Lock</button>
        <button class="btn danger" data-act="wallet-forget">Forget</button></div>
      <div class="tiny faint" style="margin-top:10px">The wallet file is PBKDF2-HMAC-SHA256 (${WALLET_ITER.toLocaleString()} iterations) + encrypt-then-MAC. Lose the passphrase and the key is unrecoverable.</div>`;
  }
  const st = S.selftest;
  $('selftestSub').textContent = st ? (st.ok ? 'passed' : 'failed') : 'running…';
  $('selftestBody').innerHTML = st ? `<dl class="kv2">
      <dt>SHA-256</dt><dd>${st.sha ? '✓ constants derived from primes' : '✗'}</dd>
      <dt>Ed25519 round-trip</dt><dd>${st.round ? '✓ sign → verify' : '✗'}</dd>
      <dt>Server verifies us</dt><dd>${st.server ? '✓ libsodium accepted our signature' : '✗'}</dd>
      <dt>We verify server</dt><dd>${st.client ? '✓ libsodium signature verified in JS' : '✗'}</dd>
      <dt>Key id format</dt><dd>${st.pem ? '✓ base64(PEM SPKI) matches OpenSSL' : '✗'}</dd>
      <dt>Detail</dt><dd>${esc(st.detail || 'all checks green')}</dd></dl>
      <button class="btn sm" style="margin-top:12px" data-act="selftest">Run again</button>`
    : '<div class="tiny faint">Running cross-checks…</div>';
  $('prefTheme').value = S.prefs.theme; $('prefDensity').value = S.prefs.density;
  $('prefMotion').checked = S.prefs.motion; $('prefSound').checked = S.prefs.sound; $('prefVerify').checked = S.prefs.verify;
  $('prefAuto').checked = S.prefs.autoSync; $('prefSync').value = S.prefs.syncSec;
}

/* ---------------------------------------------------------------- actions */
async function syncNow(quiet) {
  if (S.syncing || !S.backend) return;
  S.syncing = true;
  try {
    let guard = 0, added = 0;
    for (;;) {
      const r = await S.backend.pull(S.lastId);
      if (!r.lines || !r.lines.length) break;
      const res = await addLines(r.lines.map(x => x.line));
      added += res.added; S.lastId = r.last; guard++;
      if (r.lines.length < 400 || guard > 250) break;
    }
    S.lastSync = nowSec(); saveLocal();
    if (added) { render(); if (!quiet) Sound.play('tick'); }
    else render();
  } catch (e) { if (!quiet) toast('Sync failed', 'bad', String(e.message || e)); }
  finally { S.syncing = false; }
}
async function pushLines(lines, label) {
  try {
    const r = await S.backend.push(lines);
    if (r.rejected && r.rejected.length) toast('Partially rejected', 'warn', `${r.accepted.length} accepted, ${r.rejected.length} rejected: ${r.rejected[0].err}`);
    return r;
  } catch (e) { toast('Broadcast failed', 'bad', String(e.message || e)); return null; }
}
async function castVote() {
  if (!S.key) return toast('Wallet locked', 'warn', 'Unlock your wallet first.');
  const opt = S.ui.voteChoice;
  if (!opt) return toast('Pick an option', 'warn', 'Select a ballot option.');
  const hashes = [...S.ui.voteCoins];
  if (!hashes.length) return toast('No coins selected', 'warn', 'Pick at least one coin.');
  const lines = []; let weight = 0;
  for (const hash of hashes) {
    const t = S.st.tokens.get(hash);
    if (!t || t.spent || t.owner !== S.key.id) return toast('Coin unavailable', 'bad', short(hash, 6) + ' is not spendable by you.');
    lines.push(makeLine(S.key, 'SIGNED_VOTE', [b64(enc(opt)), hash])); weight += t.amount;
  }
  await addLines(lines, { skipVerify: true }); render(); Sound.play('vote'); Viz.pulse('SIGNED_VOTE');
  toast('Ballot cast', 'ok', `${opt} — ${lines.length} coin(s), ${weight} weight.`);
  const r = await pushLines(lines);
  const acc = new Set((r && r.accepted) || []);
  const bad = lines.filter(l => !acc.has(hex(sha256(enc(l)))));
  if (bad.length) {
    const badH = new Set(bad.map(l => hex(sha256(enc(l)))));
    S.lines = S.lines.filter(l => !badH.has(l.hash)); badH.forEach(h => S.byHash.delete(h)); replay(); render();
    toast(bad.length === lines.length ? 'Vote rejected' : 'Partially rejected', 'bad', `${bad.length} line(s) not accepted.`);
  } else { Mesh.broadcast(lines); S.ui.voteCoins.clear(); syncNow(true); }
}
async function doTransfer(hash, to, hours) {
  const t = S.st.tokens.get(hash);
  if (!S.key || !t || t.owner !== S.key.id || t.spent) return toast('Cannot send', 'bad', 'Coin is not spendable by you.');
  if (!idToPub(to)) return toast('Bad address', 'bad', 'Recipient must be a base64 PEM public key id.');
  const line = makeLine(S.key, 'SIGNED_TRANSFER', [hash, to, String(t.amount), String(nowSec() + hours * 3600)]);
  await addLines([line], { skipVerify: true }); render(); Sound.play('transfer');
  toast('Coin sent', 'ok', `${short(hash, 6)} → ${nameOf(to)}`);
  const r = await pushLines([line]);
  if (!r || (r.rejected && r.rejected.length && !r.accepted.length)) {
    S.lines = S.lines.filter(l => l.line !== line); S.byHash.delete(hex(sha256(enc(line)))); replay(); render();
    toast('Transfer rejected', 'bad', (r && r.rejected[0] && r.rejected[0].err) || 'network error');
  } else { Mesh.broadcast([line]); syncNow(true); }
}
function coinBundle(hashes) {
  const coins = hashes.map(h => {
    const t = S.st.tokens.get(h); if (!t) return null;
    return { token_hash: h, amount: t.amount, owner: t.owner, spent: t.spent, lines: t.history.map(x => (S.byHash.get(x) || {}).line).filter(Boolean) };
  }).filter(Boolean);
  return { format: 'evote-coins', version: 2, exported: new Date().toISOString(), owner: S.key ? S.key.id : null, coins };
}
function exportCoins(hashes, name) {
  if (!hashes.length) return toast('Nothing selected', 'warn', 'Select at least one coin.');
  download(name || 'evote-coins.json', JSON.stringify(coinBundle(hashes), null, 2));
  toast('Coins exported', 'ok', `${hashes.length} coin(s) with full provenance.`);
}
function exportLedger(txt) {
  const lines = S.lines.map(l => l.line);
  if (txt) download('evote-ledger.txt', lines.join('\n'), 'text/plain');
  else download('evote-ledger.json', JSON.stringify({ format: 'evote-ledger', version: 2, exported: new Date().toISOString(), lines }, null, 2));
  toast('Ledger exported', 'ok', `${lines.length} signed lines.`);
}
async function importText(text, push) {
  let lines = [], kind = 'ledger';
  const trimmed = text.trim();
  if (trimmed.startsWith('{')) {
    const j = JSON.parse(trimmed);
    if (j.format === 'evote-coins') { kind = 'coin bundle'; j.coins.forEach(c => lines.push(...c.lines)); }
    else if (j.format === 'evote-voucher') { kind = 'voucher'; lines = j.lines || []; }
    else if (j.lines) lines = j.lines;
    else throw new Error('unrecognised JSON file');
  } else lines = trimmed.split('\n').map(s => s.trim()).filter(Boolean);
  const res = await addLines(lines);
  render();
  toast(kind === 'voucher' ? 'Voucher redeemed' : 'Ledger merged', res.added ? 'ok' : 'info', `${res.added} new line(s), ${res.verified} verified, ${S.bad.size} total rejected.`);
  if (push && res.added) await pushLines(lines);
  return res;
}
async function runSelftest() {
  const st = { sha: hex(sha256(enc('abc'))) === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', round: false, server: false, client: false, pem: false, ok: false, detail: '' };
  try {
    const k = ED.keyFromSeed(rand(32));
    const msg = enc('evote selftest ' + Date.now());
    const sig = ED.sign(msg, k);
    st.round = ED.verify(msg, sig, k.pub);
    st.pem = !!idToPub(k.id) && hex(idToPub(k.id)) === hex(k.pub);
    if (S.backend && S.boot && S.boot.installed) {
      const r = await S.backend.selftest({ msg: dec(msg), pub: k.id, sig: b64(sig) });
      st.server = !!r.valid;
      st.client = ED.verify(enc(r.serverMsg), unb64(r.serverSig), idToPub(r.serverPub));
    } else { st.server = st.round; st.client = st.round; st.detail = 'local round-trip (no server installed yet)'; }
    st.ok = st.sha && st.round && st.server && st.client && st.pem;
    if (!st.detail) st.detail = st.ok ? 'JS Ed25519 cross-checked against libsodium' : 'one or more checks failed';
  } catch (e) { st.detail = String(e.message || e); }
  S.selftest = st; $('ncCrypto').textContent = st.ok ? 'verified' : 'check';
  render();
}

/* ---------------------------------------------------------------- wallet flows */
function walletCreateModal() {
  openModal(`<h3>Create a wallet</h3><p class="muted">A fresh Ed25519 key is generated in this tab. The passphrase encrypts the file — it never leaves your browser.</p>`,
    `<div class="field"><label class="f">Label</label><input id="nwLabel" placeholder="e.g. ada" value="my wallet"></div>
     <div class="field"><label class="f">Passphrase</label><input id="nwPass" type="password" placeholder="at least 8 characters"></div>
     <div class="field"><label class="f">Repeat passphrase</label><input id="nwPass2" type="password"></div>
     <div class="progress" style="margin-bottom:12px"><i id="nwBar" style="width:0%"></i></div>
     <div class="row"><button class="btn primary" data-act="wallet-create-go" style="flex:1">Generate &amp; encrypt</button>
       <button class="btn ghost" data-act="close-all">Cancel</button></div>
     <div class="tiny faint" style="margin-top:10px">Deriving the key takes a second — that cost is what makes the file expensive to brute-force.</div>`);
}
async function walletCreateGo() {
  const label = $('nwLabel').value.trim() || 'my wallet';
  const p1 = $('nwPass').value, p2 = $('nwPass2').value;
  if (p1.length < 8) return toast('Passphrase too short', 'warn', 'Use at least 8 characters.');
  if (p1 !== p2) return toast('Passphrases differ', 'warn', 'Both fields must match.');
  const btn = document.querySelector('[data-act="wallet-create-go"]'); btn.disabled = true; btn.textContent = 'Deriving key…';
  try {
    const key = ED.keyFromSeed(rand(32));
    const file = await walletEncrypt(key, p1, label, f => { $('nwBar').style.width = (f * 100).toFixed(0) + '%'; });
    S.key = key; S.label = label; S.created = nowSec(); S.pass = p1; S.walletFile = file;
    LS.set('wallet', file); sessionStorage.setItem('evote.pass', p1);
    closeAll(); Sound.play('unlock'); render(); Viz.build();
    toast('Wallet created', 'ok', 'Export the file to keep it safe.', 'Export now', () => download('evote-wallet.json', JSON.stringify(file, null, 2)));
    if (S.boot && S.boot.faucet) setTimeout(() => toast('Test allowance available', 'info', 'Claim 3 coins to try voting and transfers.', 'Claim', claimAllowance), 900);
  } catch (e) { toast('Could not create wallet', 'bad', String(e.message || e)); }
  finally { btn.disabled = false; btn.textContent = 'Generate & encrypt'; }
}
async function walletUnlock(pass) {
  if (!S.walletFile) return toast('No wallet file', 'warn', 'Create or import one first.');
  try {
    const r = await walletDecrypt(S.walletFile, pass, f => setProgress(f));
    S.key = r.key; S.label = r.label || 'my wallet'; S.created = r.created; S.pass = pass;
    sessionStorage.setItem('evote.pass', pass);
    if (S.walletFile.version !== 3) {               // re-save old v2 files in the fixed v3 format
      const up = await walletEncrypt(r.key, pass, S.label, f => setProgress(f));
      up.created = r.created; S.walletFile = up; LS.set('wallet', up);
      toast('Wallet file upgraded', 'warn', 'Re-saved with the fixed encryption (v3). Export it again and delete old copies.', 'Export now', () => download('evote-wallet.json', JSON.stringify(up, null, 2)));
    }
    setProgress(0); closeAll(); Sound.play('unlock'); render(); Viz.build();
    toast('Wallet unlocked', 'ok', nameOf(S.key.id));
  } catch (e) { setProgress(0); toast('Unlock failed', 'bad', String(e.message || e)); }
}
function walletImportModal() { pickFile('wallet'); }
async function handleFile(file) {
  const text = await file.text();
  if (S.fileMode === 'wallet') {
    try {
      const j = JSON.parse(text);
      if (j.format !== 'evote-wallet') throw new Error('not an EVOTE wallet file');
      S.walletFile = j; LS.set('wallet', j);
      openModal(`<h3>Unlock imported wallet</h3><p class="muted">${esc(j.label || 'wallet')} · ${esc(short(j.pub, 12))}</p>`,
        `<div class="field"><label class="f">Passphrase</label><input id="impPass" type="password"></div>
         <div class="progress" style="margin-bottom:12px"><i id="impBar" style="width:0%"></i></div>
         <button class="btn primary" style="width:100%" data-act="wallet-import-unlock">Unlock wallet</button>`);
    } catch (e) { toast('Import failed', 'bad', String(e.message || e)); }
  } else {
    try { await importText(text, true); } catch (e) { toast('Import failed', 'bad', String(e.message || e)); }
  }
}
async function claimAllowance() {
  if (!S.key) return toast('No wallet', 'warn', 'Create a wallet first.');
  try {
    const r = await S.backend.claim(S.key.id);
    await addLines(r.lines, { skipVerify: true }); render(); Sound.play('mint');
    toast('Allowance claimed', 'ok', `${r.lines.length} coins minted to your address.`);
    syncNow(true);
  } catch (e) { toast('Claim failed', 'bad', String(e.message || e)); }
}
function receiveModal() {
  if (!S.key) return walletCreateModal();
  openModal(`<h3>Receive coins</h3><p class="muted">Give this address to the admin or to anyone sending you a coin. It is your public key — safe to share.</p>`,
    `<label class="f">Your address</label><div class="codebox" id="recvAddr">${esc(S.key.id)}</div>
     <div class="row" style="margin-top:12px"><button class="btn primary" data-act="copy-addr" style="flex:1">Copy address</button>
       <button class="btn" data-act="close-all">Done</button></div>
     <div class="tiny faint" style="margin-top:10px">Label: ${esc(S.label)} · ${myCoins('unspent').length} unspent coins held</div>`);
}
function transferModal(hash) {
  const t = S.st.tokens.get(hash); if (!t) return;
  const known = [...new Set([...S.st.tokens.values()].map(x => x.owner))].filter(p => p !== S.key.id);
  openModal(`<h3>Send coin</h3><p class="muted">${esc(short(hash, 14))} · ${t.amount} weight. Ownership moves; the coin stays unspent and can still vote for its new owner.</p>`,
    `<div class="field"><label class="f">Recipient address</label><input id="tfTo" placeholder="base64 PEM public key id">
      <div class="addrbook">${known.slice(0, 10).map(p => `<button data-act="tf-pick" data-pub="${esc(p)}">${esc(nameOf(p))}</button>`).join('')}</div></div>
     <div class="field"><label class="f">Offer expires in (hours)</label><input id="tfHours" type="number" min="1" max="720" value="24"></div>
     <button class="btn primary" style="width:100%" data-act="transfer-go" data-hash="${esc(hash)}">Sign &amp; send</button>`);
}
function voucherModal(hashes) {
  const coins = hashes.map(h => S.st.tokens.get(h)).filter(t => t && S.key && t.owner === S.key.id && !t.spent);
  if (!coins.length) return toast('Nothing to sign', 'warn', 'Select unspent coins you own.');
  const opts = (S.boot && S.boot.ballot && S.boot.ballot.options) || [];
  openModal(`<h3>Sign offline voucher</h3><p class="muted">Signs ${coins.length} coin(s) now and exports a file. It is <b>not broadcast</b>. Redeem by importing it on any replica — ownership then moves automatically.</p>`,
    `<div class="field"><label class="f">Action</label><select id="voKind"><option value="transfer">Transfer ownership</option><option value="vote">Cast ballot</option></select></div>
     <div id="voTransfer"><div class="field"><label class="f">Recipient address</label><input id="voTo" placeholder="base64 PEM public key id"></div>
       <div class="field"><label class="f">Expires in (hours)</label><input id="voHours" type="number" value="24" min="1" max="720"></div></div>
     <div id="voVote" style="display:none"><div class="field"><label class="f">Option</label><select id="voOpt">${opts.map(o => `<option>${esc(o)}</option>`).join('')}</select></div></div>
     <button class="btn primary" style="width:100%" data-act="voucher-sign" data-hashes="${esc(hashes.join(','))}">Sign &amp; export voucher</button>
     <div class="tiny faint" style="margin-top:10px">Includes the provenance chain so it redeems on a fresh replica. Until redeemed you can still sign a conflicting spend — deliver each voucher once.</div>`);
  $('voKind').addEventListener('change', () => { $('voTransfer').style.display = $('voKind').value === 'transfer' ? '' : 'none'; $('voVote').style.display = $('voKind').value === 'vote' ? '' : 'none'; });
}
function signVoucher(hashes) {
  if (!S.key) return toast('Wallet locked', 'warn', 'Unlock first.');
  const kind = $('voKind').value, spends = [], prov = new Set();
  let to = '', hrs = 24, opt = '';
  if (kind === 'transfer') {
    to = $('voTo').value.trim();
    if (!idToPub(to)) return toast('Bad address', 'bad', 'Recipient must be a valid key id.');
    hrs = clamp(parseInt($('voHours').value, 10) || 24, 1, 720);
  } else {
    opt = $('voOpt').value;
    if (!opt) return toast('Pick an option', 'warn', 'No ballot option selected.');
  }
  for (const h of hashes) {
    const t = S.st.tokens.get(h); if (!t || t.spent || t.owner !== S.key.id) continue;
    t.history.forEach(x => { const l = S.byHash.get(x); if (l) prov.add(l.line); });
    if (kind === 'transfer') spends.push(makeLine(S.key, 'SIGNED_TRANSFER', [h, to, String(t.amount), String(nowSec() + hrs * 3600)]));
    else spends.push(makeLine(S.key, 'SIGNED_VOTE', [b64(enc(opt)), h]));
  }
  if (!spends.length) return toast('Nothing signed', 'warn', 'No spendable coins.');
  download('evote-voucher.json', JSON.stringify({ format: 'evote-voucher', version: 1, kind, created: new Date().toISOString(), signer: S.key.id, lines: [...prov, ...spends], spends: spends.length, note: 'Not yet broadcast. Import on any replica to redeem.' }, null, 2));
  closeAll(); Sound.play('transfer');
  toast('Voucher exported', 'ok', `${spends.length} spend(s) + provenance. Import to redeem.`);
}
function inspectCoin(hash) {
  const t = S.st.tokens.get(hash); if (!t) return;
  const chain = t.history.map(h => S.byHash.get(h)).filter(Boolean);
  openDrawer('Coin ' + short(hash, 8), `
    <dl class="kv2"><dt>Token</dt><dd>${esc(hash)}</dd><dt>Amount</dt><dd>${t.amount}</dd>
      <dt>Owner</dt><dd>${esc(nameOf(t.owner))}</dd><dt>Issuer</dt><dd>${esc(nameOf(t.issuer))}</dd>
      <dt>State</dt><dd>${t.spent ? 'spent (voted)' : 'unspent'}</dd><dt>Minted</dt><dd>${fmtTime(t.ts)}</dd></dl>
    <div class="row" style="margin:14px 0">
      <button class="btn sm" data-act="export-coin" data-hash="${esc(hash)}">Export this coin</button>
      ${!t.spent && S.key && t.owner === S.key.id ? `<button class="btn sm" data-act="vote-with" data-hash="${esc(hash)}">Vote with it</button>
      <button class="btn sm ghost" data-act="transfer" data-hash="${esc(hash)}">Send</button>
      <button class="btn sm ghost" data-act="voucher" data-hash="${esc(hash)}">Offline voucher</button>` : ''}</div>
    <label class="f">Provenance chain (${chain.length} lines)</label>
    ${chain.map((l, i) => `<div class="optrow"><span class="badge ${l.type === 'SIGNED_ISSUE' ? 'issue' : l.type === 'SIGNED_VOTE' ? 'vote' : 'transfer'}">${i + 1}</span>
      <div style="flex:1;min-width:0"><b style="font-size:12px">${esc(l.type.replace('SIGNED_', ''))}</b><div class="tiny faint mono">${esc(nameOf(l.pub))} · ${ago(l.ts)}</div></div>
      <button class="btn sm ghost" data-act="inspect" data-hash="${esc(l.hash)}">View</button></div>`).join('')}`);
}
function inspectLine(hash) {
  const l = S.byHash.get(hash); if (!l) return;
  let payload = '';
  if (l.type === 'SIGNED_VOTE') { try { payload = dec(unb64(l.p[5])); } catch (e) { payload = '(undecodable)'; } }
  openDrawer(l.type.replace('SIGNED_', '') + ' line', `
    <dl class="kv2"><dt>Type</dt><dd>${esc(l.type)}</dd><dt>Signer</dt><dd>${esc(nameOf(l.pub))}</dd>
      <dt>Timestamp</dt><dd>${fmtTime(l.ts)}</dd><dt>Nonce</dt><dd>${esc(l.nonce)}</dd>
      ${payload ? `<dt>Choice</dt><dd>${esc(payload)}</dd>` : ''}
      ${l.p[5] ? `<dt>Token</dt><dd>${esc(l.p[5])}</dd>` : ''}
      ${l.p[6] ? `<dt>Counterparty</dt><dd>${esc(l.p[6].length > 64 ? nameOf(l.p[6]) : l.p[6])}</dd>` : ''}
      <dt>Signature</dt><dd>${S.bad.has(l.hash) ? 'INVALID' : 'Ed25519 · verified'}</dd><dt>Hash</dt><dd>${esc(l.hash)}</dd></dl>
    <label class="f" style="margin-top:14px">Raw wire line</label><div class="codebox">${esc(l.line)}</div>
    <div class="row" style="margin-top:12px"><button class="btn sm" data-act="copy-line" data-hash="${esc(l.hash)}">Copy line</button>
      <button class="btn sm ghost" data-act="reverify" data-hash="${esc(l.hash)}">Re-verify signature</button></div>`);
}

/* ---------------------------------------------------------------- admin flows */
async function adminUnlock() {
  const tok = $('adminTok').value.trim();
  if (!tok) return toast('Token required', 'warn', 'Enter the admin token.');
  try {
    const a = await S.backend.admin('state', {}, tok);
    S.ui.adminToken = tok; S.ui.admin = a; render(); Sound.play('unlock');
    toast('Admin unlocked', 'ok', 'Treasury controls available.');
  } catch (e) { toast('Admin rejected', 'bad', String(e.message || e)); }
}
async function adminRefresh() {
  if (!S.ui.adminToken) return;
  try { S.ui.admin = await S.backend.admin('state', {}, S.ui.adminToken); render(); } catch (e) { toast('Refresh failed', 'bad', String(e.message || e)); }
}
async function adminMint() {
  const to = $('mintTo').value.trim(), count = parseInt($('mintCount').value, 10) || 1, amount = parseInt($('mintAmount').value, 10) || 1;
  const label = $('mintLabel').value.trim();
  try {
    const r = await S.backend.admin('issue', { to, count, amount, label }, S.ui.adminToken);
    await addLines(r.lines, { skipVerify: true });
    Sound.play('mint'); Viz.pulse('SIGNED_ISSUE'); render();
    toast('Minted', 'ok', `${r.lines.length} coin(s) → ${nameOf(to)}`);
    Mesh.broadcast(r.lines); adminRefresh(); syncNow(true);
  } catch (e) { toast('Mint failed', 'bad', String(e.message || e)); }
}
async function adminSaveBallot() {
  const opts = [...document.querySelectorAll('[data-act="bal-opt"]')].map(i => i.value.trim()).filter(Boolean);
  try {
    const r = await S.backend.admin('ballot', { question: $('balQ').value.trim(), options: opts, closed: $('balClosed').checked }, S.ui.adminToken);
    S.boot.ballot = r.ballot; replay(); render(); adminRefresh();
    toast('Ballot saved', 'ok', `${opts.length} options · ${r.ballot.closed ? 'closed' : 'open'}`);
  } catch (e) { toast('Save failed', 'bad', String(e.message || e)); }
}

/* ---------------------------------------------------------------- WebRTC mesh */
const Mesh = {
  async join() {
    if (S.mode !== 'server') return toast('Mesh unavailable', 'warn', 'WebRTC signalling needs the PHP backend.');
    const room = $('meshRoom').value.trim(); if (!room) return toast('Room required', 'warn', 'Name a room to join.');
    try {
      const ice = await S.backend.sig({ op: 'ice' });
      S.mesh.ice = ice.iceServers || [];
      S.mesh.room = room; S.mesh.joined = true; S.mesh.since = 0;
      this.send('', 'presence'); render();
      toast('Joined room', 'ok', `${room} · ${S.mesh.ice.length} ICE server(s)`);
    } catch (e) { toast('Join failed', 'bad', String(e.message || e)); }
  },
  leave() {
    for (const [id] of S.mesh.pcs) this.drop(id);
    S.mesh.joined = false; S.mesh.peers.clear(); render();
    toast('Left room', 'info', 'WebRTC mesh disconnected.');
  },
  send(target, kind, payload) {
    if (!S.mesh.joined) return;
    S.backend.sig({ op: 'push', room: S.mesh.room, sender: S.mesh.myId, target, kind, payload: payload || {} }).catch(() => {});
  },
  learn(peer) {
    if (!peer || peer === S.mesh.myId || S.mesh.peers.has(peer)) return;
    S.mesh.peers.set(peer, { state: 'negotiating', rx: 0, tx: 0 });
    this.send(peer, 'presence');
    if (S.mesh.myId < peer) this.attach(peer, this.pc(peer).createDataChannel('gossip', { ordered: true }));
    render();
  },
  pc(peer) {
    if (S.mesh.pcs.has(peer)) return S.mesh.pcs.get(peer);
    const pc = new RTCPeerConnection({ iceServers: S.mesh.ice });
    S.mesh.pcs.set(peer, pc); S.mesh.making.set(peer, false); S.mesh.ignore.set(peer, false);
    pc.onicecandidate = e => { if (e.candidate) this.send(peer, 'candidate', { candidate: e.candidate }); };
    pc.ondatachannel = e => this.attach(peer, e.channel);
    pc.onnegotiationneeded = async () => {
      try { S.mesh.making.set(peer, true); await pc.setLocalDescription(); this.send(peer, 'offer', { sdp: pc.localDescription }); }
      catch (err) {} finally { S.mesh.making.set(peer, false); }
    };
    pc.onconnectionstatechange = () => {
      const p = S.mesh.peers.get(peer); if (p) { p.state = pc.connectionState; render(); }
      if (pc.connectionState === 'failed' || pc.connectionState === 'closed') this.drop(peer);
    };
    return pc;
  },
  drop(peer) {
    try { const pc = S.mesh.pcs.get(peer); if (pc) pc.close(); } catch (e) {}
    S.mesh.pcs.delete(peer); S.mesh.chans.delete(peer); S.mesh.authed.delete(peer);
    S.mesh.making.delete(peer); S.mesh.ignore.delete(peer); S.mesh.buf.delete(peer); S.mesh.peers.delete(peer);
    render();
  },
  attach(peer, ch) {
    S.mesh.chans.set(peer, ch);
    ch.onopen = () => {
      const p = S.mesh.peers.get(peer); if (p) p.state = 'open';
      if (S.key) { const hello = makeLine(S.key, 'HELLO', []); ch.send(JSON.stringify({ t: 'HELLO', line: hello })); }
      else ch.send(JSON.stringify({ t: 'ANON' }));
      render();
    };
    ch.onclose = () => { S.mesh.authed.delete(peer); S.mesh.chans.delete(peer); render(); };
    ch.onmessage = async ev => {
      let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      const p = S.mesh.peers.get(peer) || { rx: 0, tx: 0 };
      if (m.t === 'HELLO') {
        const v = parseLine(m.line || '');
        if (v && v.type === 'HELLO' && Math.abs(nowSec() - v.ts) < 300 && verifyParsed(v)) {
          S.mesh.authed.set(peer, v.pub); Sound.play('peer');
          ch.send(JSON.stringify({ t: 'SYNC', lines: S.lines.slice(-400).map(l => l.line) }));
          toast('Peer authenticated', 'ok', short(v.pub, 8));
        } else { ch.close(); }
        render(); return;
      }
      if (m.t === 'ANON') { ch.send(JSON.stringify({ t: 'SYNC', lines: S.lines.slice(-400).map(l => l.line) })); return; }
      if (m.t === 'SYNC' && Array.isArray(m.lines)) {
        p.rx += m.lines.length; S.mesh.rx += m.lines.length;
        const res = await addLines(m.lines);
        if (res.added) { render(); syncNow(true); }
      }
    };
  },
  broadcast(lines) {
    for (const [id, ch] of S.mesh.chans) {
      if (ch.readyState !== 'open') continue;
      for (let i = 0; i < lines.length; i += 40) {
        try { ch.send(JSON.stringify({ t: 'SYNC', lines: lines.slice(i, i + 40) })); S.mesh.tx += Math.min(40, lines.length - i); } catch (e) {}
      }
      const p = S.mesh.peers.get(id); if (p) p.tx += lines.length;
    }
  },
  async handle(m) {
    const peer = m.sender;
    if (m.kind === 'presence') { this.learn(peer); return; }
    this.learn(peer);
    const pc = this.pc(peer), polite = S.mesh.myId > peer;
    try {
      if (m.kind === 'offer') {
        const collision = S.mesh.making.get(peer) || pc.signalingState !== 'stable';
        S.mesh.ignore.set(peer, !polite && collision);
        if (S.mesh.ignore.get(peer)) return;
        await pc.setRemoteDescription(m.payload.sdp);
        await this.flush(peer, pc);
        await pc.setLocalDescription();
        this.send(peer, 'answer', { sdp: pc.localDescription });
      } else if (m.kind === 'answer') {
        if (pc.signalingState === 'have-local-offer') { await pc.setRemoteDescription(m.payload.sdp); await this.flush(peer, pc); }
      } else if (m.kind === 'candidate') {
        if (pc.remoteDescription) { try { await pc.addIceCandidate(m.payload.candidate); } catch (e) {} }
        else { const b = S.mesh.buf.get(peer) || []; b.push(m.payload.candidate); S.mesh.buf.set(peer, b); }
      }
    } catch (e) {}
  },
  async flush(peer, pc) { const b = S.mesh.buf.get(peer) || []; S.mesh.buf.set(peer, []); for (const c of b) { try { await pc.addIceCandidate(c); } catch (e) {} } },
  async poll() {
    if (!S.mesh.joined || S.mesh.polling) return;
    S.mesh.polling = true;
    try {
      const r = await S.backend.sig({ op: 'poll', room: S.mesh.room, sender: S.mesh.myId, since: S.mesh.since });
      for (const m of (r.msgs || [])) { S.mesh.since = Math.max(S.mesh.since, m.id); await this.handle(m); }
    } catch (e) {} finally { S.mesh.polling = false; }
  }
};

/* ---------------------------------------------------------------- install / onboarding */
function installModal() {
  const b = (S.boot && S.boot.ballot) || { question: 'Community Treasury — Season 4 allocation', options: ['Developer grants', 'Infrastructure & relays', 'Education & docs', 'Reserve / rainy day'] };
  openModal(`<h3>Install this treasury</h3><p class="muted">First run: this creates the issuer key and the admin token. Whoever completes this screen owns the admin area — do it now.</p>`,
    `<div class="field"><label class="f">Admin token (min 8 chars)</label><input id="inTok" type="password" placeholder="keep this secret"></div>
     ${S.boot && S.boot.installGuard ? '<div class="field"><label class="f">Install key</label><input id="inKey" type="password"></div>' : ''}
     <div class="field"><label class="f">Ballot question</label><input id="inQ" value="${esc(b.question)}"></div>
     <div class="field"><label class="f">Options (one per line)</label><textarea id="inOpts" rows="4">${esc(b.options.join('\n'))}</textarea></div>
     <label class="switch" style="margin-bottom:14px"><input type="checkbox" id="inSeed" checked><span class="tr"></span>Seed demo voters &amp; ballots</label>
     <button class="btn primary" style="width:100%" data-act="install-go">Create treasury &amp; launch</button>`);
}
async function installGo() {
  const token = $('inTok').value;
  const opts = $('inOpts').value.split('\n').map(s => s.trim()).filter(Boolean);
  const btn = document.querySelector('[data-act="install-go"]'); btn.disabled = true; btn.textContent = 'Creating issuer key…';
  try {
    const r = await S.backend.install({ token, question: $('inQ').value.trim(), options: opts, seed: $('inSeed').checked, installKey: $('inKey') ? $('inKey').value : '' });
    S.ui.adminToken = token;
    closeAll(); toast('Treasury created', 'ok', `${r.seeded || 0} demo lines seeded.`);
    await boot(true); onboarding();
  } catch (e) { toast('Install failed', 'bad', String(e.message || e)); btn.disabled = false; btn.textContent = 'Create treasury & launch'; }
}
function onboarding() {
  if (S.key) return;
  openModal(`<h3>Welcome to the console</h3><p class="muted">The ledger is public and already loaded. To hold coins and vote you need a wallet — it is generated here, in your browser, and never sent to the server.</p>`,
    `<div class="row" style="gap:10px">
      <button class="btn primary" style="flex:1" data-act="wallet-create">Create a wallet</button>
      <button class="btn" style="flex:1" data-act="wallet-import">Import wallet file</button></div>
     <button class="btn ghost" style="width:100%;margin-top:10px" data-act="close-all">Explore read-only first</button>
     <div class="tiny faint" style="margin-top:12px">Read-only mode still verifies every signature, lists the ledger and shows live results.</div>`);
}

/* ---------------------------------------------------------------- boot */
async function boot(keepWallet) {
  let backend = ServerBackend(), info = null;
  try { info = await backend.boot(); if (!info || info.ok !== true) throw new Error('bad boot'); }
  catch (e) { backend = LocalBackend(); info = await backend.boot(); }
  S.backend = backend; S.boot = info; S.mode = info.mode === 'server' ? 'server' : 'local';
  $('dotMode').className = 'dot ' + (S.mode === 'server' ? 'live' : 'warn');
  $('txtMode').textContent = S.mode === 'server' ? 'bulletin board' : 'local vault';
  if (!keepWallet) { S.lines = []; S.byHash.clear(); S.lastId = 0; }
  if (info.installed) await syncNow(true);
  render();
  return info;
}
async function init() {
  loadPrefs(); applyPrefs();
  S.walletFile = LS.get('wallet', null);
  const cached = LS.get('lines', []); S.verified = new Set(LS.get('verified', []));
  if (cached.length) { for (const raw of cached) { const v = parseLine(raw); if (v) { S.byHash.set(v.hash, v); S.lines.push(v); } } }
  // A truncated cache is missing the oldest lines (issues of older coins), so pulling only from
  // lastId would leave those coins invisible after a reload. Re-pull the full ledger instead.
  S.lastId = LS.get('linesTrunc', false) ? 0 : LS.get('lastId', 0);
  Viz.init();
  const info = await boot(true);
  replay(); render();
  const saved = sessionStorage.getItem('evote.pass');
  if (S.walletFile && saved) { try { await walletUnlock(saved); } catch (e) {} }
  await runSelftest();
  if (!info.installed) installModal(); else if (!S.key) onboarding();
  hashLink();
  setInterval(() => { if (S.prefs.autoSync && S.boot && S.boot.installed) syncNow(true); }, Math.max(2, S.prefs.syncSec) * 1000);
  setInterval(() => Mesh.poll(), 1300);
  setInterval(() => { if (S.mesh.joined) Mesh.send('', 'presence'); }, 25000);
  setInterval(() => { if (S.lastSync) $('ncSync').textContent = ago(S.lastSync); }, 5000);
  const obs = new IntersectionObserver(es => {
    es.forEach(e => { if (e.isIntersecting) { S.ui.section = e.target.id; document.querySelectorAll('[data-nav]').forEach(a => a.classList.toggle('active', a.dataset.nav === e.target.id)); } });
  }, { rootMargin: '-25% 0px -65% 0px' });
  document.querySelectorAll('main section').forEach(s => obs.observe(s));
}
/* index.php#rawtx=<url-encoded line(s)>  or  #voucher=<url-encoded voucher JSON>
   fills the Sneakernet box. A fragment never reaches the server, so signed lines stay out of logs. */
function hashLink() {
  const m = /^#(rawtx|voucher)=(.+)$/s.exec(location.hash || '');
  if (!m) return;
  let text = '';
  try { text = decodeURIComponent(m[2]).trim(); } catch (e) { return toast('Bad link', 'bad', 'The transaction in this link is damaged.'); }
  history.replaceState(null, '', location.pathname + location.search);
  const box = $('pasteBox'); if (!box || !text) return;
  box.value = text;
  window.scrollTo({ top: box.getBoundingClientRect().top + window.scrollY - 140, behavior: 'smooth' });
  toast(m[1] === 'voucher' ? 'Voucher loaded from link' : 'Transaction loaded from link', 'info', 'Check it in the Sneakernet box, then merge.', 'Verify & merge', async () => {
    try { await importText(box.value.trim(), true); box.value = ''; } catch (err) { toast('Merge failed', 'bad', String(err.message || err)); }
  });
}
function applyPrefs() {
  document.documentElement.dataset.theme = S.prefs.theme;
  document.documentElement.dataset.density = S.prefs.density;
  document.documentElement.dataset.motion = S.prefs.motion ? 'on' : 'off';
  const b = $('btnSound'); if (b) { b.classList.toggle('on', S.prefs.sound); b.title = S.prefs.sound ? 'Sound on — click to mute' : 'Sound muted — click to enable'; }
  const v = S.prefs.viz;
  const set = (id, val, txt) => { const e = $(id); if (e) e.value = val; const t = $(txt); if (t) t.textContent = null; };
  if ($('vSpeed')) { $('vSpeed').value = v.speed * 10; $('vSpeedV').textContent = v.speed.toFixed(1) + '×'; }
  if ($('vGlow')) { $('vGlow').value = v.glow * 10; $('vGlowV').textContent = Math.round(v.glow * 100) + '%'; }
  if ($('vParts')) { $('vParts').value = v.particles * 10; $('vPartsV').textContent = v.particles.toFixed(1) + '×'; }
  if ($('vOrbit')) { $('vOrbit').value = v.orbit * 10; $('vOrbitV').textContent = Math.round(v.orbit * 100) + '%'; }
  if ($('vTrail')) { $('vTrail').value = v.trails * 20; $('vTrailV').textContent = Math.round(v.trails * 100) + '%'; }
  if ($('vScale')) { $('vScale').value = v.scale * 10; $('vScaleV').textContent = v.scale.toFixed(1) + '×'; }
  if ($('vGrid')) $('vGrid').checked = v.grid;
  if ($('vMotion')) $('vMotion').checked = S.prefs.motion;
  if ($('vTheme')) $('vTheme').value = S.prefs.theme;
}

/* ---------------------------------------------------------------- events */
document.addEventListener('click', async e => {
  const nav = e.target.closest('[data-nav]');
  if (nav) { e.preventDefault(); const t = document.getElementById(nav.dataset.nav); if (t) window.scrollTo({ top: t.offsetTop - 74, behavior: S.prefs.motion ? 'smooth' : 'auto' }); return; }
  const f = e.target.closest('[data-filter]');
  if (f) { S.ui.coinFilter = f.dataset.filter; document.querySelectorAll('[data-filter]').forEach(c => c.classList.toggle('on', c === f)); S.ui.sel.clear(); render(); return; }
  const lf = e.target.closest('[data-lfilter]');
  if (lf) { S.ui.lfilter = lf.dataset.lfilter; document.querySelectorAll('[data-lfilter]').forEach(c => c.classList.toggle('on', c === lf)); S.ui.llimit = 120; render(); return; }
  const t = e.target.closest('[data-act]'); if (!t) return;
  const act = t.dataset.act, hash = t.dataset.hash;
  if (act !== 'coin-sel') Sound.ready();
  switch (act) {
    case 'close-all': closeAll(); break;
    case 'sound': S.prefs.sound = !S.prefs.sound; savePrefs(); applyPrefs(); if (S.prefs.sound) Sound.play('tick'); render(); break;
    case 'theme': { const order = ['midnight', 'ember', 'chlorophyll']; S.prefs.theme = order[(order.indexOf(S.prefs.theme) + 1) % 3]; savePrefs(); applyPrefs(); render(); break; }
    case 'goto-admin': window.scrollTo({ top: $('admin').offsetTop - 74, behavior: 'smooth' }); break;
    case 'goto-vault': window.scrollTo({ top: $('vault').offsetTop - 74, behavior: 'smooth' }); break;
    case 'goto-ballot': case 'quick-vote': window.scrollTo({ top: $('ballot').offsetTop - 74, behavior: 'smooth' }); break;
    case 'sync-now': await syncNow(); toast('Synced', 'info', `${S.lines.length} lines in replica.`); break;
    case 'viz-export': Viz.exportPNG(); break;
    case 'viz-reset': S.prefs.viz = { speed: 1, glow: 1, particles: 1, orbit: 1, trails: .5, scale: 1, grid: true }; savePrefs(); applyPrefs(); break;
    case 'viz-random': S.prefs.viz = { speed: +(Math.random() * 2.4 + .2).toFixed(1), glow: +(Math.random() * 1.8).toFixed(1), particles: +(Math.random() * 2.5 + .3).toFixed(1), orbit: +(Math.random() * .8 + .6).toFixed(2), trails: +Math.random().toFixed(2), scale: +(Math.random() * 1.2 + .6).toFixed(1), grid: Math.random() < .6 }; savePrefs(); applyPrefs(); Viz.build(); break;
    case 'claim': await claimAllowance(); break;
    case 'receive': receiveModal(); break;
    case 'copy-addr': if (S.key) { navigator.clipboard.writeText(S.key.id).then(() => toast('Address copied', 'ok', 'Paste it to the sender or admin.')); } break;
    case 'copy-line': { const l = S.byHash.get(hash); if (l) navigator.clipboard.writeText(l.line).then(() => toast('Line copied', 'ok', 'Paste it into any replica.')); break; }
    case 'reverify': { const l = S.byHash.get(hash); if (l) { const ok = verifyParsed(l); if (ok) { S.verified.add(hash); S.bad.delete(hash); } else S.bad.add(hash); replay(); render(); toast(ok ? 'Signature valid' : 'Signature INVALID', ok ? 'ok' : 'bad', short(hash, 8)); } break; }
    case 'inspect': inspectLine(hash); break;
    case 'inspect-coin': if (!e.target.closest('input,button')) inspectCoin(hash); break;
    case 'coin-sel': { e.stopPropagation(); if (t.checked) S.ui.sel.add(hash); else S.ui.sel.delete(hash); render(); break; }
    case 'coin-select-all': { const list = coinList(); if (t.checked) list.forEach(c => S.ui.sel.add(c.hash)); else S.ui.sel.clear(); render(); break; }
    case 'clear-sel': S.ui.sel.clear(); render(); break;
    case 'export-selected': exportCoins([...S.ui.sel], 'evote-coins-selected.json'); break;
    case 'export-coin': e.stopPropagation(); exportCoins([hash], 'evote-coin-' + hash.slice(0, 8) + '.json'); break;
    case 'export-coins-all': exportCoins(myCoins('all').map(c => c.hash), 'evote-coins-all.json'); break;
        case 'vote-coin': if (t.checked) S.ui.voteCoins.add(hash); else S.ui.voteCoins.delete(hash); render(); break;
    case 'vote-select-all': myCoins('unspent').forEach(c => S.ui.voteCoins.add(c.hash)); render(); break;
    case 'vote-select-none': S.ui.voteCoins.clear(); render(); break;
    case 'vote-add-one': { const next = myCoins('unspent').find(c => !S.ui.voteCoins.has(c.hash));
      if (!next) { toast('No more coins', 'warn', 'All unspent coins already selected. Claim or mint more.'); break; }
      S.ui.voteCoins.add(next.hash); render(); break; }
    case 'vote-selected': S.ui.voteCoins = new Set([...S.ui.sel]); window.scrollTo({ top: $('ballot').offsetTop - 74, behavior: 'smooth' }); render(); toast('Coins loaded', 'info', `${S.ui.voteCoins.size} coin(s) ready to vote.`); break;
    case 'vote-with': S.ui.voteCoins = new Set([hash]); window.scrollTo({ top: $('ballot').offsetTop - 74, behavior: 'smooth' }); render(); break;
    case 'voucher': voucherModal([hash]); break;
    case 'voucher-selected': voucherModal([...S.ui.sel]); break;
    case 'voucher-sign': signVoucher(t.dataset.hashes.split(',')); break;
    case 'transfer': e.stopPropagation(); transferModal(hash); break;
    case 'tf-pick': $('tfTo').value = t.dataset.pub; break;
    case 'transfer-go': { const to = $('tfTo').value.trim(), hrs = clamp(parseInt($('tfHours').value, 10) || 24, 1, 720); closeAll(); await doTransfer(hash, to, hrs); break; }
    case 'pick-option': S.ui.voteChoice = t.dataset.opt; render(); break;
    case 'cast-vote': await castVote(); break;
    case 'export-tally': { const tt = tally(); download('evote-results.csv', 'option,weight,coins,percent\n' + tt.rows.map(r => `"${r.name.replace(/"/g, '""')}",${r.weight},${r.count},${r.pct.toFixed(2)}`).join('\n'), 'text/csv'); toast('Results exported', 'ok', 'CSV saved.'); break; }
    case 'export-ledger': exportLedger(false); break;
    case 'export-ledger-txt': exportLedger(true); break;
    case 'export-all': { download('evote-everything.json', JSON.stringify({ format: 'evote-bundle', version: 2, exported: new Date().toISOString(), wallet: S.walletFile, ledger: S.lines.map(l => l.line), coins: coinBundle(myCoins('all').map(c => c.hash)) }, null, 2)); toast('Everything exported', 'ok', 'Wallet file + ledger + coins.'); break; }
    case 'import-ledger': pickFile('ledger'); break;
    case 'paste-ingest': { const v = $('pasteBox').value.trim(); if (!v) break; try { await importText(v, true); $('pasteBox').value = ''; } catch (err) { toast('Merge failed', 'bad', String(err.message || err)); } break; }
    case 'ledger-more': S.ui.llimit += 200; render(); break;
    case 'clear-ledger': { const snap = S.lines.map(l => l.line), id = S.lastId;
      S.lines = []; S.byHash.clear(); S.verified.clear(); S.bad.clear(); S.lastId = 0; replay(); saveLocal(); render();
      toast('Local replica cleared', 'warn', 'Server copy untouched.', 'Undo', async () => { await addLines(snap, { skipVerify: true }); S.lastId = id; saveLocal(); render(); }); break; }
    case 'save-view': { const name = prompt('Name this view', `${S.ui.coinFilter} · ${S.ui.coinSort}`); if (!name) break;
      S.ui.views.push({ name, filter: S.ui.coinFilter, sort: S.ui.coinSort, q: S.ui.coinQuery }); LS.set('views', S.ui.views); render(); toast('View saved', 'ok', name); break; }
    case 'load-view': { const i = +t.dataset.i, v = S.ui.views[i];
      if (e.offsetX > t.offsetWidth - 26) { S.ui.views.splice(i, 1); LS.set('views', S.ui.views); render(); toast('View removed', 'info', v.name, 'Undo', () => { S.ui.views.splice(i, 0, v); LS.set('views', S.ui.views); render(); }); }
      else { S.ui.coinFilter = v.filter; S.ui.coinSort = v.sort; S.ui.coinQuery = v.q || ''; $('coinQuery').value = S.ui.coinQuery; $('coinSort').value = v.sort;
        document.querySelectorAll('[data-filter]').forEach(c => c.classList.toggle('on', c.dataset.filter === v.filter)); render(); }
      break; }
    case 'mesh-join': await Mesh.join(); break;
    case 'mesh-leave': Mesh.leave(); break;
    case 'admin-unlock': await adminUnlock(); break;
    case 'admin-lock': S.ui.admin = null; S.ui.adminToken = ''; render(); break;
    case 'admin-refresh': await adminRefresh(); break;
    case 'admin-export': { try { const r = await S.backend.admin('export', {}, S.ui.adminToken); download('evote-server-ledger.json', JSON.stringify({ format: 'evote-ledger', version: 2, lines: r.lines }, null, 2)); toast('Server ledger exported', 'ok', `${r.lines.length} lines.`); } catch (err) { toast('Export failed', 'bad', String(err.message || err)); } break; }
    case 'mint': await adminMint(); break;
    case 'mint-pick': $('mintTo').value = t.dataset.pub; break;
    case 'faucet': { try { await S.backend.admin('faucet', { enabled: t.checked }, S.ui.adminToken); S.boot.faucet = t.checked; adminRefresh(); toast('Faucet ' + (t.checked ? 'enabled' : 'disabled'), 'info', ''); } catch (err) { toast('Failed', 'bad', String(err.message || err)); } break; }
    case 'seed-demo': { try { const r = await S.backend.admin('seed', { voters: 4, coins: 4 }, S.ui.adminToken); await syncNow(true); Sound.play('mint'); toast('Demo voters seeded', 'ok', `${r.seeded} lines added.`); adminRefresh(); } catch (err) { toast('Seed failed', 'bad', String(err.message || err)); } break; }
    case 'bal-add': { const v = $('balNew').value.trim(); if (!v) break; const host = $('balOpts'); const i = host.children.length;
      host.appendChild(el('div', 'optrow drag', `<span class="grip">⠿</span><input value="${esc(v)}" data-act="bal-opt" data-i="${i}" style="flex:1"><button class="iconbtn" data-act="bal-del" data-i="${i}">✕</button>`));
      host.lastChild.draggable = true; $('balNew').value = ''; break; }
    case 'bal-del': t.closest('.optrow').remove(); break;
    case 'bal-save': await adminSaveBallot(); break;
    case 'issuer-add': { try { await S.backend.admin('issuer_add', { pub: $('issPub').value.trim(), label: $('issLabel').value.trim() }, S.ui.adminToken); await adminRefresh(); await boot(true); toast('Issuer added', 'ok', ''); } catch (err) { toast('Failed', 'bad', String(err.message || err)); } break; }
    case 'issuer-del': { const pub = t.dataset.pub; try { await S.backend.admin('issuer_del', { pub }, S.ui.adminToken); await adminRefresh(); await boot(true);
      toast('Issuer removed', 'warn', short(pub, 8), 'Undo', async () => { await S.backend.admin('issuer_add', { pub }, S.ui.adminToken); await adminRefresh(); await boot(true); }); } catch (err) { toast('Failed', 'bad', String(err.message || err)); } break; }
    case 'conflict-view': openDrawer('Conflict evidence', `<label class="f">Spend A (kept)</label><div class="codebox">${esc(t.dataset.a)}</div><label class="f" style="margin-top:12px">Spend B (rejected)</label><div class="codebox">${esc(t.dataset.b)}</div><p class="tiny faint" style="margin-top:12px">Both lines carry valid signatures from the same owner. Deterministic replay keeps the earlier (ts, hash); the pair is proof of equivocation.</p>`); break;
    case 'wallet-create': walletCreateModal(); break;
    case 'wallet-create-go': await walletCreateGo(); break;
    case 'wallet-import': walletImportModal(); break;
    case 'wallet-import-unlock': await walletUnlock($('impPass').value); break;
    case 'wallet-unlock': await walletUnlock($('unlockPass').value); break;
    case 'wallet-export': if (S.walletFile) { download('evote-wallet.json', JSON.stringify(S.walletFile, null, 2)); toast('Wallet exported', 'ok', 'Encrypted file saved.'); } else toast('No wallet', 'warn', 'Create one first.'); break;
    case 'wallet-lock': S.key = null; S.pass = ''; sessionStorage.removeItem('evote.pass'); render(); toast('Wallet locked', 'info', 'Passphrase required to sign again.'); break;
    case 'wallet-forget': { const f = S.walletFile; S.key = null; S.walletFile = null; S.pass = ''; LS.del('wallet'); sessionStorage.removeItem('evote.pass'); render();
      toast('Wallet forgotten', 'warn', 'Removed from this browser.', 'Undo', () => { S.walletFile = f; LS.set('wallet', f); render(); }); break; }
    case 'install-go': await installGo(); break;
    case 'selftest': await runSelftest(); toast('Self-test complete', S.selftest.ok ? 'ok' : 'bad', S.selftest.detail); break;
  }
});
document.addEventListener('input', e => {
  const t = e.target;
  if (t.dataset.act === 'coin-query') { S.ui.coinQuery = t.value; render(); }
  if (t.dataset.act === 'ledger-query') { S.ui.lquery = t.value; S.ui.llimit = 120; render(); }
  if (t.dataset.act === 'wallet-label' && S.key) { S.label = t.value; if (S.walletFile) { S.walletFile.label = t.value; LS.set('wallet', S.walletFile); } render(); }
  if (t.dataset.viz) {
    const k = t.dataset.viz;
    if (k === 'theme') { S.prefs.theme = t.value; applyPrefs(); }
    else if (k === 'grid') S.prefs.viz.grid = t.checked;
    else if (k === 'motion') { S.prefs.motion = t.checked; applyPrefs(); }
    else S.prefs.viz[k] = (k === 'trails' ? +t.value / 20 : +t.value / 10);
    savePrefs(); applyPrefs();
  }
  if (t.dataset.pref) {
    const k = t.dataset.pref;
    if (k === 'syncSec') S.prefs.syncSec = clamp(+t.value, 2, 30);
    else if (t.type === 'checkbox') S.prefs[k] = t.checked;
    else S.prefs[k] = t.value;
    savePrefs(); applyPrefs(); render();
  }
});
document.addEventListener('change', e => {
  const t = e.target;
  if (t.dataset.act === 'coin-sort') { S.ui.coinSort = t.value; render(); }
  if (t.id === 'voteCoin') S.ui.voteCoin = t.value;
  if (t.id === 'filePick' && t.files && t.files[0]) handleFile(t.files[0]);
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeAll();
  if (e.key === '/' && !/input|textarea|select/i.test(document.activeElement.tagName)) { e.preventDefault(); window.scrollTo({ top: $('coins').offsetTop - 74, behavior: 'smooth' }); setTimeout(() => $('coinQuery').focus(), 320); }
  if (e.key === 'Enter' && document.activeElement.id === 'adminTok') adminUnlock();
  if (e.key === 'Enter' && document.activeElement.id === 'unlockPass') walletUnlock($('unlockPass').value);
  if (e.key === 'Enter' && document.activeElement.id === 'impPass') walletUnlock($('impPass').value);
});
let dragEl = null;
document.addEventListener('dragstart', e => { const r = e.target.closest('.drag'); if (!r) return; dragEl = r; e.dataTransfer.effectAllowed = 'move'; try { e.dataTransfer.setData('text/plain', r.dataset.i || ''); } catch (err) {} });
document.addEventListener('dragover', e => { const r = e.target.closest('.drag'); if (!r || !dragEl || r === dragEl) return; e.preventDefault(); r.classList.add('over'); });
document.addEventListener('dragleave', e => { const r = e.target.closest('.drag'); if (r) r.classList.remove('over'); });
document.addEventListener('drop', e => {
  const r = e.target.closest('.drag'); if (!r || !dragEl || r === dragEl) return;
  e.preventDefault(); r.classList.remove('over');
  const host = r.parentElement;
  const kids = [...host.children];
  if (kids.indexOf(dragEl) < kids.indexOf(r)) host.insertBefore(dragEl, r.nextSibling); else host.insertBefore(dragEl, r);
  [...host.children].forEach((c, i) => { c.dataset.i = i; const inp = c.querySelector('input'); if (inp) inp.dataset.i = i; const b = c.querySelector('button'); if (b) b.dataset.i = i; });
  dragEl = null;
});
window.addEventListener('error', ev => { console.error(ev.error || ev.message); });
/* ============ BULK SEND · My Coins multi-select → one address (self-contained) ============ */
const BULK = { hashes: new Set(), busy: false };

function bulkKnown() {
  const me = S.key ? S.key.id : '', set = new Set();
  for (const t of S.st.tokens.values()) if (t.owner && t.owner !== me) set.add(t.owner);
  if (S.boot && S.boot.serverPub && S.boot.serverPub !== me) set.add(S.boot.serverPub);
  return [...set].slice(0, 12);
}
function bulkCoins() {
  return [...BULK.hashes].map(h => S.st.tokens.get(h)).filter(t => t && S.key && t.owner === S.key.id && !t.spent);
}
function bulkWeight() { return bulkCoins().reduce((a, t) => a + t.amount, 0); }

function transferModal(hash) {
  if (!S.key) return toast('Wallet locked', 'warn', 'Unlock your wallet to send coins.');
  if (!S.st.tokens.get(hash)) return toast('Coin not found', 'bad', 'That coin is not in your replica.');
  const sel = S.ui.sel;
  const start = (sel.size > 1 && sel.has(hash)) ? [...sel] : [hash];
  BULK.hashes = new Set(start.filter(h => { const t = S.st.tokens.get(h); return t && t.owner === S.key.id && !t.spent; }));
  BULK.busy = false;
  const known = bulkKnown();
  openModal(`<h3>Send coins</h3><p class="muted">Move one or many coins to a single address. Ownership transfers on the ledger; the coins stay unspent and can still vote for their new owner.</p>`, `
    <div class="field"><label class="f">Recipient address</label>
      <input id="btTo" placeholder="base64 PEM public key id" autocomplete="off" spellcheck="false">
      <div class="addrbook">${known.map(p => `<button data-act="bt-pick" data-pub="${esc(p)}">${esc(nameOf(p))}</button>`).join('')}</div>
      <div class="tiny faint" id="btToHint" style="margin-top:6px">Paste an address or pick a known holder.</div></div>
    <div class="row" style="align-items:flex-end;margin-bottom:6px">
      <div style="flex:1;min-width:150px"><label class="f">Send weight</label><input id="btWeight" type="number" min="1" step="1" placeholder="e.g. 7 - picks the coins for you"></div>
      <button class="btn sm" data-act="bt-weight" style="margin-bottom:2px">Pick coins</button></div>
    <div class="tiny faint" id="btWeightHint" style="margin-bottom:10px"></div>
    <div class="row" style="align-items:flex-end">
      <div style="flex:1;min-width:150px"><label class="f">Offer expires in (hours)</label><input id="btHours" type="number" min="1" max="720" value="24"></div>
      <div class="row" style="gap:6px;padding-bottom:2px">
        <button class="btn sm ghost" data-act="bt-all">All unspent</button>
        <button class="btn sm ghost" data-act="bt-none">Clear</button>
        ${sel.size ? `<button class="btn sm ghost" data-act="bt-include-sel">+ ${sel.size} selected</button>` : ''}
      </div></div>
    <label class="f" style="margin-top:12px">Coins in this transfer</label>
    <div id="btList" style="max-height:210px;overflow:auto;border:1px solid var(--line);border-radius:10px;padding:6px"></div>
    <div id="btSummary" style="margin-top:12px"></div>
    <div class="progress" style="margin:12px 0"><i id="btBar" style="width:0%"></i></div>
    <div class="row">
      <button class="btn primary" id="btSend" data-act="bt-send" style="flex:1">Sign &amp; send</button>
      <button class="btn" data-act="bt-voucher">Sign offline</button>
      <button class="btn ghost" data-act="close-all">Cancel</button></div>
    <div class="tiny faint" style="margin-top:10px">Each coin signs its own line, so a partial rejection never moves the others. Accepted transfers are permanent.</div>`);
  bulkRender();
  setTimeout(() => { const i = $('btTo'); if (i) i.focus(); }, 70);
}

/* Pick unspent coins that add up to exactly `target` weight. Coins can't be split, so when no
   exact set exists it returns the nearest totals below and above instead. Bounded subset-sum
   per distinct coin amount; falls back to largest-first greedy for huge inputs. */
function weightPlan(coins, target) {
  const total = coins.reduce((a, c) => a + c.amount, 0);
  if (!(target >= 1) || !coins.length) return { exact: null, below: null, above: null, total };
  const groups = new Map();
  [...coins].sort((a, b) => a.updated - b.updated).forEach(c => { if (!groups.has(c.amount)) groups.set(c.amount, []); groups.get(c.amount).push(c); });
  const amts = [...groups.keys()].sort((a, b) => b - a);
  const lim = Math.min(total, target + amts[0]);
  const build = s => { const out = []; for (let k = amts.length - 1; k >= 0; k--) { const n = layers[k][s]; out.push(...groups.get(amts[k]).slice(0, n)); s -= n * amts[k]; } return out; };
  let layers = [];
  if (amts.length * (lim + 1) > 3e6) {                 // greedy fallback
    const pick = []; let sum = 0;
    for (const c of [...coins].sort((a, b) => b.amount - a.amount)) if (sum + c.amount <= target) { pick.push(c); sum += c.amount; }
    return sum === target ? { exact: pick, below: null, above: null, total } : { exact: null, below: sum ? { weight: sum, coins: pick } : null, above: null, total };
  }
  let reach = new Uint8Array(lim + 1); reach[0] = 1;
  for (const a of amts) {
    const cnt = groups.get(a).length, nr = reach.slice(), u = new Uint32Array(lim + 1);
    for (let s = a; s <= lim; s++) if (!reach[s] && nr[s - a] && u[s - a] < cnt) { nr[s] = 1; u[s] = u[s - a] + 1; }
    layers.push(u); reach = nr;
  }
  if (target <= lim && reach[target]) return { exact: build(target), below: null, above: null, total };
  let lo = Math.min(target, lim); while (lo > 0 && !reach[lo]) lo--;
  let hi = target + 1; while (hi <= lim && !reach[hi]) hi++;
  return { exact: null, total,
           below: lo > 0 ? { weight: lo, coins: build(lo) } : null,
           above: hi <= lim ? { weight: hi, coins: build(hi) } : null };
}
function bulkPickWeight(w) {
  const hint = $('btWeightHint'); if (!hint) return;
  const target = w != null ? w : parseInt(($('btWeight') || {}).value, 10);
  if (!(target >= 1)) { hint.textContent = 'Enter a whole number of weight to send.'; return; }
  const plan = weightPlan(myCoins('unspent'), target);
  const use = list => { BULK.hashes = new Set(list.map(c => c.hash)); bulkRender(); };
  if (plan.exact) { use(plan.exact); $('btWeight').value = target; hint.textContent = `Picked ${plan.exact.length} coin(s) = exactly ${target} weight.`; return; }
  BULK.hashes.clear(); bulkRender();                  // never leave an old pick selected when there is no exact match
  if (target > plan.total) { hint.textContent = `You only hold ${plan.total} unspent weight.`; return; }
  const opt = o => o ? `<button class="btn sm ghost" data-act="bt-weight-alt" data-w="${o.weight}">Use ${o.weight} (${o.coins.length} coin${o.coins.length === 1 ? '' : 's'})</button>` : '';
  hint.innerHTML = `No exact set of coins adds up to ${target} (coins can't be split). Closest: ${opt(plan.below)} ${opt(plan.above)}`;
}

function bulkRender() {
  const list = $('btList'); if (!list) return;
  const all = myCoins('unspent'), coins = bulkCoins();
  list.innerHTML = all.length ? all.map(c => {
    const on = BULK.hashes.has(c.hash);
    return `<div class="optrow" data-act="bt-toggle" data-hash="${esc(c.hash)}" style="cursor:pointer;margin-bottom:5px;${on ? 'border-color:var(--cyan);background:color-mix(in srgb,var(--cyan) 10%,transparent)' : ''}">
      <input type="checkbox" ${on ? 'checked' : ''} style="pointer-events:none" tabindex="-1" aria-hidden="true">
      <div style="flex:1;min-width:0"><b class="mono" style="font-size:12px">${esc(short(c.hash, 10))}</b><div class="tiny faint">${c.amount} weight · ${ago(c.updated)}</div></div>
      <span class="badge ${on ? 'ok' : 'neutral'}">${on ? 'included' : c.amount}</span></div>`;
  }).join('') : '<div class="tiny faint" style="padding:8px">No unspent coins available.</div>';
  const to = (($('btTo') || {}).value || '').trim();
  const valid = !!idToPub(to) && to !== S.key.id;
  const w = bulkWeight();
  $('btSummary').innerHTML = `<div class="optrow" style="border-color:color-mix(in srgb,var(--indigo) 45%,var(--line));background:linear-gradient(90deg,color-mix(in srgb,var(--indigo) 14%,transparent),transparent)">
    <div style="flex:1"><b style="font-size:13px">${coins.length} coin${coins.length === 1 ? '' : 's'} · ${w} weight</b>
      <div class="tiny faint">${valid ? 'to ' + esc(nameOf(to)) : 'recipient not set'}</div></div>
    <span class="badge ${valid && coins.length ? 'ok' : 'neutral'}">${valid && coins.length ? 'ready' : 'incomplete'}</span></div>`;
  const btn = $('btSend');
  btn.disabled = BULK.busy || !valid || !coins.length;
  if (!BULK.busy) btn.textContent = coins.length > 1 ? `Sign & send ${coins.length} coins` : 'Sign & send 1 coin';
  const hint = $('btToHint');
  if (hint) hint.textContent = !to ? 'Paste an address or pick a known holder.'
    : to === S.key.id ? 'That is your own address — choose a different recipient.'
    : valid ? 'Address looks valid.' : 'Not a valid base64 PEM public key id.';
}

async function bulkSend() {
  if (BULK.busy) return;
  const to = $('btTo').value.trim();
  if (!idToPub(to)) return toast('Bad address', 'bad', 'Recipient must be a valid public key id.');
  if (to === S.key.id) return toast('Own address', 'warn', 'Pick a different recipient.');
  const coins = bulkCoins();
  if (!coins.length) return toast('Nothing to send', 'warn', 'Include at least one unspent coin.');
  const hrs = clamp(parseInt($('btHours').value, 10) || 24, 1, 720);
  BULK.busy = true;
  const btn = $('btSend'); btn.disabled = true;
  const lines = [], weights = [];
  for (let i = 0; i < coins.length; i++) {
    btn.textContent = `Signing ${i + 1}/${coins.length}…`;
    $('btBar').style.width = ((i / coins.length) * 60).toFixed(0) + '%';
    lines.push(makeLine(S.key, 'SIGNED_TRANSFER', [coins[i].hash, to, String(coins[i].amount), String(nowSec() + hrs * 3600)]));
    weights.push(coins[i].amount);
    await tick();
  }
  $('btBar').style.width = '70%';
  await addLines(lines, { skipVerify: true });
  render(); Sound.play('transfer'); coins.forEach(() => Viz.pulse('SIGNED_TRANSFER'));
  const accepted = new Set();
  let netErr = '';
  for (let i = 0; i < lines.length; i += 200) {
    try {
      const r = await S.backend.push(lines.slice(i, i + 200));
      ((r && r.accepted) || []).forEach(h => accepted.add(h));
    } catch (err) { netErr = String(err.message || err); }
    $('btBar').style.width = (70 + Math.min(1, (i + 200) / lines.length) * 30).toFixed(0) + '%';
    await tick();
  }
  const okLines = [], bad = [];
  lines.forEach((l, i) => (accepted.has(hex(sha256(enc(l)))) ? okLines.push({ l, w: weights[i] }) : bad.push(l)));
  if (bad.length) {
    const badH = new Set(bad.map(l => hex(sha256(enc(l)))));
    S.lines = S.lines.filter(l => !badH.has(l.hash));
    badH.forEach(h => { S.byHash.delete(h); S.verified.delete(h); });
    replay();
  }
  BULK.busy = false; $('btBar').style.width = '100%';
  closeAll(); S.ui.sel.clear(); BULK.hashes.clear();
  render(); syncBulkUI();
  if (okLines.length) {
    const w = okLines.reduce((a, x) => a + x.w, 0);
    toast('Coins sent', 'ok', `${okLines.length} coin(s) · ${w} weight → ${nameOf(to)}`);
    Mesh.broadcast(okLines.map(x => x.l)); syncNow(true);
  }
  if (bad.length) toast(bad.length === lines.length ? 'Transfer rejected' : 'Partially rejected', 'bad',
    `${bad.length} coin(s) not accepted — they remain yours.${netErr ? ' ' + netErr : ''} Use “Sign offline” to prepare transfers without a connection.`);
}

function bulkVoucher() {
  if (!S.key) return toast('Wallet locked', 'warn', 'Unlock first.');
  const coins = bulkCoins();
  if (!coins.length) return toast('Nothing to sign', 'warn', 'Include at least one coin.');
  const to = $('btTo').value.trim();
  if (!idToPub(to)) return toast('Bad address', 'bad', 'Recipient must be a valid public key id.');
  const hrs = clamp(parseInt($('btHours').value, 10) || 24, 1, 720);
  const prov = new Set(), spends = [];
  for (const c of coins) {
    c.history.forEach(x => { const l = S.byHash.get(x); if (l) prov.add(l.line); });
    spends.push(makeLine(S.key, 'SIGNED_TRANSFER', [c.hash, to, String(c.amount), String(nowSec() + hrs * 3600)]));
  }
  download('evote-transfer-voucher.json', JSON.stringify({
    format: 'evote-voucher', version: 1, kind: 'transfer', created: new Date().toISOString(),
    signer: S.key.id, recipient: to, lines: [...prov, ...spends], spends: spends.length,
    note: 'Not yet broadcast. Import on any replica to redeem.' }, null, 2));
  closeAll(); Sound.play('transfer');
  toast('Voucher exported', 'ok', `${spends.length} transfer(s) + provenance. Import to redeem.`);
}

function syncBulkUI() {
  const n = S.ui.sel.size;
  const bar = document.querySelector('#coinBulk .bulkbar');
  if (bar) {
    let b = bar.querySelector('[data-act="send-selected"]');
    if (!b) {
      b = document.createElement('button');
      b.className = 'btn sm primary'; b.dataset.act = 'send-selected';
      const anchor = bar.querySelector('[data-act="vote-selected"]') || bar.querySelector('[data-act="export-selected"]');
      if (anchor && anchor.nextSibling) bar.insertBefore(b, anchor.nextSibling); else bar.appendChild(b);
    }
    const label = `Send ${n} →`;
    if (b.textContent !== label) b.textContent = label;
    b.title = `Send all ${n} selected coin(s) to one address`;
  }
  document.querySelectorAll('#coinRows [data-act="transfer"]').forEach(b => {
    const multi = n > 1 && S.ui.sel.has(b.dataset.hash);
    const label = multi ? `Send ${n}` : 'Send';
    if (b.textContent !== label) b.textContent = label;
    b.classList.toggle('primary', multi);
    b.classList.toggle('ghost', !multi);
    b.title = multi ? `Send all ${n} selected coins to one address` : 'Send this coin';
  });
}

let bulkSyncing = false;
const bulkMO = new MutationObserver(() => {
  if (bulkSyncing) return;
  bulkSyncing = true;
  try { syncBulkUI(); } finally { bulkSyncing = false; }
});
if ($('coins')) bulkMO.observe($('coins'), { childList: true, subtree: true });

document.addEventListener('click', e => {
  const t = e.target.closest('[data-act]'); if (!t) return;
  const act = t.dataset.act, hash = t.dataset.hash;
  if (act === 'send-selected') {
    const hs = [...S.ui.sel].filter(h => { const c = S.st.tokens.get(h); return c && S.key && c.owner === S.key.id && !c.spent; });
    if (!hs.length) return toast('Nothing to send', 'warn', 'Select unspent coins you own.');
    transferModal(hs[0]);
  }
  else if (act === 'bt-toggle') { if (BULK.hashes.has(hash)) BULK.hashes.delete(hash); else BULK.hashes.add(hash); bulkRender(); }
  else if (act === 'bt-all') { myCoins('unspent').forEach(c => BULK.hashes.add(c.hash)); bulkRender(); }
  else if (act === 'bt-none') { BULK.hashes.clear(); bulkRender(); }
  else if (act === 'bt-include-sel') { [...S.ui.sel].forEach(h => { const c = S.st.tokens.get(h); if (c && S.key && c.owner === S.key.id && !c.spent) BULK.hashes.add(h); }); bulkRender(); }
  else if (act === 'bt-pick') { $('btTo').value = t.dataset.pub; bulkRender(); }
  else if (act === 'bt-send') bulkSend();
  else if (act === 'bt-voucher') bulkVoucher();
  else if (act === 'bt-weight') bulkPickWeight();
  else if (act === 'bt-weight-alt') bulkPickWeight(parseInt(t.dataset.w, 10));
}, true);

document.addEventListener('input', e => {
  if (e.target && (e.target.id === 'btTo' || e.target.id === 'btHours')) bulkRender();
});
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.target && e.target.id === 'btTo') { e.preventDefault(); bulkSend(); }
  if (e.key === 'Enter' && e.target && e.target.id === 'btWeight') { e.preventDefault(); bulkPickWeight(); }
});
syncBulkUI();
/* ============ end bulk send ============ */
init();
</script>
</body>
</html>