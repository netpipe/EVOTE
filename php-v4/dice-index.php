<?php
declare(strict_types=1);
/**
 * EVOTE DICE — single-file, no-login dice game for EVOTE coins.
 *
 *   Players deposit with an EVOTE voucher (or raw tx lines) made out to this site's address,
 *   roll provably-fair dice, and cash out whole coins back to any EVOTE address.
 *   The site signs its own payouts with its wallet (loaded once in the admin page).
 *
 *   Deploy: upload this file (e.g. /dice/index.php), set EVOTE_URL below, open ?admin.
 *   Needs PHP >= 8.0 with sodium + pdo_sqlite + curl, and the EVOTE redeem/balance API.
 *
 *   Money unit inside the site: milli-weight (1 coin weight = 1000). Coins themselves can't be
 *   split, so cash-outs are whole weights; any fraction stays on the player's balance.
 */

const EVOTE_URL  = 'http://127.0.0.1/php-new3-3/index.php';   // server-side URL of the EVOTE index.php
const DATA_DIR   = __DIR__ . '/dice-data';                    // best: a folder outside the web root
const DB_FILE    = DATA_DIR . '/dice.sqlite';
const KEY_FILE   = DATA_DIR . '/master-key.php';
const M          = 1000;                                       // milli-weight per weight
const DEFAULTS   = ['edge' => '1', 'min_bet' => '0.1', 'max_profit_pct' => '1', 'paused' => '0'];
const ADMIN_MAX_FAILS = 5;                    // wrong admin passwords per IP ...
const ADMIN_LOCK_SEC  = 900;                  // ... before that IP is locked out for 15 minutes

/* ---------------------------------------------------------------- storage */

function db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    if (!is_dir(DATA_DIR)) @mkdir(DATA_DIR, 0700, true);
    foreach ([DATA_DIR . '/.htaccess' => "Require all denied\nDeny from all\n", DATA_DIR . '/index.html' => '',
              DATA_DIR . '/web.config' => "<?xml version=\"1.0\"?><configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n"] as $f => $c)
        if (!is_file($f)) @file_put_contents($f, $c);
    $pdo = new PDO('sqlite:' . DB_FILE);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA busy_timeout=8000');
    $pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_fails (ip TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_admin_fails ON admin_fails(ip,ts);
CREATE TABLE IF NOT EXISTS players (
  id TEXT PRIMARY KEY, balance INTEGER NOT NULL DEFAULT 0, addr TEXT NOT NULL DEFAULT '',
  server_seed TEXT NOT NULL, client_seed TEXT NOT NULL, nonce INTEGER NOT NULL DEFAULT 0,
  wagered INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS deposits (line_hash TEXT PRIMARY KEY, player TEXT NOT NULL, weight INTEGER NOT NULL, from_addr TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS bets (
  id INTEGER PRIMARY KEY AUTOINCREMENT, player TEXT NOT NULL, amount INTEGER NOT NULL, target INTEGER NOT NULL,
  roll INTEGER NOT NULL, win INTEGER NOT NULL, payout INTEGER NOT NULL, seed_hash TEXT NOT NULL,
  client_seed TEXT NOT NULL, nonce INTEGER NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_bets_player ON bets(player, id);
CREATE TABLE IF NOT EXISTS seeds (player TEXT NOT NULL, server_seed TEXT NOT NULL, seed_hash TEXT NOT NULL, client_seed TEXT NOT NULL, last_nonce INTEGER NOT NULL, revealed INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cashouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, player TEXT NOT NULL, to_addr TEXT NOT NULL, weight INTEGER NOT NULL,
  coins INTEGER NOT NULL, status TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL);
SQL);
    return $pdo;
}
function meta_get(string $k): ?string { $q = db()->prepare('SELECT v FROM meta WHERE k=?'); $q->execute([$k]); $v = $q->fetchColumn(); return $v === false ? null : (string)$v; }
function meta_set(string $k, string $v): void { db()->prepare('INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v')->execute([$k, $v]); }
function setting(string $k): string { return meta_get('set_' . $k) ?? DEFAULTS[$k]; }

/* Master key: lives in a PHP file that prints nothing over HTTP. It encrypts the site wallet's
   seed (sodium secretbox) before it is stored in SQLite. */
function master_key(): string {
    if (is_file(KEY_FILE) && preg_match('/KEY=([A-Za-z0-9+\/=]+)/', (string)file_get_contents(KEY_FILE), $m)) {
        $k = base64_decode($m[1], true); if ($k !== false && strlen($k) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES) return $k;
    }
    $k = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    if (@file_put_contents(KEY_FILE, "<?php http_response_code(404); exit; ?>\nKEY=" . base64_encode($k) . "\n", LOCK_EX) === false)
        throw new RuntimeException('cannot write ' . KEY_FILE . ' - check folder permissions');
    @chmod(KEY_FILE, 0600);
    return $k;
}
function seal(string $plain): string { $n = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES); return base64_encode($n . sodium_crypto_secretbox($plain, $n, master_key())); }
function unseal(string $box): ?string {
    $raw = base64_decode($box, true); if ($raw === false || strlen($raw) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) return null;
    $p = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), master_key());
    return $p === false ? null : $p;
}

/* ---------------------------------------------------------------- EVOTE crypto + API */

function pub_id_from_raw(string $raw): string {
    $der = hex2bin('302a300506032b6570032100') . $raw;
    return base64_encode("-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n");
}
function raw_from_pub_id(string $id): ?string {
    $pem = base64_decode($id, true); if ($pem === false) return null;
    $der = base64_decode((string)preg_replace('/-----(BEGIN|END)[^-]*-----|\s+/', '', $pem), true);
    if ($der === false || strlen($der) !== 44 || substr($der, 0, 12) !== hex2bin('302a300506032b6570032100')) return null;
    return substr($der, 12);
}
/* Opens an evote-wallet.json file (v2 legacy stream or v3) exactly like the EVOTE wallet does. */
function wallet_decrypt(array $f, string $pass): array {
    if (($f['format'] ?? '') !== 'evote-wallet') throw new RuntimeException('not an EVOTE wallet file');
    $v3 = (int)($f['version'] ?? 2) === 3;
    $salt = base64_decode((string)($f['kdf']['salt'] ?? ''), true); $nonce = base64_decode((string)($f['nonce'] ?? ''), true);
    $ct = base64_decode((string)($f['ct'] ?? ''), true); $tag = base64_decode((string)($f['tag'] ?? ''), true);
    $iter = (int)($f['kdf']['iter'] ?? 60000);
    if ($salt === false || $nonce === false || $ct === false || $tag === false || $iter < 1000 || $iter > 5000000) throw new RuntimeException('damaged wallet file');
    $dk = hash_pbkdf2('sha256', $pass, $salt, $iter, 64, true);
    [$kE, $kM] = [substr($dk, 0, 32), substr($dk, 32)];
    $want = hash_hmac('sha256', ($v3 ? 'evote-wallet-v3' : 'evote-wallet-v2') . $salt . $nonce . $ct, $kM, true);
    if (!hash_equals($want, $tag)) throw new RuntimeException('wrong passphrase');
    $plain = '';
    $step = $v3 ? 32 : 64;
    for ($i = 0; $i < strlen($ct); $i += $step) {
        $ks = hash_hmac('sha256', ($v3 ? 'ks3' : '') . $nonce . pack('N', intdiv($i, $step)), $kE, true);
        $chunk = substr($ct, $i, $step);
        // v2 had only 32 keystream bytes per 64-byte block: bytes 32-63 were stored in the clear
        $plain .= (substr($chunk, 0, 32) ^ substr($ks, 0, strlen(substr($chunk, 0, 32)))) . substr($chunk, 32);
    }
    $data = json_decode($plain, true);
    $seed = is_array($data) ? hex2bin((string)($data['seed'] ?? '')) : false;
    if ($seed === false || strlen($seed) !== 32) throw new RuntimeException('wallet contents unreadable');
    $kp = sodium_crypto_sign_seed_keypair($seed);
    $pub = pub_id_from_raw(sodium_crypto_sign_publickey($kp));
    if ($pub !== ($f['pub'] ?? '')) throw new RuntimeException('wallet public key mismatch');
    return ['seed' => $seed, 'pub' => $pub];
}
function site_key(): ?array {
    $box = meta_get('wallet_box'); if ($box === null) return null;
    $seed = unseal($box); if ($seed === null || strlen($seed) !== 32) return null;
    $kp = sodium_crypto_sign_seed_keypair($seed);
    return ['sk' => sodium_crypto_sign_secretkey($kp), 'pub' => pub_id_from_raw(sodium_crypto_sign_publickey($kp))];
}
function site_addr(): string { return (string)meta_get('wallet_pub'); }
function make_line(array $k, string $type, array $fields): string {
    $payload = implode('|', array_merge([$type, '1', $k['pub'], (string)time(), base64_encode(random_bytes(16))], $fields));
    return $payload . '|' . base64_encode(sodium_crypto_sign_detached($payload, $k['sk']));
}
function evote(string $action, array $body): array {
    $c = curl_init(EVOTE_URL . '?action=' . $action);
    curl_setopt_array($c, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_encode($body), CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_TIMEOUT => 25, CURLOPT_CONNECTTIMEOUT => 8]);
    $raw = curl_exec($c); $code = (int)curl_getinfo($c, CURLINFO_HTTP_CODE); $err = curl_error($c);
    if ($raw === false) throw new RuntimeException('EVOTE server unreachable: ' . $err);
    $j = json_decode((string)$raw, true);
    if (!is_array($j)) throw new RuntimeException("EVOTE server gave an unexpected reply (HTTP $code)");
    if (empty($j['ok'])) throw new RuntimeException('EVOTE: ' . ($j['err'] ?? "HTTP $code"));
    return $j;
}
/* Exact whole-coin set for `target` weight (bounded subset-sum per coin size), else nearest. */
function pick_coins(array $coins, int $target): array {
    $groups = [];
    usort($coins, fn($a, $b) => $a['updated'] <=> $b['updated']);
    foreach ($coins as $c) $groups[$c['amount']][] = $c;
    krsort($groups); $amts = array_keys($groups);
    $total = array_sum(array_column($coins, 'amount'));
    if ($target < 1 || !$coins) return ['exact' => null, 'below' => 0, 'above' => 0];
    $lim = min($total, $target + $amts[0]);
    if (count($amts) * ($lim + 1) > 4000000) $lim = min($lim, intdiv(4000000, count($amts)) - 1);
    $reach = array_fill(0, $lim + 1, false); $reach[0] = true; $layers = [];
    foreach ($amts as $a) {
        $cnt = count($groups[$a]); $nr = $reach; $u = array_fill(0, $lim + 1, 0);
        for ($s = $a; $s <= $lim; $s++) if (!$reach[$s] && $nr[$s - $a] && $u[$s - $a] < $cnt) { $nr[$s] = true; $u[$s] = $u[$s - $a] + 1; }
        $layers[] = $u; $reach = $nr;
    }
    $build = function (int $s) use ($amts, $layers, $groups) {
        $out = [];
        for ($k = count($amts) - 1; $k >= 0; $k--) { $n = $layers[$k][$s]; foreach (array_slice($groups[$amts[$k]], 0, $n) as $c) $out[] = $c; $s -= $n * $amts[$k]; }
        return $out;
    };
    if ($target <= $lim && $reach[$target]) return ['exact' => $build($target), 'below' => 0, 'above' => 0];
    $lo = min($target, $lim); while ($lo > 0 && !$reach[$lo]) $lo--;
    $hi = $target + 1; while ($hi <= $lim && !$reach[$hi]) $hi++;
    return ['exact' => null, 'below' => $lo, 'above' => $hi <= $lim ? $hi : 0];
}

/* ---------------------------------------------------------------- game */

function fmt(int $m): string { return rtrim(rtrim(number_format($m / M, 3, '.', ''), '0'), '.') ?: '0'; }
function parse_amount($v): ?int {                 // "1.25" weight -> 1250 milli, max 3 decimals
    $v = trim((string)$v);
    if (!preg_match('/^\d{1,9}(\.\d{1,3})?$/', $v)) return null;
    [$i, $f] = array_pad(explode('.', $v), 2, '');
    return (int)$i * M + (int)str_pad($f, 3, '0');
}
function new_seed(): string { return bin2hex(random_bytes(32)); }
/* Roll 0..9999 (shown /100 as 0.00-99.99) = first 4 bytes of HMAC-SHA256(server_seed, client_seed:nonce) */
function roll_for(string $serverSeed, string $clientSeed, int $nonce): int {
    $h = hash_hmac('sha256', $clientSeed . ':' . $nonce, $serverSeed);
    return (int)floor(hexdec(substr($h, 0, 8)) / 4294967296 * 10000);
}
function player_id(string $playKey): string { return hash('sha256', 'evote-dice|' . $playKey); }
function player(bool $create = false): ?array {
    $key = (string)($_SERVER['HTTP_X_PLAY_KEY'] ?? '');
    if (!preg_match('/^[0-9a-f]{40}$/', $key)) return null;
    $id = player_id($key);
    $q = db()->prepare('SELECT * FROM players WHERE id=?'); $q->execute([$id]);
    $p = $q->fetch(PDO::FETCH_ASSOC);
    if (!$p && $create) {
        db()->prepare('INSERT OR IGNORE INTO players(id,server_seed,client_seed,created,updated) VALUES(?,?,?,?,?)')
            ->execute([$id, new_seed(), bin2hex(random_bytes(8)), time(), time()]);
        $q->execute([$id]); $p = $q->fetch(PDO::FETCH_ASSOC);
    }
    return $p ?: null;
}
function liabilities(): int { return (int)db()->query('SELECT COALESCE(SUM(balance),0) FROM players')->fetchColumn(); }
function site_holdings(): array {
    if (site_addr() === '') return ['weight' => 0, 'coins' => []];
    $b = evote('balance', ['pub' => site_addr()]);
    return ['weight' => (int)$b['weight'], 'coins' => $b['coins']];
}
function bank_view(): array {
    $h = site_holdings(); $liab = liabilities();
    $free = $h['weight'] * M - $liab;
    return ['holdings' => $h['weight'] * M, 'liabilities' => $liab, 'free' => $free,
            'max_profit' => max(0, (int)floor($free * (float)setting('max_profit_pct') / 100))];
}
function player_view(array $p): array {
    $bets = db()->prepare('SELECT id,amount,target,roll,win,payout,nonce,ts,seed_hash,client_seed FROM bets WHERE player=? ORDER BY id DESC LIMIT 25');
    $bets->execute([$p['id']]);
    $seeds = db()->prepare('SELECT server_seed,seed_hash,client_seed,last_nonce FROM seeds WHERE player=? ORDER BY rowid DESC LIMIT 5');
    $seeds->execute([$p['id']]);
    return ['balance' => fmt((int)$p['balance']), 'balance_m' => (int)$p['balance'], 'addr' => $p['addr'],
            'seed_hash' => hash('sha256', $p['server_seed']), 'client_seed' => $p['client_seed'], 'nonce' => (int)$p['nonce'],
            'wagered' => fmt((int)$p['wagered']),
            'bets' => array_map(fn($b) => ['id' => (int)$b['id'], 'amount' => fmt((int)$b['amount']), 'target' => (int)$b['target'] / 100,
                'roll' => (int)$b['roll'] / 100, 'win' => (bool)$b['win'], 'payout' => fmt((int)$b['payout']), 'nonce' => (int)$b['nonce'], 'ts' => (int)$b['ts'],
                'seed_hash' => $b['seed_hash'], 'client_seed' => $b['client_seed']], $bets->fetchAll(PDO::FETCH_ASSOC)),
            'old_seeds' => $seeds->fetchAll(PDO::FETCH_ASSOC)];
}
function with_lock(callable $fn) {               // one money-moving request at a time
    $fh = fopen(DATA_DIR . '/money.lock', 'c'); flock($fh, LOCK_EX);
    try { return $fn(); } finally { flock($fh, LOCK_UN); fclose($fh); }
}

/* ---------------------------------------------------------------- http */

function out(array $a, int $code = 200): void { http_response_code($code); header('Content-Type: application/json'); header('Cache-Control: no-store'); echo json_encode($a); exit; }
function fail(string $err, int $code = 400): void { out(['ok' => false, 'err' => $err], $code); }
function same_origin(): bool {
    $host = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
    foreach (['HTTP_ORIGIN', 'HTTP_REFERER'] as $h) if (!empty($_SERVER[$h])) {
        $p = parse_url((string)$_SERVER[$h]);
        if (($p['host'] ?? '') !== '' && strtolower($p['host'] . (isset($p['port']) ? ':' . $p['port'] : '')) !== $host) return false;
    }
    return true;
}
/* Admin password attempt limiter: ADMIN_MAX_FAILS wrong passwords from one IP within
   ADMIN_LOCK_SEC lock that IP out of the admin until ADMIN_LOCK_SEC after its last miss.
   A correct login clears the count. Behind a proxy/CDN every visitor shares the proxy's IP. */
function admin_ip(): string { return (string)($_SERVER['REMOTE_ADDR'] ?? ''); }
function admin_wait(): int {
    $db = db(); $db->prepare('DELETE FROM admin_fails WHERE ts<?')->execute([time() - ADMIN_LOCK_SEC]);
    $q = $db->prepare('SELECT COUNT(*), MAX(ts) FROM admin_fails WHERE ip=?'); $q->execute([admin_ip()]);
    [$n, $last] = $q->fetch(PDO::FETCH_NUM);
    return (int)$n >= ADMIN_MAX_FAILS ? max(1, (int)$last + ADMIN_LOCK_SEC - time()) : 0;
}
function admin_fail(): void { db()->prepare('INSERT INTO admin_fails(ip,ts) VALUES(?,?)')->execute([admin_ip(), time()]); }
function admin_clear(): void { db()->prepare('DELETE FROM admin_fails WHERE ip=?')->execute([admin_ip()]); }
function admin_ok(): bool {
    $h = meta_get('admin_hash'); $t = (string)($_SERVER['HTTP_X_ADMIN_PASS'] ?? '');
    return $h !== null && $t !== '' && sodium_crypto_pwhash_str_verify($h, $t);
}

$action = (string)($_GET['action'] ?? '');
if ($action !== '') {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') fail('POST required', 405);
    if (!same_origin()) fail('cross-origin blocked', 403);
    if (stripos((string)($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json') === false) fail('application/json required', 415);
    $in = json_decode((string)file_get_contents('php://input'), true); if (!is_array($in)) $in = [];
    try {
        switch ($action) {

        case 'state': {
            $p = player();
            $view = ['ok' => true, 'site' => site_addr(), 'ready' => site_addr() !== '' && meta_get('admin_hash') !== null,
                     'installed' => meta_get('admin_hash') !== null, 'paused' => setting('paused') === '1',
                     'edge' => (float)setting('edge'), 'min_bet' => setting('min_bet'), 'player' => $p ? player_view($p) : null];
            try { $b = bank_view(); $view['max_profit'] = fmt($b['max_profit']); $view['bank_ok'] = true; }
            catch (Throwable $e) { $view['max_profit'] = '0'; $view['bank_ok'] = false; $view['bank_err'] = $e->getMessage(); }
            out($view);
        }

        case 'new_player': {
            $key = bin2hex(random_bytes(20));
            $_SERVER['HTTP_X_PLAY_KEY'] = $key; $p = player(true);
            out(['ok' => true, 'play_key' => $key, 'player' => player_view($p)]);
        }

        case 'deposit': {
            $p = player(true); if (!$p) fail('missing play key');
            if (site_addr() === '') fail('the site wallet is not set up yet');
            $body = ['to' => site_addr()];
            $v = $in['voucher'] ?? null;
            if (is_string($v) && $v !== '' && $v[0] === '{') $v = json_decode($v, true);
            if (is_array($v)) {
                if (($v['format'] ?? '') === 'evote-coins') { $lines = []; foreach ((array)($v['coins'] ?? []) as $c) foreach ((array)($c['lines'] ?? []) as $l) $lines[] = $l; $body['lines'] = $lines; }
                else $body['voucher'] = $v;
            } elseif (is_string($v) && trim($v) !== '') $body['raw'] = $v;
            else fail('paste a voucher or signed transfer lines');
            $r = with_lock(function () use ($body, $p) {
                $r = evote('redeem', $body);
                $credit = 0; $from = '';
                $db = db(); $db->beginTransaction();
                foreach ($r['items'] as $it) {
                    if (($it['status'] ?? '') !== 'deposited' || ($it['to'] ?? '') !== site_addr()) continue;
                    $ins = $db->prepare('INSERT OR IGNORE INTO deposits(line_hash,player,weight,from_addr,ts) VALUES(?,?,?,?,?)');
                    $ins->execute([$it['hash'], $p['id'], (int)$it['amount'], $it['from'], time()]);
                    if ($ins->rowCount() === 1) { $credit += (int)$it['amount']; $from = $from ?: $it['from']; }
                }
                if ($credit > 0) {
                    $db->prepare("UPDATE players SET balance=balance+?, addr=CASE WHEN addr='' THEN ? ELSE addr END, updated=? WHERE id=?")
                       ->execute([$credit * M, $from, time(), $p['id']]);
                }
                $db->commit();
                return ['credit' => $credit, 'items' => $r['items']];
            });
            $p = player();
            $msgs = array_values(array_filter(array_map(fn($i) => ($i['status'] ?? '') === 'deposited' ? null : ($i['status'] . (isset($i['err']) ? ': ' . $i['err'] : '')), $r['items'])));
            out(['ok' => true, 'credited' => $r['credit'], 'notes' => $msgs, 'player' => player_view($p)]);
        }

        case 'bet': {
            if (setting('paused') === '1') fail('the game is paused by the admin');
            $amount = parse_amount($in['amount'] ?? ''); $target = (int)round(((float)($in['target'] ?? 0)) * 100);
            if ($amount === null || $amount < 1) fail('enter a bet amount (up to 3 decimals)');
            if ($amount < (parse_amount(setting('min_bet')) ?? 0)) fail('minimum bet is ' . setting('min_bet'));
            if ($target < 200 || $target > 9800) fail('roll-under target must be between 2.00 and 98.00');
            $res = with_lock(function () use ($amount, $target) {
                $p = player(); if (!$p) fail('missing play key');
                if ((int)$p['balance'] < $amount) fail('not enough balance');
                $edge = (float)setting('edge');
                $payout = (int)floor($amount * (100 - $edge) / ($target / 100));
                $profit = $payout - $amount;
                $bank = bank_view();
                if ($profit > $bank['max_profit']) fail('max win per roll right now is ' . fmt($bank['max_profit']) . ' - lower the bet or raise the target');
                $roll = roll_for($p['server_seed'], $p['client_seed'], (int)$p['nonce']);
                $win = $roll < $target;
                $delta = $win ? $profit : -$amount;
                $db = db(); $db->beginTransaction();
                $u = $db->prepare('UPDATE players SET balance=balance+?, nonce=nonce+1, wagered=wagered+?, updated=? WHERE id=? AND nonce=? AND balance>=?');
                $u->execute([$delta, $amount, time(), $p['id'], (int)$p['nonce'], $amount]);
                if ($u->rowCount() !== 1) { $db->rollBack(); fail('please retry'); }
                $db->prepare('INSERT INTO bets(player,amount,target,roll,win,payout,seed_hash,client_seed,nonce,ts) VALUES(?,?,?,?,?,?,?,?,?,?)')
                   ->execute([$p['id'], $amount, $target, $roll, $win ? 1 : 0, $win ? $payout : 0, hash('sha256', $p['server_seed']), $p['client_seed'], (int)$p['nonce'], time()]);
                $db->commit();
                return ['roll' => $roll / 100, 'win' => $win, 'payout' => fmt($win ? $payout : 0), 'profit' => fmt(abs($delta)), 'nonce' => (int)$p['nonce']];
            });
            out(['ok' => true] + $res + ['player' => player_view(player())]);
        }

        case 'seed': {                       // set client seed and/or rotate (reveals the old server seed)
            $p = player(true); if (!$p) fail('missing play key');
            $cs = trim((string)($in['client_seed'] ?? $p['client_seed']));
            if (!preg_match('/^[A-Za-z0-9_.:-]{1,64}$/', $cs)) fail('client seed: 1-64 letters, digits or _ . : -');
            with_lock(function () use ($p, $cs) {
                $db = db(); $db->beginTransaction();
                $db->prepare('INSERT INTO seeds(player,server_seed,seed_hash,client_seed,last_nonce,revealed) VALUES(?,?,?,?,?,?)')
                   ->execute([$p['id'], $p['server_seed'], hash('sha256', $p['server_seed']), $p['client_seed'], (int)$p['nonce'], time()]);
                $db->prepare('UPDATE players SET server_seed=?, client_seed=?, nonce=0, updated=? WHERE id=?')->execute([new_seed(), $cs, time(), $p['id']]);
                $db->commit();
            });
            out(['ok' => true, 'player' => player_view(player())]);
        }

        case 'cashout': {
            $p = player(); if (!$p) fail('missing play key');
            $to = trim((string)($in['to'] ?? '')); $w = (int)($in['weight'] ?? 0);
            if (raw_from_pub_id($to) === null) fail('enter a valid EVOTE address (base64 PEM public key id)');
            if ($to === site_addr()) fail('that is the site address - use your own');
            if ($w < 1) fail('enter a whole number of weight');
            $res = with_lock(function () use ($p, $to, $w) {
                $key = site_key(); if (!$key) fail('the site wallet is not loaded');
                $p = player();
                if ((int)$p['balance'] < $w * M) fail('your balance is ' . fmt((int)$p['balance']));
                $h = site_holdings();
                $plan = pick_coins($h['coins'], $w);
                if (!$plan['exact']) fail("no exact set of the site's coins adds up to $w right now (coins can't be split). Closest: "
                    . implode(' or ', array_filter([$plan['below'] ? $plan['below'] : null, $plan['above'] ? $plan['above'] : null])));
                $db = db();
                $db->beginTransaction();               // take the balance first, refund whatever does not land
                $u = $db->prepare('UPDATE players SET balance=balance-?, addr=?, updated=? WHERE id=? AND balance>=?');
                $u->execute([$w * M, $to, time(), $p['id'], $w * M]);
                if ($u->rowCount() !== 1) { $db->rollBack(); fail('please retry'); }
                $db->prepare('INSERT INTO cashouts(player,to_addr,weight,coins,status,ts) VALUES(?,?,?,?,?,?)')->execute([$p['id'], $to, $w, count($plan['exact']), 'signing', time()]);
                $cid = (int)$db->lastInsertId();
                $db->commit();
                $lines = array_map(fn($c) => make_line($key, 'SIGNED_TRANSFER', [$c['hash'], $to, (string)$c['amount'], (string)(time() + 3600)]), $plan['exact']);
                $sent = 0; $err = '';
                try {
                    $r = evote('redeem', ['lines' => $lines, 'to' => $to]);
                    $sent = (int)($r['to']['weight'] ?? 0);
                    foreach ($r['items'] as $it) if (($it['status'] ?? '') !== 'deposited') $err .= ($it['status'] ?? '?') . ' ' . ($it['err'] ?? '') . '; ';
                } catch (Throwable $e) { $err = $e->getMessage(); }
                $refund = $w - $sent;
                $db->beginTransaction();
                if ($refund > 0) $db->prepare('UPDATE players SET balance=balance+?, updated=? WHERE id=?')->execute([$refund * M, time(), $p['id']]);
                $db->prepare('UPDATE cashouts SET status=?, detail=? WHERE id=?')->execute([$sent === $w ? 'sent' : ($sent ? 'partial' : 'failed'), trim($err), $cid]);
                $db->commit();
                return ['sent' => $sent, 'refunded' => $refund, 'err' => trim($err)];
            });
            out(['ok' => true] + $res + ['player' => player_view(player())]);
        }

        /* ---- admin ---- */
        case 'admin_setup': {
            if (meta_get('admin_hash') !== null) fail('already set up', 409);
            $pw = (string)($in['password'] ?? '');
            if (strlen($pw) < 10) fail('admin password: at least 10 characters');
            master_key();
            meta_set('admin_hash', sodium_crypto_pwhash_str($pw, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE));
            out(['ok' => true]);
        }
        case 'admin': {
            if ($w = admin_wait()) fail('too many wrong admin attempts from your address - try again in ' . ceil($w / 60) . ' min', 429);
            if (!admin_ok()) { admin_fail(); fail('admin password rejected', 403); }
            admin_clear();
            $op = (string)($in['op'] ?? '');
            if ($op === 'state') {
                $bank = null; $bankErr = '';
                try { $bank = bank_view(); } catch (Throwable $e) { $bankErr = $e->getMessage(); }
                $st = db()->query('SELECT COUNT(*) n, COALESCE(SUM(amount),0) wag, COALESCE(SUM(CASE WHEN win=1 THEN payout ELSE 0 END),0) paid FROM bets')->fetch(PDO::FETCH_ASSOC);
                $dep = (int)db()->query('SELECT COALESCE(SUM(weight),0) FROM deposits')->fetchColumn();
                $co = (int)db()->query("SELECT COALESCE(SUM(weight),0) FROM cashouts WHERE status IN ('sent','partial')")->fetchColumn();
                $pl = db()->query('SELECT substr(id,1,10) id, balance, addr, wagered, updated FROM players ORDER BY updated DESC LIMIT 30')->fetchAll(PDO::FETCH_ASSOC);
                $cos = db()->query('SELECT id, substr(player,1,10) player, to_addr, weight, coins, status, detail, ts FROM cashouts ORDER BY id DESC LIMIT 20')->fetchAll(PDO::FETCH_ASSOC);
                out(['ok' => true, 'site' => site_addr(), 'wallet_loaded' => site_key() !== null,
                     'settings' => ['edge' => setting('edge'), 'min_bet' => setting('min_bet'), 'max_profit_pct' => setting('max_profit_pct'), 'paused' => setting('paused')],
                     'bank' => $bank ? ['holdings' => fmt($bank['holdings']), 'liabilities' => fmt($bank['liabilities']), 'free' => fmt($bank['free']), 'max_profit' => fmt($bank['max_profit']), 'short' => $bank['free'] < 0] : null,
                     'bank_err' => $bankErr, 'evote_url' => EVOTE_URL,
                     'stats' => ['bets' => (int)$st['n'], 'wagered' => fmt((int)$st['wag']), 'paid' => fmt((int)$st['paid']), 'house_result' => fmt((int)$st['wag'] - (int)$st['paid']),
                                 'deposited' => $dep, 'cashed_out' => $co],
                     'players' => array_map(fn($r) => ['id' => $r['id'], 'balance' => fmt((int)$r['balance']), 'wagered' => fmt((int)$r['wagered']), 'addr' => $r['addr'], 'updated' => (int)$r['updated']], $pl),
                     'cashouts' => $cos]);
            }
            if ($op === 'wallet') {
                $f = $in['wallet'] ?? null; if (is_string($f)) $f = json_decode($f, true);
                if (!is_array($f)) fail('choose the site\'s evote-wallet.json file');
                $w = with_lock(fn() => wallet_decrypt($f, (string)($in['passphrase'] ?? '')));
                if (site_addr() !== '' && site_addr() !== $w['pub'] && liabilities() > 0)
                    fail('players still hold balances on the current site wallet - switch wallets only when liabilities are 0');
                meta_set('wallet_box', seal($w['seed'])); meta_set('wallet_pub', $w['pub']);
                sodium_memzero($w['seed']);
                out(['ok' => true, 'site' => site_addr()]);
            }
            if ($op === 'settings') {
                $edge = (float)($in['edge'] ?? 1); $mp = (float)($in['max_profit_pct'] ?? 1);
                if ($edge < 0 || $edge > 10) fail('house edge must be 0-10 %');
                if ($mp <= 0 || $mp > 25) fail('max profit must be 0-25 % of the free bankroll');
                if (parse_amount($in['min_bet'] ?? '') === null) fail('min bet: a number with up to 3 decimals');
                meta_set('set_edge', (string)$edge); meta_set('set_max_profit_pct', (string)$mp);
                meta_set('set_min_bet', (string)$in['min_bet']); meta_set('set_paused', !empty($in['paused']) ? '1' : '0');
                out(['ok' => true]);
            }
            if ($op === 'import') {                // load bankroll: coin bundle / voucher / raw lines -> EVOTE
                $v = $in['data'] ?? '';
                $j = is_string($v) && $v !== '' && $v[0] === '{' ? json_decode($v, true) : null;
                $body = ['to' => site_addr()];
                if (is_array($j) && ($j['format'] ?? '') === 'evote-coins') { $lines = []; foreach ((array)$j['coins'] as $c) foreach ((array)($c['lines'] ?? []) as $l) $lines[] = $l; $body['lines'] = $lines; }
                elseif (is_array($j)) $body['voucher'] = $j;
                else $body['raw'] = (string)$v;
                $r = evote('redeem', $body);
                $h = site_holdings();
                out(['ok' => true, 'deposited_now' => (int)($r['to']['weight'] ?? 0), 'accepted_lines' => $r['accepted'], 'site_weight' => $h['weight']]);
            }
            if ($op === 'withdraw') {              // house profit -> any address, never below player liabilities
                $to = trim((string)($in['to'] ?? '')); $w = (int)($in['weight'] ?? 0);
                if (raw_from_pub_id($to) === null || $w < 1) fail('address and whole weight required');
                $res = with_lock(function () use ($to, $w) {
                    $key = site_key(); if (!$key) fail('the site wallet is not loaded');
                    $bank = bank_view();
                    if ($w * M > $bank['free']) fail('only ' . fmt(max(0, $bank['free'])) . ' is free (the rest belongs to players)');
                    $plan = pick_coins(site_holdings()['coins'], $w);
                    if (!$plan['exact']) fail('no exact coin set for that weight; closest ' . $plan['below'] . ' / ' . $plan['above']);
                    $lines = array_map(fn($c) => make_line($key, 'SIGNED_TRANSFER', [$c['hash'], $to, (string)$c['amount'], (string)(time() + 3600)]), $plan['exact']);
                    $r = evote('redeem', ['lines' => $lines, 'to' => $to]);
                    return ['sent' => (int)($r['to']['weight'] ?? 0)];
                });
                out(['ok' => true] + $res);
            }
            fail('unknown admin op');
        }

        default: fail('unknown action', 404);
        }
    } catch (Throwable $e) { fail($e->getMessage()); }
}
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EVOTE Dice</title>
<style>
:root{--bg:#060912;--panel:#0d1322;--panel2:#111a2e;--line:#1e2a44;--ink:#e6ecff;--mut:#8b97b8;--cyan:#22d3ee;--indigo:#6366f1;--green:#22c55e;--red:#ef4444;--amber:#f59e0b}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
body{background:radial-gradient(1200px 600px at 80% -10%,rgba(99,102,241,.18),transparent),radial-gradient(900px 500px at -10% 10%,rgba(34,211,238,.10),transparent),var(--bg);min-height:100vh}
.wrap{max-width:1080px;margin:0 auto;padding:18px 16px 60px}
header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.logo{font-weight:800;letter-spacing:.14em;font-size:18px}.logo span{color:var(--cyan)}
.pill{border:1px solid var(--line);border-radius:999px;padding:4px 12px;font-size:12.5px;color:var(--mut);background:rgba(13,19,34,.7)}
.pill b{color:var(--ink)}
.grid{display:grid;grid-template-columns:1.25fr 1fr;gap:16px}@media(max-width:860px){.grid{grid-template-columns:1fr}}
.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:16px;padding:16px 18px}
.card h3{margin:0 0 12px;font-size:14px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)}
label{display:block;font-size:11.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);margin:10px 0 5px}
input,textarea{width:100%;background:#0a1020;border:1px solid var(--line);color:var(--ink);border-radius:10px;padding:10px 12px;font:inherit}
textarea{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
input:focus,textarea:focus{outline:none;border-color:var(--cyan)}
.row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap}.row>*{flex:1;min-width:120px}
.btn{border:1px solid var(--line);background:#152039;color:var(--ink);border-radius:10px;padding:10px 14px;font:inherit;font-weight:600;cursor:pointer}
.btn:hover{border-color:var(--cyan)}.btn:disabled{opacity:.45;cursor:not-allowed}
.btn.primary{background:linear-gradient(90deg,var(--indigo),var(--cyan));border:0;color:#04101c}
.btn.sm{padding:6px 10px;font-size:13px;flex:0 0 auto;min-width:0}
.big{font-size:34px;font-weight:800;letter-spacing:-.02em}.mut{color:var(--mut)}.tiny{font-size:12.5px}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:12px 0}
.stat{background:#0a1020;border:1px solid var(--line);border-radius:12px;padding:8px 10px}.stat b{display:block;font-size:17px}
.roll{font-size:64px;font-weight:900;text-align:center;letter-spacing:-.03em;margin:6px 0;font-variant-numeric:tabular-nums}
.roll.win{color:var(--green)}.roll.lose{color:var(--red)}
input[type=range]{padding:0;height:6px;accent-color:var(--cyan)}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:6px 6px;border-bottom:1px solid var(--line);text-align:left}th{color:var(--mut);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em}
.w{color:var(--green)}.l{color:var(--red)}
#toast{position:fixed;right:16px;bottom:16px;max-width:380px;display:flex;flex-direction:column;gap:8px;z-index:9}
.t{background:#0d1322;border:1px solid var(--line);border-left:4px solid var(--cyan);border-radius:10px;padding:10px 12px;font-size:14px;box-shadow:0 8px 30px rgba(0,0,0,.4)}
.t.bad{border-left-color:var(--red)}.t.ok{border-left-color:var(--green)}
.notice{border:1px solid rgba(245,158,11,.4);background:rgba(245,158,11,.08);border-radius:12px;padding:10px 12px;margin-bottom:14px;font-size:14px}
.hidden{display:none!important}
</style>
</head>
<body><div class="wrap">
<header>
  <div class="logo">EVOTE <span>DICE</span></div>
  <div class="pill">house edge <b id="hEdge">1</b>%</div>
  <div class="pill">max win per roll <b id="hMax">-</b></div>
  <div class="pill" style="margin-left:auto">site address <b class="mono" id="hSite" style="font-size:11px">-</b> <button class="btn sm" id="copySite">copy</button></div>
</header>
<div id="notice" class="notice hidden"></div>

<div id="game" class="grid">
  <div>
    <div class="card">
      <h3>Roll under</h3>
      <div class="roll" id="rollOut">--.--</div>
      <div class="row">
        <div><label>Bet (weight)</label><input id="bet" value="1" inputmode="decimal"></div>
        <div><label>Roll under</label><input id="target" value="49.50" inputmode="decimal"></div>
      </div>
      <input type="range" id="slider" min="2" max="98" step="0.5" value="49.5" style="width:100%;margin-top:12px">
      <div class="stats">
        <div class="stat"><span class="tiny mut">Win chance</span><b id="sChance">-</b></div>
        <div class="stat"><span class="tiny mut">Multiplier</span><b id="sMult">-</b></div>
        <div class="stat"><span class="tiny mut">Profit on win</span><b id="sProfit">-</b></div>
      </div>
      <div class="row"><button class="btn sm" data-bet="half">½</button><button class="btn sm" data-bet="double">2×</button><button class="btn sm" data-bet="max">max</button>
        <button class="btn primary" id="rollBtn" style="flex:3">Roll dice</button></div>
    </div>
    <div class="card" style="margin-top:16px">
      <h3>Your recent rolls</h3>
      <table><thead><tr><th>#</th><th>Bet</th><th>Under</th><th>Roll</th><th>Result</th></tr></thead><tbody id="bets"></tbody></table>
    </div>
  </div>
  <div>
    <div class="card">
      <h3>Balance</h3>
      <div class="big"><span id="bal">0</span> <span class="mut" style="font-size:16px">weight</span></div>
      <div class="tiny mut">No login: your balance is tied to this play key, kept in this browser. Save it to play on another device.</div>
      <div class="row" style="margin-top:8px"><input id="playKey" class="mono" readonly><button class="btn sm" id="copyKey">copy</button></div>
      <div class="row" style="margin-top:8px"><input id="restoreKey" class="mono" placeholder="paste a saved play key to switch"><button class="btn sm" id="useKey">use</button></div>
    </div>
    <div class="card" style="margin-top:16px">
      <h3>Deposit</h3>
      <div class="tiny mut">In the EVOTE wallet, make an <b>offline voucher</b> (or "Sign offline" in Send) to the site address above, then paste the file contents here or choose the file. Signed transfer lines work too.</div>
      <textarea id="depText" rows="4" placeholder='{"format":"evote-voucher", ...}  or  SIGNED_TRANSFER|1|...' style="margin-top:8px"></textarea>
      <div class="row" style="margin-top:8px"><input type="file" id="depFile" accept=".json,.txt" style="padding:7px"><button class="btn primary" id="depBtn">Deposit</button></div>
    </div>
    <div class="card" style="margin-top:16px">
      <h3>Cash out</h3>
      <div class="tiny mut">Sends whole coins from the site's wallet to your EVOTE address. Coins can't be split; fractions stay here.</div>
      <label>Your EVOTE address</label><input id="coAddr" class="mono" placeholder="base64 PEM public key id">
      <div class="row"><div><label>Weight</label><input id="coW" inputmode="numeric" placeholder="whole number"></div><button class="btn" id="coBtn">Cash out</button></div>
    </div>
    <div class="card" style="margin-top:16px">
      <h3>Provably fair</h3>
      <div class="tiny mut">Roll = first 4 bytes of HMAC-SHA256(server seed, "client seed:nonce") / 2³² × 100. The server seed hash is fixed before you roll; rotate to reveal it and check every roll.</div>
      <label>Server seed hash (current)</label><div class="mono" id="fHash">-</div>
      <div class="row"><div><label>Client seed</label><input id="fClient" class="mono"></div><div style="flex:0 0 90px"><label>Nonce</label><input id="fNonce" readonly></div></div>
      <div class="row" style="margin-top:8px"><button class="btn" id="fRotate">Set seed + rotate</button></div>
      <div id="fOld" class="tiny" style="margin-top:10px"></div>
    </div>
  </div>
</div>

<div id="admin" class="hidden">
  <div class="card" id="adSetup"><h3>Admin setup</h3>
    <div class="tiny mut">Choose the admin password for this dice site (at least 10 characters).</div>
    <div class="row"><input id="adNewPw" type="password" placeholder="new admin password"><button class="btn primary" id="adSetupBtn">Save</button></div></div>
  <div class="card" id="adLogin" style="margin-top:16px"><h3>Admin login</h3>
    <div class="row"><input id="adPw" type="password" placeholder="admin password"><button class="btn primary" id="adLoginBtn">Open</button></div></div>
  <div id="adPanel" class="hidden">
    <div class="grid" style="margin-top:16px">
      <div class="card"><h3>Bankroll</h3><div id="adBank" class="tiny"></div>
        <label>Load coins into the bankroll</label>
        <div class="tiny mut">Send coins to the site address from any wallet, or paste an "Export coins" file / voucher made out to the site address.</div>
        <textarea id="adImport" rows="3" style="margin-top:6px"></textarea>
        <div class="row" style="margin-top:8px"><input type="file" id="adImportFile" accept=".json,.txt" style="padding:7px"><button class="btn" id="adImportBtn">Import</button></div>
        <label>Withdraw house profit</label>
        <div class="row"><input id="adWdTo" class="mono" placeholder="address"><input id="adWdW" placeholder="weight" style="flex:0 0 90px"><button class="btn sm" id="adWdBtn">Send</button></div>
      </div>
      <div class="card"><h3>Site wallet</h3><div id="adWallet" class="tiny"></div>
        <label>evote-wallet.json of the site</label><input type="file" id="adWalletFile" accept=".json" style="padding:7px">
        <label>Passphrase</label><input type="password" id="adWalletPass">
        <div class="row" style="margin-top:8px"><button class="btn primary" id="adWalletBtn">Load wallet</button></div>
        <h3 style="margin-top:18px">Settings</h3>
        <div class="row"><div><label>House edge %</label><input id="adEdge"></div><div><label>Min bet</label><input id="adMin"></div><div><label>Max win % of free bank</label><input id="adMaxP"></div></div>
        <label style="display:flex;gap:8px;align-items:center;text-transform:none;letter-spacing:0;font-size:14px;color:var(--ink)"><input type="checkbox" id="adPaused" style="width:auto"> Pause the game</label>
        <button class="btn" id="adSaveBtn" style="margin-top:6px">Save settings</button>
      </div>
    </div>
    <div class="card" style="margin-top:16px"><h3>Stats</h3><div id="adStats" class="tiny"></div></div>
    <div class="grid" style="margin-top:16px">
      <div class="card"><h3>Players</h3><table><thead><tr><th>Player</th><th>Balance</th><th>Wagered</th></tr></thead><tbody id="adPlayers"></tbody></table></div>
      <div class="card"><h3>Cash-outs</h3><table><thead><tr><th>#</th><th>Weight</th><th>Status</th></tr></thead><tbody id="adCash"></tbody></table></div>
    </div>
  </div>
</div>
<div id="toast"></div>
</div>
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const LS = { get(k) { try { return localStorage.getItem('dice.' + k); } catch (e) { return null; } }, set(k, v) { try { localStorage.setItem('dice.' + k, v); } catch (e) {} } };
const ADMIN = location.search.includes('admin');
let S = { key: LS.get('playKey') || '', st: null, adminPw: '' };

function toast(msg, kind) { const t = document.createElement('div'); t.className = 't ' + (kind || ''); t.textContent = msg; $('toast').appendChild(t); setTimeout(() => t.remove(), 6000); }
async function api(action, body, extra) {
  const h = { 'Content-Type': 'application/json' };
  if (S.key) h['X-Play-Key'] = S.key;
  if (extra) Object.assign(h, extra);
  const r = await fetch('?action=' + action, { method: 'POST', headers: h, body: JSON.stringify(body || {}) });
  const j = await r.json().catch(() => ({ ok: false, err: 'bad server reply' }));
  if (!j.ok) throw new Error(j.err || 'request failed');
  return j;
}
function short(s, n) { s = String(s || ''); return s.length > n * 2 + 1 ? s.slice(0, n) + '…' + s.slice(-n) : s; }

/* ---- game ---- */
function calc() {
  const t = parseFloat($('target').value), b = parseFloat($('bet').value), edge = S.st ? S.st.edge : 1;
  if (!(t >= 2 && t <= 98)) { $('sChance').textContent = $('sMult').textContent = $('sProfit').textContent = '-'; return; }
  const mult = (100 - edge) / t;
  $('sChance').textContent = t.toFixed(2) + '%';
  $('sMult').textContent = mult.toFixed(4) + '×';
  $('sProfit').textContent = b > 0 ? (Math.floor(b * 1000 * mult) / 1000 - b).toFixed(3) : '-';
}
function renderPlayer(p) {
  if (!p) return;
  $('bal').textContent = p.balance;
  $('fHash').textContent = p.seed_hash; $('fNonce').value = p.nonce;
  if (document.activeElement !== $('fClient')) $('fClient').value = p.client_seed;
  if (p.addr && !$('coAddr').value) $('coAddr').value = p.addr;
  $('bets').innerHTML = p.bets.map(b => `<tr><td>${b.nonce}</td><td>${esc(b.amount)}</td><td>${b.target.toFixed(2)}</td><td>${b.roll.toFixed(2)}</td><td class="${b.win ? 'w' : 'l'}">${b.win ? '+' + esc(b.payout) : 'lost'}</td></tr>`).join('') || '<tr><td colspan="5" class="mut">No rolls yet.</td></tr>';
  $('fOld').innerHTML = p.old_seeds.length ? '<b>Revealed seeds</b><br>' + p.old_seeds.map((s, i) => `<div class="mono" style="margin-top:4px">server ${esc(s.server_seed)}<br><span class="mut">hash ${esc(s.seed_hash)} · client ${esc(s.client_seed)} · nonces 0-${s.last_nonce - 1}</span>
    <button class="btn sm" data-verify="${i}" style="margin-left:6px">verify my rolls</button> <span id="vres${i}"></span></div>`).join('') : '';
  document.querySelectorAll('[data-verify]').forEach(b => b.onclick = () => verifySeed(p, p.old_seeds[+b.dataset.verify], 'vres' + b.dataset.verify));
}
/* Recompute every listed roll made with a revealed seed, in the browser (WebCrypto HMAC-SHA256). */
async function verifySeed(p, s, outId) {
  const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
  const te = new TextEncoder();
  const hashOk = hex(await crypto.subtle.digest('SHA-256', te.encode(s.server_seed))) === s.seed_hash;
  const key = await crypto.subtle.importKey('raw', te.encode(s.server_seed), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  let ok = 0, bad = 0;
  for (const b of p.bets.filter(x => x.seed_hash === s.seed_hash)) {
    const h = hex(await crypto.subtle.sign('HMAC', key, te.encode(b.client_seed + ':' + b.nonce)));
    const roll = Math.floor(parseInt(h.slice(0, 8), 16) / 4294967296 * 10000) / 100;
    if (Math.abs(roll - b.roll) < 1e-9) ok++; else bad++;
  }
  $(outId).innerHTML = hashOk && !bad ? `<span class="w">✓ seed matches its hash, ${ok} roll(s) verified</span>` : `<span class="l">✗ mismatch (hash ${hashOk ? 'ok' : 'WRONG'}, ${bad} bad roll(s))</span>`;
}
async function refresh() {
  try {
    const st = await api('state'); S.st = st;
    $('hEdge').textContent = st.edge; $('hMax').textContent = st.max_profit;
    $('hSite').textContent = st.site ? short(st.site, 14) : 'not set up';
    $('notice').classList.toggle('hidden', st.ready && !st.paused && st.bank_ok);
    $('notice').textContent = !st.ready ? 'This dice site is not set up yet - the admin needs to load the site wallet.' : st.paused ? 'The game is paused by the admin.' : !st.bank_ok ? 'Bankroll unavailable: ' + (st.bank_err || '') : '';
    if (st.player) renderPlayer(st.player);
    calc();
  } catch (e) { toast(e.message, 'bad'); }
}
async function ensureKey() {
  if (/^[0-9a-f]{40}$/.test(S.key)) { $('playKey').value = S.key; return; }
  const r = await api('new_player'); S.key = r.play_key; LS.set('playKey', S.key); $('playKey').value = S.key;
}
$('target').oninput = () => { $('slider').value = $('target').value; calc(); };
$('slider').oninput = () => { $('target').value = parseFloat($('slider').value).toFixed(2); calc(); };
$('bet').oninput = calc;
document.querySelectorAll('[data-bet]').forEach(b => b.onclick = () => {
  let v = parseFloat($('bet').value) || 0; const bal = S.st && S.st.player ? S.st.player.balance_m / 1000 : 0;
  v = b.dataset.bet === 'half' ? v / 2 : b.dataset.bet === 'double' ? v * 2 : bal;
  $('bet').value = (Math.floor(v * 1000) / 1000).toString(); calc();
});
$('rollBtn').onclick = async () => {
  $('rollBtn').disabled = true;
  try {
    const r = await api('bet', { amount: $('bet').value.trim(), target: $('target').value.trim() });
    const o = $('rollOut'); o.textContent = r.roll.toFixed(2); o.className = 'roll ' + (r.win ? 'win' : 'lose');
    toast(r.win ? `Win! Rolled ${r.roll.toFixed(2)} - paid ${r.payout}` : `Rolled ${r.roll.toFixed(2)} - lost ${r.profit}`, r.win ? 'ok' : '');
    renderPlayer(r.player); S.st.player = r.player;
  } catch (e) { toast(e.message, 'bad'); }
  $('rollBtn').disabled = false;
};
$('depFile').onchange = async () => { const f = $('depFile').files[0]; if (f) $('depText').value = await f.text(); };
$('depBtn').onclick = async () => {
  const v = $('depText').value.trim(); if (!v) return toast('Paste a voucher or choose the file first.', 'bad');
  $('depBtn').disabled = true;
  try {
    const r = await api('deposit', { voucher: v });
    if (r.credited > 0) { toast(`Deposited ${r.credited} weight.`, 'ok'); $('depText').value = ''; $('depFile').value = ''; }
    else toast('Nothing was credited. ' + (r.notes.join('; ') || 'Is the voucher made out to this site\'s address?'), 'bad');
    renderPlayer(r.player); refresh();
  } catch (e) { toast(e.message, 'bad'); }
  $('depBtn').disabled = false;
};
$('coBtn').onclick = async () => {
  $('coBtn').disabled = true;
  try {
    const r = await api('cashout', { to: $('coAddr').value.trim(), weight: parseInt($('coW').value, 10) });
    toast(r.sent ? `Sent ${r.sent} weight to your address.` + (r.refunded ? ` ${r.refunded} returned to your balance (${r.err}).` : '') : 'Cash-out failed, your balance is unchanged: ' + r.err, r.sent ? 'ok' : 'bad');
    renderPlayer(r.player); refresh();
  } catch (e) { toast(e.message, 'bad'); }
  $('coBtn').disabled = false;
};
$('fRotate').onclick = async () => { try { const r = await api('seed', { client_seed: $('fClient').value.trim() }); renderPlayer(r.player); toast('New server seed - the previous one is revealed below.', 'ok'); } catch (e) { toast(e.message, 'bad'); } };
$('copySite').onclick = () => S.st && S.st.site && navigator.clipboard.writeText(S.st.site).then(() => toast('Site address copied.', 'ok'));
$('copyKey').onclick = () => navigator.clipboard.writeText(S.key).then(() => toast('Play key copied - keep it somewhere safe.', 'ok'));
$('useKey').onclick = () => { const k = $('restoreKey').value.trim().toLowerCase(); if (!/^[0-9a-f]{40}$/.test(k)) return toast('A play key is 40 hex characters.', 'bad'); S.key = k; LS.set('playKey', k); $('restoreKey').value = ''; $('playKey').value = k; refresh(); };

/* #rawtx= / #voucher= link -> fill the deposit box */
function hashLink() {
  const m = /^#(rawtx|voucher)=(.+)$/s.exec(location.hash || ''); if (!m) return;
  try { $('depText').value = decodeURIComponent(m[2]); } catch (e) { return; }
  history.replaceState(null, '', location.pathname + location.search);
  toast('Transaction loaded from the link - press Deposit to redeem it.', '');
}

/* ---- admin ---- */
async function adminLoad() {
  const a = await api('admin', { op: 'state' }, { 'X-Admin-Pass': S.adminPw });
  $('adLogin').classList.add('hidden'); $('adPanel').classList.remove('hidden');
  $('adWallet').innerHTML = a.wallet_loaded ? `Loaded: <span class="mono">${esc(a.site)}</span>` : '<span class="l">No wallet loaded yet.</span>';
  $('adBank').innerHTML = a.bank ? `Site holds <b>${a.bank.holdings}</b> · owed to players <b>${a.bank.liabilities}</b> · free <b class="${a.bank.short ? 'l' : 'w'}">${a.bank.free}</b> · max win per roll <b>${a.bank.max_profit}</b>${a.bank.short ? '<br><b class="l">Warning: the site holds less than it owes players.</b>' : ''}`
    : `<span class="l">${esc(a.bank_err || 'unavailable')}</span> (EVOTE_URL = <span class="mono">${esc(a.evote_url)}</span>)`;
  const s = a.settings; $('adEdge').value = s.edge; $('adMin').value = s.min_bet; $('adMaxP').value = s.max_profit_pct; $('adPaused').checked = s.paused === '1';
  const t = a.stats;
  $('adStats').innerHTML = `${t.bets} rolls · wagered ${t.wagered} · paid out ${t.paid} · house result <b>${t.house_result}</b> · deposits ${t.deposited} · cash-outs ${t.cashed_out}`;
  $('adPlayers').innerHTML = a.players.map(p => `<tr><td class="mono">${esc(p.id)}</td><td>${esc(p.balance)}</td><td>${esc(p.wagered)}</td></tr>`).join('') || '<tr><td colspan="3" class="mut">none</td></tr>';
  $('adCash').innerHTML = a.cashouts.map(c => `<tr><td>${c.id}</td><td>${c.weight}</td><td>${esc(c.status)} <span class="mut">${esc(c.detail)}</span></td></tr>`).join('') || '<tr><td colspan="3" class="mut">none</td></tr>';
}
const adm = (op, body) => api('admin', Object.assign({ op }, body || {}), { 'X-Admin-Pass': S.adminPw });
$('adSetupBtn').onclick = async () => { try { await api('admin_setup', { password: $('adNewPw').value }); toast('Admin password saved. Log in below.', 'ok'); $('adSetup').classList.add('hidden'); } catch (e) { toast(e.message, 'bad'); } };
$('adLoginBtn').onclick = async () => { S.adminPw = $('adPw').value; try { await adminLoad(); } catch (e) { toast(e.message, 'bad'); } };
$('adWalletBtn').onclick = async () => {
  const f = $('adWalletFile').files[0]; if (!f) return toast('Choose the wallet file.', 'bad');
  $('adWalletBtn').disabled = true;
  try { const r = await adm('wallet', { wallet: await f.text(), passphrase: $('adWalletPass').value }); $('adWalletPass').value = ''; toast('Site wallet loaded.', 'ok'); await adminLoad(); } catch (e) { toast(e.message, 'bad'); }
  $('adWalletBtn').disabled = false;
};
$('adImportFile').onchange = async () => { const f = $('adImportFile').files[0]; if (f) $('adImport').value = await f.text(); };
$('adImportBtn').onclick = async () => { try { const r = await adm('import', { data: $('adImport').value.trim() }); toast(`Imported: ${r.deposited_now} weight landed now, site holds ${r.site_weight}.`, 'ok'); $('adImport').value = ''; adminLoad(); } catch (e) { toast(e.message, 'bad'); } };
$('adSaveBtn').onclick = async () => { try { await adm('settings', { edge: $('adEdge').value, min_bet: $('adMin').value, max_profit_pct: $('adMaxP').value, paused: $('adPaused').checked }); toast('Settings saved.', 'ok'); adminLoad(); } catch (e) { toast(e.message, 'bad'); } };
$('adWdBtn').onclick = async () => { try { const r = await adm('withdraw', { to: $('adWdTo').value.trim(), weight: parseInt($('adWdW').value, 10) }); toast(`Sent ${r.sent} weight.`, 'ok'); adminLoad(); } catch (e) { toast(e.message, 'bad'); } };

(async () => {
  if (ADMIN) {
    $('game').classList.add('hidden'); $('admin').classList.remove('hidden');
    const st = await api('state').catch(() => ({}));
    $('adSetup').classList.toggle('hidden', !!st.installed);
    if (st.site) $('hSite').textContent = short(st.site, 14);
    return;
  }
  try { await ensureKey(); } catch (e) { toast(e.message, 'bad'); }
  hashLink(); await refresh(); setInterval(refresh, 15000);
})();
</script>
</body>
</html>
