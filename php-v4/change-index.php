<?php
declare(strict_types=1);
/**
 * EVOTE CHANGE MACHINE — breaks a large coin into smaller ones (and back), like a bank breaking a bill.
 *
 *   The machine holds a float of coins in fixed denominations (stocked by the admin; every coin it
 *   receives joins the float). A user sends a coin by voucher / signed lines, picks the change they
 *   want, and is paid from the float. Change ALWAYS goes back to the address that paid, so the
 *   ledger keeps showing who exchanged what. If anything can't be paid exactly, the coins are refunded.
 *
 *   Deploy: upload as e.g. /change/index.php, set EVOTE_URL below, open ?admin.
 *   Needs PHP >= 8.0 with sodium + pdo_sqlite + curl, and the EVOTE redeem/balance API.
 */

const EVOTE_URL  = 'http://127.0.0.1/php-new3-3/index.php';   // server-side URL of the EVOTE index.php
const DATA_DIR   = __DIR__ . '/change-data';                  // best: a folder outside the web root
const DB_FILE    = DATA_DIR . '/change.sqlite';
const KEY_FILE   = DATA_DIR . '/master-key.php';
const HARD_MAX_COINS = 240;                                   // EVOTE accepts 250 lines per call
const DEFAULTS   = ['denoms' => '1,10,20,50,100', 'max_coins' => '200', 'paused' => '0'];
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
CREATE TABLE IF NOT EXISTS exchanges (
  id INTEGER PRIMARY KEY AUTOINCREMENT, addr TEXT NOT NULL, in_weight INTEGER NOT NULL, in_coins INTEGER NOT NULL,
  request TEXT NOT NULL, out_weight INTEGER NOT NULL DEFAULT 0, out_coins INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL);
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


/* ---------------------------------------------------------------- change logic */

function denoms(): array {
    $d = array_values(array_unique(array_filter(array_map('intval', explode(',', setting('denoms'))), fn($x) => $x >= 1)));
    rsort($d); return $d;
}
function max_coins(): int { return max(1, min(HARD_MAX_COINS, (int)setting('max_coins'))); }
function float_coins(array $exclude = []): array {
    if (site_addr() === '') return [];
    $b = evote('balance', ['pub' => site_addr()]);
    $ex = array_flip($exclude);
    return array_values(array_filter($b['coins'], fn($c) => !isset($ex[$c['hash']])));
}
function float_counts(array $coins): array {
    $n = []; foreach ($coins as $c) $n[$c['amount']] = ($n[$c['amount']] ?? 0) + 1; krsort($n); return $n;
}
/* How many coins of each denomination to pay `weight`, given what the float holds.
   mode "fewest": largest denominations first (exact subset-sum fallback); "d:X": all in X; "custom": counts. */
function plan_change(int $weight, string $mode, array $counts, array $float): array {
    $have = float_counts($float); $den = denoms();
    if ($weight < 1) return ['ok' => false, 'err' => 'nothing to exchange'];
    if ($mode === 'custom') {
        $plan = []; $sum = 0;
        foreach ($counts as $d => $n) { $d = (int)$d; $n = (int)$n; if ($n <= 0) continue;
            if (!in_array($d, $den, true)) return ['ok' => false, 'err' => "$d is not one of the machine's denominations"];
            $plan[$d] = $n; $sum += $d * $n; }
        if ($sum !== $weight) return ['ok' => false, 'err' => "your breakdown adds up to $sum, not $weight"];
    } elseif (preg_match('/^d:(\d+)$/', $mode, $m)) {
        $d = (int)$m[1];
        if (!in_array($d, $den, true)) return ['ok' => false, 'err' => "$d is not one of the machine's denominations"];
        if ($weight % $d) return ['ok' => false, 'err' => "$weight can't be paid in {$d}s only"];
        $plan = [$d => intdiv($weight, $d)];
    } else {                                   // fewest coins the float can actually pay
        $plan = []; $left = $weight;
        foreach ($den as $d) { $n = min(intdiv($left, $d), $have[$d] ?? 0); if ($n > 0) { $plan[$d] = $n; $left -= $n * $d; } }
        if ($left > 0) {
            $usable = array_values(array_filter($float, fn($c) => in_array((int)$c['amount'], $den, true)));
            $pick = pick_coins($usable, $weight);
            if (!$pick['exact']) return ['ok' => false, 'err' => "the float can't make exactly $weight right now"];
            $plan = []; foreach ($pick['exact'] as $c) $plan[(int)$c['amount']] = ($plan[(int)$c['amount']] ?? 0) + 1;
        }
    }
    krsort($plan);
    $coins = array_sum($plan);
    if ($coins > max_coins()) return ['ok' => false, 'err' => "that is $coins coins - the machine pays at most " . max_coins() . ' per exchange'];
    foreach ($plan as $d => $n) if (($have[$d] ?? 0) < $n) return ['ok' => false, 'err' => "the float has only " . ($have[$d] ?? 0) . " coin(s) of $d, you asked for $n", 'short' => $d];
    return ['ok' => true, 'plan' => $plan, 'coins' => $coins];
}
function pick_for_plan(array $plan, array $float): array {
    $by = []; usort($float, fn($a, $b) => $a['updated'] <=> $b['updated']);
    foreach ($float as $c) $by[(int)$c['amount']][] = $c;
    $out = []; foreach ($plan as $d => $n) $out = array_merge($out, array_slice($by[$d] ?? [], 0, $n));
    return $out;
}
function send_coins(array $key, array $coins, string $to): array {
    if (!$coins) return ['weight' => 0, 'err' => ''];
    $lines = array_map(fn($c) => make_line($key, 'SIGNED_TRANSFER', [$c['hash'], $to, (string)$c['amount'], (string)(time() + 3600)]), $coins);
    $err = '';
    try {
        $r = evote('redeem', ['lines' => $lines, 'to' => $to]);
        foreach ($r['items'] as $it) if (($it['status'] ?? '') !== 'deposited') $err .= ($it['status'] ?? '?') . ' ' . ($it['err'] ?? '') . '; ';
        return ['weight' => (int)($r['to']['weight'] ?? 0), 'err' => trim($err)];
    } catch (Throwable $e) { return ['weight' => 0, 'err' => $e->getMessage()]; }
}
function voucher_body($v): array {
    if (is_string($v) && $v !== '' && $v[0] === '{') $v = json_decode($v, true);
    if (is_array($v)) return ($v['format'] ?? '') === 'evote-coins'
        ? ['lines' => array_merge(...array_map(fn($c) => (array)($c['lines'] ?? []), (array)($v['coins'] ?? [])) ?: [[]])]
        : ['voucher' => $v];
    if (is_string($v) && trim($v) !== '') return ['raw' => $v];
    fail('paste a voucher or signed transfer lines');
}

/* ---------------------------------------------------------------- http */
$action = (string)($_GET['action'] ?? '');
if ($action !== '') {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') fail('POST required', 405);
    if (!same_origin()) fail('cross-origin blocked', 403);
    if (stripos((string)($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json') === false) fail('application/json required', 415);
    $in = json_decode((string)file_get_contents('php://input'), true); if (!is_array($in)) $in = [];
    try {
        switch ($action) {

        case 'state': {
            $v = ['ok' => true, 'site' => site_addr(), 'installed' => meta_get('admin_hash') !== null, 'paused' => setting('paused') === '1',
                  'denoms' => denoms(), 'max_coins' => max_coins()];
            try { $c = float_counts(float_coins()); $v['float'] = $c; $v['float_ok'] = true; }
            catch (Throwable $e) { $v['float'] = []; $v['float_ok'] = false; $v['float_err'] = $e->getMessage(); }
            out($v);
        }

        case 'quote': {
            $r = plan_change((int)($in['weight'] ?? 0), (string)($in['mode'] ?? 'fewest'), (array)($in['counts'] ?? []), float_coins());
            out(['ok' => true, 'possible' => $r['ok']] + $r);     // ok = request worked; possible = the machine can pay it
        }

        case 'exchange': {
            if (setting('paused') === '1') fail('the change machine is paused');
            if (site_addr() === '') fail('the machine is not set up yet');
            $body = voucher_body($in['voucher'] ?? null) + ['to' => site_addr()];
            $mode = (string)($in['mode'] ?? 'fewest'); $counts = (array)($in['counts'] ?? []);
            $res = with_lock(function () use ($body, $mode, $counts) {
                $key = site_key(); if (!$key) fail('the machine wallet is not loaded');
                $r = evote('redeem', $body);
                $landed = array_values(array_filter($r['items'], fn($i) => ($i['status'] ?? '') === 'deposited' && ($i['to'] ?? '') === site_addr()));
                $notes = array_values(array_filter(array_map(fn($i) => ($i['status'] ?? '') === 'deposited' ? null : (($i['status'] ?? '?') . (isset($i['err']) ? ': ' . $i['err'] : '')), $r['items'])));
                if (!$landed) return ['done' => false, 'err' => 'nothing arrived at the machine' . ($notes ? ' (' . implode('; ', $notes) . ')' : '') . ' - is the voucher made out to the machine address?'];
                $payers = array_values(array_unique(array_column($landed, 'from')));
                $inW = array_sum(array_column($landed, 'amount')); $inHashes = array_column($landed, 'coin');
                $db = db();
                $db->prepare('INSERT INTO exchanges(addr,in_weight,in_coins,request,status,ts) VALUES(?,?,?,?,?,?)')
                   ->execute([$payers[0], $inW, count($landed), json_encode(['mode' => $mode, 'counts' => $counts]), 'received', time()]);
                $xid = (int)$db->lastInsertId();
                $refund = function (string $why) use ($key, $landed, $db, $xid) {   // every coin goes back to the address it came from
                    $sent = 0; $err = '';
                    foreach (array_unique(array_column($landed, 'from')) as $who) {
                        $mine = array_map(fn($i) => ['hash' => $i['coin'], 'amount' => (int)$i['amount']], array_filter($landed, fn($i) => $i['from'] === $who));
                        $s = send_coins($key, $mine, $who); $sent += $s['weight']; $err .= $s['err'];
                    }
                    $db->prepare('UPDATE exchanges SET status=?, detail=? WHERE id=?')->execute([$err === '' ? 'refunded' : 'refund-failed', trim($why . ' ' . $err), $xid]);
                    return ['done' => false, 'refunded' => $sent, 'err' => $why . ($err ? " (refund problem: $err - the admin can see it)" : ' - your coins were sent back.')];
                };
                if (count($payers) > 1) return $refund('a voucher must come from one address');
                $plan = plan_change($inW, $mode, $counts, float_coins($inHashes));
                if (!$plan['ok']) return $refund($plan['err']);
                $pay = pick_for_plan($plan['plan'], float_coins($inHashes));
                $s = send_coins($key, $pay, $payers[0]);
                if ($s['weight'] !== $inW) {                     // pay what is missing back as the original coins' value
                    $db->prepare('UPDATE exchanges SET out_weight=?, out_coins=?, status=?, detail=? WHERE id=?')->execute([$s['weight'], count($pay), 'partial', $s['err'], $xid]);
                    return ['done' => false, 'paid' => $s['weight'], 'err' => "only {$s['weight']} of $inW was paid ({$s['err']}). The admin can see this exchange (#$xid) and settle it."];
                }
                $db->prepare('UPDATE exchanges SET out_weight=?, out_coins=?, status=? WHERE id=?')->execute([$s['weight'], count($pay), 'paid', $xid]);
                return ['done' => true, 'id' => $xid, 'in' => $inW, 'paid' => $s['weight'], 'plan' => $plan['plan'], 'to' => $payers[0]];
            });
            out(['ok' => true] + $res);
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
                $fl = null; $err = '';
                try { $coins = float_coins(); $fl = ['counts' => float_counts($coins), 'weight' => array_sum(array_column($coins, 'amount')), 'coins' => count($coins)]; }
                catch (Throwable $e) { $err = $e->getMessage(); }
                $x = db()->query('SELECT id, addr, in_weight, in_coins, request, out_weight, out_coins, status, detail, ts FROM exchanges ORDER BY id DESC LIMIT 30')->fetchAll(PDO::FETCH_ASSOC);
                $tot = db()->query("SELECT COUNT(*) n, COALESCE(SUM(in_weight),0) w FROM exchanges WHERE status='paid'")->fetch(PDO::FETCH_ASSOC);
                out(['ok' => true, 'site' => site_addr(), 'wallet_loaded' => site_key() !== null, 'float' => $fl, 'float_err' => $err, 'evote_url' => EVOTE_URL,
                     'settings' => ['denoms' => setting('denoms'), 'max_coins' => (string)max_coins(), 'paused' => setting('paused')],
                     'stats' => ['exchanges' => (int)$tot['n'], 'weight' => (int)$tot['w']], 'exchanges' => $x]);
            }
            if ($op === 'wallet') {
                $f = $in['wallet'] ?? null; if (is_string($f)) $f = json_decode($f, true);
                if (!is_array($f)) fail('choose the machine\'s evote-wallet.json file');
                $w = with_lock(fn() => wallet_decrypt($f, (string)($in['passphrase'] ?? '')));
                meta_set('wallet_box', seal($w['seed'])); meta_set('wallet_pub', $w['pub']);
                sodium_memzero($w['seed']);
                out(['ok' => true, 'site' => site_addr()]);
            }
            if ($op === 'settings') {
                $d = array_values(array_unique(array_filter(array_map('intval', explode(',', (string)($in['denoms'] ?? ''))), fn($x) => $x >= 1 && $x <= 1000000)));
                if (!$d) fail('denominations: comma-separated whole numbers, e.g. 1,10,20,50,100');
                rsort($d);
                $mc = (int)($in['max_coins'] ?? 200); if ($mc < 1 || $mc > HARD_MAX_COINS) fail('max coins per exchange: 1-' . HARD_MAX_COINS);
                meta_set('set_denoms', implode(',', $d)); meta_set('set_max_coins', (string)$mc); meta_set('set_paused', !empty($in['paused']) ? '1' : '0');
                out(['ok' => true]);
            }
            if ($op === 'import') {                // stock the float: coin bundle / voucher / raw lines made out to the machine
                $r = evote('redeem', voucher_body($in['data'] ?? '') + ['to' => site_addr()]);
                $coins = float_coins();
                out(['ok' => true, 'deposited_now' => (int)($r['to']['weight'] ?? 0), 'float_weight' => array_sum(array_column($coins, 'amount'))]);
            }
            if ($op === 'withdraw') {
                $to = trim((string)($in['to'] ?? '')); $w = (int)($in['weight'] ?? 0);
                if (raw_from_pub_id($to) === null || $w < 1) fail('address and whole weight required');
                $res = with_lock(function () use ($to, $w) {
                    $key = site_key(); if (!$key) fail('the machine wallet is not loaded');
                    $pick = pick_coins(float_coins(), $w);
                    if (!$pick['exact']) fail("no exact coin set for $w; closest {$pick['below']} / {$pick['above']}");
                    return send_coins($key, $pick['exact'], $to);
                });
                out(['ok' => true, 'sent' => $res['weight'], 'err' => $res['err']]);
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
<title>EVOTE Change Machine</title>
<style>
:root{--bg:#060912;--panel:#0d1322;--panel2:#111a2e;--line:#1e2a44;--ink:#e6ecff;--mut:#8b97b8;--cyan:#22d3ee;--indigo:#6366f1;--green:#22c55e;--red:#ef4444;--amber:#f59e0b}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
body{background:radial-gradient(1200px 600px at 80% -10%,rgba(99,102,241,.18),transparent),radial-gradient(900px 500px at -10% 10%,rgba(34,211,238,.10),transparent),var(--bg);min-height:100vh}
.wrap{max-width:1000px;margin:0 auto;padding:18px 16px 60px}
header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.logo{font-weight:800;letter-spacing:.14em;font-size:18px}.logo span{color:var(--cyan)}
.pill{border:1px solid var(--line);border-radius:999px;padding:4px 12px;font-size:12.5px;color:var(--mut);background:rgba(13,19,34,.7)}.pill b{color:var(--ink)}
.grid{display:grid;grid-template-columns:1.2fr 1fr;gap:16px}@media(max-width:860px){.grid{grid-template-columns:1fr}}
.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:16px;padding:16px 18px}
.card h3{margin:0 0 12px;font-size:14px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)}
label{display:block;font-size:11.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);margin:10px 0 5px}
input,textarea{width:100%;background:#0a1020;border:1px solid var(--line);color:var(--ink);border-radius:10px;padding:10px 12px;font:inherit}
textarea{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}input:focus,textarea:focus{outline:none;border-color:var(--cyan)}
.row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap}.row>*{flex:1;min-width:110px}
.btn{border:1px solid var(--line);background:#152039;color:var(--ink);border-radius:10px;padding:10px 14px;font:inherit;font-weight:600;cursor:pointer}
.btn:hover{border-color:var(--cyan)}.btn:disabled{opacity:.45;cursor:not-allowed}
.btn.primary{background:linear-gradient(90deg,var(--indigo),var(--cyan));border:0;color:#04101c}.btn.sm{padding:6px 10px;font-size:13px;flex:0 0 auto;min-width:0}
.mut{color:var(--mut)}.tiny{font-size:12.5px}.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:6px}
.chip{border:1px solid var(--line);border-radius:999px;padding:6px 12px;cursor:pointer;font-size:13.5px;background:#0a1020}
.chip.on{border-color:var(--cyan);background:rgba(34,211,238,.12)}
.den{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:8px;margin-top:6px}
.den div{background:#0a1020;border:1px solid var(--line);border-radius:10px;padding:8px 10px}.den b{font-size:18px}
.big{font-size:30px;font-weight:800}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:6px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--mut);font-size:11.5px;text-transform:uppercase;letter-spacing:.06em}
.w{color:var(--green)}.l{color:var(--red)}
#toast{position:fixed;right:16px;bottom:16px;max-width:400px;display:flex;flex-direction:column;gap:8px;z-index:9}
.t{background:#0d1322;border:1px solid var(--line);border-left:4px solid var(--cyan);border-radius:10px;padding:10px 12px;font-size:14px;box-shadow:0 8px 30px rgba(0,0,0,.4)}.t.bad{border-left-color:var(--red)}.t.ok{border-left-color:var(--green)}
.notice{border:1px solid rgba(245,158,11,.4);background:rgba(245,158,11,.08);border-radius:12px;padding:10px 12px;margin-bottom:14px;font-size:14px}
.hidden{display:none!important}
</style>
</head>
<body><div class="wrap">
<header>
  <div class="logo">EVOTE <span>CHANGE</span></div>
  <div class="pill">max <b id="hMax">-</b> coins per exchange</div>
  <div class="pill" style="margin-left:auto">machine address <b class="mono" id="hSite" style="font-size:11px">-</b> <button class="btn sm" id="copySite">copy</button></div>
</header>
<div id="notice" class="notice hidden"></div>

<div id="main" class="grid">
  <div>
    <div class="card">
      <h3>1 · Your coin</h3>
      <div class="tiny mut">In the EVOTE wallet, make an <b>offline voucher</b> (coin drawer, or Send → "Sign offline") for the coin(s) you want changed, made out to the machine address above. Paste it here or choose the file.</div>
      <textarea id="vText" rows="4" placeholder='{"format":"evote-voucher", ...}  or  SIGNED_TRANSFER|1|...' style="margin-top:8px"></textarea>
      <div class="row" style="margin-top:8px"><input type="file" id="vFile" accept=".json,.txt" style="padding:7px"></div>
      <div id="vInfo" class="tiny" style="margin-top:8px"></div>
    </div>
    <div class="card" style="margin-top:16px">
      <h3>2 · Change you want</h3>
      <div class="chips" id="modes"></div>
      <div id="custom" class="hidden"><div class="den" id="customIn"></div><div class="tiny mut" id="customSum" style="margin-top:6px"></div></div>
      <div id="quote" class="tiny" style="margin-top:10px"></div>
      <div class="row" style="margin-top:12px"><button class="btn" id="quoteBtn">Check</button><button class="btn primary" id="goBtn" style="flex:2">Exchange</button></div>
      <div class="tiny mut" style="margin-top:8px">The change is always paid to the address the coin came from. If it can't be paid exactly, your coin is sent back.</div>
    </div>
  </div>
  <div>
    <div class="card"><h3>Machine float</h3><div class="den" id="float"></div><div class="tiny mut" id="floatInfo" style="margin-top:8px"></div></div>
    <div class="card" style="margin-top:16px"><h3>Result</h3><div id="result" class="tiny mut">Nothing exchanged yet.</div></div>
  </div>
</div>

<div id="admin" class="hidden">
  <div class="card" id="adSetup"><h3>Admin setup</h3><div class="tiny mut">Choose the admin password (at least 10 characters).</div>
    <div class="row"><input id="adNewPw" type="password" placeholder="new admin password"><button class="btn primary" id="adSetupBtn">Save</button></div></div>
  <div class="card" id="adLogin" style="margin-top:16px"><h3>Admin login</h3><div class="row"><input id="adPw" type="password" placeholder="admin password"><button class="btn primary" id="adLoginBtn">Open</button></div></div>
  <div id="adPanel" class="hidden">
    <div class="grid" style="margin-top:16px">
      <div class="card"><h3>Float</h3><div id="adFloat" class="tiny"></div>
        <label>Stock the float</label><div class="tiny mut">Send coins to the machine address from any wallet, or paste an "Export coins" file / voucher made out to it.</div>
        <textarea id="adImport" rows="3" style="margin-top:6px"></textarea>
        <div class="row" style="margin-top:8px"><input type="file" id="adImportFile" accept=".json,.txt" style="padding:7px"><button class="btn" id="adImportBtn">Import</button></div>
        <label>Withdraw from the float</label>
        <div class="row"><input id="adWdTo" class="mono" placeholder="address"><input id="adWdW" placeholder="weight" style="flex:0 0 90px"><button class="btn sm" id="adWdBtn">Send</button></div></div>
      <div class="card"><h3>Machine wallet</h3><div id="adWallet" class="tiny"></div>
        <label>evote-wallet.json of the machine</label><input type="file" id="adWalletFile" accept=".json" style="padding:7px">
        <label>Passphrase</label><input type="password" id="adWalletPass">
        <div class="row" style="margin-top:8px"><button class="btn primary" id="adWalletBtn">Load wallet</button></div>
        <h3 style="margin-top:18px">Settings</h3>
        <div class="row"><div style="flex:2"><label>Denominations</label><input id="adDen"></div><div><label>Max coins / exchange</label><input id="adMax"></div></div>
        <label style="display:flex;gap:8px;align-items:center;text-transform:none;letter-spacing:0;font-size:14px;color:var(--ink)"><input type="checkbox" id="adPaused" style="width:auto"> Pause the machine</label>
        <button class="btn" id="adSaveBtn" style="margin-top:6px">Save settings</button></div>
    </div>
    <div class="card" style="margin-top:16px"><h3>Exchanges</h3><div id="adStats" class="tiny mut"></div>
      <table><thead><tr><th>#</th><th>In</th><th>Paid</th><th>Status</th><th>Address</th></tr></thead><tbody id="adX"></tbody></table></div>
  </div>
</div>
<div id="toast"></div>
</div>
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const ADMIN = location.search.includes('admin');
const S = { st: null, mode: 'fewest', adminPw: '', inW: 0 };
const short = (s, n) => { s = String(s || ''); return s.length > n * 2 + 1 ? s.slice(0, n) + '…' + s.slice(-n) : s; };
function toast(msg, kind) { const t = document.createElement('div'); t.className = 't ' + (kind || ''); t.textContent = msg; $('toast').appendChild(t); setTimeout(() => t.remove(), 7000); }
async function api(action, body, extra) {
  const h = Object.assign({ 'Content-Type': 'application/json' }, extra || {});
  const r = await fetch('?action=' + action, { method: 'POST', headers: h, body: JSON.stringify(body || {}) });
  const j = await r.json().catch(() => ({ ok: false, err: 'bad server reply' }));
  if (!j.ok) throw new Error(j.err || 'request failed');
  return j;
}
/* read the voucher in the browser just to show what is being exchanged (the server re-checks everything) */
function readVoucher(text) {
  let lines = []; text = text.trim(); if (!text) return null;
  try { if (text[0] === '{') { const j = JSON.parse(text); lines = j.format === 'evote-coins' ? j.coins.flatMap(c => c.lines) : (j.lines || []); } else lines = text.split('\n'); } catch (e) { return { err: 'not valid JSON' }; }
  let w = 0, n = 0; const from = new Set();
  for (const l of lines) { const p = String(l).trim().split('|'); if (p[0] === 'SIGNED_TRANSFER' && p.length === 10 && S.st && p[6] === S.st.site) { w += parseInt(p[7], 10) || 0; n++; from.add(p[2]); } }
  return { w, n, from: [...from] };
}
function showVoucher() {
  const v = readVoucher($('vText').value);
  S.inW = v && v.w ? v.w : 0;
  $('vInfo').innerHTML = !v ? '' : v.err ? `<span class="l">${esc(v.err)}</span>` : !v.n ? '<span class="l">No transfer to the machine address found in this voucher.</span>'
    : `Exchanging <b>${v.w}</b> weight (${v.n} coin${v.n === 1 ? '' : 's'}) from <span class="mono">${esc(short(v.from[0], 12))}</span>${v.from.length > 1 ? ' <span class="l">- more than one sender: not allowed</span>' : ''}`;
  renderCustom(); $('quote').textContent = '';
}
function renderModes() {
  const d = S.st.denoms;
  $('modes').innerHTML = [['fewest', 'Fewest coins'], ...d.map(x => ['d:' + x, 'All ' + x + 's']), ['custom', 'Custom']]
    .map(([m, t]) => `<div class="chip ${S.mode === m ? 'on' : ''}" data-mode="${m}">${t}</div>`).join('');
  document.querySelectorAll('[data-mode]').forEach(c => c.onclick = () => { S.mode = c.dataset.mode; renderModes(); $('custom').classList.toggle('hidden', S.mode !== 'custom'); $('quote').textContent = ''; });
  $('customIn').innerHTML = d.map(x => `<div><span class="tiny mut">${x}s</span><input type="number" min="0" step="1" value="0" data-den="${x}" style="margin-top:4px"></div>`).join('');
  document.querySelectorAll('[data-den]').forEach(i => i.oninput = renderCustom);
}
function counts() { const c = {}; document.querySelectorAll('[data-den]').forEach(i => { const n = parseInt(i.value, 10) || 0; if (n > 0) c[i.dataset.den] = n; }); return c; }
function renderCustom() { const c = counts(); const sum = Object.entries(c).reduce((a, [d, n]) => a + d * n, 0); $('customSum').textContent = `Custom total: ${sum}` + (S.inW ? ` of ${S.inW}` : ''); }
function planText(plan) { return Object.entries(plan).sort((a, b) => b[0] - a[0]).map(([d, n]) => `${n} × ${d}`).join(' + '); }
async function refresh() {
  try {
    const st = await api('state'); S.st = st;
    $('hSite').textContent = st.site ? short(st.site, 14) : 'not set up'; $('hMax').textContent = st.max_coins;
    $('notice').classList.toggle('hidden', !!st.site && !st.paused && st.float_ok);
    $('notice').textContent = !st.site ? 'This change machine is not set up yet.' : st.paused ? 'The change machine is paused.' : !st.float_ok ? 'Float unavailable: ' + (st.float_err || '') : '';
    const f = st.float || {};
    $('float').innerHTML = Object.keys(f).length ? Object.entries(f).sort((a, b) => b[0] - a[0]).map(([d, n]) => `<div><span class="tiny mut">${esc(d)}s</span><br><b>${n}</b> <span class="tiny mut">coin${n == 1 ? '' : 's'}</span></div>`).join('') : '<div class="tiny mut">empty</div>';
    $('floatInfo').textContent = 'Denominations offered: ' + st.denoms.join(', ');
    if (!$('modes').children.length) renderModes();
  } catch (e) { toast(e.message, 'bad'); }
}
$('vText').oninput = showVoucher;
$('vFile').onchange = async () => { const f = $('vFile').files[0]; if (f) { $('vText').value = await f.text(); showVoucher(); } };
$('copySite').onclick = () => S.st && S.st.site && navigator.clipboard.writeText(S.st.site).then(() => toast('Machine address copied.', 'ok'));
$('quoteBtn').onclick = async () => {
  if (!S.inW) return toast('Paste a voucher made out to the machine first.', 'bad');
  try { const q = await api('quote', { weight: S.inW, mode: S.mode, counts: counts() });
    $('quote').innerHTML = q.possible ? `<span class="w">✓ The machine can pay ${S.inW} as ${planText(q.plan)} (${q.coins} coins).</span>` : `<span class="l">✗ ${esc(q.err)}</span>`;
  } catch (e) { toast(e.message, 'bad'); }
};
$('goBtn').onclick = async () => {
  const v = $('vText').value.trim(); if (!v) return toast('Paste a voucher first.', 'bad');
  $('goBtn').disabled = true;
  try {
    const r = await api('exchange', { voucher: v, mode: S.mode, counts: counts() });
    if (r.done) { $('result').innerHTML = `<span class="w">✓ Exchange #${r.id}: received ${r.in}, paid ${r.paid} as ${planText(r.plan)}</span><br>to <span class="mono">${esc(short(r.to, 16))}</span>`; toast('Change paid to your address.', 'ok'); $('vText').value = ''; $('vFile').value = ''; showVoucher(); }
    else { $('result').innerHTML = `<span class="l">✗ ${esc(r.err)}</span>`; toast(r.err, 'bad'); }
    refresh();
  } catch (e) { toast(e.message, 'bad'); }
  $('goBtn').disabled = false;
};
function hashLink() {
  const m = /^#(rawtx|voucher)=(.+)$/s.exec(location.hash || ''); if (!m) return;
  try { $('vText').value = decodeURIComponent(m[2]); } catch (e) { return; }
  history.replaceState(null, '', location.pathname + location.search); showVoucher();
}

/* ---- admin ---- */
const adm = (op, body) => api('admin', Object.assign({ op }, body || {}), { 'X-Admin-Pass': S.adminPw });
async function adminLoad() {
  const a = await adm('state');
  $('adLogin').classList.add('hidden'); $('adPanel').classList.remove('hidden');
  $('adWallet').innerHTML = a.wallet_loaded ? `Loaded: <span class="mono">${esc(a.site)}</span>` : '<span class="l">No wallet loaded yet.</span>';
  $('adFloat').innerHTML = a.float ? `Holds <b>${a.float.weight}</b> weight in <b>${a.float.coins}</b> coins: ` + (Object.entries(a.float.counts).sort((x, y) => y[0] - x[0]).map(([d, n]) => `${n}×${d}`).join(' · ') || 'empty')
    : `<span class="l">${esc(a.float_err || 'unavailable')}</span> (EVOTE_URL = <span class="mono">${esc(a.evote_url)}</span>)`;
  $('adDen').value = a.settings.denoms; $('adMax').value = a.settings.max_coins; $('adPaused').checked = a.settings.paused === '1';
  $('adStats').textContent = `${a.stats.exchanges} paid exchange(s), ${a.stats.weight} weight changed`;
  $('adX').innerHTML = a.exchanges.map(x => `<tr><td>${x.id}</td><td>${x.in_weight} (${x.in_coins})</td><td>${x.out_weight} (${x.out_coins})</td><td class="${x.status === 'paid' ? 'w' : x.status === 'refunded' ? '' : 'l'}">${esc(x.status)} <span class="mut">${esc(x.detail)}</span></td><td class="mono">${esc(short(x.addr, 8))}</td></tr>`).join('') || '<tr><td colspan="5" class="mut">none</td></tr>';
}
$('adSetupBtn').onclick = async () => { try { await api('admin_setup', { password: $('adNewPw').value }); toast('Admin password saved. Log in below.', 'ok'); $('adSetup').classList.add('hidden'); } catch (e) { toast(e.message, 'bad'); } };
$('adLoginBtn').onclick = async () => { S.adminPw = $('adPw').value; try { await adminLoad(); } catch (e) { toast(e.message, 'bad'); } };
$('adWalletBtn').onclick = async () => {
  const f = $('adWalletFile').files[0]; if (!f) return toast('Choose the wallet file.', 'bad');
  $('adWalletBtn').disabled = true;
  try { await adm('wallet', { wallet: await f.text(), passphrase: $('adWalletPass').value }); $('adWalletPass').value = ''; toast('Machine wallet loaded.', 'ok'); await adminLoad(); } catch (e) { toast(e.message, 'bad'); }
  $('adWalletBtn').disabled = false;
};
$('adImportFile').onchange = async () => { const f = $('adImportFile').files[0]; if (f) $('adImport').value = await f.text(); };
$('adImportBtn').onclick = async () => { try { const r = await adm('import', { data: $('adImport').value.trim() }); toast(`Imported: ${r.deposited_now} weight landed, float now ${r.float_weight}.`, 'ok'); $('adImport').value = ''; adminLoad(); } catch (e) { toast(e.message, 'bad'); } };
$('adSaveBtn').onclick = async () => { try { await adm('settings', { denoms: $('adDen').value, max_coins: $('adMax').value, paused: $('adPaused').checked }); toast('Settings saved.', 'ok'); adminLoad(); } catch (e) { toast(e.message, 'bad'); } };
$('adWdBtn').onclick = async () => { try { const r = await adm('withdraw', { to: $('adWdTo').value.trim(), weight: parseInt($('adWdW').value, 10) }); toast(`Sent ${r.sent} weight.` + (r.err ? ' ' + r.err : ''), r.err ? 'bad' : 'ok'); adminLoad(); } catch (e) { toast(e.message, 'bad'); } };

(async () => {
  if (ADMIN) {
    $('main').classList.add('hidden'); $('admin').classList.remove('hidden');
    const st = await api('state').catch(() => ({}));
    $('adSetup').classList.toggle('hidden', !!st.installed);
    if (st.site) $('hSite').textContent = short(st.site, 14);
    if (st.max_coins) $('hMax').textContent = st.max_coins;
    return;
  }
  await refresh(); hashLink(); setInterval(refresh, 20000);
})();
</script>
</body>
</html>
