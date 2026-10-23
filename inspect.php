<?php
/**
 * php2shell-checker — inspect.php
 *
 * Deep, INFORMATIONAL server-posture scanner for CVE-2026-109618 /
 * CVE-2026-109619. This goes well beyond reading a version number (which any
 * online header scanner already shows): it answers the two questions that can
 * only be answered ON the server, and which decide whether you are actually
 * safe:
 *
 *   1. BACKPORT — did the OS vendor backport the fix even though the base
 *      version number still looks old? (Debian/Ubuntu `dpkg`+changelog,
 *      RHEL/Alma/Rocky `rpm --changelog`.) Resolves false positives.
 *
 *   2. RESTART — was the patched package actually loaded, i.e. were the
 *      php-fpm/apache workers restarted AFTER the package was updated? A
 *      patched package with un-restarted workers is STILL vulnerable.
 *
 * It also inventories every PHP runtime/SAPI and reads the risk-relevant ini
 * settings, then prints a consolidated verdict with EVIDENCE as text, JSON, or
 * a shareable HTML report.
 *
 * Purely informational: it reads versions, package metadata, process start
 * times and ini values. It exploits nothing and sends no network requests.
 * Run it ON the server (as root/sudo to see every runtime and package log).
 *
 * Usage:
 *   php inspect.php                 # full text report
 *   php inspect.php --json          # structured JSON
 *   php inspect.php --html report.html   # write an HTML report (or - for stdout)
 *   php inspect.php --recommend     # tailored, severity-ranked remediation steps
 *   php inspect.php --prompt        # ready-to-paste prompt for an AI assistant
 *   php inspect.php --prompt --redact    # same, with absolute paths stripped
 *
 * License: MIT.
 */

// Load the shared version matrix / evaluator from check.php as a library.
define('P2S_LIB', 1);
require __DIR__ . '/check.php';

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** Run a shell command, return [stdout, exit_code]. Empty/failed => ['', rc]. */
function sh(string $cmd): array
{
    $out = @shell_exec($cmd . ' 2>/dev/null');
    return [is_string($out) ? trim($out) : '', 0];
}

function have(string $bin): bool
{
    $p = @shell_exec('command -v ' . escapeshellarg($bin) . ' 2>/dev/null');
    return is_string($p) && trim($p) !== '';
}

/** Detect the OS family: debian | rhel | alpine | macos | unknown. */
function os_family(): string
{
    if (PHP_OS_FAMILY === 'Darwin') {
        return 'macos';
    }
    if (is_readable('/etc/os-release')) {
        $r = (string)@file_get_contents('/etc/os-release');
        $like = '';
        if (preg_match('/^ID_LIKE=(.*)$/m', $r, $m)) $like = strtolower(trim($m[1], " \"'"));
        if (preg_match('/^ID=(.*)$/m', $r, $m))      $id   = strtolower(trim($m[1], " \"'")); else $id = '';
        $hay = $id . ' ' . $like;
        if (preg_match('/debian|ubuntu/', $hay))                    return 'debian';
        if (preg_match('/rhel|fedora|centos|rocky|alma/', $hay))    return 'rhel';
        if (preg_match('/alpine/', $hay))                           return 'alpine';
    }
    if (have('dpkg'))         return 'debian';
    if (have('rpm'))          return 'rhel';
    if (have('apk'))          return 'alpine';
    return 'unknown';
}

/** Parse a PHP version from a `php -v` / `php-fpm -v` banner. */
function version_from_banner(string $banner): ?string
{
    if (preg_match('/PHP\s+(\d+\.\d+\.\d+)/i', $banner, $m)) return $m[1];
    return null;
}

// ---------------------------------------------------------------------------
// Backport detection
// ---------------------------------------------------------------------------

/**
 * Determine whether the package owning $binary has the CVE fix backported.
 *
 * @return array{backported:?bool, package:?string, pkg_version:?string, evidence:?string, method:string}
 *   backported: true (CVE found in changelog), false (checked, not present), null (couldn't check)
 */
function backport_status(string $family, ?string $binary): array
{
    $none = ['backported' => null, 'package' => null, 'pkg_version' => null, 'evidence' => null, 'method' => 'unavailable'];
    $cves = CVES;
    $cvePattern = implode('|', array_map('preg_quote', $cves));

    if ($family === 'debian' && $binary && have('dpkg')) {
        [$pkg] = sh('dpkg -S ' . escapeshellarg($binary));
        // "php8.4-cli: /usr/bin/php8.4" -> take package before the colon
        $package = ($pkg && strpos($pkg, ':') !== false) ? trim(substr($pkg, 0, strpos($pkg, ':'))) : null;
        if (!$package) return array_merge($none, ['method' => 'dpkg']);
        [$pv] = sh('dpkg-query -W -f=\'${Version}\' ' . escapeshellarg($package));
        // changelog lives in the -common or the package doc dir
        $found = null; $evidence = null;
        foreach ([$package, preg_replace('/-(cli|fpm|cgi)$/', '-common', $package)] as $p) {
            foreach (["/usr/share/doc/$p/changelog.Debian.gz", "/usr/share/doc/$p/changelog.gz"] as $cl) {
                if (is_readable($cl)) {
                    [$hit] = sh('zcat ' . escapeshellarg($cl) . ' | grep -iE ' . escapeshellarg($cvePattern));
                    if ($hit !== '') { $found = true; $evidence = strtok($hit, "\n"); break 2; }
                    $found = false; // readable but no CVE
                }
            }
        }
        return ['backported' => $found, 'package' => $package, 'pkg_version' => ($pv ?: null),
                'evidence' => $evidence, 'method' => 'dpkg+changelog'];
    }

    if ($family === 'rhel' && have('rpm')) {
        $target = $binary ?: 'php';
        [$pkg] = sh('rpm -qf ' . escapeshellarg($target));
        $package = ($pkg && stripos($pkg, 'not owned') === false && $pkg !== '') ? strtok($pkg, "\n") : 'php';
        [$chlog] = sh('rpm -q --changelog ' . escapeshellarg($package));
        if ($chlog === '') return array_merge($none, ['package' => $package, 'method' => 'rpm']);
        if (preg_match('/' . $cvePattern . '/i', $chlog, $m)) {
            return ['backported' => true, 'package' => $package, 'pkg_version' => null,
                    'evidence' => $m[0] . ' present in rpm changelog', 'method' => 'rpm+changelog'];
        }
        return ['backported' => false, 'package' => $package, 'pkg_version' => null,
                'evidence' => null, 'method' => 'rpm+changelog'];
    }

    return $none;
}

// ---------------------------------------------------------------------------
// Restart-after-patch detection
// ---------------------------------------------------------------------------

/** Epoch time the PHP package was last installed/upgraded, or null. */
function package_update_time(string $family, ?string $package, ?string $binary): ?int
{
    if ($family === 'debian') {
        if ($package) {
            // Most recent install/upgrade of this package in dpkg logs.
            [$line] = sh('grep -hE " (install|upgrade) ' . preg_quote((string)$package) . ':?" /var/log/dpkg.log /var/log/dpkg.log.1 2>/dev/null | tail -1');
            if ($line && preg_match('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/', $line, $m)) {
                $t = strtotime($m[1]);
                if ($t) return $t;
            }
        }
    } elseif ($family === 'rhel' && $package && have('rpm')) {
        [$last] = sh('rpm -q --last ' . escapeshellarg($package) . ' | head -1');
        // "php-8.3.36-1.el9  Tue 21 Oct 2026 10:00:00 ..."
        if ($last && preg_match('/\s{2,}(.+)$/', $last, $m)) {
            $t = strtotime(trim($m[1]));
            if ($t) return $t;
        }
    }
    // Fallback: mtime of the binary (approximates install time).
    if ($binary && is_file($binary)) {
        $t = @filemtime($binary);
        if ($t) return $t;
    }
    return null;
}

/**
 * Earliest start epoch of the processes for a runtime, plus how it was found.
 * @return array{start:?int, method:string, service:?string}
 */
function process_start_time(string $family, string $kind): array
{
    // Try systemd first for fpm/apache.
    $services = [];
    if ($kind === 'fpm') {
        $services = ['php-fpm', 'php8.5-fpm', 'php8.4-fpm', 'php8.3-fpm', 'php8.2-fpm', 'php-fpm.service'];
    } elseif ($kind === 'apache') {
        $services = ['apache2', 'httpd'];
    }
    if (have('systemctl')) {
        foreach ($services as $svc) {
            [$ts] = sh('systemctl show -p ActiveEnterTimestamp --value ' . escapeshellarg($svc));
            if ($ts && stripos($ts, 'n/a') === false && trim($ts) !== '') {
                $t = strtotime($ts);
                if ($t) return ['start' => $t, 'method' => 'systemctl', 'service' => $svc];
            }
        }
    }
    // Fallback: earliest matching process start via ps.
    $pattern = $kind === 'fpm' ? 'php-fpm' : ($kind === 'apache' ? 'apache2|httpd' : 'php');
    [$out] = sh('ps -eo lstart=,command= | grep -E ' . escapeshellarg($pattern) . ' | grep -v grep');
    $earliest = null;
    foreach (explode("\n", $out) as $line) {
        $line = trim($line);
        if ($line === '') continue;
        // lstart is the first 5 whitespace-separated fields (e.g. "Tue Oct 21 10:00:00 2026")
        $parts = preg_split('/\s+/', $line);
        if (count($parts) < 5) continue;
        $stamp = implode(' ', array_slice($parts, 0, 5));
        $t = strtotime($stamp);
        if ($t && ($earliest === null || $t < $earliest)) $earliest = $t;
    }
    return ['start' => $earliest, 'method' => $earliest ? 'ps' : 'none', 'service' => null];
}

// ---------------------------------------------------------------------------
// Per-runtime ini risk settings (run the actual binary so we see its config).
// ---------------------------------------------------------------------------

function ini_risk(string $binary): array
{
    $code = 'echo json_encode(['
          . '"expose_php"=>ini_get("expose_php"),'
          . '"session.upload_progress.enabled"=>ini_get("session.upload_progress.enabled"),'
          . '"memory_limit"=>ini_get("memory_limit"),'
          . '"loaded_ini"=>php_ini_loaded_file()]);';
    [$out] = sh(escapeshellarg($binary) . ' -r ' . escapeshellarg($code));
    $j = json_decode($out, true);
    return is_array($j) ? $j : [];
}

// ---------------------------------------------------------------------------
// Verdict engine
// ---------------------------------------------------------------------------

/**
 * Combine base version eval + backport + restart into a final verdict.
 * Statuses: PATCHED, VULNERABLE, NEEDS_RESTART, UNSUPPORTED, UNKNOWN.
 */
function p2s_verdict(array $base, array $backport, ?string $restart): array
{
    $status   = $base['status'];
    $conf     = 'version-based';
    $evidence = [];

    if ($backport['backported'] === true) {
        $status = 'PATCHED';
        $conf = 'confirmed (vendor changelog)';
        $evidence[] = 'Backport confirmed: ' . ($backport['evidence'] ?: 'CVE id present in package changelog');
    } elseif ($backport['backported'] === false) {
        // Changelog readable and CVE not present.
        if ($status === 'VULNERABLE') {
            $conf = 'confirmed (vendor changelog: fix absent)';
            $evidence[] = 'Vendor changelog checked; CVE ids not found.';
        } elseif ($status === 'PATCHED') {
            $evidence[] = 'Base version already >= fixed release.';
        }
    } else {
        if ($status === 'VULNERABLE') {
            $evidence[] = 'Could not read package changelog — verdict is version-based; a distro backport could still make this safe.';
        }
    }

    // Restart gate only matters when the installed code is actually patched.
    if ($status === 'PATCHED' && $restart === 'needs_restart') {
        $status = 'NEEDS_RESTART';
        $evidence[] = 'Patched package installed AFTER the workers started — the running processes have NOT loaded the fix yet. Restart them.';
    } elseif ($status === 'PATCHED' && $restart === 'ok') {
        $evidence[] = 'Workers started after the patch — running the fixed build.';
    }

    return ['status' => $status, 'confidence' => $conf, 'evidence' => $evidence];
}

// ---------------------------------------------------------------------------
// Runtime enumeration + full scan
// ---------------------------------------------------------------------------

function enumerate_runtimes(string $family): array
{
    $runtimes = [];

    // CLI binaries.
    $seen = [];
    foreach (['php','php8.2','php8.3','php8.4','php8.5','php82','php83','php84','php85'] as $name) {
        if (!have($name)) continue;
        [$path] = sh('command -v ' . escapeshellarg($name));
        $real = $path ? (realpath($path) ?: $path) : $path;
        if (!$real || isset($seen[$real])) continue;
        $seen[$real] = true;
        [$banner] = sh(escapeshellarg($real) . ' -v');
        $runtimes[] = ['kind' => 'cli', 'label' => "CLI ($name)", 'binary' => $real,
                       'version' => version_from_banner($banner)];
    }

    // FPM binaries.
    $fpmSeen = [];
    $fpmNames = ['php-fpm','php-fpm8.2','php-fpm8.3','php-fpm8.4','php-fpm8.5','php-fpm82','php-fpm83','php-fpm84','php-fpm85'];
    $fpmPaths = [];
    foreach ($fpmNames as $n) { if (have($n)) { [$p] = sh('command -v ' . escapeshellarg($n)); if ($p) $fpmPaths[] = $p; } }
    foreach (glob('/usr/sbin/php-fpm*') ?: [] as $p) $fpmPaths[] = $p;
    foreach (glob('/usr/local/sbin/php-fpm*') ?: [] as $p) $fpmPaths[] = $p;
    foreach ($fpmPaths as $p) {
        $real = realpath($p) ?: $p;
        if (isset($fpmSeen[$real]) || !is_executable($real)) continue;
        $fpmSeen[$real] = true;
        [$banner] = sh(escapeshellarg($real) . ' -v');
        $runtimes[] = ['kind' => 'fpm', 'label' => 'PHP-FPM', 'binary' => $real,
                       'version' => version_from_banner($banner)];
    }

    // Apache mod_php (presence only; its build must be tested via the web SAPI).
    $apache = null;
    foreach (['apachectl','apache2ctl','httpd','apache2'] as $a) if (have($a)) { $apache = $a; break; }
    if ($apache) {
        [$mods] = sh($apache . ' -M');
        if (stripos($mods, 'php') !== false) {
            $runtimes[] = ['kind' => 'apache', 'label' => 'Apache mod_php', 'binary' => null, 'version' => null];
        }
    }

    // Docker containers.
    if (have('docker')) {
        [$ps] = sh('docker ps --format "{{.ID}} {{.Names}}"');
        foreach (explode("\n", $ps) as $line) {
            $line = trim($line); if ($line === '') continue;
            [$id, $name] = array_pad(explode(' ', $line, 2), 2, '');
            [$banner] = sh('docker exec ' . escapeshellarg($id) . ' php -v');
            $ver = version_from_banner($banner);
            if (!$ver) continue;
            $runtimes[] = ['kind' => 'docker', 'label' => "docker: $name", 'binary' => null,
                           'version' => $ver, 'container' => $name];
        }
    }

    return $runtimes;
}

function full_scan(): array
{
    $family = os_family();
    $runtimes = enumerate_runtimes($family);
    $report = [
        'tool' => 'php2shell-checker/inspect',
        'cves' => CVES,
        'os_family' => $family,
        'scanned_at' => gmdate('c'),
        'is_root' => (function_exists('posix_geteuid') ? posix_geteuid() === 0 : null),
        'runtimes' => [],
    ];

    foreach ($runtimes as $rt) {
        $entry = $rt;

        if ($rt['kind'] === 'apache') {
            $entry['verdict'] = [
                'status' => 'CHECK_VIA_WEB', 'confidence' => 'n/a',
                'evidence' => ['mod_php is loaded (highest-risk SAPI). Its build cannot be read from the CLI — test it by placing check.php in the webroot with ALLOW_WEB=true, then delete it.'],
            ];
            $report['runtimes'][] = $entry;
            continue;
        }

        $version = $rt['version'] ?? null;
        if (!$version) {
            $entry['verdict'] = ['status' => 'UNKNOWN', 'confidence' => 'n/a', 'evidence' => ['Could not read a version for this runtime.']];
            $report['runtimes'][] = $entry;
            continue;
        }

        $base = p2s_evaluate($version);

        // Backport + restart only make sense for local, package-managed binaries.
        if ($rt['kind'] === 'docker') {
            $entry['backport'] = ['backported' => null, 'method' => 'n/a (container)'];
            $entry['verdict'] = p2s_verdict($base, ['backported' => null, 'evidence' => null], null);
            $entry['verdict']['evidence'][] = 'Container image: rebuild/pull a patched base image; restarting an old container keeps the vulnerable build.';
        } else {
            $backport = backport_status($family, $rt['binary'] ?? null);
            $entry['backport'] = $backport;

            $restart = null; $restartInfo = ['start' => null, 'method' => 'n/a', 'service' => null];
            if ($rt['kind'] === 'fpm') {
                $pkgTime = package_update_time($family, $backport['package'] ?? null, $rt['binary'] ?? null);
                $restartInfo = process_start_time($family, 'fpm');
                if ($pkgTime && $restartInfo['start']) {
                    $restart = ($restartInfo['start'] >= $pkgTime) ? 'ok' : 'needs_restart';
                }
                $entry['restart'] = [
                    'package_update_time' => $pkgTime ? gmdate('c', $pkgTime) : null,
                    'process_start_time'  => $restartInfo['start'] ? gmdate('c', $restartInfo['start']) : null,
                    'method' => $restartInfo['method'], 'service' => $restartInfo['service'],
                    'state' => $restart ?: 'unknown',
                ];
            }

            $entry['verdict'] = p2s_verdict($base, $backport, $restart);
            $entry['ini'] = $rt['binary'] ? ini_risk($rt['binary']) : [];
        }

        $entry['base_status'] = $base['status'];
        $report['runtimes'][] = $entry;
    }

    // Overall: worst status wins.
    $rank = ['NEEDS_RESTART'=>5,'VULNERABLE'=>5,'UNSUPPORTED'=>4,'UNKNOWN'=>3,'CHECK_VIA_WEB'=>2,'PATCHED'=>1];
    $worst = 'PATCHED'; $worstRank = 0;
    foreach ($report['runtimes'] as $r) {
        $s = $r['verdict']['status'];
        $sr = $rank[$s] ?? 3;
        if ($sr > $worstRank) { $worstRank = $sr; $worst = $s; }
    }
    $report['overall'] = empty($report['runtimes']) ? 'NO_RUNTIME' : $worst;
    return $report;
}

// ---------------------------------------------------------------------------
// Renderers
// ---------------------------------------------------------------------------

function render_text(array $r): string
{
    $o  = "php2shell-checker — server posture report\n";
    $o .= str_repeat('=', 64) . "\n";
    $o .= "CVEs       : " . implode(', ', $r['cves']) . "\n";
    $o .= "OS family  : {$r['os_family']}\n";
    $o .= "Scanned    : {$r['scanned_at']}";
    $o .= ($r['is_root'] === false) ? "   (not root — some probes limited; re-run with sudo)\n" : "\n";
    $o .= "OVERALL    : {$r['overall']}\n";
    $o .= str_repeat('=', 64) . "\n";

    if (empty($r['runtimes'])) { $o .= "No PHP runtime found on this host.\n"; return $o; }

    foreach ($r['runtimes'] as $rt) {
        $v = $rt['verdict'];
        $o .= "\n• {$rt['label']}";
        if (!empty($rt['binary'])) $o .= "  [{$rt['binary']}]";
        $o .= "\n";
        if (!empty($rt['version'])) $o .= "    version    : {$rt['version']}\n";
        if (!empty($rt['backport']['package'])) {
            $o .= "    package    : {$rt['backport']['package']}";
            if (!empty($rt['backport']['pkg_version'])) $o .= " ({$rt['backport']['pkg_version']})";
            $o .= "\n";
        }
        if (!empty($rt['restart']) && $rt['restart']['state'] !== 'unknown') {
            $o .= "    restart    : {$rt['restart']['state']}";
            $o .= " (pkg {$rt['restart']['package_update_time']} vs proc {$rt['restart']['process_start_time']})\n";
        }
        $o .= "    VERDICT    : {$v['status']}  [{$v['confidence']}]\n";
        foreach ($v['evidence'] as $e) {
            $o .= "      - " . wordwrap($e, 58, "\n        ", true) . "\n";
        }
    }
    $o .= "\n" . str_repeat('-', 64) . "\n";
    $o .= "Legend: PATCHED ok · NEEDS_RESTART patched but workers must restart ·\n";
    $o .= "VULNERABLE · UNSUPPORTED (EOL, migrate) · CHECK_VIA_WEB (Apache mod_php) ·\n";
    $o .= "UNKNOWN. This report only read local metadata — it exploited nothing.\n";
    return $o;
}

function render_html(array $r): string
{
    $colors = ['PATCHED'=>'#1a7f37','NEEDS_RESTART'=>'#bf8700','VULNERABLE'=>'#cf222e',
               'UNSUPPORTED'=>'#cf222e','UNKNOWN'=>'#57606a','CHECK_VIA_WEB'=>'#8250df','NO_RUNTIME'=>'#57606a'];
    $oc = $colors[$r['overall']] ?? '#57606a';
    $esc = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');

    $cards = '';
    foreach ($r['runtimes'] as $rt) {
        $v = $rt['verdict']; $c = $colors[$v['status']] ?? '#57606a';
        $meta = '';
        if (!empty($rt['version']))              $meta .= '<div><b>Version:</b> ' . $esc($rt['version']) . '</div>';
        if (!empty($rt['backport']['package']))  $meta .= '<div><b>Package:</b> ' . $esc($rt['backport']['package']) . ' ' . $esc($rt['backport']['pkg_version'] ?? '') . '</div>';
        if (!empty($rt['restart']) && $rt['restart']['state'] !== 'unknown')
            $meta .= '<div><b>Restart:</b> ' . $esc($rt['restart']['state']) . '</div>';
        $ev = '';
        foreach ($v['evidence'] as $e) $ev .= '<li>' . $esc($e) . '</li>';
        $cards .= '<div class="card"><div class="badge" style="background:' . $c . '">' . $esc($v['status'])
                . '</div><h3>' . $esc($rt['label']) . '</h3>'
                . ($rt['binary'] ? '<code>' . $esc($rt['binary']) . '</code>' : '')
                . '<div class="meta">' . $meta . '</div>'
                . '<div class="conf">confidence: ' . $esc($v['confidence']) . '</div>'
                . '<ul>' . $ev . '</ul></div>';
    }

    return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<title>php2shell-checker report</title><style>'
        . 'body{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f8fa;color:#1f2328}'
        . '.wrap{max-width:860px;margin:0 auto;padding:24px 16px}'
        . 'h1{font-size:20px;margin:0 0 4px}.sub{color:#57606a;font-size:13px;margin-bottom:16px}'
        . '.overall{color:#fff;background:' . $oc . ';padding:16px 20px;border-radius:10px;font-size:18px;font-weight:700;margin-bottom:20px}'
        . '.overall small{display:block;font-weight:400;font-size:12px;opacity:.9;margin-top:4px}'
        . '.card{background:#fff;border:1px solid #d0d7de;border-radius:10px;padding:16px;margin-bottom:14px;position:relative}'
        . '.card h3{margin:.2em 0}.badge{position:absolute;top:16px;right:16px;color:#fff;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:700}'
        . '.card code{font-size:12px;color:#57606a;word-break:break-all}.meta{margin:8px 0;font-size:13px}'
        . '.conf{font-size:12px;color:#57606a;margin:4px 0}.card ul{margin:8px 0 0;padding-left:18px;font-size:13px}'
        . '.foot{color:#57606a;font-size:12px;margin-top:20px}'
        . '</style></head><body><div class="wrap">'
        . '<h1>php2shell-checker — server posture report</h1>'
        . '<div class="sub">' . $esc(implode(', ', $r['cves'])) . ' · OS: ' . $esc($r['os_family']) . ' · ' . $esc($r['scanned_at']) . '</div>'
        . '<div class="overall">OVERALL: ' . $esc($r['overall'])
        . '<small>Informational report — version/package/restart/config detection only. No exploitation.</small></div>'
        . $cards
        . '<div class="foot">A runtime is safe only once the patched package is installed AND its workers restarted. '
        . 'Distro backports may keep an old base number; this report checks the package changelog where available.</div>'
        . '</div></body></html>';
}

// ---------------------------------------------------------------------------
// Tailored recommendations (from the scan findings)
// ---------------------------------------------------------------------------

/** Is an ini boolean-ish value effectively "on"? */
function p2s_ini_on($val): bool
{
    return !in_array(strtolower((string)$val), ['', '0', 'off', 'false', 'no'], true);
}

/** Distro-specific patch+restart commands for a given branch. */
function p2s_patch_cmds(string $family, string $branch): array
{
    if ($family === 'debian') {
        return [
            "sudo apt update && sudo apt upgrade php{$branch}-fpm php{$branch}-cli php{$branch}-common",
            "sudo systemctl restart php{$branch}-fpm   # or: sudo systemctl restart apache2 (mod_php)",
        ];
    }
    if ($family === 'rhel') {
        return [
            'sudo dnf update php php-fpm php-common',
            'sudo systemctl restart php-fpm   # or: sudo systemctl restart httpd (mod_php)',
        ];
    }
    if ($family === 'alpine') {
        return [
            'sudo apk upgrade php* ',
            'sudo rc-service php-fpm' . str_replace('.', '', $branch) . ' restart',
        ];
    }
    return ["Install the patched PHP {$branch} package for your platform (>= fixed release), then restart php-fpm/apache."];
}

/**
 * Build a de-duplicated, severity-ranked list of recommendations.
 * @return array<int,array{severity:string,title:string,detail:string,commands:array}>
 */
function build_recommendations(array $report): array
{
    $fam = $report['os_family'];
    $patchBranches = [];   // branch => true
    $restartSvc    = [];   // service => true
    $eolBranches   = [];   // branch => true
    $apacheWeb     = false;
    $dockerImages  = [];
    $unknown       = [];
    $exposePhp     = false;
    $uploadProg    = false;

    foreach ($report['runtimes'] as $rt) {
        $status = $rt['verdict']['status'];
        $branch = null;
        if (!empty($rt['version']) && preg_match('/^(\d+\.\d+)/', $rt['version'], $m)) $branch = $m[1];

        switch ($status) {
            case 'VULNERABLE':
                if ($branch) $patchBranches[$branch] = true;
                break;
            case 'NEEDS_RESTART':
                $svc = $rt['restart']['service'] ?? null;
                if (!$svc) $svc = ($fam === 'debian' && $branch) ? "php{$branch}-fpm" : 'php-fpm';
                $restartSvc[$svc] = true;
                break;
            case 'UNSUPPORTED':
                if ($branch) $eolBranches[$branch] = true;
                break;
            case 'CHECK_VIA_WEB':
                $apacheWeb = true;
                break;
            case 'UNKNOWN':
                $unknown[] = $rt['label'];
                break;
        }
        if ($rt['kind'] === 'docker' && in_array($status, ['VULNERABLE', 'NEEDS_RESTART', 'UNKNOWN'], true)) {
            $dockerImages[] = $rt['container'] ?? $rt['label'];
        }
        $ini = $rt['ini'] ?? [];
        if (array_key_exists('expose_php', $ini) && p2s_ini_on($ini['expose_php'])) $exposePhp = true;
        if (array_key_exists('session.upload_progress.enabled', $ini) && p2s_ini_on($ini['session.upload_progress.enabled'])) $uploadProg = true;
    }

    $recs = [];

    foreach (array_keys($patchBranches) as $branch) {
        $recs[] = [
            'severity' => 'CRITICAL',
            'title'    => "Patch PHP {$branch} and restart its workers",
            'detail'   => "A runtime on branch {$branch} is below the fixed release. Install the patched package AND restart — upgrading alone leaves old workers running the vulnerable code.",
            'commands' => p2s_patch_cmds($fam, $branch),
        ];
    }

    foreach (array_keys($restartSvc) as $svc) {
        $recs[] = [
            'severity' => 'CRITICAL',
            'title'    => "Restart {$svc} — patched package not yet loaded",
            'detail'   => 'The installed package is patched, but the running workers started BEFORE the update, so they still execute the old build. A restart fixes this immediately; no reinstall needed.',
            'commands' => ["sudo systemctl restart {$svc}"],
        ];
    }

    foreach (array_keys($eolBranches) as $branch) {
        $recs[] = [
            'severity' => 'HIGH',
            'title'    => "Migrate off end-of-life PHP {$branch}",
            'detail'   => "PHP {$branch} is end-of-life and gets no official fix for these CVEs. Plan a migration to a supported branch (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+). Until then the server stays exposed — isolate it and prioritise.",
            'commands' => [],
        ];
    }

    if ($dockerImages) {
        $recs[] = [
            'severity' => 'HIGH',
            'title'    => 'Rebuild affected container image(s): ' . implode(', ', array_unique($dockerImages)),
            'detail'   => 'Restarting an old container keeps the vulnerable image. Pull a patched base image and rebuild — do not just `docker restart`.',
            'commands' => ['docker pull <image>:<patched-tag>', 'docker compose up -d --build'],
        ];
    }

    if ($apacheWeb) {
        $recs[] = [
            'severity' => 'HIGH',
            'title'    => 'Test & patch Apache mod_php (highest-risk SAPI)',
            'detail'   => 'mod_php is loaded; its build cannot be read from the CLI. Test the real web runtime, then patch the matching PHP package and restart apache.',
            'commands' => [
                'cp check.php /var/www/html/   # then set ALLOW_WEB=true in it',
                '# open https://your-site/check.php in a browser, read the result, then:',
                'rm /var/www/html/check.php    # delete immediately',
                ($fam === 'rhel' ? 'sudo systemctl restart httpd' : 'sudo systemctl restart apache2'),
            ],
        ];
    }

    if ($unknown) {
        $recs[] = [
            'severity' => 'MEDIUM',
            'title'    => 'Manually verify runtime(s): ' . implode(', ', array_unique($unknown)),
            'detail'   => 'Version or branch could not be mapped automatically. Check the running version against the official PHP security advisory for CVE-2026-109618 / CVE-2026-109619.',
            'commands' => [],
        ];
    }

    if ($exposePhp) {
        $recs[] = [
            'severity' => 'LOW',
            'title'    => 'Hygiene: hide the PHP version (expose_php = Off)',
            'detail'   => 'expose_php is On, so PHP advertises its version in the X-Powered-By header. This does NOT fix the CVE — it only cuts automated reconnaissance. Best fixed in php.ini (covers all web servers).',
            'commands' => ['; php.ini', 'expose_php = Off', '# then restart php-fpm/apache; see RECOMMENDATIONS.md for Apache/Nginx/Cloudflare'],
        ];
    }

    if ($uploadProg) {
        $recs[] = [
            'severity' => 'LOW',
            'title'    => 'Temporary mitigation: disable session.upload_progress',
            'detail'   => 'Only until you patch — this reduces one attack path but is NOT a fix.',
            'commands' => ['; php.ini', 'session.upload_progress.enabled = Off', 'sudo systemctl restart php-fpm   # pick up the setting'],
        ];
    }

    if (!$recs) {
        $recs[] = [
            'severity' => 'INFO',
            'title'    => 'All detected runtimes are patched and restarted',
            'detail'   => 'No action required for these CVEs on the runtimes this scan could see. Re-run after any future PHP update, and remember a patch does not remove files/accounts created before patching.',
            'commands' => [],
        ];
    }

    // Severity ordering.
    $rank = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2, 'LOW' => 3, 'INFO' => 4];
    usort($recs, fn($a, $b) => ($rank[$a['severity']] ?? 9) <=> ($rank[$b['severity']] ?? 9));
    return $recs;
}

function render_recommendations(array $report, array $recs): string
{
    $o  = "php2shell-checker — recommended actions\n";
    $o .= str_repeat('=', 64) . "\n";
    $o .= "OS family  : {$report['os_family']}    OVERALL: {$report['overall']}\n";
    if ($report['is_root'] === false) $o .= "(not root — some probes limited; re-run with sudo for full coverage)\n";
    $o .= str_repeat('=', 64) . "\n";
    $n = 0;
    foreach ($recs as $r) {
        $n++;
        $o .= "\n[{$r['severity']}] {$n}. {$r['title']}\n";
        $o .= '    ' . wordwrap($r['detail'], 58, "\n    ", true) . "\n";
        if (!empty($r['commands'])) {
            $o .= "    ---\n";
            foreach ($r['commands'] as $c) $o .= "    $ " . $c . "\n";
        }
    }
    $o .= "\n" . str_repeat('-', 64) . "\n";
    $o .= "Full checklist & per-server snippets: RECOMMENDATIONS.md\n";
    $o .= "These are informational suggestions based on a read-only scan.\n";
    return $o;
}

// ---------------------------------------------------------------------------
// AI-assisted remediation prompt (built from the scan findings)
// ---------------------------------------------------------------------------

/** Compact, human-readable findings block for embedding in an AI prompt. */
function p2s_findings_block(array $report, bool $redact): string
{
    if (empty($report['runtimes'])) return "- (no PHP runtime detected)\n";
    $lines = [];
    foreach ($report['runtimes'] as $rt) {
        $v = $rt['verdict'];
        $bin = $rt['binary'] ?? null;
        if ($redact && $bin) $bin = basename($bin);

        $head = "- {$rt['label']}";
        if (!empty($rt['version'])) $head .= " v{$rt['version']}";
        $head .= " => {$v['status']} ({$v['confidence']})";
        if ($bin) $head .= " [bin: {$bin}]";
        if (!empty($rt['backport']['package'])) {
            $head .= " [pkg: {$rt['backport']['package']}";
            if (!empty($rt['backport']['pkg_version'])) $head .= " {$rt['backport']['pkg_version']}";
            $head .= ']';
        }
        if (!empty($rt['restart']) && ($rt['restart']['state'] ?? 'unknown') !== 'unknown') {
            $head .= " [restart: {$rt['restart']['state']}]";
        }
        $lines[] = $head;

        foreach ($v['evidence'] as $e) $lines[] = "    - " . $e;

        $ini = $rt['ini'] ?? [];
        if ($ini) {
            $flags = [];
            if (array_key_exists('expose_php', $ini))
                $flags[] = 'expose_php=' . (p2s_ini_on($ini['expose_php']) ? 'On' : 'Off');
            if (array_key_exists('session.upload_progress.enabled', $ini))
                $flags[] = 'session.upload_progress=' . (p2s_ini_on($ini['session.upload_progress.enabled']) ? 'On' : 'Off');
            if (!empty($ini['memory_limit']))
                $flags[] = 'memory_limit=' . $ini['memory_limit'];
            if (!$redact && !empty($ini['loaded_ini']))
                $flags[] = 'ini_file=' . $ini['loaded_ini'];
            if ($flags) $lines[] = '    - config: ' . implode(', ', $flags);
        }
    }
    return implode("\n", $lines) . "\n";
}

/**
 * Turn the concrete findings into specific, per-runtime tasks for the AI,
 * referencing the actual versions, packages, services and config this scan saw.
 * @return array<int,string>
 */
function p2s_prompt_tasks(array $report, string $fam): array
{
    $tasks = [];
    foreach ($report['runtimes'] as $rt) {
        $status = $rt['verdict']['status'];
        $label  = $rt['label'];
        $ver    = $rt['version'] ?? null;
        $branch = ($ver && preg_match('/^(\d+\.\d+)/', $ver, $m)) ? $m[1] : null;
        $pkg    = $rt['backport']['package'] ?? null;
        $pkgv   = $rt['backport']['pkg_version'] ?? null;
        $svc    = $rt['restart']['service'] ?? null;
        $fixed  = $branch ? (FIXED[$branch] ?? null) : null;
        $pkgTxt = $pkg ? " (package {$pkg}" . ($pkgv ? " {$pkgv}" : '') . ')' : '';

        // Containers are fixed by rebuilding the image, not by host package
        // commands — handle them only here.
        if ($rt['kind'] === 'docker') {
            if (in_array($status, ['VULNERABLE', 'NEEDS_RESTART', 'UNKNOWN'], true)) {
                $tasks[] = 'Container ' . ($rt['container'] ?? $label) . ' runs PHP ' . ($ver ?: '')
                         . ' (verdict ' . $status . ') — give exact steps to rebuild it on a patched base image'
                         . ' (not just `docker restart`) and redeploy.';
            }
            continue;
        }

        switch ($status) {
            case 'VULNERABLE':
                $t = "Fix {$label}" . ($ver ? " running PHP {$ver}{$pkgTxt}" : '')
                   . ': upgrade it to ' . ($fixed ? "the fixed {$fixed} release or newer" : 'a fixed release')
                   . " and restart it. Give the exact {$fam} package commands plus the restart command.";
                if (($rt['backport']['backported'] ?? null) === null) {
                    $t .= " My package changelog couldn't be read here, so FIRST show how to confirm"
                        . " whether {$fam} has already backported the fix" . ($pkg ? " into {$pkg}" : '')
                        . ", so I don't change versions needlessly.";
                }
                $tasks[] = $t;
                break;
            case 'NEEDS_RESTART':
                $s = $svc ?: 'the php-fpm service';
                $tasks[] = "{$label} already has the patched package installed, but its workers started"
                         . " BEFORE the update and still run the old build. Give the exact command to restart {$s}"
                         . " and a command to prove the running workers now use the fixed version.";
                break;
            case 'UNSUPPORTED':
                $tasks[] = "{$label} runs end-of-life PHP " . ($ver ?: '') . ", which gets no fix. Give a concrete"
                         . " migration plan on {$fam} to a currently-supported branch (8.3 or 8.4): install it alongside,"
                         . " switch my web server/FPM pool to it, the top app-compatibility changes to check for this jump,"
                         . " and how to roll back.";
                break;
            case 'CHECK_VIA_WEB':
                $tasks[] = "Apache mod_php is loaded (the highest-risk setup) and its exact build can't be read from the"
                         . " CLI. Walk me through safely confirming its running version via the web SAPI, then patching and"
                         . " restarting Apache on {$fam}.";
                break;
            case 'UNKNOWN':
                $tasks[] = "{$label}" . ($ver ? " (version {$ver})" : '') . " couldn't be classified automatically —"
                         . " help me determine whether it is affected and what to do.";
                break;
        }
    }

    // Config hygiene, with the actual current state.
    $exposeOn = false; $uploadOn = false;
    foreach ($report['runtimes'] as $rt) {
        $ini = $rt['ini'] ?? [];
        if (array_key_exists('expose_php', $ini) && p2s_ini_on($ini['expose_php'])) $exposeOn = true;
        if (array_key_exists('session.upload_progress.enabled', $ini) && p2s_ini_on($ini['session.upload_progress.enabled'])) $uploadOn = true;
    }
    if ($exposeOn) {
        $tasks[] = "expose_php is currently On, so my PHP version leaks in the X-Powered-By header. As OPTIONAL"
                 . " hardening (not a fix), show how to turn it off in php.ini and at the web-server level for {$fam}.";
    }
    if ($uploadOn) {
        $tasks[] = "As a TEMPORARY mitigation only until I patch, show how to disable session.upload_progress and reload workers.";
    }

    $tasks = array_values(array_unique($tasks));

    if (!$tasks) {
        $tasks[] = "Every runtime this scan saw already looks patched and restarted. Give me a short checklist to be"
                 . " certain (how to re-verify each SAPI) and the post-patch hygiene steps I shouldn't skip.";
    }
    return $tasks;
}

/** Build a ready-to-paste prompt that lets an AI produce tailored remediation. */
function build_ai_prompt(array $report, array $recs, bool $redact): string
{
    $fam = $report['os_family'];
    $findings = p2s_findings_block($report, $redact);

    $recLines = '';
    foreach ($recs as $i => $r) {
        $recLines .= ($i + 1) . ". [{$r['severity']}] {$r['title']}\n";
    }
    if ($recLines === '') $recLines = "(none)\n";

    $p  = "You are a senior Linux/PHP systems administrator assisting with DEFENSIVE\n";
    $p .= "remediation only. Below is the output of a read-only posture scan for two\n";
    $p .= "PHP engine vulnerabilities. Help me make this server safe.\n\n";

    $p .= "## Vulnerabilities\n";
    $p .= "- CVE-2026-109618 and CVE-2026-109619: unauthenticated remote code execution\n";
    $p .= "  in the PHP engine, patched 2026-10-21. Highest risk on Apache + mod_php.\n";
    $p .= "- Fixed versions by branch: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or a vendor\n";
    $p .= "  backport). PHP 8.1 and older are end-of-life and need migration.\n\n";

    $p .= "## My server\n";
    $p .= "- OS family: {$fam}\n";
    $p .= "- Overall verdict: {$report['overall']}\n";
    $p .= "- Scanned at: {$report['scanned_at']}\n\n";

    $p .= "## Findings per runtime\n";
    $p .= $findings . "\n";

    $p .= "## Preliminary recommendations from the scanner\n";
    $p .= $recLines . "\n";

    $p .= "## Exactly what I need you to solve (specific to this scan)\n";
    $p .= "Give me an ORDERED, copy-paste plan on {$fam} that resolves each item below.\n";
    $p .= "For every step say in one line WHY it is needed, and after each fix show the\n";
    $p .= "exact command to VERIFY it worked. Treat 'patched package installed' and\n";
    $p .= "'workers restarted' as SEPARATE requirements. Keep the real fix clearly apart\n";
    $p .= "from optional hardening.\n\n";
    foreach (p2s_prompt_tasks($report, $fam) as $i => $task) {
        $p .= ($i + 1) . '. ' . wordwrap($task, 76, "\n   ", true) . "\n";
    }
    $p .= "\nFinish with a short post-patch hygiene checklist (a patch does not remove\n";
    $p .= "files or accounts created before it).\n\n";

    $p .= "## Rules\n";
    $p .= "- Do NOT provide exploit code, proof-of-concept payloads, or attack steps.\n";
    $p .= "- Do NOT suggest setting memory_limit to unlimited.\n";
    $p .= "- Prefer official vendor packages; flag anything that could cause downtime so\n";
    $p .= "  I can schedule it. If you need more detail, tell me to run\n";
    $p .= "  `php inspect.php --json` and paste the result.\n";

    // User-facing wrapper (not part of the prompt the AI reads).
    $banner  = "# ---- Copy everything between the lines below into your AI assistant ----\n";
    $banner .= "# NOTE: this prompt contains details about YOUR server (versions"
             . ($redact ? "" : ", paths") . ", config).\n";
    $banner .= "# You are pasting it into an external service" . ($redact ? " (paths redacted)." : ". Use --redact to strip absolute paths.") . "\n";
    $banner .= str_repeat('-', 72) . "\n\n";
    $footer  = "\n" . str_repeat('-', 72) . "\n";
    $footer .= "# ---- End of prompt ----\n";

    return $banner . $p . $footer;
}

// ---------------------------------------------------------------------------
// Library guard + entry point
// ---------------------------------------------------------------------------

if (defined('P2S_INSPECT_LIB')) {
    return;
}

if (PHP_SAPI !== 'cli') {
    header('Content-Type: text/plain; charset=utf-8', true, 403);
    echo "inspect.php is a CLI tool — run it from a shell on the server.\n";
    exit(3);
}

$args = $argv ?? [];
$report = full_scan();

if (in_array('--prompt', $args, true)) {
    $recs = build_recommendations($report);
    echo build_ai_prompt($report, $recs, in_array('--redact', $args, true));
    $exitP = ['PATCHED' => 0, 'CHECK_VIA_WEB' => 0, 'NEEDS_RESTART' => 1, 'VULNERABLE' => 1, 'UNSUPPORTED' => 1, 'UNKNOWN' => 2, 'NO_RUNTIME' => 2];
    exit($exitP[$report['overall']] ?? 2);
}

if (in_array('--recommend', $args, true)) {
    $recs = build_recommendations($report);
    if (in_array('--json', $args, true)) {
        echo json_encode(['overall' => $report['overall'], 'os_family' => $report['os_family'], 'recommendations' => $recs],
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    } else {
        echo render_recommendations($report, $recs);
    }
    $exitR = ['PATCHED' => 0, 'CHECK_VIA_WEB' => 0, 'NEEDS_RESTART' => 1, 'VULNERABLE' => 1, 'UNSUPPORTED' => 1, 'UNKNOWN' => 2, 'NO_RUNTIME' => 2];
    exit($exitR[$report['overall']] ?? 2);
}

if (in_array('--json', $args, true)) {
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
} elseif (($i = array_search('--html', $args, true)) !== false) {
    $dest = $args[$i + 1] ?? '-';
    $html = render_html($report);
    if ($dest === '-' || $dest === null) {
        echo $html, "\n";
    } else {
        file_put_contents($dest, $html);
        echo "HTML report written to: $dest\n";
    }
} else {
    echo render_text($report);
}

$exit = ['PATCHED'=>0,'CHECK_VIA_WEB'=>0,'NEEDS_RESTART'=>1,'VULNERABLE'=>1,'UNSUPPORTED'=>1,'UNKNOWN'=>2,'NO_RUNTIME'=>2];
exit($exit[$report['overall']] ?? 2);
