<?php
/**
 * php2shell-checker — check.php
 *
 * Informational PHP runtime checker for CVE-2026-109618 and CVE-2026-109619
 * (unauthenticated RCE in the PHP engine, patched 2026-10-21).
 *
 * This script is PURELY INFORMATIONAL. It only reads the version and SAPI of
 * the PHP runtime it is executed by and compares them against the published
 * matrix of fixed versions. It performs NO exploitation and sends NO requests.
 *
 * Run it in EVERY runtime that serves your site (CLI, each PHP-FPM pool, the
 * Apache mod_php build, each container) — `php -v` in a terminal does NOT prove
 * the web runtime is patched.
 *
 * Usage (CLI):
 *   php check.php            # human-readable report
 *   php check.php --json     # machine-readable JSON
 *   php check.php --quiet    # exit code only (0 patched, 1 vulnerable, 2 unknown)
 *
 * Usage (web runtime — the ONLY reliable way to test the web SAPI):
 *   1. Set ALLOW_WEB to true below.
 *   2. Drop this file in your webroot and open it in a browser.
 *   3. DELETE IT IMMEDIATELY afterwards. Do not leave it reachable.
 *
 * License: MIT. Data from PHP.net and NCSC-NL/php2shell advisories.
 */

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// Web runtime check is opt-in so this file can't accidentally leak version
// information if left in a webroot. Set to true only while testing, then
// delete the file.
const ALLOW_WEB = false;

// Fixed (patched) version for each supported PHP branch.
// Source: PHP.net security release 2026-10-21 / NCSC-NL/php2shell.
const FIXED = [
    '8.2' => '8.2.35',
    '8.3' => '8.3.36',
    '8.4' => '8.4.27',
    '8.5' => '8.5.12',
];

// Branches that are end-of-life upstream: no official patch for these CVEs.
// 8.1 and older must be migrated to a supported, patched branch.
const EOL_MAX = '8.1'; // branches <= this are considered unsupported

const CVES = ['CVE-2026-109618', 'CVE-2026-109619'];

// ---------------------------------------------------------------------------
// Core logic (no side effects — safe to include() from other code)
// ---------------------------------------------------------------------------

/**
 * Evaluate a PHP version string against the patch matrix.
 *
 * @return array{status:string, version:string, branch:string, fixed:?string, note:string}
 *         status is one of: PATCHED, VULNERABLE, UNSUPPORTED, UNKNOWN
 */
function p2s_evaluate(string $version): array
{
    // Normalise: keep only the leading x.y.z, drop distro/build suffixes.
    $clean = $version;
    if (preg_match('/^(\d+\.\d+\.\d+)/', $version, $m)) {
        $clean = $m[1];
    }

    $parts = explode('.', $clean);
    if (count($parts) < 2) {
        return [
            'status'  => 'UNKNOWN',
            'version' => $version,
            'branch'  => $clean,
            'fixed'   => null,
            'note'    => 'Could not parse the version string.',
        ];
    }

    $branch = $parts[0] . '.' . $parts[1];

    // End-of-life branches (8.1 and older): no upstream fix.
    if (version_compare($branch, EOL_MAX, '<=')) {
        return [
            'status'  => 'UNSUPPORTED',
            'version' => $version,
            'branch'  => $branch,
            'fixed'   => null,
            'note'    => "PHP $branch is end-of-life and receives no official fix for these CVEs. "
                       . 'Migrate to a supported, patched branch (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+).',
        ];
    }

    // Known supported branch with a published fix.
    if (isset(FIXED[$branch])) {
        $fixed = FIXED[$branch];
        if (version_compare($clean, $fixed, '>=')) {
            return [
                'status'  => 'PATCHED',
                'version' => $version,
                'branch'  => $branch,
                'fixed'   => $fixed,
                'note'    => "Reported version is >= $fixed. NOTE: distro packages (Debian/Ubuntu/RHEL) "
                           . 'may backport the fix while keeping an older base number — if this shows '
                           . 'VULNERABLE but your vendor claims a patched build, verify the full package revision.',
            ];
        }
        return [
            'status'  => 'VULNERABLE',
            'version' => $version,
            'branch'  => $branch,
            'fixed'   => $fixed,
            'note'    => "Reported version is < $fixed. IMPORTANT: if this is a distro package, the vendor "
                       . 'may have backported the fix without changing the base number — check the full package '
                       . "revision against your vendor's security notice before concluding.",
        ];
    }

    // Future / unknown branch (e.g. 8.6+): can't decide from the matrix.
    return [
        'status'  => 'UNKNOWN',
        'version' => $version,
        'branch'  => $branch,
        'fixed'   => null,
        'note'    => "Branch $branch is not in the known matrix. Check the PHP.net security advisory directly.",
    ];
}

/** Map a status to a process exit code. */
function p2s_exit_code(string $status): int
{
    switch ($status) {
        case 'PATCHED':     return 0;
        case 'VULNERABLE':
        case 'UNSUPPORTED': return 1;
        default:            return 2; // UNKNOWN
    }
}

// ---------------------------------------------------------------------------
// Runtime reporting
// ---------------------------------------------------------------------------

function p2s_collect(): array
{
    $sapi = PHP_SAPI;
    $result = p2s_evaluate(PHP_VERSION);
    $result['sapi'] = $sapi;

    // mod_php under Apache is the highest-risk configuration per PHP.net.
    $result['highest_risk_sapi'] = ($sapi === 'apache2handler');

    // Temporary mitigation hint: session.upload_progress.
    $upload_progress = ini_get('session.upload_progress.enabled');
    $result['session_upload_progress_enabled'] =
        ($upload_progress === false) ? 'unknown' : ((bool)$upload_progress ? 'yes' : 'no');

    $result['cves'] = CVES;
    $result['checked_at'] = gmdate('c');
    return $result;
}

function p2s_render_text(array $r): string
{
    $icons = [
        'PATCHED'     => '[ OK ]   ',
        'VULNERABLE'  => '[ VULN ] ',
        'UNSUPPORTED' => '[ EOL ]  ',
        'UNKNOWN'     => '[ ???? ] ',
    ];
    $icon = $icons[$r['status']] ?? '[ ???? ] ';

    $out  = "php2shell-checker — informational runtime check\n";
    $out .= str_repeat('=', 60) . "\n";
    $out .= "CVEs      : " . implode(', ', $r['cves']) . "\n";
    $out .= "SAPI      : {$r['sapi']}";
    $out .= $r['highest_risk_sapi'] ? "  (<-- highest-risk config: Apache mod_php)\n" : "\n";
    $out .= "Version   : {$r['version']}  (branch {$r['branch']})\n";
    if ($r['fixed']) {
        $out .= "Fixed in  : {$r['fixed']}\n";
    }
    $out .= "upload_progress: {$r['session_upload_progress_enabled']}\n";
    $out .= str_repeat('-', 60) . "\n";
    $out .= "RESULT    : {$icon}{$r['status']}\n";
    $out .= str_repeat('-', 60) . "\n";
    $out .= wordwrap($r['note'], 60, "\n", true) . "\n";

    if ($r['status'] === 'VULNERABLE' || $r['status'] === 'UNSUPPORTED') {
        $out .= "\nNext steps:\n";
        $out .= "  * Install the patched PHP package for your branch and RESTART\n";
        $out .= "    the affected processes (php-fpm / apache2 / container).\n";
        $out .= "  * Re-run this check INSIDE each runtime, not just the CLI.\n";
        $out .= "  * Temporary (not a fix): disabling session.upload_progress and\n";
        $out .= "    restarting workers may reduce some paths.\n";
    }
    $out .= "\nThis tool only read the running version. It did not exploit anything.\n";
    return $out;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

// Stop here when this file is included as a library. Callers that only want
// p2s_evaluate() etc. define P2S_LIB before requiring, so the entry point below
// does not run (and does not exit the caller).
if (defined('P2S_LIB')) {
    return;
}

if (PHP_SAPI === 'cli') {
    $args  = $argv ?? [];
    $json  = in_array('--json', $args, true);
    $quiet = in_array('--quiet', $args, true);
    $r = p2s_collect();

    if ($json) {
        // Compact single-line JSON so callers (and php2shell-check.sh) can treat
        // output as one object per line (JSON Lines). Pipe through `jq .` to pretty-print.
        echo json_encode($r, JSON_UNESCAPED_SLASHES), "\n";
    } elseif (!$quiet) {
        echo p2s_render_text($r);
    }
    exit(p2s_exit_code($r['status']));
}

// Web runtime (the only reliable way to test the web SAPI).
if (!ALLOW_WEB) {
    header('Content-Type: text/plain; charset=utf-8', true, 403);
    echo "Web check is disabled.\n\n";
    echo "To test the web runtime: set ALLOW_WEB to true at the top of this file,\n";
    echo "reload this page, read the result, then DELETE this file immediately.\n";
    exit;
}

$r = p2s_collect();
$wantJson = isset($_GET['format']) && $_GET['format'] === 'json';
if ($wantJson) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($r, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
} else {
    header('Content-Type: text/plain; charset=utf-8');
    echo "!!! DELETE THIS FILE NOW — do not leave it reachable on a live site !!!\n\n";
    echo p2s_render_text($r);
}
