#!/usr/bin/env bash
#
# php2shell-checker — php2shell-check.sh
#
# Informational local scan for CVE-2026-109618 / CVE-2026-109619.
# Runs check.php through every PHP runtime it can find on THIS machine
# (CLI binaries, PHP-FPM pools, and any running PHP containers) and reports
# whether each one is on a patched version.
#
# It is purely informational: it only reads versions. It exploits nothing and
# makes no network requests. Run it ON the server you want to check — as root
# or with sudo if you want it to see every runtime.
#
# Usage:
#   ./php2shell-check.sh            # scan every runtime found locally
#   ./php2shell-check.sh --json     # JSON per runtime
#
# License: MIT.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK_PHP="$SCRIPT_DIR/check.php"
JSON=0
[ "${1:-}" = "--json" ] && JSON=1

if [ ! -f "$CHECK_PHP" ]; then
    echo "error: check.php not found next to this script ($CHECK_PHP)" >&2
    exit 3
fi

run_check() {
    # $1 = php binary, rest = label
    local bin="$1"; shift
    local label="$*"
    # check.php exits 1 for VULNERABLE and 2 for UNKNOWN by design, so only
    # treat exit code >= 3 (couldn't run at all) as a real failure.
    if [ "$JSON" -eq 1 ]; then
        local report
        report="$("$bin" "$CHECK_PHP" --json 2>/dev/null)"; rc=$?
        [ "$rc" -ge 3 ] && report='null'
        printf '{"runtime":"%s","binary":"%s","report":%s}\n' "$label" "$bin" "$report"
    else
        echo
        echo "### Runtime: $label  ($bin)"
        "$bin" "$CHECK_PHP" 2>/dev/null; rc=$?
        [ "$rc" -ge 3 ] && echo "  (could not run check.php with $bin)"
    fi
}

[ "$JSON" -eq 0 ] && {
    echo "php2shell-checker — local runtime scan"
    echo "CVEs: CVE-2026-109618, CVE-2026-109619"
    echo "Scanning every PHP runtime found on this host..."
}

found=0

# 1. PHP CLI binaries on PATH (php, php8.2 ... php8.5).
for bin in php php8.2 php8.3 php8.4 php8.5 php82 php83 php84 php85; do
    if command -v "$bin" >/dev/null 2>&1; then
        run_check "$(command -v "$bin")" "CLI: $bin"
        found=1
    fi
done

# 2. PHP-FPM binaries. FPM can't execute a script directly like CLI, but its
#    -v reports the exact build serving your pools — we parse that version.
fpm_check() {
    local fpmbin="$1"
    local ver
    ver="$("$fpmbin" -v 2>/dev/null | sed -n 's/^PHP \([0-9][0-9.]*\).*/\1/p' | head -1)"
    [ -z "$ver" ] && return
    found=1
    if [ "$JSON" -eq 1 ]; then
        printf '{"runtime":"FPM","binary":"%s","report":' "$fpmbin"
        # Reuse the same matrix via a tiny inline PHP evaluation.
        php -r 'define("P2S_LIB",1); require $argv[1]; echo json_encode(p2s_evaluate($argv[2]));' "$CHECK_PHP" "$ver" 2>/dev/null || echo '"error"'
        echo '}'
    else
        echo
        echo "### Runtime: PHP-FPM  ($fpmbin)"
        php -r 'define("P2S_LIB",1); require $argv[1]; $r=p2s_evaluate($argv[2]); echo "Version   : {$r["version"]} (branch {$r["branch"]})\nRESULT    : {$r["status"]}" . ($r["fixed"]?" (fixed in {$r["fixed"]})":"") . "\n" . wordwrap($r["note"],60,"\n",true) . "\n";' "$CHECK_PHP" "$ver" 2>/dev/null \
            || echo "  Version: $ver (evaluate with: php check.php on this build)"
    fi
}
for fpmbin in php-fpm php-fpm8.2 php-fpm8.3 php-fpm8.4 php-fpm8.5 php-fpm82 php-fpm83 php-fpm84 php-fpm85; do
    if command -v "$fpmbin" >/dev/null 2>&1; then
        fpm_check "$(command -v "$fpmbin")"
    fi
done
# Common sbin locations not always on PATH.
for p in /usr/sbin/php-fpm* /usr/local/sbin/php-fpm*; do
    [ -x "$p" ] && fpm_check "$p"
done

# 3. Apache mod_php — report the module so the user knows to test it via the web
#    SAPI (dropping check.php in the webroot with ALLOW_WEB=true). We cannot read
#    the mod_php build version from the CLI reliably, so we only flag its presence.
apache_bin=""
for a in apachectl apache2ctl httpd apache2; do
    command -v "$a" >/dev/null 2>&1 && { apache_bin="$a"; break; }
done
if [ -n "$apache_bin" ]; then
    if "$apache_bin" -M 2>/dev/null | grep -qi 'php'; then
        if [ "$JSON" -eq 1 ]; then
            echo '{"runtime":"Apache mod_php","report":{"status":"CHECK_VIA_WEB","note":"mod_php is loaded — test it by placing check.php in the webroot with ALLOW_WEB=true, then delete it."}}'
        else
            echo
            echo "### Runtime: Apache mod_php"
            echo "  mod_php is LOADED (highest-risk config)."
            echo "  The CLI version does NOT prove this build is patched."
            echo "  Test it: copy check.php into the webroot, set ALLOW_WEB=true,"
            echo "  open it in a browser, read the result, then DELETE the file."
        fi
        found=1
    fi
fi

# 4. Running PHP containers (if docker is available) — report their php -v.
if command -v docker >/dev/null 2>&1; then
    while read -r cid cname; do
        [ -z "$cid" ] && continue
        ver="$(docker exec "$cid" php -v 2>/dev/null | sed -n 's/^PHP \([0-9][0-9.]*\).*/\1/p' | head -1)"
        [ -z "$ver" ] && continue
        found=1
        if [ "$JSON" -eq 1 ]; then
            printf '{"runtime":"docker","container":"%s","report":' "$cname"
            php -r 'define("P2S_LIB",1); require $argv[1]; echo json_encode(p2s_evaluate($argv[2]));' "$CHECK_PHP" "$ver" 2>/dev/null || echo '"error"'
            echo '}'
        else
            echo
            echo "### Runtime: docker container '$cname'"
            php -r 'define("P2S_LIB",1); require $argv[1]; $r=p2s_evaluate($argv[2]); echo "Version   : {$r["version"]}\nRESULT    : {$r["status"]}" . ($r["fixed"]?" (fixed in {$r["fixed"]})":"") . "\n";' "$CHECK_PHP" "$ver" 2>/dev/null \
                || echo "  Version: $ver"
            echo "  NOTE: restarting an old container keeps the vulnerable image — rebuild/pull a patched base image."
        fi
    done < <(docker ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
fi

if [ "$found" -eq 0 ]; then
    echo "No PHP runtime found on this host." >&2
    exit 2
fi

[ "$JSON" -eq 0 ] && {
    echo
    echo "Done. This scan only read versions — it exploited nothing."
    echo "Remember: a runtime is only safe once the patched package is installed"
    echo "AND its processes have been restarted."
}
