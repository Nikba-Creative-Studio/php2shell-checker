#!/usr/bin/env bash
#
# php2shell-checker — remote-check.sh
#
# PASSIVE, informational remote check for CVE-2026-109618 / CVE-2026-109619.
#
# It sends ONE ordinary HTTP HEAD/GET request and reads only the `Server` and
# `X-Powered-By` response headers to guess the PHP version. It does NOT exploit
# anything, sends no payloads, and probes no paths. This is exactly what any
# browser already sees.
#
# AUTHORIZATION: Only use this against systems you own or are explicitly
# authorized to test. Scanning third-party systems without permission may be
# illegal. You must pass --i-am-authorized to confirm.
#
# Most hardened servers hide these headers (expose_php=Off). A blank result
# means "version not disclosed", NOT "safe" — use php2shell-check.sh on the
# server itself for a definitive answer.
#
# Usage:
#   ./remote-check.sh --i-am-authorized https://example.com
#   ./remote-check.sh --i-am-authorized --json https://example.com
#
# License: MIT.

set -u

AUTHORIZED=0
JSON=0
URL=""

for arg in "$@"; do
    case "$arg" in
        --i-am-authorized) AUTHORIZED=1 ;;
        --json)            JSON=1 ;;
        -*)                echo "unknown option: $arg" >&2; exit 3 ;;
        *)                 URL="$arg" ;;
    esac
done

if [ -z "$URL" ]; then
    echo "usage: $0 --i-am-authorized [--json] <url>" >&2
    exit 3
fi

if [ "$AUTHORIZED" -ne 1 ]; then
    cat >&2 <<'EOF'
Refusing to run without authorization confirmation.

Only test systems you own or are explicitly authorized to test. Re-run with:
  ./remote-check.sh --i-am-authorized <url>
EOF
    exit 4
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "error: curl is required." >&2
    exit 3
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK_PHP="$SCRIPT_DIR/check.php"

# One passive request. -I = HEAD; fall back to GET headers if HEAD is blocked.
HEADERS="$(curl -sS -I -A 'php2shell-checker (informational version check)' --max-time 15 "$URL" 2>/dev/null)"
if ! printf '%s' "$HEADERS" | grep -qi '^HTTP/'; then
    HEADERS="$(curl -sS -D - -o /dev/null -A 'php2shell-checker (informational version check)' --max-time 15 "$URL" 2>/dev/null)"
fi

SERVER_HDR="$(printf '%s' "$HEADERS" | grep -i '^Server:'       | head -1 | sed 's/^[Ss]erver:[[:space:]]*//; s/\r$//')"
POWERED_HDR="$(printf '%s' "$HEADERS" | grep -i '^X-Powered-By:' | head -1 | sed 's/^[Xx]-[Pp]owered-[Bb]y:[[:space:]]*//; s/\r$//')"

# Extract a PHP version from either header, e.g. "PHP/8.4.16".
VER="$(printf '%s\n%s' "$SERVER_HDR" "$POWERED_HDR" | sed -n 's/.*[Pp][Hh][Pp]\/\([0-9][0-9.]*\).*/\1/p' | head -1)"

if [ "$JSON" -eq 1 ]; then
    if [ -n "$VER" ] && [ -f "$CHECK_PHP" ] && command -v php >/dev/null 2>&1; then
        REPORT="$(php -r 'define("P2S_LIB",1); require $argv[1]; echo json_encode(p2s_evaluate($argv[2]));' "$CHECK_PHP" "$VER" 2>/dev/null)"
    else
        REPORT='null'
    fi
    printf '{"url":"%s","server":"%s","x_powered_by":"%s","php_version":"%s","report":%s}\n' \
        "$URL" "${SERVER_HDR//\"/}" "${POWERED_HDR//\"/}" "$VER" "${REPORT:-null}"
    exit 0
fi

echo "php2shell-checker — passive remote check"
echo "URL           : $URL"
echo "Server        : ${SERVER_HDR:-<not disclosed>}"
echo "X-Powered-By  : ${POWERED_HDR:-<not disclosed>}"
echo "------------------------------------------------------------"

if [ -z "$VER" ]; then
    echo "PHP version   : NOT DISCLOSED"
    echo
    echo "The server does not advertise its PHP version (expose_php=Off or headers"
    echo "stripped). This is good hygiene but tells you NOTHING about the patch"
    echo "status. Run php2shell-check.sh ON the server for a definitive answer."
    exit 2
fi

echo "PHP version   : $VER  (from headers — may be spoofed or stale)"
if [ -f "$CHECK_PHP" ] && command -v php >/dev/null 2>&1; then
    php -r 'define("P2S_LIB",1); require $argv[1]; $r=p2s_evaluate($argv[2]); echo "RESULT        : {$r["status"]}" . ($r["fixed"]?" (fixed in {$r["fixed"]})":"") . "\n\n" . wordwrap($r["note"],60,"\n",true) . "\n";' "$CHECK_PHP" "$VER"
fi
echo
echo "This was a passive header read only — no payload, no exploitation."
echo "For certainty, confirm on the server itself with php2shell-check.sh."
