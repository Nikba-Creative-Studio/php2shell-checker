# php2shell-checker

**Informational self-check for the 2026 PHP engine RCE vulnerabilities**

Checks whether the PHP runtime(s) serving your site are on a **patched** version
for **CVE-2026-109618** and **CVE-2026-109619** — two unauthenticated remote
code execution flaws in the PHP engine, fixed on 2026-10-21.

> ⚠️ **This is NOT an exploit.** It only reads the version and configuration of
> the PHP runtime and compares it against the published patch matrix. It sends
> no payloads and exploits nothing. Use it to check systems **you own or are
> authorized to test**.

## Why more than a header scanner?

Any online service can read a PHP version from HTTP headers — and most hardened
servers hide it anyway. The hard questions can only be answered **on the
server**, and `inspect.php` answers them:

- **Backport detection** — did your distro backport the fix while keeping an old
  base version number? Reads the package changelog (`dpkg`/`rpm`) for the CVE
  ids and gives a *definitive* verdict instead of a version guess.
- **Restart-after-patch detection** — a patched package whose `php-fpm`/`apache`
  workers were never restarted is **still vulnerable**. It compares the package
  update time against the worker start time and flags `NEEDS_RESTART`.
- **Multi-runtime / multi-SAPI inventory** + the risk-relevant `php.ini` settings.
- **Consolidated report with evidence** — text, JSON, or a shareable HTML page.

## What this is

On 2026-10-21 PHP released fixes for two critical engine vulnerabilities:

- **CVE-2026-109618** — RCE via out-of-memory corruption during request cleanup.
- **CVE-2026-109619** — RCE via stale request-owned global state reused by a later request on the same worker.

Both allow **unauthenticated remote code execution**, highest-risk on
**Apache + mod_php**. It is independent of WordPress/frameworks and runs before
application code.

## Fixed versions

| Branch | Fixed in |
|--------|----------|
| 8.2    | **8.2.35** |
| 8.3    | **8.3.36** |
| 8.4    | **8.4.27** |
| 8.5    | **8.5.12** |
| 8.1 and older | End-of-life — **migrate** to a supported branch |

Distro packages may backport the fix while keeping the base number — verify the
full package revision against your vendor's advisory.

## Usage

```bash
# Full posture report (recommended): backport + restart + config + verdict
php inspect.php                      # text
php inspect.php --json               # structured JSON with evidence
php inspect.php --html report.html   # shareable HTML report (or - for stdout)
php inspect.php --recommend          # TAILORED remediation steps for what it found
php inspect.php --recommend --json   # same recommendations, as JSON
php inspect.php --prompt             # ready-to-paste prompt for an AI assistant
php inspect.php --prompt --redact    # same, with absolute paths stripped
#   run as root/sudo for full coverage of packages, logs and process times

# Quick per-runtime scan: CLI, FPM, Apache, docker
./php2shell-check.sh
./php2shell-check.sh --json          # JSON Lines (one object/runtime; `| jq .` to format)

# A single runtime
php check.php
php check.php --json
php check.php --quiet          # exit code only: 0 patched, 1 vulnerable, 2 unknown

# Web runtime (set ALLOW_WEB=true, open in browser, then DELETE the file)

# Passive remote header check (authorized targets only)
./remote-check.sh --i-am-authorized https://example.com
```

`--recommend` prints severity-ranked actions (CRITICAL→INFO) with copy-paste
commands adapted to your OS family and findings: which branch to patch, which
service to restart (`NEEDS_RESTART`), what to migrate (EOL), which container to
rebuild, plus config hygiene (`expose_php`, `session.upload_progress`).

Run `inspect.php` as **root/sudo** so it can see every runtime, the package
logs and the process start times. Possible verdicts: `PATCHED`, `NEEDS_RESTART`
(patched but workers not restarted → still vulnerable), `VULNERABLE`,
`UNSUPPORTED` (EOL), `CHECK_VIA_WEB` (Apache mod_php), `UNKNOWN`.

### Web runtime (the only reliable test for Apache mod_php)

Place `check.php` in your webroot, set `ALLOW_WEB = true` in the file, open it
in a browser, read the result, then **delete it immediately** — do not leave it
reachable on a live site.

## Exit codes (`check.php`)

| Code | Meaning |
|------|---------|
| 0 | PATCHED |
| 1 | VULNERABLE / UNSUPPORTED |
| 2 | UNKNOWN (branch not in matrix, or version not disclosed) |

## Important

`php -v` in a terminal does **not** prove the web runtime is patched. Check
**every** runtime serving the site (each FPM pool, the Apache module, each
container). A runtime is only safe once the patched package is installed **and**
its processes have been restarted.

## Responsible use

- Only check systems you own or are authorized to test.
- This tool does not exploit, does not send payloads, and does not probe paths.
- A patch does not remove malicious files or accounts created before patching —
  if you suspect compromise, investigate and rebuild from a verified source.

## AI-assisted remediation

`php inspect.php --prompt` turns the scan findings into a ready-to-paste prompt
for an AI assistant (ChatGPT, Claude, …). The prompt embeds your per-runtime
findings and the scanner's preliminary recommendations, then asks the model for
an ordered, copy-paste remediation plan specific to your OS — while instructing
it to produce **defensive remediation only, never exploit code**.

```bash
php inspect.php --prompt            # print the prompt
php inspect.php --prompt --redact   # strip absolute paths first
php inspect.php --prompt > fix.txt  # save it to paste later
```

> The prompt contains details about **your** server (versions, config, and
> paths unless `--redact` is used). You are pasting it into an external service —
> review it first.

## Remediation & hardening

See **[RECOMMENDATIONS.md](RECOMMENDATIONS.md)** for a copy-paste checklist:
the real fix (patch + restart), version-hiding hygiene (`expose_php`,
`X-Powered-By` for Apache/Nginx/Cloudflare), temporary mitigations, EOL
migration, and a *fix vs hardening* quick reference.

## Sources

- PHP.net security release, 2026-10-21
- [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell) (CERT-EU tracked)
- [nikba.com — PHP2Shell: PHP vulnerabilities and remediation](https://nikba.com/ro/articole/php2shell-vulnerabilitati-php-remediere)

## License

MIT — see [LICENSE](LICENSE).

## Contributing

PRs welcome. Keep it informational: version/configuration detection only, no
exploit code, no payloads.
