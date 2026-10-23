# php2shell-checker

**Informational self-check for the 2026 PHP engine RCE vulnerabilities**
**Verificare informativă pentru vulnerabilitățile PHP RCE din 2026**

Checks whether the PHP runtime(s) serving your site are on a **patched** version
for **CVE-2026-109618** and **CVE-2026-109619** — two unauthenticated remote
code execution flaws in the PHP engine, fixed on 2026-10-21.

> ⚠️ **This is NOT an exploit.** It only reads the version and configuration of
> the PHP runtime and compares it against the published patch matrix. It sends
> no payloads and exploits nothing. Use it to check systems **you own or are
> authorized to test**.

### Why more than a header scanner?

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

---

## 🇷🇴 Română

### Despre ce e vorba

Pe 21 octombrie 2026 PHP a publicat patch-uri pentru două vulnerabilități
critice în motorul PHP:

- **CVE-2026-109618** — RCE prin coruperea memoriei la curățarea cererii (out-of-memory).
- **CVE-2026-109619** — RCE prin stare globală a cererii rămasă „stale" și reutilizată de o cerere ulterioară pe același worker.

Ambele permit **execuție de cod la distanță fără autentificare**. Riscul e cel
mai mare pe **Apache + mod_php**. Nu depinde de WordPress, framework sau de un
formular de login — rulează înainte de codul aplicației.

### Versiuni reparate

| Branch | Reparat în |
|--------|-----------|
| 8.2    | **8.2.35** |
| 8.3    | **8.3.36** |
| 8.4    | **8.4.27** |
| 8.5    | **8.5.12** |
| 8.1 și mai vechi | End-of-life — **migrează** la un branch suportat |

> Pachetele de distribuție (Debian/Ubuntu/RHEL) pot păstra numărul de bază dar
> adăuga o revizie cu fix-ul inclus (backport). Dacă scriptul arată VULNERABIL
> dar furnizorul tău zice că a patch-uit, verifică **revizia completă** a
> pachetului în nota de securitate a furnizorului.

### Cum se folosește

**0. Raport complet de posture pe server (recomandat — cel mai complet):**

```bash
php inspect.php                      # raport text: backport + restart + config + verdict
php inspect.php --json               # JSON structurat (cu dovezi)
php inspect.php --html raport.html   # raport HTML de partajat (sau `-` pentru stdout)
```

Rulează ca **root/sudo** ca să vadă toate runtime-urile, log-urile de pachete și
orele de start ale proceselor. Verdicte posibile: `PATCHED`, `NEEDS_RESTART`
(patch instalat dar workerii nereporniti → încă vulnerabil), `VULNERABLE`,
`UNSUPPORTED` (EOL), `CHECK_VIA_WEB` (Apache mod_php), `UNKNOWN`.

**1. Verificare rapidă pe runtime (mai simplă):**

```bash
chmod +x php2shell-check.sh
./php2shell-check.sh            # scanează toate runtime-urile: CLI, FPM, Apache, docker
./php2shell-check.sh --json     # JSON Lines (un obiect/runtime pe linie; `| jq .` pentru format)
```

**2. Un singur runtime (sau via web, pentru Apache mod_php):**

```bash
php check.php                   # raport pentru runtime-ul care rulează scriptul
php check.php --json
```

Pentru runtime-ul **web** (singura verificare sigură pentru mod_php):
pune `check.php` în webroot, setează `ALLOW_WEB = true` în fișier, deschide-l în
browser, citește rezultatul și **șterge-l imediat**.

**3. Verificare remote pasivă (doar headere):**

```bash
./remote-check.sh --i-am-authorized https://exemplu.ro
```

Citește doar headerele `Server` / `X-Powered-By`. Multe servere ascund
versiunea — un rezultat gol înseamnă „nedivulgat", NU „în siguranță".

### Important

`php -v` din terminal **nu dovedește** că runtime-ul web e patch-uit. Verifică
**fiecare** runtime care servește site-ul (fiecare pool FPM, modulul Apache,
fiecare container). Un runtime e sigur doar după ce **pachetul patch-uit e
instalat ȘI procesele au fost repornite**.

---

## 🇬🇧 English

### What this is

On 2026-10-21 PHP released fixes for two critical engine vulnerabilities:

- **CVE-2026-109618** — RCE via out-of-memory corruption during request cleanup.
- **CVE-2026-109619** — RCE via stale request-owned global state reused by a later request on the same worker.

Both allow **unauthenticated remote code execution**, highest-risk on
**Apache + mod_php**. It is independent of WordPress/frameworks and runs before
application code.

### Fixed versions

| Branch | Fixed in |
|--------|----------|
| 8.2    | **8.2.35** |
| 8.3    | **8.3.36** |
| 8.4    | **8.4.27** |
| 8.5    | **8.5.12** |
| 8.1 and older | End-of-life — **migrate** to a supported branch |

Distro packages may backport the fix while keeping the base number — verify the
full package revision against your vendor's advisory.

### Usage

```bash
# Full posture report (recommended): backport + restart + config + verdict
php inspect.php                      # text
php inspect.php --json               # structured JSON with evidence
php inspect.php --html report.html   # shareable HTML report (or - for stdout)
#   run as root/sudo for full coverage of packages, logs and process times

# Quick per-runtime scan: CLI, FPM, Apache, docker
./php2shell-check.sh
./php2shell-check.sh --json

# A single runtime
php check.php
php check.php --json
php check.php --quiet          # exit code only: 0 patched, 1 vulnerable, 2 unknown

# Web runtime (set ALLOW_WEB=true, open in browser, then DELETE the file)

# Passive remote header check (authorized targets only)
./remote-check.sh --i-am-authorized https://example.com
```

### Exit codes (`check.php`)

| Code | Meaning |
|------|---------|
| 0 | PATCHED |
| 1 | VULNERABLE / UNSUPPORTED |
| 2 | UNKNOWN (branch not in matrix, or version not disclosed) |

### Responsible use

- Only check systems you own or are authorized to test.
- This tool does not exploit, does not send payloads, and does not probe paths.
- A patch does not remove malicious files or accounts created before patching —
  if you suspect compromise, investigate and rebuild from a verified source.

---

## Remediation & hardening / Remediere și hardening

See **[RECOMMENDATIONS.md](RECOMMENDATIONS.md)** for a copy-paste checklist:
the real fix (patch + restart), version-hiding hygiene (`expose_php`,
`X-Powered-By` for Apache/Nginx/Cloudflare), temporary mitigations, EOL
migration, and a *fix vs hardening* quick reference.

## Sources

- PHP.net security release, 2026-10-21
- [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell) (CERT-EU tracked)
- [nikba.com — PHP2Shell: vulnerabilități PHP și remediere](https://nikba.com/ro/articole/php2shell-vulnerabilitati-php-remediere)

## License

MIT — see [LICENSE](LICENSE).

## Contributing

PRs welcome. Keep it informational: version/configuration detection only, no
exploit code, no payloads.
