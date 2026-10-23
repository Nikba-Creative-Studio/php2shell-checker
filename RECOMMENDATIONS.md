# Recommendations

Hardening and remediation checklist for **CVE-2026-109618** and
**CVE-2026-109619** (unauthenticated PHP engine RCE, patched 2026-10-21).

> **Read this first.** There is exactly **one real fix**: install the patched
> PHP package **and restart** the workers. Everything else on this page is
> *defense-in-depth* — it reduces exposure or reconnaissance, but a server on an
> unpatched engine stays exploitable even with every hardening step below
> applied. Hiding the version (e.g. `X-Powered-By`) hides the *symptom an
> attacker reads*, not the *vulnerability*.

## 1. The real fix (mandatory) — patch + restart

```bash
# Debian / Ubuntu
sudo apt update && sudo apt upgrade php8.4-fpm php8.4-cli php8.4-common
sudo systemctl restart php8.4-fpm       # OR: apache2 for mod_php

# RHEL / Alma / Rocky
sudo dnf update php php-fpm php-common
sudo systemctl restart php-fpm

# Docker — rebuild the image, don't restart the old container
docker pull <image>:<patched-tag>
docker compose up -d --build
```

Then **verify** definitively (backport + restart aware):

```bash
sudo php inspect.php
```

> `apt upgrade` alone does **not** restart running workers — old processes keep
> executing the vulnerable code until you `restart` them.

## 2. Hygiene: hide the PHP version (defense-in-depth, NOT a fix)

Cuts down automated reconnaissance. **Does not replace the patch.**

**Best place — from PHP (covers every web server):**
```ini
; php.ini
expose_php = Off
```

**Apache (`.htaccess` or vhost) — requires mod_headers:**
```apache
Header always unset X-Powered-By
ServerTokens Prod
ServerSignature Off
```

**Nginx:**
```nginx
fastcgi_hide_header X-Powered-By;   # strip X-Powered-By coming from PHP-FPM
server_tokens off;                  # hide nginx version in the Server header
```

**Cloudflare:**
Rules → Transform Rules → Modify Response Header → *Remove* `X-Powered-By`
as a safety net even if the origin leaks it.

> After changing it, confirm with:
> `./remote-check.sh --i-am-authorized https://example.com`
> It should report `NOT DISCLOSED`.

## 3. Temporary mitigations (from the PHP advisory — partial)

Only until you patch, never as a permanent solution:
```ini
; php.ini
session.upload_progress.enabled = Off
```
```bash
sudo systemctl restart php8.4-fpm   # restart workers to pick it up
```
- WAF / rate-limit rules may reduce some paths but **do not fix** the engine.
- Do **not** set `memory_limit` to unlimited — it can harm availability.

## 4. End-of-life branches (e.g. PHP 7.4)

PHP 7.4 / 8.0 / 8.1 are **end-of-life** — no official fix. Plan a **migration**
to a supported, patched branch (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+). Until then
the server stays exposed; isolate it and prioritise.

## 5. After patching — post-incident hygiene

- A patch does **not** remove files or accounts created before the update.
- If you suspect compromise: preserve evidence, limit exposure, investigate,
  rebuild from a verified source, and rotate credentials.
- Review logs for unusual changes.

## Quick reference — fix vs hardening

| Action | Fixes the CVE? | Effect |
|--------|:--:|--------|
| Patch PHP package **+ restart** | ✅ **YES** | The actual fix |
| `expose_php = Off` / unset `X-Powered-By` | ❌ no | Hides version from recon |
| Disable `session.upload_progress` | ⚠️ partial | Reduces one attack path (temporary) |
| WAF / Cloudflare rules | ⚠️ partial | May block some payloads |
| Migrate off EOL branch | ✅ (enables the fix) | Required for 7.4 / 8.0 / 8.1 |
