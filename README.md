# PHP2Shell — CVE-2026-109618 / CVE-2026-109619

Independent analysis and defensive tooling for two critical pre-auth RCE vulnerabilities in PHP core's session handling.

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

## Repository Structure

```
docs/
  ANALYSIS.md             — Full technical deep-dive (vulnerability mechanics, code paths,
                            exploitation primitives, all five findings)
poc/
  poc_trigger.py          — Defensive UAF trigger: sends a crafted multipart POST to detect
                            if a target is vulnerable to CVE-2026-109619 (crash = vulnerable)
mitigation/
  check_mitigation.sh     — Server audit script: checks all installed PHP binaries for
                            patch status, upload_progress config, INI scope, guard extension,
                            serializer consistency, and FPM pool hardening
```

## Usage

### Check if your server is mitigated

```bash
chmod +x mitigation/check_mitigation.sh
sudo ./mitigation/check_mitigation.sh
```

### Test a target for CVE-2026-109619 (authorized testing only)

```bash
python3 poc/poc_trigger.py https://your-server.example.com/index.php
```

Options:
- `--dry-run` — Build the payload without sending
- `--rate 16384` — Slower send rate (bytes/s) to ensure throttle trigger
- `--spray 149` — Number of heap spray fields
- `--cookie PHPSESSID=abc123` — Existing session cookie

A connection reset or 502 indicates the PHP worker crashed (vulnerable). A 200 OK means the target is either mitigated or the timing was insufficient.

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

This research is for **authorized security testing and educational purposes only**. Do not use against systems you do not own or have explicit written authorization to test. The PoC trigger is designed for crash detection (defensive verification), not exploitation.

## References

- [HOSTED-POWER php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard)
- [PHP Security Release 2026-10-21](https://www.php.net/archive/2026.php)
- [Mattias Geniar — Early mitigation steps](https://ma.ttias.be/php-cve-2026-109618-early-mitigation/)
- [Upwind — Initial Assessment](https://www.upwind.io/feed/initial-assessment-php2shell-two-critical-unpatched-php-rces-cve-2026-109618-cve-2026-109619)
- [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc)

## License

MIT
