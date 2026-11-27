# PHP2Shell RCE Chain (52704)

**CVEs:** CVE-2026-109618 / CVE-2026-109619  
**Target:** PHP 8.5.11 NTS, Apache 2.4.66, mod_php/prefork, x86-64, ASLR enabled

## What it does

Wraps `xplotas/php2shell/xplota_1/52704.py` for execution from the Xplota UI.

**Stage 1 — Disclosure (always runs)**  
Triggers the A1/B1 session-state OOM (CVE-2026-109619) to leak a forged
overlong `Set-Cookie: PHPSESSID` value that contains libphp pointers.  
Exit 0 with no `--rce` → disclosure only.

**Stage 2 — 128 MiB RCE sink (optional)**  
Feeds the leaked base into the incomplete-bucket/object-destruction path
(CVE-2026-109618) and executes an arbitrary shell command via `zif_system`.

## UI fields

| Field | Meaning |
|-------|---------|
| Targets | One `http://HOST[:PORT]` or bare `HOST[:PORT]` per line |
| RCE command | Shell command to run. Leave empty for disclosure-only mode. |
| PHP endpoint path | Defaults to `/index.php` |
| Forge page / Pointer floor / Heap-from-lib delta / zval_ptr_dtor offset / RCE block offset / RCE header count | Advanced: override calibration constants for a non-default build. Leave all empty for the validated 8.5.11 profile. |
| Timeout (s) | Per-target wall-clock timeout (default 600 s — the exploit takes several minutes) |

## Exit codes from the underlying exploit

| Code | Meaning | UI verdict |
|------|---------|------------|
| 0 | Chain succeeded | VULNERABLE |
| 1 | No overlong cookie → patched | NOT VULNERABLE |
| 2 | Normal-size cookie → patched | NOT VULNERABLE |
| 3 | No pointer candidates | INCONCLUSIVE |
| 4 | Pointer failed exact-build profile | INCONCLUSIVE |
| 5 | Main chunk absent from buckets | INCONCLUSIVE |
| 6 | RCE stage failed after disclosure | INCONCLUSIVE |

## Requirements

The exploit requires network access to a lab target running the exact validated
build (PHP 8.5.11, libphp SHA-256
`ecd97e302e8cb3fd106c0541410256ad6597cb6410166beee0ab773ff4974b36`).
Recalibrate all offsets for any other build — see the docstring in `52704.py`.
