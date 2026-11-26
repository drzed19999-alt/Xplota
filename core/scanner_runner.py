"""
Scanner discovery and async subprocess runner for modules under core/scanners/.
"""

import ast
import asyncio
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCANNERS_DIR = Path(__file__).resolve().parent / "scanners"
HISTORY_FILE = Path(__file__).resolve().parent.parent / "scan_history.json"
MAX_HISTORY = 25

# ANSI escape sequence pattern for stripping color codes from output
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_LIVE_RESULT_RE = re.compile(
    r"^\[(VULNERABLE|NOT VULNERABLE|INCONCLUSIVE|ERROR)\]\s+(\S+)(?:\s+-\s+(.*))?$"
)


@dataclass
class ScannerInfo:
    id: str
    name: str
    category: str
    description: str
    entry: Path
    cves: str | None = None
    options: dict[str, bool] = field(default_factory=dict)
    extra_fields: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "cves": self.cves,
            "options": self.options,
            "extra_fields": self.extra_fields,
        }


def _read_readme_summary(folder: Path) -> tuple[str | None, str | None]:
    readme = folder / "README.md"
    if not readme.is_file():
        return None, None
    try:
        lines = readme.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None, None

    title = None
    desc_lines: list[str] = []
    for line in lines:
        s = line.strip()
        if not s:
            if desc_lines:
                break
            continue
        if s.startswith("#") and title is None:
            title = s.lstrip("#").strip()
            continue
        if s.startswith("#"):
            break
        desc_lines.append(s)
    desc = " ".join(desc_lines) if desc_lines else None
    return title, desc


def _read_py_docstring(path: Path) -> str | None:
    try:
        src = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(src)
        doc = ast.get_docstring(tree)
        return doc.strip().splitlines()[0] if doc else None
    except Exception:
        return None


def _detect_cves(entry: Path) -> str | None:
    try:
        src = entry.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    m = re.search(r'^CVES\s*=\s*["\']([^"\']+)["\']', src, re.MULTILINE)
    if m:
        return m.group(1).strip()
    found = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", src)))
    return " / ".join(found) if found else None


def _classify_vulnerability(scanner: ScannerInfo, item: dict[str, Any]) -> str:
    """Derive a human-readable vulnerability type / detection signal from scanner output."""
    vuln = item.get("vulnerable")
    reason = str(item.get("reason") or "").lower()
    error = str(item.get("error") or "").lower()
    status_code = item.get("status_code")
    sapi = item.get("sapi")

    if vuln is True:
        if "memory exhausted" in reason or "allowed memory size" in reason:
            signal = "In-band PHP OOM"
        elif "empty body" in reason and status_code == 500:
            signal = "Differential Empty HTTP 500"
        elif "worker died" in reason or status_code in (502, 503, 504):
            signal = f"PHP-FPM Worker Crash (HTTP {status_code or '200'})"
        elif "crash pattern" in reason:
            signal = "PHP Crash Pattern (Differential)"
        elif "drop the connection" in reason or "connection reset" in error:
            signal = "Connection Drop (Worker Crash)"
        elif "slower" in reason and "resource exhaustion" in reason:
            signal = "Timing-Based Resource Exhaustion"
        elif "drastically smaller" in reason:
            signal = "Response Body Differential"
        elif "version" in reason or "unpatched" in reason or item.get("powered_by"):
            signal = "Unpatched PHP Version Banner"
        else:
            signal = "Crash / Anomaly Signal"

        prefix = f"{scanner.category} ({scanner.cves})" if scanner.cves else scanner.name
        sapi_tag = f" [{sapi}]" if sapi else ""
        return f"{prefix} — {signal}{sapi_tag}"

    if vuln is False:
        if status_code in (400, 403, 411, 413, 414, 417, 422, 429, 431):
            return f"Blocked / Rejected (HTTP {status_code})"
        return "Patched / Not Vulnerable"

    if "timed out" in error or "timed out" in reason:
        return "Timeout (Inconclusive)"
    if "ssl" in error or "tls" in error or "certificate" in error:
        return "TLS / Certificate Error"
    if error:
        return "Connection / Transport Error"
    return "Inconclusive"


def _detect_cli_options(entry: Path) -> dict[str, bool]:
    try:
        src = entry.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {}
    return {
        "url": bool(re.search(r'["\']--?u(rl)?["\']', src)),
        "list": bool(re.search(r'["\']--?l(ist)?["\']', src)),
        "threads": bool(re.search(r'["\']--?t(hreads)?["\']', src)),
        "timeout": "--timeout" in src,
        "output": bool(re.search(r'["\']--?o(utput)?["\']', src)),
        "all_results": "--all-results" in src,
        "insecure": "--insecure" in src or "-k" in src,
        "follow_redirects": "--follow-redirects" in src,
        "sapi": "--sapi" in src,
        "path": "--path" in src,
        "no_color": "--no-color" in src,
        "verbose": bool(re.search(r'["\']--?v(erbose)?["\']', src)),
        "headers": bool(re.search(r'["\']--?H["\']|--header', src)),
        "auto_paths": "--auto-paths" in src,
    }


def _load_manifest(folder: Path) -> dict[str, Any]:
    manifest = folder / "scanner.json"
    if not manifest.is_file():
        return {}
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def discover_scanners(base_dir: Path | None = None) -> list[ScannerInfo]:
    """Discover scanner entrypoints under core/scanners/."""
    root = base_dir or SCANNERS_DIR
    if not root.is_dir():
        return []

    found: dict[str, ScannerInfo] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith((".", "__pycache__")))
        cur = Path(dirpath)

        # Prefer scanner.py inside a dedicated folder
        if "scanner.py" in filenames:
            entry = cur / "scanner.py"
            rel = cur.relative_to(root).as_posix()
            parts = rel.split("/")
            category = parts[0] if len(parts) > 1 else "general"
            title, readme_desc = _read_readme_summary(cur)
            doc = _read_py_docstring(entry)
            manifest = _load_manifest(cur)
            opts = _detect_cli_options(entry)
            if isinstance(manifest.get("options"), dict):
                opts.update({k: bool(v) for k, v in manifest["options"].items()})
            found[rel] = ScannerInfo(
                id=rel,
                name=manifest.get("name") or title or parts[-1],
                category=manifest.get("category") or category,
                description=manifest.get("description") or readme_desc or doc or f"Scanner at {rel}",
                entry=entry,
                cves=manifest.get("cves") or _detect_cves(entry),
                options=opts,
                extra_fields=manifest.get("extra_fields") if isinstance(manifest.get("extra_fields"), list) else [],
            )
            # Don't descend further inside a scanner folder
            dirnames[:] = []
            continue

        # Also support standalone *.py scanners placed directly in a category folder
        for fname in sorted(filenames):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            entry = cur / fname
            rel = entry.relative_to(root).with_suffix("").as_posix()
            parts = rel.split("/")
            category = parts[0] if len(parts) > 1 else "general"
            doc = _read_py_docstring(entry)
            found[rel] = ScannerInfo(
                id=rel,
                name=entry.stem,
                category=category,
                description=doc or f"Scanner at {rel}",
                entry=entry,
                cves=_detect_cves(entry),
                options=_detect_cli_options(entry),
            )

    return sorted(found.values(), key=lambda s: (s.category, s.name.lower()))


def get_scanner(scanner_id: str, base_dir: Path | None = None) -> ScannerInfo | None:
    for sc in discover_scanners(base_dir):
        if sc.id == scanner_id:
            return sc
    return None


def _build_args(
    scanner: ScannerInfo,
    hosts_file: Path,
    output_file: Path,
    targets: list[str],
    threads: int,
    timeout: int,
    insecure: bool,
    follow_redirects: bool,
    sapi: str,
    paths: list[str],
    headers: list[str] | None = None,
) -> list[str]:
    opts = scanner.options
    args = [sys.executable, "-u", str(scanner.entry)]

    if len(targets) == 1 and opts.get("url"):
        args.extend(["-u", targets[0]])
    elif opts.get("list"):
        args.extend(["-l", str(hosts_file)])
    elif opts.get("url"):
        args.extend(["-u", targets[0]])

    if opts.get("threads"):
        args.extend(["-t", str(threads)])
    if opts.get("timeout"):
        args.extend(["--timeout", str(timeout)])
    if opts.get("output"):
        args.extend(["-o", str(output_file)])
    if opts.get("all_results"):
        args.append("--all-results")
    if insecure and opts.get("insecure"):
        args.extend(["-k"])
    if follow_redirects and opts.get("follow_redirects"):
        args.append("--follow-redirects")
    if sapi and sapi != "auto" and opts.get("sapi"):
        args.extend(["--sapi", sapi])
    if opts.get("path"):
        for p in paths:
            if p.strip():
                args.extend(["--path", p.strip()])
    if opts.get("headers") and headers:
        for h in headers:
            if ":" in h and h.strip():
                args.extend(["-H", h.strip()])
    if opts.get("no_color"):
        args.append("--no-color")
    if opts.get("verbose"):
        args.append("-v")
    return args


def load_scan_history(history_file: Path | None = None) -> list[dict[str, Any]]:
    path = history_file or HISTORY_FILE
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_scan_history(entry: dict[str, Any], history_file: Path | None = None) -> None:
    path = history_file or HISTORY_FILE
    items = load_scan_history(path)
    items.insert(0, entry)
    items = items[:MAX_HISTORY]
    try:
        path.write_text(json.dumps(items, indent=2), encoding="utf-8")
    except OSError:
        pass


def _parse_live_line(scanner: ScannerInfo, line: str) -> dict[str, Any] | None:
    clean = _ANSI_RE.sub("", line).strip()
    m = _LIVE_RESULT_RE.match(clean)
    if not m:
        return None
    verdict, target, rest = m.group(1), m.group(2), (m.group(3) or "").strip()
    vuln_map = {"VULNERABLE": True, "NOT VULNERABLE": False, "INCONCLUSIVE": None, "ERROR": None}
    vuln = vuln_map.get(verdict)
    item = {"vulnerable": vuln, "verdict": verdict, "reason": rest}
    return {
        "type": "live_result",
        "target": target,
        "vulnerable": vuln,
        "vuln_type": _classify_vulnerability(scanner, item),
        "verdict": verdict,
        "reason": rest,
    }


async def run_scanner(
    scanner: ScannerInfo,
    targets: list[str],
    threads: int = 10,
    timeout: int = 60,
    insecure: bool = False,
    follow_redirects: bool = False,
    sapi: str = "auto",
    paths: list[str] | None = None,
    headers: list[str] | None = None,
    history_file: Path | None = None,
):
    """
    Async generator that runs a scanner subprocess and yields event dicts:
      {"type": "started", "scanner": "...", "targets": int, "pid": int}
      {"type": "log", "line": "..."}
      {"type": "result", ...}
      {"type": "done", "exit_code": int, "count": int}
    """
    cleaned_targets = list(dict.fromkeys(t.strip() for t in targets if t.strip()))
    if not cleaned_targets:
        yield {"type": "error", "message": "No valid targets provided."}
        return

    with tempfile.TemporaryDirectory(prefix="xplota_scan_") as tmpdir:
        tmp = Path(tmpdir)
        hosts_file = tmp / "hosts.txt"
        output_file = tmp / "results.json"
        hosts_file.write_text("\n".join(cleaned_targets) + "\n", encoding="utf-8")

        threads = max(1, min(int(threads), 100))
        timeout = max(1, min(int(timeout), 300))

        cmd = _build_args(
            scanner=scanner,
            hosts_file=hosts_file,
            output_file=output_file,
            targets=cleaned_targets,
            threads=threads,
            timeout=timeout,
            insecure=insecure,
            follow_redirects=follow_redirects,
            sapi=sapi,
            paths=paths or [],
            headers=headers or [],
        )

        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(scanner.entry.parent),
            env=env,
        )

        yield {
            "type": "started",
            "scanner": scanner.name,
            "targets": len(cleaned_targets),
            "pid": proc.pid,
        }

        try:
            assert proc.stdout is not None
            while True:
                try:
                    raw = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout + 30)
                except asyncio.TimeoutError:
                    yield {"type": "log", "line": "[xplota] Scanner output stalled, waiting..."}
                    continue
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line:
                    yield {"type": "log", "line": line}
                    live = _parse_live_line(scanner, line)
                    if live:
                        yield live

            exit_code = await asyncio.wait_for(proc.wait(), timeout=10)

            result_count = 0
            collected_results: list[dict[str, Any]] = []
            if output_file.is_file():
                try:
                    raw_text = output_file.read_text(encoding="utf-8")
                    data = json.loads(raw_text)
                    items = data if isinstance(data, list) else data.get("results", [])
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        target = (
                            item.get("target")
                            or item.get("url")
                            or item.get("host")
                            or item.get("tested_url")
                            or ""
                        )
                        evidence = None
                        if item.get("request") or item.get("response") or item.get("tested_url"):
                            evidence = {
                                "tested_url": item.get("tested_url"),
                                "final_url": item.get("final_url"),
                                "request": item.get("request"),
                                "response": item.get("response"),
                            }
                        ev_obj = {
                            "type": "result",
                            "target": target,
                            "vulnerable": item.get("vulnerable"),
                            "vuln_type": _classify_vulnerability(scanner, item),
                            "cves": scanner.cves,
                            "status_code": item.get("status_code"),
                            "verdict": item.get("verdict"),
                            "reason": item.get("reason") or "",
                            "error": item.get("error"),
                            "powered_by": item.get("powered_by"),
                            "sapi": item.get("sapi"),
                            "evidence": evidence,
                        }
                        collected_results.append(ev_obj)
                        yield ev_obj
                        result_count += 1
                except json.JSONDecodeError as exc:
                    yield {"type": "error", "message": f"Invalid JSON in scanner output: {exc}"}
                except Exception as exc:
                    yield {"type": "error", "message": f"Failed to parse scanner output: {exc}"}

            if collected_results:
                from datetime import datetime, timezone

                _save_scan_history(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "scanner_id": scanner.id,
                        "scanner_name": scanner.name,
                        "targets": len(cleaned_targets),
                        "vulnerable": sum(1 for r in collected_results if r["vulnerable"] is True),
                        "clean": sum(1 for r in collected_results if r["vulnerable"] is False),
                        "unknown": sum(1 for r in collected_results if r["vulnerable"] is None),
                        "exit_code": exit_code,
                        "results": collected_results,
                    },
                    history_file=history_file,
                )

            yield {"type": "done", "exit_code": exit_code, "count": result_count}
        except asyncio.TimeoutError:
            yield {"type": "error", "message": "Scanner process timed out during shutdown."}
            yield {"type": "done", "exit_code": -1, "count": 0}
        finally:
            if proc.returncode is None:
                proc.kill()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    pass
