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


@dataclass
class ScannerInfo:
    id: str
    name: str
    category: str
    description: str
    entry: Path
    options: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "options": self.options,
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
        "insecure": "--insecure" in src,
        "follow_redirects": "--follow-redirects" in src,
        "sapi": "--sapi" in src,
        "path": "--path" in src,
        "no_color": "--no-color" in src,
    }


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
            found[rel] = ScannerInfo(
                id=rel,
                name=title or parts[-1],
                category=category,
                description=readme_desc or doc or f"Scanner at {rel}",
                entry=entry,
                options=_detect_cli_options(entry),
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
) -> list[str]:
    opts = scanner.options
    args = [sys.executable, str(scanner.entry)]

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
        args.append("--insecure")
    if follow_redirects and opts.get("follow_redirects"):
        args.append("--follow-redirects")
    if sapi and opts.get("sapi"):
        args.extend(["--sapi", sapi])
    if opts.get("path"):
        for p in paths:
            if p.strip():
                args.extend(["--path", p.strip()])
    if opts.get("no_color"):
        args.append("--no-color")
    return args


async def run_scanner(
    scanner: ScannerInfo,
    targets: list[str],
    threads: int = 10,
    timeout: int = 30,
    insecure: bool = False,
    follow_redirects: bool = False,
    sapi: str = "auto",
    paths: list[str] | None = None,
):
    """
    Async generator that runs a scanner subprocess and yields event dicts:
      {"type": "log", "line": "..."}
      {"type": "result", "target": "...", "vulnerable": bool|None, "reason": "...", "error": ...}
      {"type": "done", "exit_code": int, "count": int}
    """
    cleaned_targets = [t.strip() for t in targets if t.strip()]
    if not cleaned_targets:
        yield {"type": "error", "message": "No valid targets provided."}
        return

    with tempfile.TemporaryDirectory(prefix="xplota_scan_") as tmpdir:
        tmp = Path(tmpdir)
        hosts_file = tmp / "hosts.txt"
        output_file = tmp / "results.json"
        hosts_file.write_text("\n".join(cleaned_targets) + "\n", encoding="utf-8")

        cmd = _build_args(
            scanner=scanner,
            hosts_file=hosts_file,
            output_file=output_file,
            targets=cleaned_targets,
            threads=max(1, min(int(threads), 100)),
            timeout=max(1, min(int(timeout), 300)),
            insecure=insecure,
            follow_redirects=follow_redirects,
            sapi=sapi,
            paths=paths or [],
        )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(scanner.entry.parent),
        )

        try:
            assert proc.stdout is not None
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line:
                    yield {"type": "log", "line": line}

            exit_code = await proc.wait()

            result_count = 0
            if output_file.is_file():
                try:
                    data = json.loads(output_file.read_text(encoding="utf-8"))
                    items = data if isinstance(data, list) else data.get("results", [])
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        target = item.get("target") or item.get("url") or item.get("host") or ""
                        yield {
                            "type": "result",
                            "target": target,
                            "vulnerable": item.get("vulnerable"),
                            "reason": item.get("reason") or "",
                            "error": item.get("error"),
                        }
                        result_count += 1
                except Exception as exc:
                    yield {"type": "error", "message": f"Failed to parse scanner output: {exc}"}

            yield {"type": "done", "exit_code": exit_code, "count": result_count}
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
