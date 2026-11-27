"""
Persistent JSON store for vulnerable websites discovered by the pipeline.
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

VULN_FILE = Path(__file__).resolve().parent.parent / "vulnerable_sites.json"
_lock = threading.Lock()


def _normalize_domain(target: str) -> str:
    raw = (target or "").strip()
    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or raw).lower()
    return raw.split("/")[0].lower()


def load_vulnerable_sites() -> list[dict[str, Any]]:
    """Return all saved vulnerable sites, newest first."""
    with _lock:
        if not VULN_FILE.is_file():
            return []
        try:
            data = json.loads(VULN_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []


def save_vulnerable_site(entry: dict[str, Any]) -> dict[str, Any]:
    """Save or update a vulnerable site entry in ``vulnerable_sites.json``.

    Deduplicates by normalized domain so re-scanning the same host updates
    its timestamp/details instead of creating duplicate rows.
    """
    target = str(entry.get("target") or entry.get("domain") or "").strip()
    domain = _normalize_domain(target)
    record: dict[str, Any] = {
        "domain": domain,
        "target": target or domain,
        "vuln_type": entry.get("vuln_type") or "php2shell",
        "reason": entry.get("reason") or "",
        "php_version": entry.get("php_version") or "",
        "source": entry.get("source") or "",
        "signals": entry.get("signals") or [],
        "found_at": entry.get("found_at") or datetime.now(timezone.utc).isoformat(),
    }

    with _lock:
        sites: list[dict[str, Any]] = []
        if VULN_FILE.is_file():
            try:
                loaded = json.loads(VULN_FILE.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    sites = loaded
            except (OSError, json.JSONDecodeError):
                sites = []

        # Remove existing entry for same domain so newest goes to the top
        sites = [s for s in sites if _normalize_domain(str(s.get("domain") or s.get("target") or "")) != domain]
        sites.insert(0, record)

        try:
            VULN_FILE.write_text(json.dumps(sites, indent=2), encoding="utf-8")
        except OSError:
            pass

    return record


def clear_vulnerable_sites() -> None:
    """Remove all saved vulnerable sites."""
    with _lock:
        try:
            if VULN_FILE.is_file():
                VULN_FILE.unlink()
        except OSError:
            pass
