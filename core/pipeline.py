"""
Pipeline engine — continuous domain discovery → PHP fingerprint → php2shell scan.

The pipeline finds PHP sites and feeds them into the php2shell vulnerability
scanner.  Three discovery modes:

  smart    — Continuous multi-wave Certificate Transparency discovery on real
             SSL-backed domains first, falling back to clean domain generation
             only if CT is exhausted or unreachable.
  generate — Keyword → domain generation.
  wordlist — Scan a provided list of domains.

It runs until all sources are exhausted (or forever in continuous mode) and
can be stopped by the admin at any time.
"""

import asyncio
import contextlib
import string
import time
from dataclasses import dataclass
from typing import Any

from core.domain_gen import DEFAULT_TLDS, clean, generate_names, scan_domains
from core.scanner_runner import get_scanner, run_scanner
from core.smart_sources import PHP_HEAVY_TLDS, canonical_host, ct_batch_stream

# Extra word suffixes used in continuous-mode variation waves
_WORD_SUFFIXES = [
    "online", "web", "site", "shop", "store", "plus", "pro", "max",
    "cloud", "tech", "digital", "global", "world", "central", "direct",
    "group", "team", "tools", "works", "media", "data", "link",
    "one", "360", "24", "7", "x", "z", "app", "hub", "dev",
]


# ---------------------------------------------------------------------------
# Domain generator (lazy — yields one domain at a time)
# ---------------------------------------------------------------------------

def _domain_stream(keywords: list[str], tlds: list[str],
                   max_length: int, hyphens: bool, continuous: bool):
    """Yield ``(wave, domain)`` pairs.  Wave 0 is the base keyword set;
    higher waves are automatic variations produced in continuous mode."""
    cleaned_tlds = [clean(t.lstrip(".")) for t in tlds if clean(t.lstrip("."))]
    if not cleaned_tlds:
        cleaned_tlds = list(DEFAULT_TLDS)

    seen: set[str] = set()

    def _emit(wave: int, kws: list[str]):
        for name in generate_names(kws, max_length, hyphens):
            for tld in cleaned_tlds:
                d = f"{name}.{tld}"
                if d not in seen:
                    seen.add(d)
                    yield wave, d

    # Wave 0 — base keywords
    yield from _emit(0, keywords)

    if not continuous:
        return

    # Waves 1-99 — number suffixes
    for i in range(1, 100):
        yield from _emit(i, [f"{kw}{i}" for kw in keywords])

    # Waves 100+ — word suffixes
    for idx, sfx in enumerate(_WORD_SUFFIXES):
        yield from _emit(100 + idx, [f"{kw}{sfx}" for kw in keywords])

    # Waves 200+ — three-digit numbers
    for i in range(100, 10_000):
        yield from _emit(200 + i, [f"{kw}{i}" for kw in keywords])

    # Waves 10200+ — single-char suffixes
    for idx, ch in enumerate(string.ascii_lowercase):
        yield from _emit(10_200 + idx, [f"{kw}{ch}" for kw in keywords])


# ---------------------------------------------------------------------------
# Pipeline state
# ---------------------------------------------------------------------------

@dataclass
class _Stats:
    running: bool = False
    started_at: float = 0.0
    domains_generated: int = 0
    domains_checked: int = 0
    php_found: int = 0
    scanned: int = 0
    vulnerable: int = 0
    scan_clean: int = 0
    scan_errors: int = 0
    wave: int = 0
    phase: str = "idle"
    source: str = ""  # "ct", "generate", "wordlist"
    ct_fetched: int = 0

    def to_dict(self) -> dict[str, Any]:
        elapsed = time.time() - self.started_at if self.started_at else 0
        d = {k: getattr(self, k) for k in self.__dataclass_fields__}
        d["elapsed"] = round(elapsed, 1)
        return d


# ---------------------------------------------------------------------------
# Pipeline singleton
# ---------------------------------------------------------------------------

class Pipeline:
    """Manages the full discover → fingerprint → scan lifecycle."""

    def __init__(self) -> None:
        self.state = _Stats()
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._subs: list[asyncio.Queue] = []
        self._lock = asyncio.Lock()
        self._php_targets: list[dict] = []
        self._results: list[dict] = []
        self._seen_roots: set[str] = set()

    # -- public ---------------------------------------------------------

    @property
    def running(self) -> bool:
        return self.state.running

    async def start(self, **kw) -> bool:
        async with self._lock:
            if self.running:
                return False
            self._stop.clear()
            self.state = _Stats(running=True, started_at=time.time(), phase="starting")
            self._php_targets.clear()
            self._results.clear()
            self._seen_roots.clear()
            self._task = asyncio.create_task(self._run(**kw))
            return True

    async def stop(self) -> None:
        async with self._lock:
            if not self.running:
                return
            self._stop.set()
            if self._task and not self._task.done():
                self._task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await self._task
            self.state.running = False
            self.state.phase = "stopped"
            await self._emit({"type": "stopped", "stats": self.state.to_dict()})

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=5000)
        self._subs.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with contextlib.suppress(ValueError):
            self._subs.remove(q)

    def snapshot(self) -> dict[str, Any]:
        return {
            **self.state.to_dict(),
            "php_targets": self._php_targets[-100:],
            "scan_results": self._results[-100:],
        }

    # -- broadcast ------------------------------------------------------

    async def _emit(self, ev: dict) -> None:
        dead: list[asyncio.Queue] = []
        for q in self._subs:
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._subs.remove(q)

    # -- main loop ------------------------------------------------------

    async def _run(self, *, keywords, tlds, max_length=15, hyphens=False,
                   batch_size=50, concurrency=50, continuous=True,
                   scanner_threads=5, scanner_timeout=60, insecure=True,
                   follow_redirects=True, sapi="auto", scan_paths=None,
                   scan_headers=None, wordlist=None, smart_mode=True):

        scan_queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=500)
        scanner = get_scanner("php2shell/scanner_1")

        await self._emit({"type": "started", "stats": self.state.to_dict()})

        scanner_task = asyncio.create_task(self._scanner_loop(
            scanner, scan_queue, scanner_threads, scanner_timeout,
            insecure, follow_redirects, sapi, scan_paths or [], scan_headers or [],
        ))

        try:
            self.state.phase = "discovering"

            # 1) Process word-list entries first (highest priority)
            extra = [w.strip() for w in (wordlist or []) if w.strip() and not w.startswith("#")]
            if extra:
                self.state.source = "wordlist"
                await self._emit({"type": "source_change", "source": "wordlist",
                                  "count": len(extra), "stats": self.state.to_dict()})
                await self._feed_domains(
                    extra, batch_size, concurrency, scan_queue,
                    do_check=True, source="wordlist",
                )

            # 2) Smart mode: continuous multi-wave Certificate Transparency logs
            if smart_mode and not self._stop.is_set():
                self.state.source = "ct"
                self.state.phase = "CT lookup"
                await self._emit({"type": "source_change", "source": "ct",
                                  "stats": self.state.to_dict()})

                async for wave, query, domains in ct_batch_stream(
                    keywords, continuous=continuous, max_per_query=1000
                ):
                    if self._stop.is_set():
                        break
                    self.state.wave = wave
                    self.state.phase = f"CT: {query}"
                    fresh = self._filter_unseen(domains)
                    if not fresh:
                        continue
                    self.state.ct_fetched += len(fresh)
                    await self._feed_domains(
                        fresh, batch_size, concurrency, scan_queue,
                        do_check=False, source="ct",
                    )

            # 3) Generated domains (used when smart_mode is off, continuous=False
            #    after CT finishes, or as fallback if crt.sh becomes unreachable)
            if not self._stop.is_set():
                self.state.source = "generate"
                self.state.phase = "discovering"
                await self._emit({"type": "source_change", "source": "generate",
                                  "stats": self.state.to_dict()})

                # Keep original keywords cleanly — never double-expand CMS combos
                # into brute-force suffixes.
                gen_tlds = [t for t in tlds if t] or PHP_HEAVY_TLDS
                batch: list[str] = []
                for wave, domain in _domain_stream(
                    keywords, gen_tlds, max_length, hyphens, continuous
                ):
                    if self._stop.is_set():
                        break
                    root = canonical_host(domain)
                    if root in self._seen_roots:
                        continue
                    self._seen_roots.add(root)
                    self.state.wave = wave
                    self.state.domains_generated += 1
                    batch.append(domain)
                    if len(batch) >= batch_size:
                        await self._process_batch(
                            batch, concurrency, scan_queue, do_check=True, source="generate"
                        )
                        batch = []

                if batch and not self._stop.is_set():
                    await self._process_batch(
                        batch, concurrency, scan_queue, do_check=True, source="generate"
                    )

            # Signal scanner to finish
            self.state.phase = "draining"
            await self._emit({"type": "discovery_done", "stats": self.state.to_dict()})
            await scan_queue.put(None)
            await scanner_task

            self.state.phase = "complete"
            self.state.running = False
            await self._emit({"type": "complete", "stats": self.state.to_dict()})

        except asyncio.CancelledError:
            await scan_queue.put(None)
            scanner_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await scanner_task
            raise
        except Exception as exc:
            self.state.phase = "error"
            self.state.running = False
            await self._emit({"type": "error", "error": str(exc), "stats": self.state.to_dict()})

    # -- helpers ---------------------------------------------------------

    def _filter_unseen(self, domains: list[str]) -> list[str]:
        fresh: list[str] = []
        for d in domains:
            root = canonical_host(d)
            if root in self._seen_roots:
                continue
            self._seen_roots.add(root)
            fresh.append(d)
        return fresh

    async def _feed_domains(self, domains: list[str], batch_size: int,
                            concurrency: int, scan_queue: asyncio.Queue,
                            *, do_check: bool, source: str) -> None:
        for i in range(0, len(domains), batch_size):
            if self._stop.is_set():
                break
            chunk = domains[i : i + batch_size]
            self.state.domains_generated += len(chunk)
            await self._process_batch(
                chunk, concurrency, scan_queue, do_check=do_check, source=source
            )

    async def _process_batch(self, domains: list[str], concurrency: int,
                             scan_queue: asyncio.Queue, *, do_check: bool,
                             source: str) -> None:
        async with contextlib.aclosing(
            scan_domains(domains, do_check=do_check, do_php=True,
                         concurrency=concurrency, dns_mode="system")
        ) as results:
            async for r in results:
                if self._stop.is_set():
                    break
                self.state.domains_checked += 1
                is_php = bool(r.php_signals) and r.available is False
                ev: dict[str, Any] = {
                    "type": "php_found" if is_php else "checked",
                    "domain": r.domain,
                    "available": r.available,
                    "php_signals": r.php_signals,
                    "error": r.error,
                    "source": source,
                    "stats": self.state.to_dict(),
                }
                if is_php:
                    self.state.php_found += 1
                    self._php_targets.append({
                        "domain": r.domain,
                        "signals": r.php_signals,
                        "source": source,
                    })
                    target = r.target_url or r.domain
                    try:
                        scan_queue.put_nowait(target)
                    except asyncio.QueueFull:
                        pass
                await self._emit(ev)

    # -- scanner worker -------------------------------------------------

    async def _scanner_loop(self, scanner, queue: asyncio.Queue,
                            threads: int, timeout: int, insecure: bool,
                            follow_redirects: bool, sapi: str,
                            paths: list[str], headers: list[str]) -> None:
        if scanner is None:
            await self._emit({"type": "scan_error", "error": "php2shell scanner not found"})
            return

        while True:
            first = await queue.get()
            if first is None or self._stop.is_set():
                break

            # Collect small batch (up to 5) for efficiency
            batch = [first]
            for _ in range(4):
                try:
                    t = queue.get_nowait()
                    if t is None:
                        await queue.put(None)   # re-queue poison pill
                        break
                    batch.append(t)
                except asyncio.QueueEmpty:
                    break

            if not batch:
                continue

            urls = [t if "://" in t else f"https://{t}" for t in batch]
            await self._emit({
                "type": "scan_start", "targets": urls,
                "queue_remaining": queue.qsize(),
                "stats": self.state.to_dict(),
            })

            try:
                async with contextlib.aclosing(
                    run_scanner(scanner, targets=urls, threads=threads,
                               timeout=timeout, insecure=insecure,
                               follow_redirects=follow_redirects, sapi=sapi,
                               paths=paths, headers=headers)
                ) as events:
                    async for ev in events:
                        if self._stop.is_set():
                            break
                        if ev.get("type") == "result":
                            self.state.scanned += 1
                            if ev.get("vulnerable") is True:
                                self.state.vulnerable += 1
                            elif ev.get("vulnerable") is False:
                                self.state.scan_clean += 1
                            else:
                                self.state.scan_errors += 1
                            self._results.append(ev)
                        ev["_src"] = "scanner"
                        ev["stats"] = self.state.to_dict()
                        await self._emit(ev)
            except Exception as exc:
                self.state.scan_errors += 1
                await self._emit({
                    "type": "scan_error", "targets": urls,
                    "error": str(exc), "stats": self.state.to_dict(),
                })


# Global singleton
pipeline = Pipeline()
