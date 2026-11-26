"""
FastAPI backend for the domain tool UI.

Run with:
    uvicorn app:app --reload --host 0.0.0.0 --port 8000

Then open http://localhost:8000 (or http://<kali-ip>:8000 from Windows).
"""

import asyncio
import contextlib
import json
import random

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core import (
    DEFAULT_TLDS,
    clean,
    discover_scanners,
    generate_names,
    get_scanner,
    load_scan_history,
    run_scanner,
    scan_domains,
)

app = FastAPI(title="Domain Tool")
app.mount("/static", StaticFiles(directory="static"), name="static")


class GenerateRequest(BaseModel):
    keywords: list[str] = Field(min_length=1, max_length=20)
    tlds: list[str] = Field(default_factory=lambda: list(DEFAULT_TLDS), max_length=30)
    max_length: int = Field(default=15, ge=3, le=63)
    hyphens: bool = False
    count: int = Field(default=30, ge=1, le=500)


class ScanRequest(GenerateRequest):
    check: bool = True
    php: bool = False
    concurrency: int = Field(default=100, ge=1, le=200)


class ScannerRunRequest(BaseModel):
    scanner_id: str = Field(min_length=1, max_length=200)
    targets: list[str] = Field(min_length=1, max_length=500)
    threads: int = Field(default=10, ge=1, le=100)
    timeout: int = Field(default=60, ge=1, le=300)
    insecure: bool = False
    follow_redirects: bool = False
    sapi: str = Field(default="auto", pattern="^(auto|mod_php|fpm)$")
    paths: list[str] = Field(default_factory=list, max_length=50)
    headers: list[str] = Field(default_factory=list, max_length=20)


@app.get("/")
async def root():
    return FileResponse("static/index.html")


@app.post("/api/generate")
async def api_generate(req: GenerateRequest):
    """Fast, no-network: just name generation + random TLD assignment."""
    keywords = [k for k in (clean(k) for k in req.keywords) if k]
    if not keywords:
        return {"domains": []}
    names = generate_names(keywords, req.max_length, req.hyphens)
    tlds = [t for t in (clean(t.lstrip(".")) for t in req.tlds) if t] or DEFAULT_TLDS
    domains = [f"{n}.{random.choice(tlds)}" for n in names]
    random.shuffle(domains)
    return {"domains": domains[: req.count]}


@app.post("/api/scan")
async def api_scan(req: ScanRequest):
    """Streams newline-delimited JSON results as they complete."""
    keywords = [k for k in (clean(k) for k in req.keywords) if k]
    names = generate_names(keywords, req.max_length, req.hyphens)
    tlds = [t for t in (clean(t.lstrip(".")) for t in req.tlds) if t] or DEFAULT_TLDS

    max_candidates = max(300, req.count * 10)
    candidates = [f"{n}.{t}" for n in names for t in tlds][:max_candidates]

    async def stream():
        if not candidates:
            return
        count = 0
        async with contextlib.aclosing(
            scan_domains(
                candidates, do_check=req.check, do_php=req.php,
                concurrency=req.concurrency,
            )
        ) as results:
            async for result in results:
                if req.check and req.php:
                    if result.available is False and not result.php_signals:
                        continue
                elif req.check:
                    if result.available is False:
                        continue
                elif req.php:
                    if not result.php_signals:
                        continue

                payload = {
                    "domain": result.domain,
                    "available": result.available,
                    "php_signals": result.php_signals,
                    "error": result.error,
                }
                yield json.dumps(payload) + "\n"
                count += 1
                if count >= req.count:
                    break
                await asyncio.sleep(0)

    return StreamingResponse(stream(), media_type="application/x-ndjson")


@app.get("/api/scanners")
async def api_list_scanners():
    """Return all discovered scanners under core/scanners/."""
    return {"scanners": [s.to_dict() for s in discover_scanners()]}


@app.get("/api/scanners/history")
async def api_scanner_history():
    """Return recent saved scan runs."""
    return {"history": load_scan_history()}


@app.post("/api/scanners/run")
async def api_run_scanner(req: ScannerRunRequest):
    """Run a discovered scanner and stream NDJSON log/result events."""
    scanner = get_scanner(req.scanner_id)
    if scanner is None:
        raise HTTPException(status_code=404, detail=f"Scanner not found: {req.scanner_id}")

    async def stream():
        async with contextlib.aclosing(
            run_scanner(
                scanner,
                targets=req.targets,
                threads=req.threads,
                timeout=req.timeout,
                insecure=req.insecure,
                follow_redirects=req.follow_redirects,
                sapi=req.sapi,
                paths=req.paths,
                headers=req.headers,
            )
        ) as events:
            async for ev in events:
                yield json.dumps(ev) + "\n"
                await asyncio.sleep(0)

    return StreamingResponse(stream(), media_type="application/x-ndjson")
