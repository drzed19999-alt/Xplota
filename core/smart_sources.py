"""
Smart domain sources for the pipeline — high-yield alternatives to brute-force
domain name generation.

Queries Certificate Transparency logs (crt.sh) in progressive waves using both
broad keyword matches and fast prefix-anchored slices so smart discovery can
run continuously on real SSL-backed domains instead of dropping into low-yield
brute-force domain generation.
"""

import asyncio
import re
import string
from typing import TYPE_CHECKING, AsyncIterator

if TYPE_CHECKING:
    import httpx

_CRT_SH_URL = "https://crt.sh/"
_CRT_SH_TIMEOUT = 22.0

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$")

# TLDs with highest legacy/SMB PHP prevalence (for fallback generate mode)
PHP_HEAVY_TLDS = ["com", "net", "org", "info", "biz", "co"]

# PHP CMS / platform terms for keyword combos and continuous CT waves
_CMS_TERMS = (
    "wp", "wordpress", "php", "joomla", "drupal", "magento",
    "woo", "laravel", "opencart", "prestashop", "cpanel",
)

_SITE_PREFIXES = ("my", "shop", "store", "web", "admin", "portal", "blog")

_CONTINUOUS_CMS_PREFIXES = (
    "wordpress-", "wp-", "joomla-", "drupal-", "magento-",
    "opencart-", "prestashop-", "woocommerce-", "laravel-", "moodle-",
    "php-", "shop-", "store-", "cart-", "portal-", "forum-",
    "booking-", "cpanel.", "webmail.", "phpmyadmin.",
)


def canonical_host(domain: str) -> str:
    """Normalize www.<host> to <host> for deduplication."""
    d = domain.strip().lower()
    return d[4:] if d.startswith("www.") and d.count(".") >= 2 else d


def expand_keywords_for_php(keywords: list[str]) -> list[str]:
    """Expand user keywords into PHP-biased search terms (used for CT queries)."""
    expanded = list(keywords)
    for kw in keywords:
        for cms in _CMS_TERMS:
            expanded.append(f"{kw}{cms}")
            expanded.append(f"{cms}{kw}")
        for pfx in _SITE_PREFIXES:
            expanded.append(f"{pfx}{kw}")
    seen: set[str] = set()
    result: list[str] = []
    for k in expanded:
        if k and k not in seen:
            seen.add(k)
            result.append(k)
    return result


def _ct_query_plan(keywords: list[str], continuous: bool):
    """Yield ``(wave, ct_query_pattern)`` tuples ordered from highest relevance
    to broad continuous PHP-ecosystem CT slices.

    Prefix-anchored patterns (no leading '%') use Postgres prefix indexes on
    crt.sh and avoid full-table timeouts.
    """
    seen_q: set[str] = set()

    def _yield_unique(wave: int, q: str):
        if q not in seen_q:
            seen_q.add(q)
            return (wave, q)
        return None

    # Wave 0: Direct keyword wildcard + PHP/CMS combos on user keywords
    for kw in keywords:
        if len(kw) >= 3:
            item = _yield_unique(0, f"%{kw}%")
            if item:
                yield item
        for cms in _CMS_TERMS:
            for pattern in (f"%{kw}-{cms}%", f"%{cms}-{kw}%", f"{kw}{cms}%", f"{cms}{kw}%"):
                item = _yield_unique(0, pattern)
                if item:
                    yield item
        for pfx in _SITE_PREFIXES:
            for pattern in (f"{pfx}-{kw}%", f"{kw}-{pfx}%", f"{pfx}{kw}%"):
                item = _yield_unique(0, pattern)
                if item:
                    yield item

    # Wave 1: Fast prefix-anchored single-character slices on user keywords
    chars = string.ascii_lowercase + string.digits
    for ch in chars:
        for kw in keywords:
            for pattern in (f"{kw}-{ch}%", f"{kw}{ch}%"):
                item = _yield_unique(1, pattern)
                if item:
                    yield item

    # Wave 2: TLD-scoped keyword queries on PHP-heavy TLDs
    for tld in ("com", "net", "org", "info", "biz", "co", "de", "fr", "nl", "ru"):
        for kw in keywords:
            for pattern in (f"{kw}%.{tld}", f"%{kw}.{tld}", f"%{kw}-%.{tld}"):
                item = _yield_unique(2, pattern)
                if item:
                    yield item

    if not continuous:
        return

    # Wave 3: Prefix-anchored PHP CMS/ecommerce ecosystem slices (1-char)
    for idx, pfx in enumerate(_CONTINUOUS_CMS_PREFIXES):
        wave = 3 + idx
        for ch in chars:
            item = _yield_unique(wave, f"{pfx}{ch}%")
            if item:
                yield item

    # Wave 4+: Two-character slices on user keywords and top CMS prefixes
    base_prefixes = [f"{kw}-" for kw in keywords] + ["wp-", "wordpress-", "shop-", "store-", "php-", "laravel-", "joomla-"]
    wave = 100
    for c1 in string.ascii_lowercase:
        for pfx in base_prefixes:
            for c2 in string.ascii_lowercase:
                item = _yield_unique(wave, f"{pfx}{c1}{c2}%")
                if item:
                    yield item
        wave += 1


async def fetch_ct_domains(
    query: str,
    client: "httpx.AsyncClient",
    max_results: int = 1000,
    retries: int = 2,
) -> tuple[list[str], bool]:
    """Query crt.sh Certificate Transparency logs for a pattern.

    Returns ``(domains, ok)`` where ``ok`` is True if crt.sh responded cleanly
    (even with 0 domains) and False if the request failed/timed out.
    """
    raw_domains: set[str] = set()
    for attempt in range(retries + 1):
        try:
            resp = await client.get(
                _CRT_SH_URL,
                params={"q": query, "output": "json"},
                timeout=_CRT_SH_TIMEOUT,
            )
            if resp.status_code in (429, 502, 503, 504):
                if attempt < retries:
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
                return [], False
            if resp.status_code != 200:
                return [], False

            entries = resp.json()
            if not isinstance(entries, list):
                return [], True

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("common_name", "") or entry.get("name_value", "")
                for d in str(name).split("\n"):
                    d = d.strip().lower()
                    if not d or d.startswith("*") or d.startswith("."):
                        continue
                    if _DOMAIN_RE.match(d):
                        raw_domains.add(d)
                    if len(raw_domains) >= max_results * 2:
                        break
                if len(raw_domains) >= max_results * 2:
                    break

            # Prefer bare domains over www. subdomains when deduplicating roots
            ordered = sorted(raw_domains, key=lambda s: (s.startswith("www."), len(s), s))
            deduped: list[str] = []
            seen_roots: set[str] = set()
            for d in ordered:
                root = canonical_host(d)
                if root in seen_roots:
                    continue
                seen_roots.add(root)
                deduped.append(d)
                if len(deduped) >= max_results:
                    break
            return deduped, True
        except Exception:
            if attempt < retries:
                await asyncio.sleep(1.5 * (attempt + 1))
                continue
            return [], False
    return [], False


async def ct_batch_stream(
    keywords: list[str],
    continuous: bool = True,
    max_per_query: int = 1000,
    max_consecutive_failures: int = 8,
) -> AsyncIterator[tuple[int, str, list[str]]]:
    """Stream ``(wave, query, new_domains)`` batches from Certificate Transparency
    logs without duplicate canonical hosts.

    Stops early if crt.sh fails ``max_consecutive_failures`` times in a row so
    the pipeline can fall back gracefully rather than hanging.
    """
    import httpx

    seen_roots: set[str] = set()
    failures = 0

    async with httpx.AsyncClient(
        headers={"User-Agent": "Mozilla/5.0 (compatible; domain-tool/1.0)"},
        follow_redirects=True,
    ) as client:
        for wave, query in _ct_query_plan(keywords, continuous):
            domains, ok = await fetch_ct_domains(query, client, max_results=max_per_query)
            if not ok:
                failures += 1
                if failures >= max_consecutive_failures:
                    return
                await asyncio.sleep(1.0)
                continue

            failures = 0
            fresh: list[str] = []
            for d in domains:
                root = canonical_host(d)
                if root not in seen_roots:
                    seen_roots.add(root)
                    fresh.append(d)

            if fresh:
                yield wave, query, fresh

            # Polite pacing between crt.sh queries
            await asyncio.sleep(0.4)


async def ct_domain_stream(
    keywords: list[str],
    max_per_keyword: int = 1000,
    continuous: bool = True,
) -> AsyncIterator[str]:
    """Backwards-compatible flat async stream of unique domains from CT logs."""
    async for _, _, batch in ct_batch_stream(
        keywords, continuous=continuous, max_per_query=max_per_keyword
    ):
        for d in batch:
            yield d


async def bulk_php_check(
    domains: list[str], concurrency: int = 30, timeout: float = 5.0
) -> AsyncIterator[tuple[str, list[str], str | None]]:
    """Check multiple domains for PHP signals using passive GET."""
    import httpx
    from core.domain_gen import check_php

    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        headers={"User-Agent": "Mozilla/5.0 (compatible; domain-tool/1.0)"},
        follow_redirects=True,
        verify=False,
    ) as client:

        async def worker(domain: str) -> tuple[str, list[str], str | None]:
            async with sem:
                signals, err = await check_php(domain, client, timeout=timeout)
                return domain, signals, err

        tasks = [asyncio.create_task(worker(d)) for d in domains]
        for coro in asyncio.as_completed(tasks):
            yield await coro
