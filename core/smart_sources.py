"""
Smart domain sources for the pipeline — high-yield alternatives to brute-force
domain name generation.

Sources:
  1. Certificate Transparency logs (crt.sh) — real registered domains with SSL
  2. PHP-biased keyword expansion — auto-add WordPress/CMS terms
  3. Web-crawl common PHP domain lists
"""

import asyncio
import re
from typing import AsyncIterator

import httpx

# CRT.SH — Certificate Transparency log search
_CRT_SH_URL = "https://crt.sh/"
_CRT_SH_TIMEOUT = 15.0

# PHP-related keywords that dramatically increase PHP hit rate
PHP_KEYWORDS = [
    "wordpress", "wp", "joomla", "drupal", "magento", "prestashop",
    "opencart", "phpbb", "phpmyadmin", "laravel", "symfony",
    "woocommerce", "moodle", "mediawiki", "vbulletin",
    "cpanel", "webmail", "roundcube", "squirrelmail",
]

# Common PHP site prefixes (subdomains / domain prefixes)
PHP_PREFIXES = [
    "admin", "blog", "cms", "forum", "portal", "login", "panel",
    "webmail", "mail", "cpanel", "dashboard", "members",
]

# TLDs sorted by PHP prevalence (older/cheaper TLDs host way more PHP)
PHP_HEAVY_TLDS = ["com", "net", "org", "info", "biz", "co", "us", "eu", "de", "fr", "nl", "ru"]


def expand_keywords_for_php(keywords: list[str]) -> list[str]:
    """Given user keywords, expand with PHP-biased variations.
    E.g. 'shop' → ['shop', 'shopwp', 'wordpress-shop', 'shop-admin', ...]"""
    expanded = list(keywords)
    for kw in keywords:
        # Add CMS combos
        for cms in ("wp", "wordpress", "php", "joomla"):
            expanded.append(f"{kw}{cms}")
            expanded.append(f"{cms}{kw}")
        # Add common PHP site patterns
        for pfx in ("my", "the", "admin", "web"):
            expanded.append(f"{pfx}{kw}")
    # Deduplicate while preserving order
    seen = set()
    result = []
    for k in expanded:
        if k not in seen:
            seen.add(k)
            result.append(k)
    return result


async def fetch_ct_domains(keyword: str, client: httpx.AsyncClient,
                           max_results: int = 500) -> list[str]:
    """Query crt.sh Certificate Transparency logs for domains matching keyword.
    Returns deduplicated domain names (no wildcards)."""
    domains: set[str] = set()
    try:
        resp = await client.get(
            _CRT_SH_URL,
            params={"q": f"%{keyword}%", "output": "json"},
            timeout=_CRT_SH_TIMEOUT,
        )
        if resp.status_code != 200:
            return []
        entries = resp.json()
        if not isinstance(entries, list):
            return []

        for entry in entries:
            name = entry.get("common_name", "") or entry.get("name_value", "")
            # name_value can contain multiple domains separated by newlines
            for d in name.split("\n"):
                d = d.strip().lower()
                # Skip wildcards, IPs, empty
                if not d or d.startswith("*") or d.startswith("."):
                    continue
                # Basic domain validation
                if re.match(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$', d):
                    domains.add(d)
                if len(domains) >= max_results:
                    break
            if len(domains) >= max_results:
                break
    except Exception:
        pass  # CT log errors should not break the pipeline

    return list(domains)


async def ct_domain_stream(keywords: list[str],
                           max_per_keyword: int = 300) -> AsyncIterator[str]:
    """Async generator that yields real domains from Certificate Transparency
    logs for each keyword. These domains are known-registered (they have SSL
    certs), so DNS existence checks can be skipped."""
    seen: set[str] = set()

    async with httpx.AsyncClient(
        headers={"User-Agent": "Mozilla/5.0 (compatible; domain-tool/1.0)"},
        follow_redirects=True,
    ) as client:
        for keyword in keywords:
            if not keyword or len(keyword) < 2:
                continue
            domains = await fetch_ct_domains(keyword, client, max_per_keyword)
            for d in domains:
                if d not in seen:
                    seen.add(d)
                    yield d
            # Small delay between keyword queries to be polite to crt.sh
            await asyncio.sleep(0.5)


async def bulk_php_check(domains: list[str], concurrency: int = 30,
                         timeout: float = 5.0) -> AsyncIterator[tuple[str, list[str], str | None]]:
    """Check multiple domains for PHP signals using HEAD+GET.
    Yields (domain, signals, error) tuples."""
    from core.domain_gen import check_php

    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        headers={"User-Agent": "Mozilla/5.0 (compatible; domain-tool/1.0)"},
        follow_redirects=True,
    ) as client:

        async def worker(domain: str) -> tuple[str, list[str], str | None]:
            async with sem:
                signals, err = await check_php(domain, client, timeout=timeout)
                return domain, signals, err

        tasks = [asyncio.create_task(worker(d)) for d in domains]
        for coro in asyncio.as_completed(tasks):
            yield await coro
