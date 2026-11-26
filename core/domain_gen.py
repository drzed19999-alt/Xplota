"""
Domain generator: name generation + async availability and PHP-fingerprint
checks. Pure logic only -- no FastAPI / HTTP routing here.
"""

import asyncio
import itertools
import re
from dataclasses import dataclass, field

PREFIXES = ["get", "try", "use", "my", "go", "the", "hey", "join", "meet", "ez"]
SUFFIXES = ["ly", "ify", "hub", "labs", "base", "box", "hq", "kit", "wise",
            "zone", "ware", "io", "app", "now", "flow", "spot", "nest"]
DEFAULT_TLDS = ["com", "io", "co", "app", "dev", "net", "ai"]


def clean(word: str) -> str:
    cleaned = re.sub(r"[^a-z0-9-]", "", word.lower().strip())
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    return cleaned.strip("-")


def blend(a: str, b: str):
    for size in (3, 2, 1):
        if len(a) > size and len(b) > size and a[-size:] == b[:size]:
            return a + b[size:]
    if len(a) >= 4 and len(b) >= 4:
        return a[: len(a) // 2 + 1] + b[len(b) // 2:]
    return None


def generate_names(keywords, max_length=15, include_hyphens=False):
    cleaned_kws = [k for k in (clean(w) for w in keywords) if k]
    if not cleaned_kws:
        return []

    names = set()
    for kw in cleaned_kws:
        names.add(kw)
        for p in PREFIXES:
            names.add(p + kw)
            if include_hyphens:
                names.add(f"{p}-{kw}")
        for s in SUFFIXES:
            names.add(kw + s)
            if len(kw) > 1 and kw[-1] in "aeiou":
                names.add(kw[:-1] + s)
    for a, b in itertools.permutations(cleaned_kws, 2):
        names.add(a + b)
        if include_hyphens:
            names.add(f"{a}-{b}")
        blended = blend(a, b)
        if blended:
            names.add(blended)

    valid = set()
    for n in names:
        n = re.sub(r"-{2,}", "-", n).strip("-")
        if 3 <= len(n) <= max_length:
            valid.add(n)
    return sorted(valid, key=len)


@dataclass
class DomainResult:
    domain: str
    available: bool | None = None
    php_signals: list = field(default_factory=list)
    error: str | None = None


DOH_URL = "https://cloudflare-dns.com/dns-query"


async def resolve(domain: str, timeout: float = 4.0, client=None) -> tuple[bool | None, str | None]:
    """
    Check DNS existence via DNS-over-HTTPS (NS query).
    Returns (True, None) on NXDOMAIN (likely unregistered),
    (False, None) on NOERROR (zone exists), or (None, error) on failure.
    """
    owns_client = client is None
    if owns_client:
        import httpx

        client = httpx.AsyncClient()
    try:
        resp = await client.get(
            DOH_URL,
            params={"name": domain, "type": "NS"},
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return None, f"DNS HTTP {resp.status_code}"
        data = resp.json()
        status = data.get("Status")
        if status == 3:  # NXDOMAIN
            return True, None
        if status == 0:  # NOERROR
            return False, None
        return None, f"DNS status {status}"
    except Exception as e:
        return None, f"DNS error: {type(e).__name__}"
    finally:
        if owns_client:
            await client.aclose()


async def check_php(domain: str, client, timeout: float = 6.0) -> tuple[list[str], str | None]:
    """Passive fingerprint via one normal GET to the homepage."""
    signals = []
    resp = None
    last_err = None
    for scheme in ("https", "http"):
        try:
            resp = await client.get(f"{scheme}://{domain}", timeout=timeout, follow_redirects=True)
            break
        except Exception as e:
            last_err = e
    if resp is None:
        return signals, f"HTTP error: {type(last_err).__name__}"

    headers = resp.headers
    body = resp.text[:200_000].lower()
    final_url = str(resp.url).lower()

    if "php" in headers.get("x-powered-by", "").lower():
        signals.append(f"X-Powered-By: {headers.get('x-powered-by')}")
    if "php" in headers.get("server", "").lower():
        signals.append(f"Server: {headers.get('server')}")
    cookies = resp.headers.get_list("set-cookie") if hasattr(headers, "get_list") else []
    if any("phpsessid" in c.lower() for c in cookies):
        signals.append("PHPSESSID cookie")
    if ".php" in final_url:
        signals.append("URL ends in .php")
    if re.search(r'(href|action|src)=["\'][^"\']*\.php', body):
        signals.append(".php links in page")
    if "wp-content" in body or "wp-includes" in body:
        signals.append("WordPress (PHP) paths")
    return signals, None


async def scan_domains(domains, do_check: bool, do_php: bool,
                        concurrency: int = 100, progress_cb=None):
    """Yields DomainResult objects as checks complete, for live streaming."""
    import httpx

    concurrency = max(1, min(int(concurrency), 200))
    sem = asyncio.Semaphore(concurrency)
    total = len(domains)
    done = 0

    async with httpx.AsyncClient(headers={"User-Agent": "Mozilla/5.0 (compatible; domain-tool/1.0)"}) as client:

        async def worker(domain):
            nonlocal done
            async with sem:
                result = DomainResult(domain=domain)
                try:
                    if do_check or do_php:
                        avail, dns_err = await resolve(domain, client=client)
                        result.available = avail
                        if dns_err:
                            result.error = dns_err
                        elif do_php and avail is False:
                            signals, http_err = await check_php(domain, client)
                            result.php_signals = signals
                            if http_err and not signals:
                                result.error = http_err
                except Exception as e:
                    result.error = str(e)
                done += 1
                if progress_cb:
                    progress_cb(done, total)
                return result

        tasks = [asyncio.create_task(worker(d)) for d in domains]
        try:
            for coro in asyncio.as_completed(tasks):
                yield await coro
        finally:
            pending = [t for t in tasks if not t.done()]
            for t in pending:
                t.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
