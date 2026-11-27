"""
Domain generator: name generation + async availability and PHP-fingerprint
checks. Pure logic only -- no FastAPI / HTTP routing here.
"""

import asyncio
import concurrent.futures
import itertools
import re
import socket
import time
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
    target_url: str | None = None


DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_FALLBACK_URL = "https://dns.google/resolve"

# Cooldown timestamp when primary DoH hits ConnectTimeout/ConnectError
_doh_cooldown_until: float = 0.0

# Dedicated DNS threadpool + concurrency cap so getaddrinfo never stalls behind
# asyncio's small default executor or overwhelms local NAT DNS forwarders.
_dns_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=64, thread_name_prefix="xplota_dns"
)
_DNS_SEMAPHORES: dict[int, asyncio.Semaphore] = {}


def _get_dns_semaphore() -> asyncio.Semaphore:
    loop_id = id(asyncio.get_running_loop())
    sem = _DNS_SEMAPHORES.get(loop_id)
    if sem is None:
        sem = asyncio.Semaphore(24)
        _DNS_SEMAPHORES[loop_id] = sem
    return sem


async def resolve_system(domain: str, timeout: float = 3.0) -> tuple[bool | None, str | None]:
    """Resolve via the OS DNS resolver (getaddrinfo IPv4 on a dedicated pool).
    Returns (False, None) if an A record exists, (True, None) on NXDOMAIN/no data,
    or (None, error) on timeout/other failure."""
    loop = asyncio.get_running_loop()
    sem = _get_dns_semaphore()
    try:
        async with sem:
            await asyncio.wait_for(
                loop.run_in_executor(
                    _dns_executor,
                    socket.getaddrinfo,
                    domain,
                    None,
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                ),
                timeout=timeout,
            )
            return False, None
    except asyncio.TimeoutError:
        return None, "DNS error: SystemTimeout"
    except socket.gaierror:
        return True, None
    except Exception as e:
        return None, f"DNS error: {type(e).__name__}"


async def resolve(domain: str, timeout: float = 4.0, client=None,
                  url: str = DOH_URL) -> tuple[bool | None, str | None]:
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
            url,
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


_PHP_COOKIES = (
    ("phpsessid", "PHPSESSID cookie"),
    ("laravel_session", "Laravel session cookie"),
    ("wordpress_test_cookie", "WordPress cookie"),
    ("wp-settings-", "WordPress cookie"),
    ("woocommerce_items_in_cart", "WooCommerce cookie"),
    ("wp_woocommerce_session", "WooCommerce cookie"),
    ("prestashop-", "PrestaShop cookie"),
    ("ocsessid", "OpenCart cookie"),
    ("moodlesession", "Moodle cookie"),
    ("phpbb3_", "phpBB cookie"),
    ("xf_session", "XenForo cookie"),
    ("ci_session", "CodeIgniter cookie"),
    ("cakephp", "CakePHP cookie"),
)

_PHP_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']*'
    r'(?:wordpress|joomla|drupal|prestashop|magento|opencart|typo3|mediawiki|moodle|vbulletin|phpbb)'
    r'[^"\']*)',
    re.IGNORECASE,
)


async def _probe_php(domain: str, client, timeout: float | None = 5.0) -> tuple[list[str], str | None, str | None]:
    """Passive fingerprint via one normal GET to the homepage.
    Returns (signals, error, working_target_url)."""
    signals: list[str] = []
    resp = None
    last_err = None
    working_scheme = None
    req_kwargs: dict = {"follow_redirects": True}
    if timeout is not None:
        req_kwargs["timeout"] = timeout
    for scheme in ("https", "http"):
        try:
            resp = await client.get(f"{scheme}://{domain}", **req_kwargs)
            working_scheme = scheme
            break
        except Exception as e:
            last_err = e
    if resp is None:
        return signals, f"HTTP error: {type(last_err).__name__}", None

    headers = resp.headers
    body = resp.text[:200_000].lower()
    final_url_raw = str(resp.url)
    final_url = final_url_raw.lower()

    # Determine concrete target URL to pass to scanners (preserve scheme + .php path if redirected)
    target_url = final_url_raw if ".php" in final_url else f"{working_scheme}://{domain}"

    if "php" in headers.get("x-powered-by", "").lower():
        signals.append(f"X-Powered-By: {headers.get('x-powered-by')}")
    if "php" in headers.get("server", "").lower():
        signals.append(f"Server: {headers.get('server')}")
    if headers.get("x-pingback"):
        signals.append("WordPress X-Pingback header")
    if "wp-json" in headers.get("link", "").lower() or "api.w.org" in headers.get("link", "").lower():
        signals.append("WordPress REST API Link header")
    x_gen = headers.get("x-generator", "")
    if any(k in x_gen.lower() for k in ("php", "wordpress", "joomla", "drupal", "prestashop", "typo3", "mediawiki", "moodle")):
        signals.append(f"X-Generator: {x_gen}")
    if headers.get("x-drupal-cache") or headers.get("x-drupal-dynamic-cache"):
        signals.append("Drupal cache header")
    if headers.get("x-magento-tags") or headers.get("x-magento-cache-debug"):
        signals.append("Magento cache header")

    cookies = resp.headers.get_list("set-cookie") if hasattr(headers, "get_list") else []
    cookie_blob = "\n".join(c.lower() for c in cookies)
    matched_cookie_labels: set[str] = set()
    for needle, label in _PHP_COOKIES:
        if needle in cookie_blob and label not in matched_cookie_labels:
            matched_cookie_labels.add(label)
            signals.append(label)
    if re.search(r'(?:^|[;\s])s?sess[0-9a-f]{32}=', cookie_blob):
        signals.append("Drupal session cookie")

    if ".php" in final_url:
        signals.append("URL ends in .php")
    if re.search(r'(?:href|action|src)=["\'][^"\']*\.php|/index\.php\?', body):
        signals.append(".php links in page")
    if any(m in body for m in ("wp-content", "wp-includes", "/wp-json/", "api.w.org", "xmlrpc.php")):
        signals.append("WordPress (PHP) paths")
    gen_match = _PHP_GENERATOR_RE.search(body)
    if gen_match and not ("wordpress" in gen_match.group(1) and any("WordPress" in s for s in signals)):
        signals.append(f"CMS generator: {gen_match.group(1)[:40]}")
    if "/sites/default/files/" in body:
        signals.append("Drupal paths")
    if "/media/jui/" in body or "/components/com_" in body:
        signals.append("Joomla paths")
    if "catalog/view/theme/" in body:
        signals.append("OpenCart paths")
    if "skin/frontend/" in body or "pub/static/frontend/" in body:
        signals.append("Magento paths")

    return signals, None, target_url


async def check_php(domain: str, client, timeout: float = 6.0) -> tuple[list[str], str | None]:
    """Passive fingerprint via one normal GET to the homepage."""
    signals, err, _ = await _probe_php(domain, client, timeout=timeout)
    return signals, err


async def scan_domains(domains, do_check: bool, do_php: bool,
                        concurrency: int = 100, progress_cb=None,
                        dns_mode: str = "auto"):
    """Yields DomainResult objects as checks complete, for live streaming.

    ``dns_mode``:
      - ``"system"``: use OS DNS (``getaddrinfo``) — fast, never rate-limited by DoH.
      - ``"doh"``: DoH only (cloudflare-dns.com).
      - ``"auto"``: try DoH, and on ConnectTimeout/ConnectError fall back to
        secondary DoH / system DNS with a 60s cooldown on the timed-out DoH host.
    """
    import httpx

    global _doh_cooldown_until
    concurrency = max(1, min(int(concurrency), 200))
    sem = asyncio.Semaphore(concurrency)
    total = len(domains)
    done = 0

    client_kwargs: dict = {
        "headers": {"User-Agent": "Mozilla/5.0 (compatible; domain-tool/1.0)"},
        "verify": False,
    }
    timeout_cls = getattr(httpx, "Timeout", None)
    if timeout_cls is not None:
        client_kwargs["timeout"] = timeout_cls(timeout=5.0, connect=2.5)
    limits_cls = getattr(httpx, "Limits", None)
    if limits_cls is not None:
        client_kwargs["limits"] = limits_cls(
            max_connections=max(concurrency + 20, 100),
            max_keepalive_connections=min(concurrency, 50),
        )

    async with httpx.AsyncClient(**client_kwargs) as client:

        async def _resolve_domain(domain: str) -> tuple[bool | None, str | None]:
            global _doh_cooldown_until
            if dns_mode == "system":
                return await resolve_system(domain)

            if dns_mode == "auto" and time.monotonic() < _doh_cooldown_until:
                return await resolve_system(domain)

            avail, err = await resolve(domain, client=client)
            if err and dns_mode == "auto" and any(
                k in err for k in ("ConnectTimeout", "ConnectError", "TimeoutException")
            ):
                # Try secondary DoH once, then fall back to system DNS
                avail2, err2 = await resolve(domain, client=client, url=DOH_FALLBACK_URL)
                if err2 is None:
                    return avail2, None
                _doh_cooldown_until = time.monotonic() + 60.0
                return await resolve_system(domain)
            return avail, err

        async def worker(domain):
            nonlocal done
            async with sem:
                result = DomainResult(domain=domain)
                try:
                    if do_check or do_php:
                        avail, dns_err = await _resolve_domain(domain)
                        result.available = avail
                        # If do_check is False (e.g. CT domains), still run PHP probe
                        # even on a transient DNS timeout so live sites aren't dropped.
                        should_probe = do_php and (
                            avail is False or (dns_err is not None and not do_check)
                        )
                        if dns_err and not should_probe:
                            result.error = dns_err
                        elif should_probe:
                            if dns_err:
                                result.available = False
                            signals, http_err, target_url = await _probe_php(domain, client, timeout=None)
                            result.php_signals = signals
                            result.target_url = target_url
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
