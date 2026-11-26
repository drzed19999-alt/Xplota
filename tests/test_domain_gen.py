import asyncio
import contextlib
import sys
import types
import unittest

from core.domain_gen import blend, check_php, clean, generate_names, resolve, scan_domains


class FakeHeaders(dict):
    def __init__(self, data=None, cookies=None):
        super().__init__({k.lower(): v for k, v in (data or {}).items()})
        self._cookies = cookies or []

    def get(self, key, default=None):
        return super().get(key.lower(), default)

    def get_list(self, key):
        if key.lower() == "set-cookie":
            return list(self._cookies)
        return []


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, headers=None, cookies=None, text="", url="https://example.com"):
        self.status_code = status_code
        self._json = json_data or {}
        self.headers = FakeHeaders(headers, cookies)
        self.text = text
        self.url = url

    def json(self):
        return self._json


class TestNameGeneration(unittest.TestCase):
    def test_clean_strips_invalid_and_hyphens(self):
        self.assertEqual(clean("  --Coffee!! "), "coffee")
        self.assertEqual(clean("my--app-"), "my-app")
        self.assertEqual(clean("---"), "")

    def test_blend_overlap_and_midpoint(self):
        self.assertEqual(blend("coffee", "feed"), "coffeed")
        self.assertEqual(blend("roast", "star"), "roastar")
        self.assertEqual(blend("code", "craft"), "codaft")
        self.assertIsNone(blend("go", "up"))

    def test_generate_names_handles_edge_cases(self):
        self.assertEqual(generate_names(["---", "   "]), [])
        # Single-char vowel keyword should not emit bare suffixes
        names_a = generate_names(["a"], max_length=15)
        self.assertNotIn("hub", names_a)
        self.assertNotIn("labs", names_a)

        names = generate_names(["--coffee-", "roast!"], max_length=12, include_hyphens=True)
        self.assertTrue(all(3 <= len(n) <= 12 for n in names))
        self.assertTrue(all(not n.startswith("-") and not n.endswith("-") and "--" not in n for n in names))


class TestAsyncChecks(unittest.IsolatedAsyncioTestCase):
    async def test_resolve_statuses(self):
        class FakeClient:
            def __init__(self, handler):
                self._handler = handler

            async def get(self, url, **kwargs):
                return self._handler(url, kwargs)

            async def aclose(self):
                pass

        # NXDOMAIN -> available
        avail, err = await resolve("free.example", client=FakeClient(lambda *_: FakeResponse(200, {"Status": 3})))
        self.assertTrue(avail)
        self.assertIsNone(err)

        # NOERROR -> taken
        avail, err = await resolve("taken.example", client=FakeClient(lambda *_: FakeResponse(200, {"Status": 0})))
        self.assertFalse(avail)
        self.assertIsNone(err)

        # HTTP 500 -> unknown with error
        avail, err = await resolve("err.example", client=FakeClient(lambda *_: FakeResponse(500)))
        self.assertIsNone(avail)
        self.assertEqual(err, "DNS HTTP 500")

        # Network error -> unknown with error
        def raise_err(*_):
            raise TimeoutError("timed out")

        avail, err = await resolve("timeout.example", client=FakeClient(raise_err))
        self.assertIsNone(avail)
        self.assertIn("TimeoutError", err)

    async def test_check_php_signals_and_errors(self):
        class PhpClient:
            async def get(self, url, **kwargs):
                return FakeResponse(
                    200,
                    headers={"X-Powered-By": "PHP/8.2", "Server": "Apache PHP"},
                    cookies=["PHPSESSID=abc123; path=/"],
                    text='<a href="/login.php">Login</a><link href="/wp-content/style.css">',
                    url="https://example.com/index.php",
                )

        signals, err = await check_php("example.com", PhpClient())
        self.assertIsNone(err)
        self.assertEqual(len(signals), 6)

        class FailClient:
            async def get(self, url, **kwargs):
                raise ConnectionError("refused")

        signals, err = await check_php("down.example", FailClient())
        self.assertEqual(signals, [])
        self.assertEqual(err, "HTTP error: ConnectionError")

    async def test_scan_domains_cancels_pending_on_early_break(self):
        cancelled_count = 0

        class SlowClient:
            def __init__(self, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, url, **kwargs):
                nonlocal cancelled_count
                domain = kwargs["params"]["name"]
                if domain == "fast.com":
                    return FakeResponse(200, {"Status": 3})
                try:
                    await asyncio.sleep(5)
                except asyncio.CancelledError:
                    cancelled_count += 1
                    raise
                return FakeResponse(200, {"Status": 3})

        fake_httpx = types.ModuleType("httpx")
        fake_httpx.AsyncClient = SlowClient
        prev = sys.modules.get("httpx")
        sys.modules["httpx"] = fake_httpx
        try:
            results = []
            async with contextlib.aclosing(
                scan_domains(["fast.com", "slow1.com", "slow2.com"], do_check=True, do_php=False, concurrency=10)
            ) as gen:
                async for res in gen:
                    results.append(res)
                    break
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].domain, "fast.com")
            self.assertEqual(cancelled_count, 2)
        finally:
            if prev is None:
                sys.modules.pop("httpx", None)
            else:
                sys.modules["httpx"] = prev


if __name__ == "__main__":
    unittest.main()
