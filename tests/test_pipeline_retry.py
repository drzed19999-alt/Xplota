import unittest

from core.pipeline import _build_retry_params, _is_retryable_error


class PipelineRetryTests(unittest.TestCase):
    def test_is_retryable_error(self):
        self.assertTrue(_is_retryable_error("Timeout (Inconclusive)"))
        self.assertTrue(_is_retryable_error("Connection / Transport Error"))
        self.assertTrue(_is_retryable_error("TLS / Certificate Error"))
        self.assertFalse(_is_retryable_error("DNS error: NXDOMAIN"))
        self.assertFalse(_is_retryable_error("404 Not Found"))

    def test_build_retry_params_timeout(self):
        cfg1 = _build_retry_params(
            "https://slow.example.com", "Timeout (Inconclusive)", 1,
            base_timeout=60, base_threads=5, base_insecure=False,
            base_redirects=True, base_paths=[],
        )
        self.assertEqual(cfg1["timeout"], 90)
        self.assertEqual(cfg1["threads"], 1)
        self.assertEqual(cfg1["target"], "https://slow.example.com")

        cfg2 = _build_retry_params(
            "https://slow.example.com", "Timeout (Inconclusive)", 2,
            base_timeout=60, base_threads=5, base_insecure=False,
            base_redirects=True, base_paths=[],
        )
        self.assertEqual(cfg2["timeout"], 120)
        self.assertEqual(cfg2["paths"], ["/"])

    def test_build_retry_params_transport(self):
        cfg1 = _build_retry_params(
            "https://drop.example.com", "Connection / Transport Error", 1,
            base_timeout=60, base_threads=5, base_insecure=False,
            base_redirects=True, base_paths=[],
        )
        self.assertEqual(cfg1["target"], "http://drop.example.com")
        self.assertTrue(cfg1["insecure"])
        self.assertEqual(cfg1["threads"], 1)

        cfg2 = _build_retry_params(
            "http://drop.example.com", "Connection / Transport Error", 2,
            base_timeout=60, base_threads=5, base_insecure=True,
            base_redirects=True, base_paths=[],
        )
        self.assertFalse(cfg2["follow_redirects"])
        self.assertEqual(cfg2["timeout"], 90)


if __name__ == "__main__":
    unittest.main()
