import contextlib
import json
import tempfile
import unittest
from pathlib import Path

from core.scanner_runner import (
    discover_scanners,
    get_scanner,
    load_scan_history,
    run_scanner,
    _classify_vulnerability,
    ScannerInfo,
)


class TestScannerRunner(unittest.IsolatedAsyncioTestCase):
    def test_discovers_real_php2shell_scanner(self):
        scanners = discover_scanners()
        ids = [s.id for s in scanners]
        self.assertIn("php2shell/scanner_1", ids)

        sc = get_scanner("php2shell/scanner_1")
        self.assertIsNotNone(sc)
        assert sc is not None
        self.assertEqual(sc.category, "php2shell")
        self.assertEqual(sc.name, "php2shell-scanner")
        self.assertEqual(sc.cves, "CVE-2026-109618 / CVE-2026-109619")
        self.assertTrue(sc.options["url"])
        self.assertTrue(sc.options["list"])
        self.assertTrue(sc.options["output"])
        self.assertTrue(sc.options["sapi"])

    async def test_run_custom_scanner_streams_all_event_types(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            sc_dir = root / "demo" / "sample_scan"
            sc_dir.mkdir(parents=True)
            (sc_dir / "README.md").write_text("# Demo Scanner\n\nChecks demo targets.\n", encoding="utf-8")
            (sc_dir / "scanner.py").write_text(
                'import argparse, json\n'
                'p = argparse.ArgumentParser()\n'
                'p.add_argument("-u", "--url")\n'
                'p.add_argument("-l", "--list")\n'
                'p.add_argument("-o", "--output")\n'
                'p.add_argument("--all-results", action="store_true")\n'
                'p.add_argument("--no-color", action="store_true")\n'
                'args = p.parse_args()\n'
                'print("scanning...")\n'
                'print("progress: 50%")\n'
                'with open(args.output, "w") as f:\n'
                '    json.dump({"results": [{"host": args.url, "vulnerable": True, "reason": "matched", "verdict": "VULNERABLE"}]}, f)\n',
                encoding="utf-8",
            )

            sc = get_scanner("demo/sample_scan", base_dir=root)
            self.assertIsNotNone(sc)
            assert sc is not None

            events = []
            async with contextlib.aclosing(run_scanner(sc, targets=["https://example.com"])) as stream:
                async for ev in stream:
                    events.append(ev)

            types_seen = [e["type"] for e in events]
            # Should emit started, log(s), result(s), and done
            self.assertIn("started", types_seen)
            self.assertIn("log", types_seen)
            self.assertIn("result", types_seen)
            self.assertIn("done", types_seen)

            started = next(e for e in events if e["type"] == "started")
            self.assertEqual(started["scanner"], "Demo Scanner")
            self.assertEqual(started["targets"], 1)

            res = next(e for e in events if e["type"] == "result")
            self.assertEqual(res["target"], "https://example.com")
            self.assertTrue(res["vulnerable"])
            self.assertEqual(res["reason"], "matched")
            self.assertEqual(res["verdict"], "VULNERABLE")
            self.assertIn("Crash / Anomaly Signal", res["vuln_type"])

            done = next(e for e in events if e["type"] == "done")
            self.assertEqual(done["count"], 1)

    async def test_deduplicates_targets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            sc_dir = root / "dedup" / "scanner_a"
            sc_dir.mkdir(parents=True)
            (sc_dir / "scanner.py").write_text(
                'import argparse, json\n'
                'p = argparse.ArgumentParser()\n'
                'p.add_argument("-l", "--list")\n'
                'p.add_argument("-o", "--output")\n'
                'p.add_argument("--all-results", action="store_true")\n'
                'p.add_argument("--no-color", action="store_true")\n'
                'args = p.parse_args()\n'
                'with open(args.list) as f: hosts = [l.strip() for l in f if l.strip()]\n'
                'print(f"hosts: {len(hosts)}")\n'
                'with open(args.output, "w") as f:\n'
                '    json.dump({"results": [{"host": h, "vulnerable": False, "reason": "clean"} for h in hosts]}, f)\n',
                encoding="utf-8",
            )

            sc = get_scanner("dedup/scanner_a", base_dir=root)
            assert sc is not None

            events = []
            async with contextlib.aclosing(
                run_scanner(sc, targets=["https://a.com", "https://a.com", "https://b.com"])
            ) as stream:
                async for ev in stream:
                    events.append(ev)

            started = next(e for e in events if e["type"] == "started")
            self.assertEqual(started["targets"], 2)

            done = next(e for e in events if e["type"] == "done")
            self.assertEqual(done["count"], 2)

    async def test_manifest_live_parsing_evidence_and_history(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            sc_dir = root / "web" / "custom_scan"
            sc_dir.mkdir(parents=True)
            (sc_dir / "scanner.json").write_text(
                json.dumps({
                    "name": "Custom Manifest Scanner",
                    "cves": "CVE-2026-99999",
                    "extra_fields": [{"name": "mode", "label": "mode", "type": "text", "default": "fast"}],
                }),
                encoding="utf-8",
            )
            (sc_dir / "scanner.py").write_text(
                'import argparse, json\n'
                'p = argparse.ArgumentParser()\n'
                'p.add_argument("-u", "--url")\n'
                'p.add_argument("-o", "--output")\n'
                'p.add_argument("-H", "--header", action="append")\n'
                'args = p.parse_args()\n'
                'print("[VULNERABLE] https://t.example/index.php - Status: 500")\n'
                'with open(args.output, "w") as f:\n'
                '    json.dump({"results": [{"host": "https://t.example/index.php", "vulnerable": True, "status_code": 500, "reason": "HTTP 500 with an empty body", "tested_url": "https://t.example/index.php", "request": "POST /index.php", "response": "HTTP/1.1 500"}]}, f)\n',
                encoding="utf-8",
            )

            sc = get_scanner("web/custom_scan", base_dir=root)
            assert sc is not None
            self.assertEqual(sc.name, "Custom Manifest Scanner")
            self.assertEqual(sc.cves, "CVE-2026-99999")
            self.assertTrue(sc.options["headers"])
            self.assertEqual(len(sc.extra_fields), 1)

            hist_file = root / "history.json"
            events = []
            async with contextlib.aclosing(
                run_scanner(sc, targets=["https://t.example"], headers=["Authorization: Bearer abc"], history_file=hist_file)
            ) as stream:
                async for ev in stream:
                    events.append(ev)

            self.assertTrue(any(e["type"] == "live_result" and e["vulnerable"] is True for e in events))
            res = next(e for e in events if e["type"] == "result")
            self.assertIsNotNone(res["evidence"])
            self.assertEqual(res["evidence"]["request"], "POST /index.php")
            self.assertIn("Differential Empty HTTP 500", res["vuln_type"])

            history = load_scan_history(hist_file)
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["vulnerable"], 1)


class TestClassifyVulnerability(unittest.TestCase):
    """Tests for the new detection signal classification."""

    def _scanner(self, name="test", cves=None):
        return ScannerInfo(
            id="test/scan",
            name=name,
            category="test",
            description="test",
            entry=Path("."),
            cves=cves,
        )

    def test_crash_pattern_signal(self):
        sc = self._scanner(cves="CVE-2026-99999")
        item = {"vulnerable": True, "reason": "PHP crash pattern detected in probe response: Fatal error:"}
        result = _classify_vulnerability(sc, item)
        self.assertIn("PHP Crash Pattern (Differential)", result)

    def test_connection_drop_signal(self):
        sc = self._scanner()
        item = {"vulnerable": True, "reason": "probe caused the server to drop the connection: connection reset"}
        result = _classify_vulnerability(sc, item)
        self.assertIn("Connection Drop (Worker Crash)", result)

    def test_timing_signal(self):
        sc = self._scanner()
        item = {"vulnerable": True, "reason": "probe took 15.0s vs control 1.0s (15x slower) with HTTP 500, indicating resource exhaustion"}
        result = _classify_vulnerability(sc, item)
        self.assertIn("Timing-Based Resource Exhaustion", result)

    def test_body_differential_signal(self):
        sc = self._scanner()
        item = {"vulnerable": True, "reason": "probe response body (100 bytes) is drastically smaller than control (5000 bytes)"}
        result = _classify_vulnerability(sc, item)
        self.assertIn("Response Body Differential", result)

    def test_existing_oom_signal_unchanged(self):
        sc = self._scanner(cves="CVE-2026-109618")
        item = {"vulnerable": True, "reason": "memory exhausted in Unknown"}
        result = _classify_vulnerability(sc, item)
        self.assertIn("In-band PHP OOM", result)

    def test_existing_empty_500_unchanged(self):
        sc = self._scanner()
        item = {"vulnerable": True, "reason": "empty body response", "status_code": 500}
        result = _classify_vulnerability(sc, item)
        self.assertIn("Differential Empty HTTP 500", result)

    def test_existing_fpm_crash_unchanged(self):
        sc = self._scanner()
        item = {"vulnerable": True, "reason": "worker died mid-request", "status_code": 502}
        result = _classify_vulnerability(sc, item)
        self.assertIn("PHP-FPM Worker Crash (HTTP 502)", result)

    def test_version_banner_still_works(self):
        sc = self._scanner()
        item = {"vulnerable": True, "reason": "unpatched release: PHP/8.3.20"}
        result = _classify_vulnerability(sc, item)
        self.assertIn("Unpatched PHP Version Banner", result)


if __name__ == "__main__":
    unittest.main()
