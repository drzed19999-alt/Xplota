import contextlib
import json
import tempfile
import unittest
from pathlib import Path

from core.scanner_runner import discover_scanners, get_scanner, run_scanner


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
        self.assertTrue(sc.options["url"])
        self.assertTrue(sc.options["list"])
        self.assertTrue(sc.options["output"])
        self.assertTrue(sc.options["sapi"])

    async def test_run_custom_scanner_streams_logs_and_results(self):
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
                'with open(args.output, "w") as f:\n'
                '    json.dump({"results": [{"host": args.url, "vulnerable": True, "reason": "matched"}]}, f)\n',
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
            self.assertIn("log", types_seen)
            self.assertIn("result", types_seen)
            self.assertEqual(events[-1]["type"], "done")
            self.assertEqual(events[-1]["count"], 1)
            res = next(e for e in events if e["type"] == "result")
            self.assertEqual(res["target"], "https://example.com")
            self.assertTrue(res["vulnerable"])
            self.assertEqual(res["reason"], "matched")


if __name__ == "__main__":
    unittest.main()
