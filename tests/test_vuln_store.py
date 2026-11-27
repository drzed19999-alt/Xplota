import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import vuln_store


class VulnStoreTests(unittest.TestCase):
    def test_save_load_dedup_and_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_file = Path(tmp) / "vulnerable_sites.json"
            with patch.object(vuln_store, "VULN_FILE", tmp_file):
                self.assertEqual(vuln_store.load_vulnerable_sites(), [])

                first = vuln_store.save_vulnerable_site({
                    "target": "https://example.com/index.php",
                    "vuln_type": "php2shell",
                    "reason": "CVE-2026-109618",
                    "php_version": "PHP/8.1",
                    "source": "ct",
                })
                self.assertEqual(first["domain"], "example.com")

                vuln_store.save_vulnerable_site({
                    "target": "https://second.org",
                    "vuln_type": "php2shell",
                    "reason": "body differential",
                    "source": "generate",
                })

                # Re-saving example.com should deduplicate and move it to the top
                vuln_store.save_vulnerable_site({
                    "target": "http://example.com/",
                    "vuln_type": "php2shell",
                    "reason": "updated",
                    "source": "ct",
                })

                loaded = vuln_store.load_vulnerable_sites()
                self.assertEqual(len(loaded), 2)
                self.assertEqual(loaded[0]["domain"], "example.com")
                self.assertEqual(loaded[0]["reason"], "updated")
                self.assertEqual(loaded[1]["domain"], "second.org")

                vuln_store.clear_vulnerable_sites()
                self.assertEqual(vuln_store.load_vulnerable_sites(), [])


if __name__ == "__main__":
    unittest.main()
