import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.core import ROOT, compare_reports, execute_scan, scan_one, specs


class LocalSecretScannerIntegrationTests(unittest.TestCase):
    @unittest.skipUnless((ROOT / "tools/bin" / ("gitleaks.exe" if os.name == "nt" else "gitleaks")).is_file(), "local Gitleaks build unavailable")
    def test_git_history_finding_is_redacted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Fixture"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "fixture@example.test"], check=True)
            fake_key = "AKIA" + "QWERTYUIOPASDFGH"
            (repo / "config.txt").write_text(f"AWS_ACCESS_KEY_ID={fake_key}\n")
            subprocess.run(["git", "-C", str(repo), "add", "config.txt"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
            spec = next(item for item in specs() if item["id"] == "secrets")
            findings, stage, gaps = scan_one(spec, {"repo": str(repo), "url": "", "host": ""}, root)
            self.assertEqual(stage["state"], "completed", gaps)
            self.assertGreaterEqual(len(findings), 1)
            self.assertNotIn(fake_key, json.dumps({"findings": findings, "stage": stage, "gaps": gaps}))
            with patch("app.core.specs", return_value=[spec]):
                first = execute_scan({"local_path": str(repo), "profile": "standard"}, lambda _: None)
                second = execute_scan({"local_path": str(repo), "profile": "standard"}, lambda _: None)
            comparison = compare_reports(first, second)
            self.assertGreaterEqual(comparison["summary"]["still_present"], 1)
            self.assertEqual(comparison["summary"]["not_observed_on_rescan"], 0)
            self.assertNotIn(fake_key, json.dumps({"first": first, "second": second, "comparison": comparison}))


if __name__ == "__main__":
    unittest.main()
