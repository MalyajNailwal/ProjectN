"""run()'s retry loop: _attempt is the only seam that touches a real process, so it is the only thing
mocked here -- no real Node.js, Chromium, Playwright install, or network involved. run() imports
playwright.sync_api lazily (inside the function, so this module stays importable without Playwright
installed, matching app/browser_probe.py's own lazy import of the same package); a fake module is
injected into sys.modules so that import resolves to a mock instead of the real, uninstalled package."""

import sys
import tempfile
import types
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

from app.performance_probe import run


class PerformanceRetryTests(unittest.TestCase):
    def setUp(self):
        mock_sync_playwright = MagicMock()
        mock_sync_playwright.return_value.__enter__.return_value.chromium.executable_path = __file__  # any real file
        fake_sync_api = types.ModuleType("playwright.sync_api")
        fake_sync_api.sync_playwright = mock_sync_playwright
        fake_playwright = types.ModuleType("playwright")
        fake_playwright.sync_api = fake_sync_api
        modules_patch = patch.dict(sys.modules, {"playwright": fake_playwright, "playwright.sync_api": fake_sync_api})
        modules_patch.start()
        self.addCleanup(modules_patch.stop)
        which_patch = patch("app.performance_probe.shutil.which", return_value="/usr/bin/node")
        which_patch.start()
        self.addCleanup(which_patch.stop)

    def test_retries_once_after_a_fast_failure_then_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            calls = []

            def fake_attempt(command, cwd, env, timeout):
                calls.append(1)
                if len(calls) == 1:
                    return CompletedProcess(args=command, returncode=1, stderr="blocked (Status code: 403)")
                output.write_text('{"runtimeError": null}')
                return CompletedProcess(args=command, returncode=0)

            with patch("app.performance_probe._attempt", side_effect=fake_attempt):
                run("https://example.test", output, Path(tmp), {"categories": ["performance"], "transient_retry_attempts": 1, "transient_retry_wait_seconds": 0})
            self.assertEqual(len(calls), 2)
            self.assertIn("runtimeError", output.read_text())

    def test_gives_up_after_exhausting_retries_and_writes_a_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            calls = []

            def fake_attempt(command, cwd, env, timeout):
                calls.append(1)
                return CompletedProcess(args=command, returncode=1, stderr="still blocked")

            with patch("app.performance_probe._attempt", side_effect=fake_attempt):
                with self.assertRaises(SystemExit):
                    run("https://example.test", output, Path(tmp), {"categories": ["performance"], "transient_retry_attempts": 1, "transient_retry_wait_seconds": 0})
            self.assertEqual(len(calls), 2)  # the initial attempt plus exactly one retry, then it gives up
            self.assertIn("error", output.read_text())

    def test_succeeds_on_the_first_attempt_without_retrying(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            calls = []

            def fake_attempt(command, cwd, env, timeout):
                calls.append(1)
                output.write_text('{"runtimeError": null}')
                return CompletedProcess(args=command, returncode=0)

            with patch("app.performance_probe._attempt", side_effect=fake_attempt):
                run("https://example.test", output, Path(tmp), {"categories": ["performance"], "transient_retry_attempts": 1, "transient_retry_wait_seconds": 0})
            self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
