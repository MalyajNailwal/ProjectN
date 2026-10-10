"""Stopping a scan terminates scanner child processes and keeps an honest partial report."""

import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.core import ScanCancelled, execute_scan, run_tool

# The scanner stand-in starts a grandchild that appends to a file until it is killed.
GRANDCHILD = "import sys, time\nwhile True:\n    open(sys.argv[1], 'a').write('x')\n    time.sleep(0.05)\n"
PARENT = "import subprocess, sys, time\nsubprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]])\ntime.sleep(60)\n"


class CancelTests(unittest.TestCase):
    def test_cancel_stops_the_whole_scanner_process_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            heartbeat = Path(temp) / "heartbeat"
            cancel = threading.Event()
            threading.Timer(1.5, cancel.set).start()
            started = time.monotonic()
            with self.assertRaises(ScanCancelled):
                run_tool([sys.executable, "-c", PARENT, GRANDCHILD, str(heartbeat)], 30, cancel)
            self.assertLess(time.monotonic() - started, 10)
            time.sleep(0.5)
            size = heartbeat.stat().st_size
            time.sleep(0.5)
            self.assertGreater(size, 0)
            self.assertEqual(heartbeat.stat().st_size, size, "grandchild process kept running after cancel")

    def test_cancelled_scan_reports_unfinished_steps(self):
        cancel = threading.Event()
        cancel.set()
        with tempfile.TemporaryDirectory() as temp:
            report = execute_scan({"local_path": temp, "profile": "standard"}, lambda *_: None, cancel)
        self.assertTrue(report["cancelled"])
        self.assertTrue(report["steps"])
        self.assertEqual({step["state"] for step in report["steps"]}, {"not_run"})
        self.assertIn("scan_cancelled", {item["code"] for item in report["limitations"]})
        unassessed = [item for item in report["limitations"] if item["code"] == "capability_not_assessed"]
        self.assertTrue(unassessed)
        self.assertTrue(all("stopped" in item["resolution"] for item in unassessed), "stopped steps must not be reported as missing setup")
        self.assertEqual(report["findings"], [])


if __name__ == "__main__":
    unittest.main()
