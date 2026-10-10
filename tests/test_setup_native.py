"""Full setup reports all independent component failures in one pass."""

import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import setup_native


class FullSetupTests(unittest.TestCase):
    def run_all(self, components: dict, disk_gb: dict | None = None, free_gb: float = 100) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(setup_native.os.environ), patch.object(setup_native, "CACHE", Path(temp) / "cache"), patch.object(setup_native, "COMPONENTS", components), patch.object(setup_native, "DISK_GB", disk_gb or {}), patch.object(setup_native.shutil, "disk_usage", return_value=SimpleNamespace(free=free_gb * 1024**3)), patch.object(setup_native.sys, "argv", ["setup_native.py", "all"]):
            setup_native.main()

    def test_full_setup_continues_after_one_component_fails(self):
        failing = Mock(side_effect=RuntimeError("missing toolchain"))
        succeeding = Mock()
        with self.assertRaisesRegex(SystemExit, "Scanner setup failed: first"):
            self.run_all({"first": failing, "second": succeeding})
        failing.assert_called_once()
        succeeding.assert_called_once()

    def test_low_disk_skips_only_the_component_that_does_not_fit(self):
        large, small = Mock(), Mock()
        with self.assertRaisesRegex(SystemExit, "Scanner setup failed: large"):
            self.run_all({"large": large, "small": small}, {"large": 3.0, "small": 0.5}, free_gb=1.0)
        large.assert_not_called()
        small.assert_called_once()

    def test_every_pinned_source_is_cloned_by_one_setup_component(self):
        owned = [path for name in setup_native.COMPONENTS for path in setup_native.component_sources(name)]
        self.assertEqual(sorted(owned), sorted(setup_native.LOCK))


class TextEncodingTests(unittest.TestCase):
    def test_file_reads_name_utf8(self):
        # Windows defaults to a legacy code page; scanner package files contain UTF-8 text.
        root = Path(__file__).resolve().parent.parent
        unsafe = [f"{path.relative_to(root)}:{number}" for path in sorted([*root.glob("app/*.py"), *root.glob("scripts/*.py")]) for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1) if re.search(r"\.read_text\((?![^)]*encoding=)|\.open\((?![^)]*(encoding=|\"rb\"|'rb'))", line) and "urlopen" not in line and "tarfile.open" not in line and "opener.open" not in line]
        self.assertEqual(unsafe, [])


if __name__ == "__main__":
    unittest.main()
