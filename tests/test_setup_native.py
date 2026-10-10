"""Full setup reports all independent component failures in one pass."""

import re
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import setup_native


class FullSetupTests(unittest.TestCase):
    def test_full_setup_continues_after_one_component_fails(self):
        failing = Mock(side_effect=RuntimeError("missing toolchain"))
        succeeding = Mock()
        with patch.object(setup_native, "COMPONENTS", {"first": failing, "second": succeeding}), patch.object(setup_native.sys, "argv", ["setup_native.py", "all"]):
            with self.assertRaisesRegex(SystemExit, "Scanner setup failed: first"):
                setup_native.main()
        failing.assert_called_once()
        succeeding.assert_called_once()


class TextEncodingTests(unittest.TestCase):
    def test_file_reads_name_utf8(self):
        # Windows defaults to a legacy code page; scanner package files contain UTF-8 text.
        root = Path(__file__).resolve().parent.parent
        unsafe = [f"{path.relative_to(root)}:{number}" for path in sorted([*root.glob("app/*.py"), *root.glob("scripts/*.py")]) for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1) if re.search(r"\.read_text\((?![^)]*encoding=)|\.open\((?![^)]*(encoding=|\"rb\"|'rb'))", line) and "urlopen" not in line and "tarfile.open" not in line and "opener.open" not in line]
        self.assertEqual(unsafe, [])


if __name__ == "__main__":
    unittest.main()
