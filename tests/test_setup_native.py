"""Full setup reports all independent component failures in one pass."""

import unittest
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


if __name__ == "__main__":
    unittest.main()
