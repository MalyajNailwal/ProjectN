"""Windows uses an installed Nmap runtime while retaining its local source checkout."""

import unittest
from unittest.mock import patch

from app import core
from scripts import setup_native


class WindowsNmapTests(unittest.TestCase):
    def test_installed_nmap_is_resolved_on_windows(self):
        spec = next(item for item in core.specs() if item["id"] == "ports")
        with patch.dict(core.os.environ, {"PROJECTN_SCANNER_PORTS": ""}), patch.object(core.os, "name", "nt"), patch.object(core.shutil, "which", return_value="C:\\Nmap\\nmap.exe"):
            self.assertEqual(core.executable_for(spec), "C:\\Nmap\\nmap.exe")

    def test_windows_setup_accepts_configured_nmap_runtime(self):
        with patch.dict(setup_native.os.environ, {"PROJECTN_SCANNER_PORTS": ""}), patch.object(setup_native.os, "name", "nt"), patch.object(setup_native.shutil, "which", return_value="C:\\Nmap\\nmap.exe"):
            setup_native.build_nmap()


if __name__ == "__main__":
    unittest.main()
