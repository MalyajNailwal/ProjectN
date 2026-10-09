"""Keep the distributable source lock aligned with scanner configuration."""

import unittest
from unittest.mock import patch

from scripts import clone_sources


class SourceLockTests(unittest.TestCase):
    def test_every_configured_repository_is_pinned(self):
        entries = clone_sources.repositories()
        self.assertEqual(len(entries), len(clone_sources.LOCK))
        self.assertEqual({item["path"] for item in entries}, set(clone_sources.LOCK))

    def test_configuration_drift_is_rejected(self):
        with patch.object(clone_sources, "LOCK", {}):
            with self.assertRaisesRegex(ValueError, "paths differ"):
                clone_sources.repositories()


if __name__ == "__main__":
    unittest.main()
