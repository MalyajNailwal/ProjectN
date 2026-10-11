"""Catches exactly the drift this project hit: new scan stages shipped in app/core.py without a matching
README update. Fails the moment someone adds a stage label here without mentioning it in the README, instead
of relying on a person noticing later."""

import re
import unittest

from app.core import ROOT

# Mechanism steps, not scan capabilities -- they have no "runs when"/evidence semantics of their own and do
# not belong in a capability table. Add to this list only for a genuinely non-capability step; anything that
# produces its own findings or coverage gaps belongs in the README instead.
NOT_A_CAPABILITY = {"Clone public repository"}


class DocsInSyncTests(unittest.TestCase):
    def test_every_stage_label_in_execute_scan_is_mentioned_in_the_readme(self):
        core_source = (ROOT / "app/core.py").read_text(encoding="utf-8")
        labels = set(re.findall(r'"label":\s*"([^"]+)"', core_source)) - NOT_A_CAPABILITY
        self.assertTrue(labels, "no stage labels found in app/core.py -- the pattern this test looks for may have changed")

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        missing = sorted(label for label in labels if label not in readme)
        self.assertEqual(missing, [], "Stage label(s) in app/core.py not mentioned anywhere in README.md -- add a row for each to the capability table(s): " + ", ".join(missing))


if __name__ == "__main__":
    unittest.main()
