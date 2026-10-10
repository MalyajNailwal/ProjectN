"""Keep the distributable source lock aligned with scanner configuration."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
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

    def test_windows_git_enables_long_paths_for_upstream_sources(self):
        with patch.object(clone_sources.os, "name", "nt"), patch.object(clone_sources.subprocess, "run") as command:
            clone_sources.git("clone", "https://example.invalid/source.git")
        self.assertEqual(command.call_args.args[0][:4], ["git", "-c", "core.longpaths=true", "clone"])

    def test_update_moves_clean_checkouts_and_refuses_local_changes(self):
        def git(cwd: Path, *args: str) -> str:
            return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            upstream = root / "upstream"
            upstream.mkdir()
            git(upstream, "init", "-q", "-b", "main")
            git(upstream, "config", "user.email", "fixture@example.test")
            git(upstream, "config", "user.name", "Fixture")
            (upstream / "file").write_text("one")
            git(upstream, "add", "file")
            git(upstream, "commit", "-qm", "one")
            first = git(upstream, "rev-parse", "HEAD")
            (upstream / "file").write_text("two")
            git(upstream, "commit", "-qam", "two")
            second = git(upstream, "rev-parse", "HEAD")
            for name in ("clean", "edited"):
                git(root, "clone", "-q", str(upstream), name)
                git(root / name, "checkout", "-q", "--detach", first)
            (root / "edited" / "file").write_text("local change")
            lock = root / "source-lock.json"
            lock.write_text(json.dumps({"schema_version": 1, "repositories": {"clean": first, "edited": first}}))
            entries = [{"label": name, "path": name, "upstream": str(upstream)} for name in ("clean", "edited")]
            with patch.object(clone_sources, "ROOT", root):
                status = clone_sources.update(entries, True, lock)
            self.assertEqual(status, 1)
            self.assertEqual(json.loads(lock.read_text())["repositories"], {"clean": second, "edited": first})
            self.assertEqual(git(root / "clean", "rev-parse", "HEAD"), second)
            self.assertEqual(git(root / "edited", "rev-parse", "HEAD"), first)


if __name__ == "__main__":
    unittest.main()
