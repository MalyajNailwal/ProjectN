"""Clone pinned upstream source checkouts into purpose-named local folders."""

from __future__ import annotations

import json
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = json.loads((ROOT / "config/scanners.json").read_text())
LOCK = json.loads((ROOT / "config/source-lock.json").read_text())["repositories"]


def git(*args: str) -> subprocess.CompletedProcess[str]:
    options = ["-c", "core.longpaths=true"] if os.name == "nt" else []
    return subprocess.run(["git", *options, *args], capture_output=True, text=True, check=False)


def repositories() -> list[dict[str, str]]:
    indexed = {item["source"]: {"label": item["label"], "path": item["source"], "upstream": item["upstream"]} for item in CONFIG["scanners"]}
    for item in CONFIG["support_repositories"]:
        indexed.setdefault(item["path"], item)
    if set(indexed) != set(LOCK):
        raise ValueError("Source lock and scanner configuration paths differ; update both before cloning")
    if any(not re.fullmatch(r"[0-9a-f]{40}", commit) for commit in LOCK.values()):
        raise ValueError("Source lock contains an invalid commit")
    return list(indexed.values())


def main() -> int:
    parser = argparse.ArgumentParser(description="Clone or verify pinned scanner sources")
    parser.add_argument("--verify", action="store_true", help="Check local sources without cloning or changing files")
    parser.add_argument("--path", action="append", choices=sorted(LOCK), help="Limit cloning or verification to this configured source path; may be repeated")
    args = parser.parse_args()
    entries = [item for item in repositories() if not args.path or item["path"] in args.path]
    failures = []
    for item in entries:
        destination = ROOT / item["path"]
        expected = LOCK[item["path"]]
        if not destination.exists() and not args.verify:
            destination.parent.mkdir(parents=True, exist_ok=True)
            print(f"CLONING {item['label']}: {item['path']}", flush=True)
            result = git("clone", "--depth", "1", "--single-branch", "--no-recurse-submodules", "--", item["upstream"], str(destination))
            if result.returncode:
                print(result.stderr.strip(), file=sys.stderr)
                failures.append(item["label"])
                continue
            current = git("-C", str(destination), "rev-parse", "HEAD")
            if current.returncode or current.stdout.strip() != expected:
                fetched = git("-C", str(destination), "fetch", "--depth", "1", "origin", expected)
                checked = git("-C", str(destination), "checkout", "--detach", expected) if fetched.returncode == 0 else fetched
                if checked.returncode:
                    print(checked.stderr.strip(), file=sys.stderr)
                    failures.append(item["label"])
                    continue
        if not (destination / ".git").exists():
            print(f"MISSING {item['label']}: {item['path']}", file=sys.stderr)
            failures.append(item["label"])
            continue
        current = git("-C", str(destination), "rev-parse", "HEAD")
        remote = git("-C", str(destination), "remote", "get-url", "origin")
        if current.returncode or current.stdout.strip() != expected or remote.returncode or remote.stdout.strip() != item["upstream"]:
            print(f"MISMATCH {item['label']}: {item['path']} (expected {expected}); inspect local checkout", file=sys.stderr)
            failures.append(item["label"])
            continue
        print(f"READY   {item['label']}: {item['path']} @ {expected[:12]}", flush=True)
    if failures:
        print("Failed: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("All source repositories match the pinned revisions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
