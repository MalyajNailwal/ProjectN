"""Clone, verify, or deliberately update pinned upstream source checkouts in purpose-named local folders."""

from __future__ import annotations

import json
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK_PATH = ROOT / "config/source-lock.json"
CONFIG = json.loads((ROOT / "config/scanners.json").read_text(encoding="utf-8"))
LOCK = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["repositories"]


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


def update(entries: list[dict[str, str]], apply: bool, lock_path: Path = LOCK_PATH) -> int:
    """Compare pins with each upstream default branch; with apply, move pins and clean local checkouts."""
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    changed, failures = [], []
    for item in entries:
        pinned = lock["repositories"][item["path"]]
        remote = git("ls-remote", "--", item["upstream"], "HEAD")
        latest = remote.stdout.split()[0] if remote.returncode == 0 and remote.stdout.strip() else ""
        if not re.fullmatch(r"[0-9a-f]{40}", latest):
            print(f"UNKNOWN {item['label']}: could not read the upstream default branch", file=sys.stderr)
            failures.append(item["label"])
            continue
        if latest == pinned:
            print(f"CURRENT {item['label']} @ {pinned[:12]}")
            continue
        print(f"NEWER   {item['label']}: {pinned[:12]} -> {latest[:12]}", flush=True)
        if not apply:
            continue
        destination = ROOT / item["path"]
        if (destination / ".git").exists():
            status = git("-C", str(destination), "status", "--porcelain", "--untracked-files=no")
            if status.returncode or status.stdout.strip():
                print(f"SKIPPED {item['label']}: the local checkout has changes; keep or discard them first", file=sys.stderr)
                failures.append(item["label"])
                continue
            fetched = git("-C", str(destination), "fetch", "--depth", "1", "origin", latest)
            checked = git("-C", str(destination), "checkout", "--detach", latest) if fetched.returncode == 0 else fetched
            if checked.returncode:
                print(f"FAILED  {item['label']}: {checked.stderr.strip()}", file=sys.stderr)
                failures.append(item["label"])
                continue
        lock["repositories"][item["path"]] = latest
        changed.append(item["path"])
    if changed:
        lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        components = sorted({word for spec in CONFIG["scanners"] + CONFIG["support_repositories"] if {spec.get("source"), spec.get("rules_source"), spec.get("path")} & set(changed) for word in spec.get("setup", "").split()})
        print(f"\nUpdated {len(changed)} pin(s) in config/source-lock.json.")
        print(f"Next: python scripts/setup_native.py {' '.join(components) or 'all'}; python scripts/doctor.py --strict; python -m unittest discover -s tests; python scripts/smoke_local.py. Commit the lock file only after these pass.")
    elif not apply:
        print("\nRun with --update to move the newer pins; add --path to choose specific sources.")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Clone or verify pinned scanner sources")
    parser.add_argument("--verify", action="store_true", help="Check local sources without cloning or changing files")
    parser.add_argument("--path", action="append", choices=sorted(LOCK), help="Limit cloning or verification to this configured source path; may be repeated")
    parser.add_argument("--upstream", action="store_true", help="Show which pins have a newer upstream commit (reads the network, changes nothing)")
    parser.add_argument("--update", action="store_true", help="Move newer pins and clean local checkouts to the upstream default-branch commit")
    args = parser.parse_args()
    entries = [item for item in repositories() if not args.path or item["path"] in args.path]
    if args.upstream or args.update:
        return update(entries, args.update)
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
