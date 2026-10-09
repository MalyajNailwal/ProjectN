"""Clone pinned upstream source checkouts into purpose-named local folders."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = json.loads((ROOT / "config/scanners.json").read_text())


def main() -> int:
    entries = [{"label": item["label"], "path": item["source"], "upstream": item["upstream"]} for item in CONFIG["scanners"]]
    entries += CONFIG["support_repositories"]
    failures = []
    for item in entries:
        destination = ROOT / item["path"]
        if (destination / ".git").exists():
            print(f"EXISTS  {item['label']}: {destination.relative_to(ROOT)}", flush=True)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        print(f"CLONING {item['label']}: {destination.relative_to(ROOT)}", flush=True)
        result = subprocess.run(["git", "clone", "--depth", "1", "--single-branch", "--no-recurse-submodules", "--", item["upstream"], str(destination)], check=False)
        if result.returncode:
            failures.append(item["label"])
    if failures:
        print("Failed: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("All source repositories are present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
