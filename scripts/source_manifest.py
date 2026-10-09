"""Record the exact local upstream revisions used by the scanner workstation."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = json.loads((ROOT / "config" / "scanners.json").read_text())


def git_value(path: Path, *args: str) -> str | None:
    result = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True, timeout=15, shell=False)
    return result.stdout.strip() if result.returncode == 0 else None


def entry(item: dict, path_key: str) -> dict:
    relative = item[path_key]
    path = ROOT / relative
    present = (path / ".git").exists()
    licenses = sorted(file.name for file in path.iterdir() if file.is_file() and file.name.lower().startswith(("license", "copying"))) if present else []
    return {
        "purpose": item["label"],
        "path": relative,
        "upstream": item["upstream"],
        "present": present,
        "commit": git_value(path, "rev-parse", "HEAD") if present else None,
        "working_tree_changed": bool(git_value(path, "status", "--porcelain")) if present else None,
        "license_files": licenses,
    }


def main() -> None:
    indexed: dict[str, dict] = {}
    for item in CONFIG["scanners"]:
        if item["source"] not in indexed:
            indexed[item["source"]] = entry(item, "source")
    for item in CONFIG["support_repositories"]:
        if item["path"] not in indexed:
            indexed[item["path"]] = entry(item, "path")
    entries = list(indexed.values())
    result = {"created_at": datetime.now(timezone.utc).isoformat(), "repositories": entries}
    destination = ROOT / "data" / "source-manifest.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Recorded {len(entries)} repositories in {destination}")


if __name__ == "__main__":
    main()
