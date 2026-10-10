"""Check whether dependencies declared in package.json/requirements.txt actually exist on their registry.

AI coding assistants sometimes invent plausible-looking package names that are not published anywhere
(https://arxiv.org/abs/2406.10279 measured this in roughly a fifth of AI-generated code). A name that does
not exist yet is not itself a compromise, but it is a live supply-chain risk: anyone can register that exact
name later with malicious code, and the next `npm install`/`pip install` in this project runs it automatically
("slopsquatting"). This makes only read-only existence lookups against the public registry (npmjs.org,
pypi.org) -- the same kind of external call app/core.py already makes via the dependencies scanner (OSV) -- and
never installs, downloads, or executes anything from either registry.
"""

from __future__ import annotations

import fnmatch
import json
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

from app.core import finding, gap

CONFIG = json.loads((Path(__file__).resolve().parent.parent / "config" / "slopsquat_probe.json").read_text(encoding="utf-8"))
REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
# Vendor/build directories to skip when repo is not a git checkout; a git checkout is scoped by
# git ls-files instead, which is what already keeps the other code scanners (gitleaks, semgrep,
# OSV) out of node_modules and ProjectN's own git-ignored tools/.
SKIP_DIR_NAMES = frozenset({"node_modules", ".git", "vendor", "dist", "build", ".venv", "venv", "__pycache__", "tools"})


def tracked_files(repo: Path) -> list[Path] | None:
    """Git-tracked files under `repo`, or None if it is not a git checkout (caller falls back to a walk)."""
    if not (repo / ".git").exists():
        return None
    try:
        result = subprocess.run(["git", "-C", str(repo), "ls-files"], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return [repo / line for line in result.stdout.splitlines() if line]


def candidate_files(repo: Path, name_pattern: str) -> list[Path]:
    tracked = tracked_files(repo)
    if tracked is not None:
        return [path for path in tracked if fnmatch.fnmatch(path.name, name_pattern)]
    return [path for path in repo.rglob(name_pattern) if not SKIP_DIR_NAMES & set(path.relative_to(repo).parts)]


def npm_dependency_names(repo: Path) -> set[str]:
    names: set[str] = set()
    for manifest in candidate_files(repo, "package.json"):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        for key in ("dependencies", "devDependencies"):
            if isinstance(data.get(key), dict):
                names.update(name for name in data[key] if isinstance(name, str))
    return names


def python_dependency_names(repo: Path) -> set[str]:
    names: set[str] = set()
    for manifest in candidate_files(repo, "requirements*.txt"):
        try:
            lines = manifest.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = REQUIREMENT_NAME_RE.match(line)
            if match:
                names.add(match.group(1))
    return names


def registry_exists(url: str, timeout: float) -> bool | None:
    """True/False when the registry gives a clear answer; None when the lookup itself was inconclusive."""
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout) as response:
            return response.status == 200
    except urllib.error.HTTPError as exc:
        with exc:
            return False if exc.code == 404 else None
    except (OSError, ValueError):
        return None


def inspect_slopsquat(repo: Path, cancel=None) -> tuple[list[dict], dict, list[dict]]:
    label = "Dependency name verification"
    limit = CONFIG["max_packages"]
    npm_names = sorted(npm_dependency_names(repo))
    py_names = sorted(python_dependency_names(repo))
    candidates = [(name, "npm", f"https://registry.npmjs.org/{quote(name, safe='')}") for name in npm_names]
    candidates += [(name, "PyPI", f"https://pypi.org/pypi/{quote(name, safe='')}/json") for name in py_names]
    truncated = len(candidates) > limit
    candidates = candidates[:limit]

    if not candidates:
        return [], {"id": "slopsquat", "label": label, "state": "skipped", "summary": "No package.json or requirements.txt dependencies were found"}, [
            gap("slopsquat_not_applicable", "No npm or PyPI dependency declarations were found to verify.", "This check only applies when the source includes a package.json or requirements.txt.", "slopsquat")
        ]

    missing, inconclusive, checked, interrupted = [], 0, 0, False
    for name, registry, url in candidates:
        if cancel is not None and cancel.is_set():
            interrupted = True
            break
        checked += 1
        exists = registry_exists(url, CONFIG["timeout_seconds"])
        if exists is False:
            missing.append({"name": name, "registry": registry})
        elif exists is None:
            inconclusive += 1

    found = [
        finding(
            "slopsquat",
            f"Package '{item['name']}' does not exist on {item['registry']}",
            "medium",
            item["registry"],
            f"{item['registry']} has no published package named '{item['name']}', which this project declares as a dependency. "
            "This is not proof of compromise -- the name may simply be a typo or not published yet -- but an unpublished name "
            "is a live supply-chain risk: anyone can register it later with malicious code, and it would run automatically "
            "the next time dependencies are installed.",
            "Confirm this package name is correct. If an AI assistant invented it, remove it and use the real package name; "
            "if it is intentional and not yet published, pin to a specific trusted source instead of the public registry.",
            "slopsquat:nonexistent-package",
            "observed",
        )
        for item in missing
    ]

    issues = []
    if truncated:
        issues.append(gap("slopsquat_truncated", f"Only the first {limit} dependency name(s) were checked.", "Increase max_packages in config/slopsquat_probe.json to check every dependency in a larger project.", "slopsquat"))
    if inconclusive:
        issues.append(gap("slopsquat_lookup_inconclusive", f"{inconclusive} of {checked} registry lookup(s) did not return a clear answer (network issue or rate limit).", "Rerun the scan; a package in this group was neither confirmed to exist nor confirmed missing.", "slopsquat"))
    if interrupted:
        issues.append(gap("scan_cancelled", f"Dependency name verification was stopped by the user after {checked} of {len(candidates)} package(s).", "Start a new scan of the same source to check the remaining package names.", "slopsquat"))

    summary = f"{len(missing)} of {checked} dependency name(s) not found on their registry" if checked else "No dependency names could be checked"
    state = "partial" if interrupted else "completed" if checked else "failed"
    details = {"checked": checked, "missing": [item["name"] for item in missing], "inconclusive": inconclusive}
    return found, {"id": "slopsquat", "label": label, "state": state, "summary": summary, "details": details}, issues
