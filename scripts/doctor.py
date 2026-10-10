"""Show local scanner readiness and return a failure for incomplete full setups."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.core import readiness, specs  # noqa: E402

# Toolchain used by `bootstrap.py --with-scanners`; scanner readiness below is what scans actually depend on.
PREREQUISITES = [
    ("git", "--version", "scanner source cloning"),
    ("node", "--version", "dashboard build, accessibility and performance runtimes"),
    ("go", "version", "Go scanner and callback server builds"),
    ("java", "-version", "application scanner build and runtime (Java 17+)"),
    ("ruby", "--version", "technology profiler"),
    ("uv", "--version", "Python scanner runtimes"),
    *([("nmap", "--version", "port scanning with the official Windows release")] if os.name == "nt" else [("make", "--version", "Nmap source build"), ("cc", "--version", "Nmap source build")]),
]
INSTALL_HINT = (
    "winget install Git.Git OpenJS.NodeJS.LTS GoLang.Go EclipseAdoptium.Temurin.17.JDK RubyInstallerTeam.RubyWithDevKit.3.3 astral-sh.uv Insecure.Nmap"
    if os.name == "nt"
    else "xcode-select --install; brew install node go ruby uv; brew install --cask temurin@17"
)


def prerequisite(command: str, flag: str) -> str | None:
    path = shutil.which(command)
    if not path:
        return None
    try:
        result = subprocess.run([path, flag], capture_output=True, text=True, timeout=15, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return "found, but did not report a version"
    lines = (result.stdout or result.stderr).strip().splitlines()
    return lines[0] if lines else "found"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="Exit with an error if any configured scanner is not ready")
    options = parser.parse_args()
    print("Prerequisites for full scanner setup")
    missing = []
    for command, flag, purpose in PREREQUISITES:
        version = prerequisite(command, flag)
        print(f"{'FOUND  ' if version else 'MISSING'} {command:<5} {version or ''}  ({purpose})")
        if not version:
            missing.append(command)
    if missing:
        print(f"        Install: {INSTALL_HINT}")
    print("\nScanner capabilities")
    states = [readiness(spec) for spec in specs()]
    for state in states:
        print(f"{'READY  ' if state['ready'] else 'MISSING'} {state['label']}")
        if not state["ready"]:
            for reason in state["limitations"]:
                print(f"        {reason}")
            if state["resolution"]:
                print(f"        Next: {state['resolution']}")
    count = sum(state["ready"] for state in states)
    print(f"{count}/{len(states)} scanner capabilities ready")
    return 1 if options.strict and count != len(states) else 0


if __name__ == "__main__":
    raise SystemExit(main())
