"""Run ProjectN's tests and local startup check using its bootstrapped environment."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-stage", action="append", default=[], help="Require the named scanner in the fixture scan")
    parser.add_argument("--ui", action="store_true", help="Launch the fixture scan from the dashboard in a real browser")
    options = parser.parse_args()
    if not PYTHON.is_file():
        raise RuntimeError("Local Python environment is missing; run scripts/bootstrap.py first")
    subprocess.run([str(PYTHON), "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT, check=True)
    smoke = [str(PYTHON), str(ROOT / "scripts/smoke_local.py")]
    for stage in options.require_stage:
        smoke.extend(("--require-stage", stage))
    if options.ui:
        smoke.append("--ui")
    subprocess.run(smoke, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
