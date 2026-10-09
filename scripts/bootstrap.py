"""Prepare the ProjectN app on macOS or Windows from a fresh Git clone."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def run(*args: str) -> None:
    print("Running:", " ".join(args), flush=True)
    executable = shutil.which(args[0]) or args[0]
    subprocess.run((executable, *args[1:]), cwd=ROOT, check=True, shell=False)


def require(command: str, reason: str) -> None:
    if not shutil.which(command):
        raise RuntimeError(f"{command} is required for {reason}. Install it, then rerun this command.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-scanners", action="store_true", help="Also download and build all scanner runtimes (large; needs native toolchains)")
    options = parser.parse_args()

    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or newer is required.")
    require("node", "the dashboard build")
    require("npm", "the dashboard build")
    node_version = subprocess.run([shutil.which("node") or "node", "--version"], capture_output=True, text=True, check=True).stdout.strip()
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", node_version)
    if not match or (int(match.group(1)), int(match.group(2))) < (22, 19):
        raise RuntimeError(f"Node.js 22.19 or newer is required; found {node_version or 'unknown'}")
    if options.with_scanners:
        for command, reason in (("git", "scanner source cloning"), ("go", "Go scanner builds"), ("java", "the application scanner"), ("ruby", "the technology profiler"), ("gem", "Ruby dependencies"), ("uv", "Python scanner runtimes")):
            require(command, reason)
        if os.name == "nt":
            override = os.getenv("PROJECTN_SCANNER_PORTS")
            if not shutil.which("nmap") and not (override and Path(override).expanduser().is_file()):
                raise RuntimeError("Install the official Windows Nmap release and add nmap.exe to PATH, or set PROJECTN_SCANNER_PORTS to its executable before --with-scanners. Windows source compilation additionally needs nmap-mswin32-aux and Visual Studio.")
        else:
            for command in ("make", "cc"):
                require(command, "the native Nmap build")

    if not PYTHON.is_file():
        print("Creating local Python environment", flush=True)
        venv.create(ROOT / ".venv", with_pip=True)
    run(str(PYTHON), "-m", "pip", "install", "-e", str(ROOT))
    run("npm", "ci", "--prefix", str(ROOT / "web"))
    run("npm", "run", "build", "--prefix", str(ROOT / "web"))

    if options.with_scanners:
        run(str(PYTHON), str(ROOT / "scripts/clone_sources.py"))
        run(str(PYTHON), str(ROOT / "scripts/setup_native.py"), "all")
        run(str(PYTHON), str(ROOT / "scripts/doctor.py"), "--strict")
    print("\nProjectN is ready to start:", flush=True)
    print(f"  {PYTHON} {ROOT / 'scripts/run_local.py'}", flush=True)
    if not options.with_scanners:
        print("Scanner runtimes are optional for the app setup. Install them with --with-scanners when their native toolchains are ready.", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Setup failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
