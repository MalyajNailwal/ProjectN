"""Build or install local scanner runtimes beside their cloned sources on macOS/Windows."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCANNERS = json.loads((ROOT / "config/scanners.json").read_text())["scanners"]
APPLICATION = json.loads((ROOT / "config/application_scan.json").read_text())


def run(*command: str, cwd: Path = ROOT) -> None:
    print("Running:", " ".join(command), flush=True)
    executable = shutil.which(command[0]) or command[0]
    subprocess.run([executable, *command[1:]], cwd=cwd, check=True, shell=False)


def environment_python(name: str) -> Path:
    return ROOT / "tools/venvs" / name / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def environment_command(name: str, command: str) -> Path:
    return ROOT / "tools/venvs" / name / ("Scripts" if os.name == "nt" else "bin") / (command + (".exe" if os.name == "nt" else ""))


def build_go() -> None:
    binary_dir = ROOT / "tools/bin"
    binary_dir.mkdir(parents=True, exist_ok=True)
    for spec in SCANNERS:
        if target := spec.get("go_build_target"):
            output = binary_dir / (spec["executable"] + (".exe" if os.name == "nt" else ""))
            run("go", "build", "-p", "2", "-o", str(output), target, cwd=ROOT / spec["source"])


def build_callback_service() -> None:
    source = ROOT / "tools/web/callback-service/source"
    binary_dir = ROOT / "tools/bin"
    binary_dir.mkdir(parents=True, exist_ok=True)
    output = binary_dir / ("callback-service" + (".exe" if os.name == "nt" else ""))
    run("go", "build", "-p", "2", "-o", str(output), "./cmd/interactsh-server", cwd=source)


def install_semgrep() -> None:
    source = ROOT / "tools/code/static-analyzer/source/cli/pyproject.toml"
    version = tomllib.loads(source.read_text())["project"]["version"]
    run("uv", "venv", str(environment_python("static-analyzer").parents[1]))
    run("uv", "pip", "install", "--python", str(environment_python("static-analyzer")), f"semgrep=={version}")


def install_browser() -> None:
    version = (ROOT / "tools/web/browser-journeys/python-bindings/DRIVER_VERSION").read_text().strip()
    run("uv", "venv", str(environment_python("browser-journeys").parents[1]))
    run("uv", "pip", "install", "--python", str(environment_python("browser-journeys")), f"playwright=={version}")
    run(str(environment_command("browser-journeys", "playwright")), "install", "chromium")


def build_application() -> None:
    base = ROOT / "tools/web/application-scanner"
    wrapper = str(base / "core" / ("gradlew.bat" if os.name == "nt" else "gradlew"))
    run(wrapper, ":zap:distCore", "--no-daemon", cwd=base / "core")
    wrapper = str(base / "add-ons" / ("gradlew.bat" if os.name == "nt" else "gradlew"))
    tasks = [f":addOns:{name}:jarZapAddOn" for name in APPLICATION["addons"]]
    run(wrapper, *tasks, "--no-daemon", cwd=base / "add-ons")
    run(sys.executable, str(ROOT / "scripts/prepare_application_scanner.py"))


def install_accessibility() -> None:
    source = ROOT / "tools/quality/accessibility/source"
    version = json.loads((source / "package.json").read_text())["version"]
    with tempfile.TemporaryDirectory(prefix="projectn-axe-") as temp:
        run("npm", "pack", f"axe-core@{version}", "--pack-destination", temp, "--silent")
        archive = Path(temp) / f"axe-core-{version}.tgz"
        with tarfile.open(archive) as package:
            script = package.extractfile("package/axe.js")
            if script is None:
                raise RuntimeError("Matching axe package has no browser script")
            (source / "axe.js").write_bytes(script.read())


def install_performance() -> None:
    source = ROOT / "tools/quality/performance/source"
    version = json.loads((source / "package.json").read_text())["version"]
    runtime = ROOT / "tools/venvs/performance"
    run("npm", "install", "--prefix", str(runtime), "--ignore-scripts", "--no-audit", f"lighthouse@{version}")


def install_technology() -> None:
    run("gem", "install", "addressable", "--user-install", "--no-document")


def build_nmap() -> None:
    source = ROOT / "tools/network/port-and-service-mapper/source"
    if os.name == "nt":
        override = os.getenv("PROJECTN_SCANNER_PORTS")
        installed = str(Path(override).expanduser()) if override and Path(override).expanduser().is_file() else shutil.which("nmap")
        if not installed:
            raise RuntimeError("Install the official Windows Nmap release and add nmap.exe to PATH, or set PROJECTN_SCANNER_PORTS to its executable. The cloned Nmap source remains available in tools/network/port-and-service-mapper/source. Windows source compilation requires the separate nmap-mswin32-aux bundle and Visual Studio; see https://nmap.org/book/inst-windows.html")
        print(f"Using installed Windows Nmap runtime: {installed}", flush=True)
        return
    run("./configure", "--without-zenmap", "--without-nping", "--without-ndiff", cwd=source)
    run("make", "-j2", cwd=source)
    destination = ROOT / "tools/bin/nmap"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / "nmap", destination)


COMPONENTS = {
    "go": build_go,
    "callback": build_callback_service,
    "semgrep": install_semgrep,
    "browser": install_browser,
    "application": build_application,
    "accessibility": install_accessibility,
    "performance": install_performance,
    "technology": install_technology,
    "nmap": build_nmap,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("components", nargs="+", choices=[*COMPONENTS, "all"])
    parser.add_argument("--clone", action="store_true", help="Clone missing scanner sources first")
    options = parser.parse_args()
    if options.clone:
        run(sys.executable, str(ROOT / "scripts/clone_sources.py"))
    selected = list(COMPONENTS) if "all" in options.components else options.components
    failures = []
    for name in selected:
        print(f"\nSetting up {name}", flush=True)
        try:
            COMPONENTS[name]()
        except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
            print(f"FAILED {name}: {exc}", file=sys.stderr, flush=True)
            failures.append(name)
            if "all" not in options.components:
                break
    if failures:
        raise SystemExit("Scanner setup failed: " + ", ".join(failures))


if __name__ == "__main__":
    main()
