"""Run the cloned Lighthouse CLI with the locally installed Chromium browser."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright


def run(url: str, output: Path, source: Path, settings: dict) -> None:
    source = source.resolve()
    output = output.resolve()
    with sync_playwright() as playwright:
        chrome = playwright.chromium.executable_path
    node = shutil.which("node")
    if not node or not Path(chrome).is_file():
        raise RuntimeError("Node.js or local Chromium is unavailable")
    command = [node, str(source / "cli/index.js"), url, "--output=json", f"--output-path={output}", "--quiet", "--chrome-flags=--headless=new", "--only-categories=" + ",".join(settings["categories"])]
    environment = {**os.environ, "CHROME_PATH": chrome}
    completed = subprocess.run(command, cwd=source, capture_output=True, text=True, timeout=600, shell=False, env=environment)
    if completed.returncode != 0 or not output.is_file():
        print(completed.stderr[-2000:], file=sys.stderr)
        output.write_text(json.dumps({"error": "Lighthouse did not produce a complete JSON report", "exit_code": completed.returncode}))
        raise SystemExit(2)


if __name__ == "__main__":
    target, result_path, source_path, config_path = sys.argv[1:5]
    run(target, Path(result_path), Path(source_path), json.loads(Path(config_path).read_text(encoding="utf-8")))
