"""Run the cloned Lighthouse CLI with the locally installed Chromium browser."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


def _attempt(command: list[str], cwd: Path, env: dict, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, shell=False, env=env)


def run(url: str, output: Path, source: Path, settings: dict) -> None:
    from playwright.sync_api import sync_playwright

    source = source.resolve()
    output = output.resolve()
    with sync_playwright() as playwright:
        chrome = playwright.chromium.executable_path
    node = shutil.which("node")
    if not node or not Path(chrome).is_file():
        raise RuntimeError("Node.js or local Chromium is unavailable")
    # Lighthouse's default user agent announces itself ("...Chrome-Lighthouse"), which some hosts
    # (observed on Vercel) block outright with 403 while a normal browser request passes. This
    # flag keeps Chrome's own real user agent instead, matching what the browser-driven stages
    # (crawler/accessibility/application) already send.
    command = [node, str(source / "cli/index.js"), url, "--output=json", f"--output-path={output}", "--quiet", "--chrome-flags=--headless=new", "--no-emulated-user-agent", "--only-categories=" + ",".join(settings["categories"])]
    environment = {**os.environ, "CHROME_PATH": chrome}
    attempts = settings.get("transient_retry_attempts", 1) + 1
    for attempt in range(1, attempts + 1):
        completed = _attempt(command, source, environment, 600)
        if completed.returncode == 0 and output.is_file():
            return
        if attempt < attempts:
            # Observed directly on a real target: a page that blocks this one request (a site's bot/rate
            # defenses tightening under the request volume of this scan's own earlier stages, then easing
            # again within seconds) is not distinguishable here from a page that is genuinely unreachable,
            # so this retries either way -- bounded, and the wait gives a transient block time to lift.
            time.sleep(settings.get("transient_retry_wait_seconds", 5))
            continue
        print(completed.stderr[-2000:], file=sys.stderr)
        output.write_text(json.dumps({"error": "Lighthouse did not produce a complete JSON report", "exit_code": completed.returncode}))
        raise SystemExit(2)


if __name__ == "__main__":
    target, result_path, source_path, config_path = sys.argv[1:5]
    run(target, Path(result_path), Path(source_path), json.loads(Path(config_path).read_text(encoding="utf-8")))
