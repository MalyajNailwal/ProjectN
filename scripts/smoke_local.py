"""Check a fresh native install by starting the app on a local ephemeral port."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                with urllib.request.urlopen(base + "/api/health", timeout=2) as response:
                    health = json.load(response)
                with urllib.request.urlopen(base + "/", timeout=2) as response:
                    page = response.read().decode("utf-8")
                with urllib.request.urlopen(base + "/api/scanners", timeout=2) as response:
                    scanners = json.load(response)
                if health.get("status") != "ok" or "ProjectN" not in page or not isinstance(scanners, list):
                    raise RuntimeError("App returned an incomplete health, dashboard, or scanner response")
                print(f"Native app smoke passed: dashboard, health, and {len(scanners)} scanner status entries")
                return 0
            except (urllib.error.URLError, TimeoutError):
                time.sleep(0.25)
        output = process.communicate(timeout=2)[0] if process.poll() is not None else ""
        raise RuntimeError(f"App did not become ready within 20 seconds. {output[-1500:]}")
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


if __name__ == "__main__":
    raise SystemExit(main())
