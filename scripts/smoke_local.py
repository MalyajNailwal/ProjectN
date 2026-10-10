"""Check a fresh native install by starting the app on a local ephemeral port."""

from __future__ import annotations

import argparse
import json
import functools
import http.server
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class FixtureHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass


class FixtureServer(http.server.ThreadingHTTPServer):
    def handle_error(self, *args: object) -> None:
        pass


def scan_fixture(base: str, required_stages: list[str], profile: str) -> None:
    site = ROOT / "tests/fixtures/site"
    handler = functools.partial(FixtureHandler, directory=str(site))
    server = FixtureServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}/"
        request = urllib.request.Request(base + "/api/scans", data=json.dumps({"url": target, "profile": profile, "authorized_intrusive": profile == "full"}).encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=5) as response:
            scan_id = json.load(response)["id"]
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            with urllib.request.urlopen(base + f"/api/scans/{scan_id}", timeout=5) as response:
                scan = json.load(response)
            if scan["status"] == "completed":
                report = scan["result"]
                if not report or not report.get("stages") or report["target"].get("url") != target:
                    raise RuntimeError("Fixture scan completed without a usable report")
                for stage_id in required_stages:
                    stage = next((item for item in report["stages"] if item["id"] == stage_id), None)
                    if not stage or stage["state"] not in {"completed", "partial"}:
                        raise RuntimeError(f"Required scanner stage {stage_id} did not run successfully")
                print(f"Fixture website scan passed: {len(report['stages'])} stages")
                return
            if scan["status"] == "failed":
                raise RuntimeError("Fixture website scan failed")
            time.sleep(0.25)
        raise RuntimeError("Fixture website scan did not finish within 180 seconds")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-stage", action="append", default=[], help="Require a scanner stage to finish the fixture scan")
    parser.add_argument("--profile", choices=("standard", "full"), default="standard", help="Fixture scan profile")
    options = parser.parse_args()
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
                scan_fixture(base, options.require_stage, options.profile)
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
