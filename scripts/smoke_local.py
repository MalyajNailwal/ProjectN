"""Check a fresh native install by starting the app on a local ephemeral port."""

from __future__ import annotations

import argparse
import json
import functools
import http.server
import os
import socket
import subprocess
import sys
import tempfile
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


def scan_fixture(base: str, required_stages: list[str], profile: str, fields: dict, timeout: float) -> None:
    site = ROOT / "tests/fixtures/site"
    handler = functools.partial(FixtureHandler, directory=str(site))
    server = FixtureServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}/"
        request = urllib.request.Request(base + "/api/scans", data=json.dumps({"url": target, "profile": profile, "authorized_intrusive": profile == "full", **fields}).encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=5) as response:
            scan_id = json.load(response)["id"]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with urllib.request.urlopen(base + f"/api/scans/{scan_id}", timeout=5) as response:
                scan = json.load(response)
            if scan["status"] == "completed":
                report = scan["result"]
                if not report or not report.get("stages") or report["target"].get("url") != target:
                    raise RuntimeError("Fixture scan completed without a usable report")
                for stage in report["stages"]:
                    print(f"  {stage['id']}: {stage['state']} ({stage.get('summary', '')})")
                for stage_id in required_stages:
                    stage = next((item for item in report["stages"] if item["id"] == stage_id), None)
                    if not stage or stage["state"] not in {"completed", "partial"}:
                        raise RuntimeError(f"Required scanner stage {stage_id} did not run successfully")
                print(f"Fixture scan passed: {len(report['stages'])} stages, {len(report['findings'])} findings, {len(report['limitations'])} limitations")
                return
            if scan["status"] == "failed":
                raise RuntimeError("Fixture website scan failed")
            time.sleep(0.25)
        running = [step["label"] for step in scan.get("steps", []) if step["state"] == "running"]
        raise RuntimeError(f"Fixture scan did not finish within {timeout:.0f} seconds; still running: {', '.join(running) or scan['progress']}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-stage", action="append", default=[], help="Require a scanner stage to finish the fixture scan")
    parser.add_argument("--profile", choices=("standard", "full"), default="standard", help="Fixture scan profile")
    parser.add_argument("--field", action="append", default=[], metavar="KEY=VALUE", help="Extra scan request field, such as local_path=. or port_range=1-1024; may be repeated")
    parser.add_argument("--timeout", type=float, default=180, help="Seconds to wait for the fixture scan")
    options = parser.parse_args()
    fields = {}
    for item in options.field:
        key, _, value = item.partition("=")
        try:
            fields[key] = json.loads(value)
        except json.JSONDecodeError:
            fields[key] = value
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    # The server log goes to a file: an unread pipe fills during long scans and blocks the app.
    # A separate data directory keeps smoke scans out of the user's history and running scans;
    # Windows can briefly keep the SQLite file locked after the server exits, so cleanup is best effort.
    with tempfile.TemporaryFile(mode="w+") as log, tempfile.TemporaryDirectory(prefix="projectn-smoke-", ignore_cleanup_errors=True) as data:
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=ROOT,
            env={**os.environ, "PROJECTN_DATA_DIR": data},
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            deadline = time.monotonic() + 60
            while True:
                try:
                    with urllib.request.urlopen(base + "/api/health", timeout=5) as response:
                        health = json.load(response)
                    with urllib.request.urlopen(base + "/", timeout=5) as response:
                        page = response.read().decode("utf-8")
                    with urllib.request.urlopen(base + "/api/scanners", timeout=30) as response:
                        scanners = json.load(response)
                    break
                except (urllib.error.URLError, TimeoutError):
                    if process.poll() is not None or time.monotonic() > deadline:
                        log.seek(0)
                        raise RuntimeError(f"App did not become ready within 60 seconds. {log.read()[-1500:]}")
                    time.sleep(0.25)
            if health.get("status") != "ok" or "ProjectN" not in page or not isinstance(scanners, list):
                raise RuntimeError("App returned an incomplete health, dashboard, or scanner response")
            print(f"Native app smoke passed: dashboard, health, and {len(scanners)} scanner status entries")
            scan_fixture(base, options.require_stage, options.profile, fields, options.timeout)
            return 0
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

if __name__ == "__main__":
    raise SystemExit(main())
