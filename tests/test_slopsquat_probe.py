"""Hallucinated-dependency probe: manifest parsing is pure file reading; registry lookups go to a local
fake registry standing in for npm/PyPI, never to a real npm or PyPI host."""

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from app.slopsquat_probe import inspect_slopsquat, npm_dependency_names, python_dependency_names, registry_exists


class FakeRegistry(BaseHTTPRequestHandler):
    """200 for any path under a name in `published`, 404 otherwise -- like a real package registry."""

    published: set[str] = set()

    def log_message(self, *a):
        pass

    def do_GET(self):
        name = self.path.strip("/").split("/")[0]
        if name in self.published:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
        else:
            self.send_response(404)
            self.end_headers()


class SlopsquatProbeTests(unittest.TestCase):
    def run_registry(self, published=frozenset()):
        """Starts a local fake registry and patches registry_exists to redirect npm/PyPI URLs to it."""
        FakeRegistry.published = set(published)
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeRegistry)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        base_url = f"http://127.0.0.1:{server.server_port}"

        def redirected(url, timeout):
            local_url = url.replace("https://registry.npmjs.org", base_url).replace("https://pypi.org/pypi", base_url).removesuffix("/json")
            return registry_exists(local_url, timeout)

        patcher = patch("app.slopsquat_probe.registry_exists", side_effect=redirected)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_project(self, root: Path, npm_names=(), py_names=()):
        if npm_names:
            (root / "package.json").write_text(json.dumps({"dependencies": {name: "1.0.0" for name in npm_names}}))
        if py_names:
            (root / "requirements.txt").write_text("\n".join(f"{name}==1.0.0" for name in py_names))

    def test_parses_npm_and_python_manifests_and_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_project(root, npm_names=["react"], py_names=["flask"])
            (root / "node_modules").mkdir()
            (root / "node_modules" / "package.json").write_text(json.dumps({"dependencies": {"ignored": "1.0.0"}}))
            self.assertEqual(npm_dependency_names(root), {"react"})
            self.assertEqual(python_dependency_names(root), {"flask"})

    def test_no_manifests_is_skipped_with_a_gap(self):
        with tempfile.TemporaryDirectory() as temp:
            found, stage, issues = inspect_slopsquat(Path(temp))
        self.assertEqual(found, [])
        self.assertEqual(stage["state"], "skipped")
        self.assertEqual({i["code"] for i in issues}, {"slopsquat_not_applicable"})

    def test_nonexistent_package_becomes_a_medium_finding(self):
        self.run_registry(published={"react"})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_project(root, npm_names=["react", "react-codeshift-totally-fake"])
            found, stage, issues = inspect_slopsquat(root)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "medium")
        self.assertIn("react-codeshift-totally-fake", found[0]["title"])
        self.assertEqual(stage["details"]["missing"], ["react-codeshift-totally-fake"])

    def test_all_packages_published_produces_no_findings(self):
        self.run_registry(published={"react", "vite"})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_project(root, npm_names=["react", "vite"])
            found, stage, issues = inspect_slopsquat(root)
        self.assertEqual(found, [])
        self.assertEqual(stage["details"]["missing"], [])

    def test_python_package_checked_against_pypi_shaped_url(self):
        self.run_registry(published={"flask"})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_project(root, py_names=["flask", "totally-hallucinated-pkg"])
            found, stage, issues = inspect_slopsquat(root)
        self.assertEqual(stage["details"]["missing"], ["totally-hallucinated-pkg"])
        self.assertEqual(found[0]["location"], "PyPI")

    def test_cancel_stops_early_and_reports_partial(self):
        self.run_registry(published=set())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_project(root, npm_names=["a", "b", "c"])
            cancel = threading.Event()
            cancel.set()
            found, stage, issues = inspect_slopsquat(root, cancel)
        self.assertEqual(stage["state"], "partial")
        self.assertEqual(stage["details"]["checked"], 0)
        self.assertIn("scan_cancelled", {i["code"] for i in issues})


if __name__ == "__main__":
    unittest.main()
