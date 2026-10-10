"""Supabase table-exposure probe: parsing is pure string matching; the REST calls go to a local fake
PostgREST server standing in for Supabase, never to a real supabase.co host."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from app.supabase_probe import discover_project, inspect_supabase


def fake_jwt() -> str:
    import base64
    part = lambda data: base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return f"{part({'alg': 'HS256'})}.{part({'role': 'anon'})}.ZmFrZQ"


class FakePostgrest(BaseHTTPRequestHandler):
    """Serves canned responses keyed by path; `exposed_tables`/`schema`/`buckets` are set per-test on the class."""

    exposed_tables: set[str] = set()
    schema: dict | None = None
    buckets: list[dict] = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/rest/v1/":
            if self.schema is not None:
                self._json(200, {"definitions": self.schema})
            else:
                self._json(404, {})
            return
        if path == "/storage/v1/bucket":
            self._json(200, self.buckets)
            return
        table = path.removeprefix("/rest/v1/")
        if table in self.exposed_tables:
            self._json(200, [{"id": 1, "email": "fixture@example.test"}])
        else:
            self._json(200, [])

    def _json(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class SupabaseProbeTests(unittest.TestCase):
    def run_server(self, exposed_tables=frozenset(), schema=None, buckets=()):
        FakePostgrest.exposed_tables = set(exposed_tables)
        FakePostgrest.schema = schema
        FakePostgrest.buckets = list(buckets)
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakePostgrest)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return f"http://127.0.0.1:{server.server_port}"

    def test_discover_project_parses_url_and_key_from_page_body(self):
        key = fake_jwt()
        body = f"<script>createClient('https://abcdefghijklmnopqrst.supabase.co', '{key}')</script>"
        self.assertEqual(discover_project(body), ("https://abcdefghijklmnopqrst.supabase.co", key))
        self.assertIsNone(discover_project("<html>no supabase here</html>"))

    def test_no_project_on_page_is_skipped_with_a_gap(self):
        found, stage, issues = inspect_supabase("<html>plain site</html>")
        self.assertEqual(found, [])
        self.assertEqual(stage["state"], "skipped")
        self.assertEqual({i["code"] for i in issues}, {"supabase_not_detected"})

    def test_exposed_table_becomes_a_finding_with_columns_but_no_row_values(self):
        base_url = self.run_server(exposed_tables={"profiles"}, schema={"profiles": {}})
        with patch("app.supabase_probe.discover_project", return_value=(base_url, "fixture-key")):
            found, stage, issues = inspect_supabase("<html/>")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "high")
        self.assertIn("columns", found[0]["evidence"].lower())
        self.assertNotIn("fixture@example.test", json.dumps(found))  # row value never stored
        self.assertEqual(stage["details"]["exposed_tables"], ["profiles"])
        self.assertTrue(stage["details"]["schema_introspectable"])

    def test_sensitive_table_name_is_critical_severity(self):
        base_url = self.run_server(exposed_tables={"users"}, schema={"users": {}})
        with patch("app.supabase_probe.discover_project", return_value=(base_url, "fixture-key")):
            found, _, _ = inspect_supabase("<html/>")
        self.assertEqual(found[0]["severity"], "critical")

    def test_protected_tables_produce_no_finding(self):
        base_url = self.run_server(exposed_tables=set(), schema={"users": {}})
        with patch("app.supabase_probe.discover_project", return_value=(base_url, "fixture-key")):
            found, stage, issues = inspect_supabase("<html/>")
        self.assertEqual(found, [])
        self.assertEqual(stage["details"]["exposed_tables"], [])

    def test_no_schema_falls_back_to_bounded_guess_list_and_reports_the_gap(self):
        base_url = self.run_server(exposed_tables=set(), schema=None)
        with patch("app.supabase_probe.discover_project", return_value=(base_url, "fixture-key")):
            found, stage, issues = inspect_supabase("<html/>")
        self.assertFalse(stage["details"]["schema_introspectable"])
        self.assertLessEqual(stage["details"]["tables_checked"], 15)
        self.assertIn("supabase_guess_list_only", {i["code"] for i in issues})

    def test_public_bucket_becomes_a_needs_review_finding(self):
        base_url = self.run_server(exposed_tables=set(), schema={}, buckets=[
            {"name": "avatars", "public": True},
            {"name": "backups", "public": False},
        ])
        with patch("app.supabase_probe.discover_project", return_value=(base_url, "fixture-key")):
            found, stage, issues = inspect_supabase("<html/>")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "medium")
        self.assertEqual(found[0]["confidence"], "needs-review")
        self.assertIn("avatars", found[0]["title"])
        self.assertEqual(stage["details"]["public_buckets"], ["avatars"])

    def test_cancel_stops_early_and_reports_partial(self):
        base_url = self.run_server(exposed_tables=set(), schema={"users": {}})
        cancel = threading.Event()
        cancel.set()
        with patch("app.supabase_probe.discover_project", return_value=(base_url, "fixture-key")):
            found, stage, issues = inspect_supabase("<html/>", cancel)
        self.assertEqual(stage["state"], "partial")
        self.assertEqual(stage["details"]["tables_checked"], 0)
        self.assertIn("scan_cancelled", {i["code"] for i in issues})


if __name__ == "__main__":
    unittest.main()
