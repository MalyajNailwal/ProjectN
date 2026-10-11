"""Supabase table-exposure probe: parsing is pure string matching; the REST calls go to a local fake
PostgREST server standing in for Supabase, never to a real supabase.co host."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from app.supabase_probe import decode_jwt_payload, discover_project, inspect_supabase, leaked_service_role_key


def fake_jwt(role: str = "anon", iss: str = "supabase", ref: str = "abcdefghijklmnopqrst") -> str:
    import base64
    part = lambda data: base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return f"{part({'alg': 'HS256'})}.{part({'role': role, 'iss': iss, 'ref': ref})}.ZmFrZQ"


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

    def test_project_found_only_in_a_linked_script_is_still_discovered(self):
        key = fake_jwt()
        script = f"createClient('https://abcdefghijklmnopqrst.supabase.co', '{key}')".encode()

        class ScriptPage(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(script)))
                self.end_headers()
                self.wfile.write(script)

        script_server = ThreadingHTTPServer(("127.0.0.1", 0), ScriptPage)
        threading.Thread(target=script_server.serve_forever, daemon=True).start()
        self.addCleanup(script_server.shutdown)
        self.addCleanup(script_server.server_close)
        script_url = f"http://127.0.0.1:{script_server.server_port}/chunk.js"

        # The real discover_project regex requires a *.supabase.co host, which a local test server can't be;
        # request_json is patched so the probe's own follow-up calls (table/bucket checks) stay local instead
        # of trying to reach that fake host for real -- discovery itself, the thing under test, is not mocked.
        with patch("app.supabase_probe.request_json", return_value=(None, None)):
            found, stage, issues = inspect_supabase("<html>no supabase here</html>", links=[script_url])
        self.assertEqual(stage["details"]["project_url"], "https://abcdefghijklmnopqrst.supabase.co")
        self.assertNotEqual(stage["state"], "skipped")

    def test_decode_jwt_payload_reads_claims_without_a_secret(self):
        token = fake_jwt(role="service_role", ref="xyz")
        payload = decode_jwt_payload(token)
        self.assertEqual(payload["role"], "service_role")
        self.assertEqual(payload["ref"], "xyz")
        self.assertIsNone(decode_jwt_payload("not-a-jwt"))

    def test_leaked_service_role_key_ignores_anon_and_unrelated_tokens(self):
        anon = fake_jwt(role="anon")
        other_service = fake_jwt(role="service_role", iss="some-other-issuer")
        self.assertIsNone(leaked_service_role_key([f"<script>{anon}</script>", f"<script>{other_service}</script>"]))

    def test_leaked_service_role_key_found_across_candidates(self):
        leaked = fake_jwt(role="service_role", ref="leaked-project")
        payload = leaked_service_role_key(["clean page", f"<script>{leaked}</script>"])
        self.assertEqual(payload["ref"], "leaked-project")

    def test_leaked_service_role_key_becomes_a_critical_finding_even_without_a_discoverable_project(self):
        leaked = fake_jwt(role="service_role", ref="leaked-project")
        found, stage, issues = inspect_supabase(f"<script>{leaked}</script>", links=[])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "critical")
        self.assertEqual(found[0]["rule"], "supabase:service-role-key-exposed")
        self.assertIn("leaked-project", found[0]["location"])
        self.assertNotIn(leaked, json.dumps(found))  # the key's own value is never stored
        self.assertEqual(stage["state"], "partial")

    def test_leaked_service_role_key_finding_appears_alongside_table_findings(self):
        leaked = fake_jwt(role="service_role", ref="leaked-project")
        base_url = self.run_server(exposed_tables={"profiles"}, schema={"profiles": {}})
        with patch("app.supabase_probe.discover_project", return_value=(base_url, "fixture-key")):
            found, stage, issues = inspect_supabase(f"<script>{leaked}</script>", links=[])
        self.assertEqual({item["rule"] for item in found}, {"supabase:service-role-key-exposed", "supabase:rls-missing"})

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
