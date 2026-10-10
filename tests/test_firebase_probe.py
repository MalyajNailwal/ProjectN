"""Firebase Realtime Database exposure probe: parsing is pure string matching; the database request goes to
a local fake server standing in for Firebase, never to a real firebaseio.com host."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from app.firebase_probe import discover_project, inspect_firebase, request_json


class FakeFirebase(BaseHTTPRequestHandler):
    """Serves a canned shallow-listing response; `shallow_data` is set per-test on the class."""

    shallow_data = None  # None => simulate a database that denies the request (Firebase returns null or an error)

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.shallow_data is None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"null")
            return
        payload = json.dumps(self.shallow_data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class FirebaseProbeTests(unittest.TestCase):
    def run_server(self, shallow_data=None):
        FakeFirebase.shallow_data = shallow_data
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeFirebase)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return f"http://127.0.0.1:{server.server_port}"

    def test_discover_project_parses_rtdb_and_hosting_domains(self):
        self.assertEqual(discover_project("<script>databaseURL:'https://my-app.firebaseio.com'</script>"), "my-app")
        self.assertEqual(discover_project("<link href='https://other-app.firebaseapp.com/favicon.ico'>"), "other-app")
        self.assertIsNone(discover_project("<html>no firebase here</html>"))

    def test_no_project_on_page_is_skipped_with_a_gap(self):
        found, stage, issues = inspect_firebase("<html>plain site</html>")
        self.assertEqual(found, [])
        self.assertEqual(stage["state"], "skipped")
        self.assertEqual({i["code"] for i in issues}, {"firebase_not_detected"})

    def test_open_database_becomes_a_finding_with_keys_but_no_values(self):
        base_url = self.run_server(shallow_data={"users": True, "orders": True})
        with patch("app.firebase_probe.request_json", side_effect=lambda url, timeout: request_json(f"{base_url}/.json", timeout)):
            found, stage, issues = inspect_firebase("<script>https://fixture-proj.firebaseio.com</script>")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "critical")  # "users" is a sensitive-word key
        self.assertIn("users", found[0]["evidence"])
        self.assertNotIn("True", json.dumps(found))  # the shallow marker value itself is never asserted/stored as data
        self.assertTrue(stage["details"]["exposed"])

    def test_closed_database_produces_no_finding(self):
        base_url = self.run_server(shallow_data=None)
        with patch("app.firebase_probe.request_json", side_effect=lambda url, timeout: request_json(f"{base_url}/.json", timeout)):
            found, stage, issues = inspect_firebase("<script>https://fixture-proj.firebaseio.com</script>")
        self.assertEqual(found, [])
        self.assertFalse(stage["details"]["exposed"])

    def test_cancel_before_running_reports_partial(self):
        cancel = threading.Event()
        cancel.set()
        found, stage, issues = inspect_firebase("<script>https://fixture-proj.firebaseio.com</script>", cancel)
        self.assertEqual(found, [])
        self.assertEqual(stage["state"], "partial")
        self.assertIn("scan_cancelled", {i["code"] for i in issues})


if __name__ == "__main__":
    unittest.main()
