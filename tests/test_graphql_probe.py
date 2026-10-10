"""GraphQL introspection probe: requests go to a local fake server, never a real site."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.graphql_probe import inspect_graphql


class FakeGraphQL(BaseHTTPRequestHandler):
    """Answers introspection only on `open_path`; every other path returns 404, like a site with no GraphQL."""

    open_path: str | None = None

    def log_message(self, *a):
        pass

    def do_POST(self):
        if self.path == self.open_path:
            body = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}, "types": [{"name": "Query"}, {"name": "User"}]}}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


class GraphQLProbeTests(unittest.TestCase):
    def run_server(self, open_path=None):
        FakeGraphQL.open_path = open_path
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeGraphQL)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return f"http://127.0.0.1:{server.server_port}"

    def test_open_introspection_becomes_a_medium_finding(self):
        base_url = self.run_server(open_path="/graphql")
        found, stage, issues = inspect_graphql(base_url)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "medium")
        self.assertEqual(found[0]["location"], base_url + "/graphql")
        self.assertEqual(stage["details"]["introspection_endpoint"], base_url + "/graphql")
        self.assertEqual(stage["details"]["type_count"], 2)

    def test_no_graphql_endpoint_produces_no_finding(self):
        base_url = self.run_server(open_path=None)
        found, stage, issues = inspect_graphql(base_url)
        self.assertEqual(found, [])
        self.assertIsNone(stage["details"]["introspection_endpoint"])
        self.assertEqual(stage["state"], "completed")

    def test_tries_a_later_candidate_path_when_the_first_is_closed(self):
        base_url = self.run_server(open_path="/api/graphql")
        found, stage, issues = inspect_graphql(base_url)
        self.assertEqual(found[0]["location"], base_url + "/api/graphql")

    def test_cancel_stops_early_and_reports_partial(self):
        base_url = self.run_server(open_path=None)
        cancel = threading.Event()
        cancel.set()
        found, stage, issues = inspect_graphql(base_url, cancel)
        self.assertEqual(found, [])
        self.assertEqual(stage["state"], "partial")
        self.assertEqual(stage["details"]["checked_paths"], 0)
        self.assertIn("scan_cancelled", {i["code"] for i in issues})


if __name__ == "__main__":
    unittest.main()
