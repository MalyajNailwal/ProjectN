import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.web_probe import inspect_website


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')
            return
        body = b'<html><a href="/docs">Docs</a><form action="/signup" method="post"></form></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "session=DO-NOT-REPORT; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class WebsiteProbeTests(unittest.TestCase):
    def test_observed_headers_forms_and_secret_redaction(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            findings, stage, gaps = inspect_website(url, "127.0.0.1")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(stage["state"], "completed")
        self.assertIn(f"http://127.0.0.1:{server.server_port}/docs", stage["details"]["links"])
        self.assertEqual(stage["details"]["forms"][0]["method"], "POST")
        self.assertTrue(any(item["rule"] == "header:content-security-policy" for item in findings))
        self.assertTrue(any(item["rule"] == "cookie:httponly" for item in findings))
        self.assertNotIn("DO-NOT-REPORT", json.dumps({"findings": findings, "stage": stage, "gaps": gaps}))

    def test_html_only_headers_are_not_reported_for_json(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            findings, stage, _ = inspect_website(f"http://127.0.0.1:{server.server_port}/json", "127.0.0.1")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(stage["state"], "completed")
        self.assertNotIn("header:content-security-policy", {item["rule"] for item in findings})
        self.assertNotIn("header:referrer-policy", {item["rule"] for item in findings})


if __name__ == "__main__":
    unittest.main()
