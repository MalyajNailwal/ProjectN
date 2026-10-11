"""Hosting/CDN, backend-as-a-service, and framework signals come only from already-fetched headers and body
(except baas in Full scope, which may also check a bounded number of already-discovered linked scripts)."""

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.infra_probe import inspect_infrastructure


class InfraProbeTests(unittest.TestCase):
    def test_matches_multiple_categories_from_headers_and_body(self):
        headers = {"server": "cloudflare", "cf-ray": "8a1b2c3d4e5f6789-DEL", "cf-cache-status": "DYNAMIC"}
        body = "<html><script>window.__NEXT_DATA__={}</script><script src='/_next/static/x.js'></script>https://abcdefghijklmnopqrst.supabase.co supabase-js</html>"
        found, stage, issues = inspect_infrastructure(headers, body)
        self.assertEqual(found, [])
        self.assertEqual(stage["state"], "completed")
        self.assertEqual(issues, [])
        self.assertEqual(stage["details"]["hosting"][0]["id"], "cloudflare")
        self.assertEqual(stage["details"]["baas"][0]["id"], "supabase")
        self.assertEqual(stage["details"]["frameworks"][0]["id"], "nextjs")
        for category in ("hosting", "baas", "frameworks"):
            self.assertEqual(stage["details"][category][0]["match_percent"], 100)

    def test_percent_is_a_literal_fraction_of_named_signals_not_a_guess(self):
        # Cloudflare's weakest single signal (cf-cache-status, weight 2 of 8 total) must report exactly 2/8=25%.
        found, stage, issues = inspect_infrastructure({"cf-cache-status": "DYNAMIC"}, "")
        match = stage["details"]["hosting"][0]
        self.assertEqual(match["match_percent"], 25)
        self.assertEqual(match["confidence"], "possible")
        self.assertEqual(match["evidence"], ["CF-Cache-Status header"])

    def test_no_response_is_skipped_not_a_silent_empty_pass(self):
        found, stage, issues = inspect_infrastructure({}, "")
        self.assertEqual(stage["state"], "skipped")
        self.assertEqual({item["code"] for item in issues}, {"infra_not_assessed"})

    def test_plain_response_with_no_known_signals_reports_a_gap(self):
        found, stage, issues = inspect_infrastructure({"server": "nginx"}, "<html>static site, no framework markers</html>")
        self.assertEqual(stage["state"], "completed")
        self.assertEqual(stage["details"], {"hosting": [], "baas": [], "frameworks": []})
        self.assertEqual({item["code"] for item in issues}, {"infra_signals_not_matched"})

    def test_header_matching_is_case_insensitive_and_scoped_to_its_own_header(self):
        found, stage, issues = inspect_infrastructure({"Server": "Vercel"}, "")
        self.assertEqual(stage["details"]["hosting"][0]["id"], "vercel")
        self.assertEqual(stage["details"]["baas"], [])

    def test_baas_signal_found_only_in_a_linked_script_is_still_matched(self):
        script = b"https://abcdefghijklmnopqrst.supabase.co supabase-js"

        class ScriptPage(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(script)))
                self.end_headers()
                self.wfile.write(script)

        server = ThreadingHTTPServer(("127.0.0.1", 0), ScriptPage)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        script_url = f"http://127.0.0.1:{server.server_port}/chunk.js"

        without_links = inspect_infrastructure({}, "<html>plain page, no supabase mentioned</html>")[1]
        self.assertEqual(without_links["details"]["baas"], [])

        with_links = inspect_infrastructure({}, "<html>plain page, no supabase mentioned</html>", links=[script_url])[1]
        self.assertEqual(with_links["details"]["baas"][0]["id"], "supabase")
        # The root body used for hosting/frameworks matching must stay untouched by the script fetch.
        self.assertEqual(with_links["details"]["frameworks"], [])


if __name__ == "__main__":
    unittest.main()
