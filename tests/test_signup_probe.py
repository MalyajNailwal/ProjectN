"""Signup rate-limit probe: requests go to a local fake server, never a real site. Confirms every submission
carries deliberately invalid values (so a real server would reject it as a non-account)."""

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from app.signup_probe import inspect_signup_rate_limit, invalid_payload, looks_like_signup

SIGNUP_FORM = {
    "page": "https://example.test/signup",
    "action": None,  # set per-test to the fake server URL
    "method": "POST",
    "fields": [
        {"name": "email", "type": "email"},
        {"name": "password", "type": "password"},
        {"name": "confirm_password", "type": "password"},
        {"name": "tos", "type": "checkbox"},
        {"name": "submit", "type": "submit"},
    ],
}


class FakeSignup(BaseHTTPRequestHandler):
    """limit_after N requests starts returning 429; None means never rate-limit. Also records every payload
    received so a test can assert it was never valid-looking account data."""

    limit_after: int | None = None
    received: list[dict] = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        FakeSignup.received.append(parse_qs(body))
        count = len(FakeSignup.received)
        if self.limit_after is not None and count > self.limit_after:
            payload = b"Too many requests, please try again later."
            self.send_response(429)
        else:
            payload = b'{"error":"invalid email"}'
            self.send_response(400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class SignupProbeTests(unittest.TestCase):
    def run_server(self, limit_after=None):
        FakeSignup.limit_after = limit_after
        FakeSignup.received = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeSignup)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return f"http://127.0.0.1:{server.server_port}/signup"

    def test_looks_like_signup_requires_post_and_password_signal(self):
        self.assertTrue(looks_like_signup(SIGNUP_FORM))
        login_form = {"method": "POST", "action": "/login", "page": "/login", "fields": [{"name": "email", "type": "email"}, {"name": "password", "type": "password"}]}
        self.assertFalse(looks_like_signup(login_form))  # one password field, no signup-shaped path
        get_form = {**SIGNUP_FORM, "method": "GET"}
        self.assertFalse(looks_like_signup(get_form))

    def test_invalid_payload_never_contains_a_well_formed_email_or_real_looking_password(self):
        payload = invalid_payload(SIGNUP_FORM["fields"])
        self.assertEqual(payload["email"], "not-an-email")
        self.assertNotIn("@", payload["email"])  # sanity: literally not an email shape
        self.assertEqual(len(payload["password"]), 1)  # fails any real minimum-length check
        self.assertNotIn("tos", payload)  # checkboxes are left unchecked, not forced
        self.assertNotIn("submit", payload)

    def test_no_rate_limiting_becomes_a_needs_review_finding_and_payload_stays_invalid(self):
        action = self.run_server(limit_after=None)
        forms = [{**SIGNUP_FORM, "action": action}]
        found, stage, issues = inspect_signup_rate_limit(forms)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "medium")
        self.assertEqual(found[0]["confidence"], "needs-review")
        self.assertEqual(stage["details"]["attempts"], 8)
        self.assertFalse(stage["details"]["rate_limited"])
        for submission in FakeSignup.received:
            self.assertEqual(submission["email"], ["not-an-email"])  # never a well-formed address

    def test_rate_limiting_present_produces_no_finding_and_stops_early(self):
        action = self.run_server(limit_after=3)
        forms = [{**SIGNUP_FORM, "action": action}]
        found, stage, issues = inspect_signup_rate_limit(forms)
        self.assertEqual(found, [])
        self.assertTrue(stage["details"]["rate_limited"])
        self.assertLess(stage["details"]["attempts"], 8)  # stopped as soon as 429 was seen

    def test_no_signup_form_discovered_is_skipped_with_a_gap(self):
        found, stage, issues = inspect_signup_rate_limit([{"method": "POST", "action": "/contact", "page": "/contact", "fields": [{"name": "message", "type": "text"}]}])
        self.assertEqual(found, [])
        self.assertEqual(stage["state"], "skipped")
        self.assertEqual({i["code"] for i in issues}, {"signup_form_not_found"})

    def test_cancel_stops_early_and_reports_partial(self):
        action = self.run_server(limit_after=None)
        forms = [{**SIGNUP_FORM, "action": action}]
        cancel = threading.Event()
        cancel.set()
        found, stage, issues = inspect_signup_rate_limit(forms, cancel)
        self.assertEqual(found, [])
        self.assertEqual(stage["state"], "partial")
        self.assertEqual(stage["details"]["attempts"], 0)
        self.assertIn("scan_cancelled", {i["code"] for i in issues})


if __name__ == "__main__":
    unittest.main()
