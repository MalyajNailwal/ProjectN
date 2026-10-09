import unittest

from app.tls_probe import inspect_tls


class TlsScopeTests(unittest.TestCase):
    def test_http_target_does_not_claim_tls_inspection(self):
        findings, stage, gaps = inspect_tls("http://example.test/", "example.test")
        self.assertEqual(findings, [])
        self.assertEqual(stage["state"], "skipped")
        self.assertEqual(gaps[0]["code"], "https_not_selected")
