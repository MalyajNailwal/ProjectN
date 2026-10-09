import unittest

from app.browser_probe import clean_url, same_origin


class BrowserScopeTests(unittest.TestCase):
    def test_rendered_discovery_stays_on_exact_origin_and_redacts_query(self):
        origin = "https://example.test:8443/"
        self.assertTrue(same_origin("https://example.test:8443/app", origin))
        self.assertFalse(same_origin("https://other.example.test:8443/app", origin))
        self.assertFalse(same_origin("http://example.test:8443/app", origin))
        self.assertEqual(clean_url("https://example.test:8443/app?token=secret#step"), "https://example.test:8443/app")
