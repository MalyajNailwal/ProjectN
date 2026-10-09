import tempfile
import unittest
from pathlib import Path

from app.api_spec_probe import inspect_api_spec


class ApiSpecTests(unittest.TestCase):
    def test_declared_observed_and_undocumented_routes_stay_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "openapi.yaml"
            source.write_text("openapi: 3.0.0\npaths:\n  /api/users/{id}:\n    get: {}\n  /api/admin:\n    post: {}\n")
            observed = [{"method": "GET", "url": "https://example.test/api/users/42?token=PRIVATE", "status": 200}, {"method": "GET", "url": "https://example.test/api/health", "status": 200}]
            findings, stage, limitations = inspect_api_spec(source, "https://example.test/", observed)
            self.assertEqual(findings, [])
            self.assertEqual(stage["state"], "completed")
            self.assertEqual(stage["details"]["declared_observed_count"], 1)
            self.assertEqual(len(stage["details"]["undocumented_observed"]), 1)
            self.assertNotIn("PRIVATE", str(stage))
            self.assertEqual({item["code"] for item in limitations}, {"api_routes_not_observed", "api_routes_undocumented"})

    def test_remote_reference_is_not_loaded(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "openapi.json"
            source.write_text('{"openapi":"3.0.0","paths":{"/api/ping":{"get":{"$ref":"https://example.test/remote.json"}}}}')
            _, stage, _ = inspect_api_spec(source, "https://example.test/", [])
            self.assertEqual(stage["details"]["declared_count"], 1)

    def test_server_base_path_is_applied_before_matching(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "openapi.yaml"
            source.write_text("openapi: 3.0.0\nservers:\n  - url: https://example.test/v1\npaths:\n  /users:\n    get: {}\n")
            _, stage, limitations = inspect_api_spec(source, "https://example.test/", [{"method": "GET", "url": "https://example.test/v1/users", "status": 200}])
            self.assertEqual(stage["details"]["declared"][0]["path"], "/v1/users")
            self.assertTrue(stage["details"]["declared"][0]["observed"])
            self.assertFalse(limitations)


if __name__ == "__main__":
    unittest.main()
