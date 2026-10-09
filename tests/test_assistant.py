import json
import os
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from app.assistant import draft_remediation, post_json


FINDING = {"fingerprint": "abc123", "scanner": "tls_config", "rule": "tls:protocol:TLSv1.0", "title": "Outdated TLS", "severity": "high", "evidence": "Nmap enumerated TLSv1.0", "remediation": "Disable TLSv1.0", "verification": "Rerun TLS enumeration", "location": "private.example.test"}


class FakeResponse:
    status = 200

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, *_):
        return self.body


class AssistantTests(unittest.TestCase):
    def test_local_model_draft_requires_matching_evidence_citation(self):
        response = {"response": json.dumps({"summary": "TLSv1.0 was observed", "fix_steps": ["Disable TLSv1.0"], "verification": "Rerun", "uncertainty": "Other hosts were not scanned", "citation": "finding:abc123"})}
        with patch.dict(os.environ, {"PROJECTN_AI_PROVIDER": "ollama", "PROJECTN_LOCAL_MODEL": "local-test-model"}), patch("app.assistant.urllib.request.urlopen", return_value=FakeResponse(json.dumps(response).encode())) as call:
            draft = draft_remediation(FINDING)
        self.assertEqual(draft["citation"], "finding:abc123")
        sent = json.loads(call.call_args.args[0].data)
        self.assertNotIn("private.example.test", sent["prompt"])

    def test_secret_findings_are_not_sent_to_model(self):
        with patch.dict(os.environ, {"PROJECTN_AI_PROVIDER": "ollama", "PROJECTN_LOCAL_MODEL": "local-test-model"}):
            with self.assertRaises(ValueError):
                draft_remediation({**FINDING, "scanner": "secrets"})

    def test_openrouter_free_requires_consent_and_uses_zero_retention_filter(self):
        response = {"choices": [{"message": {"content": json.dumps({"summary": "TLSv1.0 was observed", "fix_steps": ["Disable TLSv1.0"], "verification": "Rerun", "uncertainty": "Other hosts were not scanned", "citation": "finding:abc123"})}}]}
        environment = {"PROJECTN_AI_PROVIDER": "openrouter", "OPENROUTER_API_KEY": "test-only-key", "PROJECTN_OPENROUTER_MODEL": "openrouter/free"}
        with patch.dict(os.environ, environment), patch("app.assistant.post_json", return_value=response) as call:
            with self.assertRaisesRegex(ValueError, "explicit consent"):
                draft_remediation(FINDING)
            call.assert_not_called()
            draft = draft_remediation(FINDING, allow_external=True)
        self.assertEqual(draft["model"], "openrouter/free")
        self.assertTrue(call.call_args.args[1]["provider"]["zdr"])
        self.assertEqual(call.call_args.args[1]["response_format"], {"type": "json_object"})
        self.assertEqual(call.call_args.args[2]["Authorization"], "Bearer test-only-key")

    def test_provider_rate_limit_has_actionable_error_without_response_body(self):
        response_error = HTTPError("https://openrouter.ai", 429, "private provider detail", {}, None)
        try:
            with patch("app.assistant.urllib.request.urlopen", side_effect=response_error):
                with self.assertRaisesRegex(RuntimeError, "retry later") as failure:
                    post_json("https://openrouter.ai/api/v1/chat/completions", {}, {})
        finally:
            response_error.close()
        self.assertNotIn("private provider detail", str(failure.exception))


if __name__ == "__main__":
    unittest.main()
