"""Shareable exports preserve scan evidence, scope, and safe redaction."""

import io
import unittest
import xml.etree.ElementTree as ET
import zipfile
from unittest.mock import patch

from fastapi import HTTPException

from app import main
from app.report_document import blocks_for, make_docx, make_html, safe


def sample():
    return {
        "id": "12345678-1234-1234-1234-123456789abc",
        "target": {"url": "https://example.test/?token=private", "profile": "full"},
        "result": {
            "target": {"url": "https://example.test/", "profile": "full"},
            "retry_of": "previous-scan", "requested_steps": ["accessibility"],
            "started_at": 1, "finished_at": 2, "cancelled": False,
            "findings": [{"scanner": "accessibility", "title": "Button has no accessible name", "severity": "critical", "confidence": "needs-review", "location": "https://example.test/form?token=private", "evidence": "Unnamed button found", "remediation": "Give the button an accessible name.", "verification": "Retest with a screen reader.", "rule": "button-name"}],
            "stages": [{"id": "accessibility", "label": "Accessibility checks", "state": "partial", "summary": "One page observed", "runtime_version": "4.10.0", "source_revision": "a" * 40, "rules_revision": "b" * 40, "details": {"diagnostic": "password=do-not-share"}}],
            "limitations": [{"scanner": "accessibility", "code": "page_cap", "message": "Page cap reached", "resolution": "Raise the page cap and retry."}],
        },
    }


class ReportDocumentTests(unittest.TestCase):
    def test_docx_contains_evidence_header_footer_and_no_diagnostic(self):
        blocks, target, scan_id = blocks_for(sample())
        result = make_docx(blocks, target, scan_id)
        with zipfile.ZipFile(io.BytesIO(result)) as package:
            for name in ("word/document.xml", "word/styles.xml", "word/header1.xml", "word/footer1.xml", "word/_rels/document.xml.rels"):
                ET.fromstring(package.read(name))
            body = package.read("word/document.xml").decode()
            self.assertIn("Unnamed button found", body)
            self.assertIn("Raise the page cap", body)
            self.assertIn("previous-scan", body)
            self.assertIn("a" * 40, body)
            self.assertNotIn("do-not-share", body)
            self.assertNotIn("token=private", body)

    def test_html_escapes_untrusted_text_and_keeps_all_findings(self):
        item = sample()
        item["result"]["findings"][0]["title"] = "<script>alert(1)</script>"
        blocks, target, scan_id = blocks_for(item)
        result = make_html(blocks, target, scan_id)
        self.assertIn("&lt;script&gt;", result)
        self.assertNotIn("<script>", result)
        self.assertIn("F001", result)
        self.assertEqual(safe("https://example.test/a?token=private"), "https://example.test/a")

    def test_download_checks_format_and_report_state(self):
        with self.assertRaises(HTTPException) as invalid:
            main.download_scan("some-id", "html")
        self.assertEqual(invalid.exception.status_code, 422)
        with patch.object(main, "scan_detail", return_value={"result": None}):
            with self.assertRaises(HTTPException) as pending:
                main.download_scan("some-id", "docx")
        self.assertEqual(pending.exception.status_code, 409)
        with patch.object(main, "scan_detail", return_value=sample()):
            response = main.download_scan("12345678-1234-1234-1234-123456789abc", "docx")
        self.assertEqual(response.headers["content-type"], "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertTrue(response.body.startswith(b"PK"))


if __name__ == "__main__":
    unittest.main()
