import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.core import compare_reports, execute_scan, full_scan_options, parse_output, port_in_ranges, response_signal_gaps, scan_one, validate_oob_server, validate_repo_url, validate_target_url


class TargetValidationTests(unittest.TestCase):
    def test_rejects_credentials_and_non_http_website(self):
        for value in ("https://user:pass@example.com", "file:///etc/passwd", "javascript:alert(1)", "https://example.com:0", "https://example.com:bad", "https://example.com/path\nheader"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_target_url(value)

    def test_github_url_is_restricted_to_public_https_shape(self):
        self.assertEqual(validate_repo_url("https://github.com/acme/site"), "https://github.com/acme/site.git")
        for value in ("git@github.com:acme/site.git", "https://evil.example/acme/site", "https://github.com/acme/site/tree/main"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_repo_url(value)

    def test_oob_server_requires_credential_free_https_origin(self):
        self.assertEqual(validate_oob_server("https://callback.example.test/"), "https://callback.example.test")
        for value in ("http://callback.example.test", "https://token@callback.example.test", "https://callback.example.test/path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_oob_server(value)

    def test_unreachable_oob_server_keeps_public_callback_disabled(self):
        spec = {"id": "templates", "label": "Templates", "source": "tools/web/template-scanner/engine", "args": ["-ni"], "full_args": ["-ni"], "output": "nuclei", "timeout": 5}
        ready = {"ready": True, "executable": "fixture-scanner", "source_revision": "rev", "source_version": None, "runtime_version": None, "runtime_origin": "fixture", "rules_revision": "rules", "rules_dirty": False, "runtime": None}
        with tempfile.TemporaryDirectory() as temp, patch("app.core.readiness", return_value=ready), patch("app.core.oob_server_reachable", return_value=False), patch("app.core.run_tool", return_value=SimpleNamespace(returncode=0)) as command:
            _, stage, gaps = scan_one(spec, {"profile": "full", "oob_server": "https://callback.example.test"}, Path(temp))
        self.assertIn("-ni", command.call_args.args[0])
        self.assertEqual(stage["state"], "partial")
        self.assertIn("oob_server_unreachable", {item["code"] for item in gaps})

    def test_errored_scanner_without_observations_is_failed_not_partial(self):
        spec = {"id": "static", "label": "Source analysis", "source": "tools/code/static-analyzer/source", "args": ["{output}"], "output": "semgrep", "timeout": 5}
        ready = {"ready": True, "executable": "fixture-scanner", "source_revision": "rev", "source_version": None, "runtime_version": None, "runtime_origin": "fixture", "rules_revision": "rules", "rules_dirty": False, "runtime": None}

        def invalid_rules(argv, *_args, **_options):
            Path(argv[1]).write_text(json.dumps({"results": [], "errors": [{"type": "SemgrepError"}], "paths": {"scanned": []}}))
            # The credential-like line is assembled at run time so no key-shaped text is committed.
            return SimpleNamespace(returncode=7, stdout="", stderr="invalid configuration file found\n" + "api_key" + "=" + "abcdef0123456789")

        with tempfile.TemporaryDirectory() as temp, patch("app.core.readiness", return_value=ready), patch("app.core.run_tool", side_effect=invalid_rules):
            _, stage, gaps = scan_one(spec, {"profile": "standard"}, Path(temp))
        self.assertEqual(stage["state"], "failed")
        self.assertEqual(stage["details"]["diagnostic"], "invalid configuration file found\napi_key=[redacted]")
        self.assertIn("scanner_error", {item["code"] for item in gaps})

    def test_dependency_scan_reports_checked_lockfiles_or_their_absence(self):
        spec = {"id": "dependencies", "label": "Dependency vulnerabilities", "source": "tools/code/dependency-risk/source", "args": ["{output}"], "output": "osv", "timeout": 5}
        ready = {"ready": True, "executable": "fixture-scanner", "source_revision": "rev", "source_version": None, "runtime_version": None, "runtime_origin": "fixture", "rules_revision": None, "rules_dirty": False, "runtime": None}
        for log, state, codes in (("Scanned /repo/web/package-lock.json file and found 120 packages\n", "completed", set()), ("No package sources found\n", "skipped", {"no_files_analyzed"})):
            def osv(argv, *_args, **_options):
                Path(argv[1]).write_text(json.dumps({"results": []}))
                return SimpleNamespace(returncode=0, stdout="", stderr=log)

            with self.subTest(state=state), tempfile.TemporaryDirectory() as temp, patch("app.core.readiness", return_value=ready), patch("app.core.run_tool", side_effect=osv):
                _, stage, gaps = scan_one(spec, {"profile": "standard", "repo": "/repo"}, Path(temp))
            self.assertEqual(stage["state"], state)
            self.assertEqual({item["code"] for item in gaps}, codes)
        self.assertEqual(stage["details"]["lockfiles"], [])

    def test_throttling_and_blocking_responses_become_limitations(self):
        stages = [{"id": "surface", "details": {"status": 403}}, {"id": "crawler", "details": {"status_counts": {"200": 4, "429": 3}}}, {"id": "browser", "details": {"pages": [{"url": "https://example.test/a", "status": 429}]}}]
        gaps = {item["code"]: item for item in response_signal_gaps(stages)}
        self.assertEqual(set(gaps), {"access_denied", "rate_limited"})
        self.assertIn("4 request", gaps["rate_limited"]["message"])
        self.assertEqual(gaps["rate_limited"]["scanner"], "browser, crawler")
        self.assertEqual(response_signal_gaps([{"id": "crawler", "details": {"status_counts": {"200": 9}}}]), [])

    def test_full_website_scan_requires_explicit_authorization(self):
        with self.assertRaisesRegex(ValueError, "explicit authorization"):
            execute_scan({"url": "https://example.test", "profile": "full"}, lambda *_: None)

    def test_journey_file_requires_full_website_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            journey = Path(temp) / "journey.json"
            journey.write_text('{"journeys": []}')
            with self.assertRaisesRegex(ValueError, "Journey file requires"):
                execute_scan({"url": "https://example.test", "profile": "standard", "journey_file": str(journey)}, lambda *_: None)

    def test_full_scan_options_are_configurable_and_validate_ports(self):
        options = full_scan_options({"port_depth": "custom", "port_range": "443,8000-9000", "crawl_depth": 42})
        self.assertEqual(options["port_range"], "443,8000-9000")
        self.assertEqual((options["port_flag"], options["port_value"]), ("-p", "443,8000-9000"))
        self.assertEqual(options["crawl_depth"], 42)
        for port_range in ("0", "65536", "9000-8000", "80,abc"):
            with self.subTest(port_range=port_range), self.assertRaises(ValueError):
                full_scan_options({"port_depth": "custom", "port_range": port_range})

    def test_port_depth_presets_select_nmaps_top_ports(self):
        presets = {"quick": "100", "standard": "1000", "thorough": "5000"}
        for depth, count in presets.items():
            with self.subTest(depth=depth):
                options = full_scan_options({"port_depth": depth})
                self.assertEqual((options["port_flag"], options["port_value"]), ("--top-ports", count))
        self.assertEqual((full_scan_options({"port_depth": "full"})["port_flag"], full_scan_options({"port_depth": "full"})["port_value"]), ("-p", "1-65535"))
        with self.assertRaisesRegex(ValueError, "Port depth"):
            full_scan_options({"port_depth": "extreme"})


class OutputTests(unittest.TestCase):
    def test_secret_value_never_enters_normalized_finding(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "secrets.json"
            report.write_text(json.dumps([{"Description":"API key", "File":"src/config.py", "StartLine":12, "RuleID":"generic-api-key", "Secret":"DO-NOT-REPORT-THIS", "Match":"DO-NOT-REPORT-THIS"}]))
            findings, _ = parse_output({"id":"secrets","output":"gitleaks"}, report)
            self.assertEqual(len(findings), 1)
            self.assertNotIn("DO-NOT-REPORT-THIS", json.dumps(findings))

    def test_dependency_advisory_includes_package_and_fixed_version(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "osv.json"
            report.write_text(json.dumps({"results": [{"source": {"path": "package-lock.json"}, "packages": [{"package": {"name": "example", "version": "1.0", "ecosystem": "npm"}, "vulnerabilities": [{"id": "GHSA-example", "summary": "Example issue", "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1"}]}]}]}]}]}]}))
            findings, details = parse_output({"id": "dependencies", "output": "osv"}, report)
            self.assertEqual(details["observed"], 1)
            self.assertIn("npm/example@1.0", findings[0]["evidence"])
            self.assertIn("1.1", findings[0]["remediation"])

    def test_application_alert_is_normalized_without_request_body(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "application.json"
            report.write_text(json.dumps({"site": [{"@name": "https://example.test", "alerts": [{"alertRef": "1001", "name": "Missing header", "riskcode": "2", "solution": "<p>Set a safe response header.</p>", "instances": [{"uri": "https://example.test/login", "method": "GET", "param": "", "evidence": "SECRET-BODY"}]}]}]}))
            findings, details = parse_output({"id": "application", "output": "zap"}, report)
            self.assertEqual(details["observed"], 1)
            self.assertEqual(findings[0]["severity"], "medium")
            self.assertIn("Set a safe response header", findings[0]["remediation"])
            self.assertNotIn("SECRET-BODY", json.dumps(findings))

    def test_accessibility_violation_preserves_rule_and_selector(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "axe.json"
            report.write_text(json.dumps({"pages": [{"url": "https://example.test"}], "violations": [{"page": "https://example.test", "id": "image-alt", "impact": "serious", "help": "Images must have alternate text", "help_url": "https://dequeuniversity.com/rules/axe/image-alt", "selectors": [["img.hero"]]}]}))
            findings, details = parse_output({"id": "accessibility", "output": "axe"}, report)
            self.assertEqual(details["observed"], 1)
            self.assertEqual(findings[0]["severity"], "high")
            self.assertIn("img.hero", findings[0]["evidence"])

    def test_lighthouse_measurement_is_not_labeled_as_vulnerability(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "lighthouse.json"
            report.write_text(json.dumps({"lighthouseVersion": "13.5.0", "requestedUrl": "https://example.test/", "categories": {"performance": {"title": "Performance", "score": 0.6, "auditRefs": [{"id": "largest-contentful-paint"}]}}, "audits": {"largest-contentful-paint": {"title": "Largest Contentful Paint", "score": 0.3, "displayValue": "5 s", "description": "Improve the main content rendering."}}}))
            findings, details = parse_output({"id": "performance", "output": "lighthouse"}, report)
            self.assertEqual(details["categories"]["performance"]["score"], 0.6)
            self.assertEqual(findings[0]["severity"], "info")
            self.assertIn("Improve the main content", findings[0]["remediation"])

    def test_journey_cookie_issue_uses_flags_without_cookie_value(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "journey.json"
            report.write_text(json.dumps({"journeys": [{"name": "Login", "passed": False, "final_url": "https://example.test/account", "issues": [{"step": 4, "type": "cookie_flags", "cookie": "session", "missing": ["httpOnly"]}]}], "failed": 1}))
            findings, details = parse_output({"id": "journeys", "output": "journey"}, report)
            self.assertEqual(details["failed"], 1)
            self.assertIn("httpOnly", findings[0]["remediation"])
            self.assertNotIn("value", json.dumps(findings))

    def test_port_states_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "ports.xml"
            report.write_text('<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" version="1"/></port><port protocol="tcp" portid="22"><state state="filtered"/></port></ports></host></nmaprun>')
            _, details = parse_output({"id":"ports","output":"nmap"}, report)
            self.assertEqual([item["state"] for item in details["ports"]], ["open", "filtered"])
            self.assertEqual(details["state_counts"], {"open": 1, "filtered": 1})
            self.assertEqual(details["scanned_count"], 2)

    def test_crawler_inventory_counts_observed_json_responses_without_query_values(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "crawler.jsonl"
            report.write_text(json.dumps({"request": {"method": "GET", "endpoint": "https://example.test/api/users?token=DO-NOT-REPORT"}, "response": {"status_code": 200, "headers": {"content_type": "application/json; charset=utf-8"}}}) + "\n")
            findings, details = parse_output({"id": "crawler", "output": "katana", "inventory_limit": 5}, report)
            self.assertEqual(findings, [])
            self.assertEqual(details["api_observed"], 1)
            self.assertEqual(details["api_endpoints"][0]["url"], "https://example.test/api/users")
            self.assertNotIn("DO-NOT-REPORT", json.dumps(details))

    def test_rescan_only_marks_absence_when_same_check_completed(self):
        old = {"findings": [{"fingerprint": "a", "scanner": "surface"}, {"fingerprint": "b", "scanner": "secrets"}], "stages": [{"id": "surface", "state": "completed", "source_revision": "probe1", "rules_dirty": False}, {"id": "secrets", "state": "completed", "source_revision": "rev1", "rules_revision": "rules1", "rules_dirty": False}]}
        new = {"findings": [], "stages": [{"id": "surface", "state": "completed", "source_revision": "probe1", "rules_dirty": False}, {"id": "secrets", "state": "skipped", "source_revision": "rev1", "rules_revision": "rules1", "rules_dirty": False}]}
        result = compare_reports(old, new)
        self.assertEqual([item["fingerprint"] for item in result["not_observed_on_rescan"]], ["a"])
        self.assertEqual([item["fingerprint"] for item in result["not_verifiable"]], ["b"])

        new["stages"][0]["source_revision"] = "probe2"
        changed = compare_reports(old, new)
        self.assertEqual([item["fingerprint"] for item in changed["not_verifiable"]], ["a", "b"])

    def test_explicit_website_port_is_checked_against_actual_scan_range(self):
        ranges = ["80,443,8000-8009,8443"]
        self.assertTrue(port_in_ranges(8004, ranges))
        self.assertFalse(port_in_ranges(8765, ranges))


if __name__ == "__main__":
    unittest.main()
