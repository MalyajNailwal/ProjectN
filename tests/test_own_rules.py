"""ProjectN's own checks in rules/ match their target issues with the real scanners when installed."""

import base64
import functools
import http.server
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from app.core import ROOT, executable_for, specs


def fake_jwt(role: str) -> str:
    # Built at test time so no key-shaped string is committed; the signature is not valid.
    part = lambda data: base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{part({'alg': 'HS256', 'typ': 'JWT'})}.{part({'iss': 'supabase', 'ref': 'fixture', 'role': role})}.ZmFrZXNpZ25hdHVyZQ"


def scanner(spec_id: str) -> str | None:
    return executable_for(next(spec for spec in specs() if spec["id"] == spec_id))


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass


class OwnRulesTests(unittest.TestCase):
    def test_semgrep_rules_flag_browser_secrets_only(self):
        semgrep = scanner("static")
        if not semgrep:
            self.skipTest("source-analysis runtime is not installed")
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            (source / "client.js").write_text(
                "const a = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY\n"
                "const b = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY\n"
                "const ok1 = process.env.NEXT_PUBLIC_SUPABASE_URL\n"
                "const ok2 = process.env.STRIPE_SECRET_KEY\n"
                f"const service = '{fake_jwt('service_role')}'\n"
                f"const anon = '{fake_jwt('anon')}'\n"
            )
            output = source / "result.json"
            subprocess.run([semgrep, "scan", "--metrics=off", "--config", str(ROOT / "rules/semgrep"), "--json", "--output", str(output), str(source / "client.js")], capture_output=True, timeout=300, check=False)
            results = json.loads(output.read_text())["results"]
        hits = sorted((row["check_id"].rsplit(".", 1)[-1], row["start"]["line"]) for row in results)
        self.assertEqual(hits, [("public-env-secret", 1), ("public-env-secret", 2), ("supabase-service-role-key", 5)])

    def test_nuclei_template_finds_service_role_key_in_page_script(self):
        nuclei = scanner("templates")
        if not nuclei:
            self.skipTest("template-scanner runtime is not installed")
        for role, expected in (("service_role", True), ("anon", False)):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as temp:
                site = Path(temp)
                (site / "assets").mkdir()
                (site / "index.html").write_text('<!doctype html><script type="module" src="/assets/app.js"></script>')
                (site / "assets/app.js").write_text(f"createClient('https://fixture.supabase.co', '{fake_jwt(role)}')")
                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=str(site)))
                threading.Thread(target=server.serve_forever, daemon=True).start()
                try:
                    result = subprocess.run([nuclei, "-u", f"http://127.0.0.1:{server.server_port}/", "-t", str(ROOT / "rules/nuclei"), "-jsonl", "-silent", "-duc", "-ni", "-nc"], capture_output=True, text=True, timeout=300, check=False)
                finally:
                    server.shutdown()
                    server.server_close()
                matched = "supabase-service-role-key-exposed" in result.stdout
                self.assertEqual(matched, expected, result.stdout + result.stderr[-500:])

    def test_nuclei_template_finds_client_side_api_keys(self):
        nuclei = scanner("templates")
        if not nuclei:
            self.skipTest("template-scanner runtime is not installed")
        # Synthetic, pattern-shaped values built at test time; none of these are real credentials.
        keys = {
            "openai-api-key": "sk-" + "a" * 20 + "T3BlbkFJ" + "b" * 20,
            "anthropic-api-key": "sk-ant-api03-" + "c" * 93 + "AA",
            "stripe-secret-key": "sk_test_" + "d" * 24,
            "aws-access-key": "AKIA" + "E" * 16,
        }
        with tempfile.TemporaryDirectory() as temp:
            site = Path(temp)
            (site / "assets").mkdir()
            (site / "index.html").write_text('<!doctype html><script type="module" src="/assets/app.js"></script>')
            (site / "assets/app.js").write_text("\n".join(f"const {name.replace('-', '_')} = '{value}'" for name, value in keys.items()))
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=str(site)))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                result = subprocess.run([nuclei, "-u", f"http://127.0.0.1:{server.server_port}/", "-t", str(ROOT / "rules/nuclei" / "client-side-api-keys-exposed.yaml"), "-jsonl", "-silent", "-duc", "-ni", "-nc"], capture_output=True, text=True, timeout=300, check=False)
            finally:
                server.shutdown()
                server.server_close()
            for name in keys:
                self.assertIn(name, result.stdout, f"{name} not matched: {result.stdout}{result.stderr[-500:]}")

            (site / "assets/app.js").write_text("const greeting = 'hello world'")
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=str(site)))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                clean = subprocess.run([nuclei, "-u", f"http://127.0.0.1:{server.server_port}/", "-t", str(ROOT / "rules/nuclei" / "client-side-api-keys-exposed.yaml"), "-jsonl", "-silent", "-duc", "-ni", "-nc"], capture_output=True, text=True, timeout=300, check=False)
            finally:
                server.shutdown()
                server.server_close()
            self.assertEqual(clean.stdout.strip(), "", f"matched a page with no keys: {clean.stdout}")

    def test_semgrep_rules_flag_log_injection_access_control_and_loose_dependencies(self):
        semgrep = scanner("static")
        if not semgrep:
            self.skipTest("source-analysis runtime is not installed")
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            (source / "client.tsx").write_text(
                "console.log(`Login attempt for user ${req.body.username}`)\n"
                "logger.info(`Processing order ${req.query.orderId}`)\n"
                "console.log(\"safe literal only\")\n"
                "\n"
                "function AdminPanel() {\n"
                "  if (user.role === \"admin\") {\n"
                "    return <Dashboard />\n"
                "  }\n"
                "}\n"
                "\n"
                "const order = await db.order.findFirst({ where: { id: orderId, userId: req.body.userId } })\n"
                "const safeOrder = await db.order.findFirst({ where: { id: orderId, userId: session.user.id } })\n"
            )
            (source / "server.py").write_text(
                "import logging\n"
                "logging.info(f\"User {request.form['username']} not found\")\n"
                "logger.error(f\"Order failed: {request.args['id']}\")\n"
                "print(\"safe literal\")\n"
                "logging.info(\"also safe, no interpolation\")\n"
            )
            (source / "package.json").write_text(json.dumps({
                "name": "demo",
                "scripts": {"postinstall": "node setup.js"},
                "dependencies": {"left-pad": "^1.3.0", "express": "4.18.2", "lodash": "~4.17.21", "react": "18.2.0"},
            }, indent=1))
            output = source / "result.json"
            subprocess.run([semgrep, "scan", "--metrics=off", "--config", str(ROOT / "rules/semgrep"), "--json", "--output", str(output), str(source)], capture_output=True, timeout=300, check=False)
            results = json.loads(output.read_text())["results"]
        hits = sorted((row["check_id"].rsplit(".", 1)[-1], Path(row["path"]).name, row["start"]["line"]) for row in results)
        self.assertEqual(hits, [
            ("client-role-check-only", "client.tsx", 6),
            ("idor-identity-from-request", "client.tsx", 11),
            ("install-script-present", "package.json", 4),
            ("log-injection-from-request", "client.tsx", 1),
            ("log-injection-from-request", "client.tsx", 2),
            ("log-injection-from-request-python", "server.py", 2),
            ("log-injection-from-request-python", "server.py", 3),
            ("loose-version-range", "package.json", 7),
            ("loose-version-range", "package.json", 9),
        ])


if __name__ == "__main__":
    unittest.main()
