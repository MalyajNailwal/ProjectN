"""Enumerate accepted TLS suites with the locally built Nmap NSE script."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from app.core import ROOT, finding, gap, readiness, specs

CONFIG_PATH = ROOT / "config/tls_scan.json"
CONFIG = json.loads(CONFIG_PATH.read_text())
SCRIPT = ROOT / "tools/network/port-and-service-mapper/source/scripts/ssl-enum-ciphers.nse"


def parse_tls_xml(path: Path, host: str, port: int) -> tuple[list[dict], dict]:
    root = ET.parse(path).getroot()
    scripts = root.findall(".//port/script[@id='ssl-enum-ciphers']")
    versions = []
    for script in scripts:
        for table in script.findall("./table"):
            version = table.get("key", "")
            if not version.startswith(("TLS", "SSL")):
                continue
            ciphers = []
            for cipher in table.findall("./table[@key='ciphers']/table"):
                fields = {elem.get("key"): (elem.text or "").strip() for elem in cipher.findall("./elem")}
                if fields.get("name"):
                    ciphers.append({"name": fields["name"], "strength": fields.get("strength"), "key_exchange": fields.get("kex_info")})
            warnings = [(elem.text or "").strip() for elem in table.findall("./table[@key='warnings']/elem")]
            versions.append({"version": version, "ciphers": ciphers, "warnings": warnings})
    found = []
    for item in versions:
        version = item["version"]
        if version in {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}:
            found.append(finding("tls_config", f"Outdated protocol {version} is accepted", "high", f"{host}:{port}", f"Nmap ssl-enum-ciphers enumerated {len(item['ciphers'])} suites for {version}.", "Disable this protocol on the TLS terminator; permit supported modern TLS versions, then repeat cipher enumeration.", f"tls:protocol:{version}", "observed"))
        weak = [cipher for cipher in item["ciphers"] if cipher["strength"] in CONFIG["weak_cipher_grades"]]
        if weak:
            examples = ", ".join(cipher["name"] for cipher in weak[:5])
            found.append(finding("tls_config", f"Weak TLS cipher suites accepted on {version}", "medium", f"{host}:{port}", f"Nmap graded {len(weak)} accepted suites C-F; examples: {examples}.", "Disable the listed weak cipher suites on the TLS terminator and rerun enumeration.", f"tls:weak-ciphers:{version}", "observed"))
    return found, {"versions": versions, "observed": len(versions), "script_result_present": bool(scripts)}


def inspect_tls_config(url: str, host: str) -> tuple[list[dict], dict, list[dict]]:
    label = "TLS protocol and cipher configuration"
    if urlparse(url).scheme != "https":
        return [], {"id": "tls_config", "label": label, "state": "skipped", "summary": "Target URL uses HTTP"}, [gap("tls_config_http", "TLS configuration cannot be enumerated on an HTTP origin.", "Provide the HTTPS origin if one exists.", "tls_config")]
    spec = next(item for item in specs() if item["id"] == "ports")
    ready = readiness(spec)
    if not ready["ready"]:
        return [], {"id": "tls_config", "label": label, "state": "skipped", "summary": "Local Nmap is unavailable"}, [gap("tls_config_unavailable", "; ".join(ready["limitations"]), ready["resolution"], "tls_config")]
    port = urlparse(url).port or 443
    with tempfile.TemporaryDirectory(prefix="projectn-tls-") as temp:
        output = Path(temp) / "tls.xml"
        command = [ready["executable"], "-sT", "-sV", "-Pn", "-p", str(port), "--script", "ssl-enum-ciphers", "-oX", str(output), host]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=CONFIG["timeout_seconds"], shell=False, env={**os.environ, "NMAPDIR": str(ROOT / spec["source"])})
            found, details = parse_tls_xml(output, host, port) if output.is_file() else ([], {"versions": [], "observed": 0, "script_result_present": False})
        except (OSError, subprocess.TimeoutExpired, ET.ParseError, ValueError) as exc:
            return [], {"id": "tls_config", "label": label, "state": "failed", "summary": type(exc).__name__}, [gap("tls_config_failed", "TLS cipher enumeration could not be completed.", "Check target access, Nmap NSE support and the configured timeout, then retry.", "tls_config")]
    state = "completed" if result.returncode == 0 and details["script_result_present"] and details["versions"] else "partial"
    stage = {"id": "tls_config", "label": label, "state": state, "summary": f"{len(details['versions'])} accepted TLS versions; {sum(len(item['ciphers']) for item in details['versions'])} suites", "details": details, "exit_code": result.returncode, "source_revision": ready["source_revision"], "rules_revision": hashlib.sha256(SCRIPT.read_bytes() + CONFIG_PATH.read_bytes()).hexdigest(), "rules_dirty": False}
    issues = [] if state == "completed" else [gap("tls_config_incomplete", "Nmap did not return a complete ssl-enum-ciphers result.", "Check HTTPS reachability and Nmap script diagnostics, then rerun Full scan.", "tls_config")]
    return found, stage, issues
