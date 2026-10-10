from __future__ import annotations

import hashlib
import html
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import tomllib
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv("PROJECTN_DATA_DIR") or ROOT / "data")
CONFIG = json.loads((ROOT / "config" / "scanners.json").read_text(encoding="utf-8"))
COVERAGE = json.loads((ROOT / "config" / "coverage.json").read_text(encoding="utf-8"))
FULL_DEFAULTS = json.loads((ROOT / "config" / "full_scan.json").read_text(encoding="utf-8"))
APPLICATION_CONFIG = json.loads((ROOT / "config" / "application_scan.json").read_text(encoding="utf-8"))
JOURNEY_COVERAGE = json.loads((ROOT / "config" / "journey_coverage.json").read_text(encoding="utf-8"))
PERFORMANCE_CONFIG = json.loads((ROOT / "config" / "performance.json").read_text(encoding="utf-8"))
GITHUB_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


class ScanCancelled(Exception):
    """Raised when the user stops a scan; the running scanner process tree is already terminated."""


def stop_process_tree(process: subprocess.Popen) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)], capture_output=True, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    process.kill()
    process.wait()
    for stream in (process.stdout, process.stderr):
        if stream:
            stream.close()


def run_tool(argv: list[str], timeout: float, cancel=None, **options) -> subprocess.CompletedProcess:
    """Run a scanner like subprocess.run, but stop its whole process tree on timeout or user cancellation."""
    session = {} if os.name == "nt" else {"start_new_session": True}
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", shell=False, **session, **options)
    deadline = time.monotonic() + timeout
    while True:
        try:
            stdout, stderr = process.communicate(timeout=0.5)
            return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            if cancel is not None and cancel.is_set():
                stop_process_tree(process)
                raise ScanCancelled from None
            if time.monotonic() > deadline:
                stop_process_tree(process)
                raise subprocess.TimeoutExpired(argv, timeout) from None


# Nmap's own frequency-ranked port lists; --top-ports N covers the services most commonly found open.
# A full 1-65535 scan is still available (depth "full") but rarely changes the result against a real host
# behind a firewall or CDN, where almost every port above the common set answers "closed" or "filtered".
PORT_DEPTHS = {"quick": "100", "standard": "1000", "thorough": "5000"}


def full_scan_options(request: dict) -> dict:
    options = {key: request.get(key) if request.get(key) is not None else default for key, default in FULL_DEFAULTS.items()}
    depth = options.get("port_depth") or "standard"
    if depth not in {*PORT_DEPTHS, "full", "custom"}:
        raise ValueError("Port depth must be quick, standard, thorough, full, or custom.")
    options["port_depth"] = depth
    if depth == "custom":
        port_range = options["port_range"]
        if not isinstance(port_range, str) or not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", port_range):
            raise ValueError("Port range must be comma-separated TCP ports or ranges, such as 80,443,8000-9000.")
        for segment in port_range.split(","):
            bounds = [int(part) for part in segment.split("-")]
            if any(port < 1 or port > 65535 for port in bounds) or bounds[0] > bounds[-1]:
                raise ValueError("Port range must contain valid TCP ports from 1 through 65535.")
        options["port_flag"], options["port_value"] = "-p", port_range
    elif depth == "full":
        options["port_flag"], options["port_value"] = "-p", "1-65535"
    else:
        options["port_flag"], options["port_value"] = "--top-ports", PORT_DEPTHS[depth]
    for key in ("crawl_depth", "crawl_duration_minutes", "template_rate", "inventory_limit", "browser_page_limit"):
        if type(options[key]) is not int or options[key] < 1:
            raise ValueError(f"{key} must be a positive whole number.")
    return options


def validate_target_url(value: str) -> tuple[str, str]:
    value = value.strip()
    if re.search(r"[\x00-\x1f\x7f]", value) or any(char.isspace() for char in value):
        raise ValueError("Website URL contains invalid whitespace or control characters.")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter an http:// or https:// website URL without embedded credentials.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Website URL has an invalid port.") from exc
    if port == 0:
        raise ValueError("Website URL has an invalid port.")
    return urlunparse(parsed._replace(fragment="")), parsed.hostname


def public_url(value: str) -> str:
    """Keep target identity while withholding query values from stored reports."""
    return urlunparse(urlparse(value)._replace(query="", fragment=""))


def validate_oob_server(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or re.search(r"\s", value):
        raise ValueError("OOB callback server must be an HTTPS origin without credentials or a path.")
    return value.strip().rstrip("/")


def oob_server_reachable(value: str) -> bool:
    try:
        with urllib.request.urlopen(urllib.request.Request(value, method="GET"), timeout=5) as response:
            return response.status < 500
    except urllib.error.HTTPError as exc:
        return exc.code < 500
    except (OSError, ValueError):
        return False


def validate_repo_url(value: str) -> str:
    match = GITHUB_RE.fullmatch(value.strip())
    if not match or match.group(1) in {".", ".."} or match.group(2) in {".", ".."}:
        raise ValueError("Enter a public GitHub repository HTTPS URL, such as https://github.com/owner/repo.")
    return f"https://github.com/{match.group(1)}/{match.group(2)}.git"


def specs() -> list[dict]:
    return CONFIG["scanners"]


def executable_for(spec: dict) -> str | None:
    override = os.getenv(f"PROJECTN_SCANNER_{spec['id'].upper()}")
    if override:
        candidate = Path(override).expanduser()
        return str(candidate) if candidate.is_file() else None
    if spec["id"] == "technology":
        return shutil.which("ruby")
    if spec["id"] == "application":
        return shutil.which("java")
    if spec["id"] == "ports" and os.name == "nt":
        return shutil.which("nmap")
    suffix = ".exe" if os.name == "nt" else ""
    if spec["id"] == "static":
        environment_bin = ROOT / "tools" / "venvs" / "static-analyzer" / ("Scripts" if os.name == "nt" else "bin") / ("semgrep" + suffix)
        if environment_bin.is_file():
            return str(environment_bin)
    if spec["id"] in {"browser", "journeys", "accessibility", "performance"}:
        environment_python = ROOT / "tools" / "venvs" / "browser-journeys" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        return str(environment_python) if environment_python.is_file() else None
    candidate = ROOT / "tools" / "bin" / (spec["executable"] + suffix)
    return str(candidate) if candidate.is_file() else None


def readiness(spec: dict) -> dict:
    executable = executable_for(spec)
    source = ROOT / spec["source"]
    missing = []
    if not (source / ".git").exists():
        missing.append("local scanner source repository is missing")
    if not executable:
        missing.append(f"{spec['executable']} executable was not found")
    if spec["id"] == "technology" and not (source / "whatweb").is_file():
        missing.append("local technology-profiler source is missing")
    if executable and spec.get("ruby_requires"):
        for package in spec["ruby_requires"]:
            check = subprocess.run([executable, "-e", f"require '{package}'"], capture_output=True, timeout=10, shell=False)
            if check.returncode:
                missing.append(f"Ruby dependency {package} is missing")
    if spec["id"] == "templates" and not (ROOT / "tools/web/template-scanner/checks").is_dir():
        missing.append("local vulnerability checks are missing")
    if spec["id"] == "static" and not (ROOT / "tools/code/static-analyzer/checks/.git").exists():
        missing.append("local source-analysis rules are missing")
    if spec["id"] == "accessibility" and not (source / "axe.js").is_file():
        missing.append("locally built accessibility script is missing")
    source_version = None
    runtime_version = None
    if spec["id"] == "ports" and executable:
        try:
            check = subprocess.run([executable, "-version"], capture_output=True, text=True, timeout=10, shell=False)
            match = re.search(r"Nmap version ([^\s]+)", check.stdout) if check.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            match = None
        runtime_version = match.group(1) if match else None
        if runtime_version is None:
            missing.append("Nmap executable did not return a version")
    if spec["id"] == "static":
        source_version = tomllib.loads((source / "cli/pyproject.toml").read_text(encoding="utf-8"))["project"]["version"] if (source / "cli/pyproject.toml").is_file() else None
        python = ROOT / "tools/venvs/static-analyzer" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if python.is_file():
            check = subprocess.run([str(python), "-c", "from importlib.metadata import version; print(version('semgrep'))"], capture_output=True, text=True, timeout=10, shell=False)
            runtime_version = check.stdout.strip() if check.returncode == 0 else None
    elif spec["id"] in {"browser", "journeys"}:
        source_version = (source / "DRIVER_VERSION").read_text(encoding="utf-8").strip() if (source / "DRIVER_VERSION").is_file() else None
        python = ROOT / "tools/venvs/browser-journeys" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if python.is_file():
            check = subprocess.run([str(python), "-c", "from importlib.metadata import version; print(version('playwright'))"], capture_output=True, text=True, timeout=10, shell=False)
            runtime_version = check.stdout.strip() if check.returncode == 0 else None
    elif spec["id"] == "accessibility" and (source / "package.json").is_file() and (source / "axe.js").is_file():
        source_version = json.loads((source / "package.json").read_text(encoding="utf-8"))["version"]
        with (source / "axe.js").open(encoding="utf-8", errors="replace") as script:
            header = script.readline()
        match = re.search(r"axe v([0-9.]+)", header)
        runtime_version = match.group(1) if match else None
    runtime = None
    if spec["id"] == "performance":
        package = ROOT / "tools/venvs/performance/node_modules/lighthouse"
        runtime = str(package) if (package / "cli/index.js").is_file() else None
        if runtime is None:
            missing.append("matching local Lighthouse runtime is missing")
        if (source / "package.json").is_file() and (package / "package.json").is_file():
            source_version = json.loads((source / "package.json").read_text(encoding="utf-8"))["version"]
            runtime_version = json.loads((package / "package.json").read_text(encoding="utf-8"))["version"]
    if source_version and runtime_version != source_version:
        missing.append(f"runtime version {runtime_version or 'unknown'} does not match cloned source version {source_version}")
    if spec["id"] == "application":
        distribution = ROOT / "tools/web/application-scanner/core/zap/build/distFiles"
        jars = sorted(distribution.glob("zap-*.jar"))
        runtime = str(jars[-1]) if jars else None
        if runtime is None:
            missing.append("locally built application-scanner core distribution is missing")
        plugins = distribution / "plugin"
        for name in APPLICATION_CONFIG["addons"]:
            if not list(plugins.glob(f"{name}-*.zap")):
                missing.append(f"application-scanner add-on {name} is missing")
    revision = None
    if (source / ".git").exists():
        check = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10, shell=False)
        revision = check.stdout.strip() if check.returncode == 0 else None
    rules_revision = None
    rules_dirty = None if spec["id"] == "application" else False
    if spec.get("rules_source"):
        rules = ROOT / spec["rules_source"]
        if rules.is_file():
            rules_revision = hashlib.sha256(rules.read_bytes()).hexdigest()
        elif (rules / ".git").exists():
            check = subprocess.run(["git", "-C", str(rules), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10, shell=False)
            rules_revision = check.stdout.strip() if check.returncode == 0 else None
            if spec["id"] != "application":
                status = subprocess.run(["git", "-C", str(rules), "status", "--porcelain"], capture_output=True, text=True, timeout=15, shell=False)
                rules_dirty = bool(status.stdout.strip()) or status.returncode != 0
    if spec["id"] == "application" and runtime and not missing:
        digest = hashlib.sha256()
        runtime_files = [Path(runtime)]
        plugin_dir = Path(runtime).parent / "plugin"
        for name in APPLICATION_CONFIG["addons"]:
            runtime_files.extend(sorted(plugin_dir.glob(f"{name}-*.zap")))
        for artifact in runtime_files:
            digest.update(artifact.name.encode())
            with artifact.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        rules_revision = digest.hexdigest()
        rules_dirty = False
    if spec.get("local_rules"):
        # ProjectN's own checks are part of the rule revision, so rescans notice rule changes.
        local = ROOT / spec["local_rules"]
        digest = hashlib.sha256((rules_revision or "").encode())
        for rule_file in sorted(path for path in local.rglob("*") if path.is_file()):
            digest.update(rule_file.relative_to(ROOT).as_posix().encode())
            digest.update(rule_file.read_bytes())
        rules_revision = digest.hexdigest()
        if not local.is_dir():
            missing.append(f"ProjectN rules folder {spec['local_rules']} is missing")
    return {"id": spec["id"], "label": spec["label"], "kind": spec["kind"], "ready": not missing, "source_present": (source / ".git").exists(), "source_revision": revision, "source_version": source_version, "runtime_version": runtime_version, "runtime_origin": "Official Windows Nmap runtime" if spec["id"] == "ports" and os.name == "nt" else "Version-matched package" if spec["id"] in {"static", "browser", "journeys", "accessibility", "performance"} else "Cloned source script" if spec["id"] == "technology" else "Built from source", "rules_revision": rules_revision, "rules_dirty": rules_dirty, "executable": executable, "runtime": runtime, "limitations": missing, "resolution": "Install official Nmap for Windows and add it to PATH or set PROJECTN_SCANNER_PORTS; the source checkout is kept separately." if spec["id"] == "ports" and os.name == "nt" and missing else f"Run `python scripts/setup_native.py {spec['setup']}` from the ProjectN folder (on Windows `py -3`), or set PROJECTN_SCANNER_{spec['id'].upper()} to your own build, then refresh Tool setup." if missing else None}


SECRET_TEXT = re.compile(r"(?i)((?:api[_-]?key|token|secret|password|passwd|authorization|cookie)[\"']?\s*[=:]\s*)\S+|[A-Za-z0-9_+=-]{32,}")


def diagnostic(*outputs: str | None) -> str:
    """Last lines of a failed scanner's output, with credential-like values masked, for the report."""
    lines = [line for text in outputs for line in (text or "").splitlines() if line.strip()][-12:]
    return SECRET_TEXT.sub(lambda match: (match.group(1) or "") + "[redacted]", "\n".join(lines))[-1500:]


def gap(code: str, message: str, resolution: str, scanner: str | None = None) -> dict:
    return {"code": code, "message": message, "resolution": resolution, "scanner": scanner}


def builtin_revision(*paths: str) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        digest.update(relative.encode())
        digest.update((ROOT / relative).read_bytes())
    return digest.hexdigest()


def finding(scanner: str, title: str, severity: str, location: str, evidence: str, remediation: str, rule: str = "", confidence: str = "needs-review") -> dict:
    return {"id": str(uuid.uuid4()), "scanner": scanner, "title": title, "severity": severity.lower(), "location": location, "evidence": evidence[:1000], "remediation": remediation, "rule": rule, "confidence": confidence, "verification": "Apply the fix, then rerun this scan against the same target and check."}


def port_in_ranges(port: int, ranges: list[str]) -> bool:
    for group in ranges:
        for segment in group.split(","):
            bounds = segment.strip().split("-", 1)
            if bounds[0].isdigit() and (int(bounds[0]) == port if len(bounds) == 1 else bounds[1].isdigit() and int(bounds[0]) <= port <= int(bounds[1])):
                return True
    return False


def summarize_port_states(details: dict) -> None:
    counts: dict[str, int] = {}
    for item in details.get("ports", []):
        counts[item["state"]] = counts.get(item["state"], 0) + 1
    for item in details.get("aggregate_states", []):
        counts[item["state"]] = counts.get(item["state"], 0) + item["count"]
    details["state_counts"] = counts
    details["scanned_count"] = sum(counts.values())


def parse_output(spec: dict, output: Path) -> tuple[list[dict], dict]:
    kind = spec["output"]
    if not output.is_file() or output.stat().st_size == 0:
        return [], {"observed": 0}
    if kind in {"nuclei", "katana"}:
        rows = [json.loads(line) for line in output.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
        if kind == "katana":
            inventory = {}
            for row in rows:
                request = row.get("request") if isinstance(row.get("request"), dict) else {}
                response = row.get("response") if isinstance(row.get("response"), dict) else {}
                raw_url = request.get("endpoint") or row.get("url")
                if not raw_url:
                    continue
                clean_url = public_url(raw_url)
                headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}
                content_type = str(headers.get("content_type", "")).split(";", 1)[0].lower()
                inventory[(request.get("method", "GET"), clean_url)] = {"method": request.get("method", "GET"), "url": clean_url, "status": response.get("status_code"), "content_type": content_type}
            entries = sorted(inventory.values(), key=lambda item: (item["url"], item["method"]))
            api_entries = [item for item in entries if item["content_type"] == "application/json" or item["content_type"].endswith("+json")]
            limit = spec.get("inventory_limit", 500)
            return [], {"observed": len(entries), "status_counts": dict(Counter(str(item["status"]) for item in entries if item["status"])), "urls": sorted({item["url"] for item in entries})[:limit], "api_endpoints": api_entries[:limit], "api_observed": len(api_entries), "inventory_truncated": len(entries) > limit or len(api_entries) > limit}
        found = []
        for row in rows:
            info = row.get("info", {})
            found.append(finding(spec["id"], info.get("name", row.get("template-id", "Template match")), info.get("severity", "unknown"), row.get("matched-at", row.get("host", "")), row.get("matcher-name", "Template matcher reported a hit"), info.get("remediation", "Review the matched template, confirm the affected component, apply the vendor or configuration fix, and rescan."), row.get("template-id", "")))
        return found, {"observed": len(rows), "oob_interactions": sum(bool(row.get("interaction")) for row in rows)}
    if kind == "nmap":
        tree = ET.parse(output)
        ports = []
        scan_ranges = [item.attrib.get("services", "") for item in tree.findall("./scaninfo")]
        aggregate_states = []
        host_states = []
        for host in tree.findall(".//host"):
            address = host.find("address")
            ip = address.attrib.get("addr", "") if address is not None else ""
            host_status = host.find("status")
            host_states.append({"host": ip, "state": host_status.attrib.get("state", "unknown") if host_status is not None else "unknown"})
            for extra in host.findall("./ports/extraports"):
                aggregate_states.append({"host": ip, "state": extra.attrib.get("state", "unknown"), "count": int(extra.attrib.get("count", "0"))})
            for item in host.findall("./ports/port"):
                state = item.find("state")
                service = item.find("service")
                ports.append({"host": ip, "protocol": item.attrib.get("protocol"), "port": int(item.attrib.get("portid", "0")), "state": state.attrib.get("state", "unknown") if state is not None else "unknown", "service": service.attrib.get("name", "unknown") if service is not None else "unknown", "version": service.attrib.get("version", "") if service is not None else "", "service_method": service.attrib.get("method", "unknown") if service is not None else "unknown", "service_confidence": int(service.attrib.get("conf", "0")) if service is not None else 0})
        details = {"observed": len(ports), "ports": ports, "scanned_ports": scan_ranges, "aggregate_states": aggregate_states, "hosts": host_states, "vantage": "this machine"}
        summarize_port_states(details)
        return [], details
    data = json.loads(output.read_text(encoding="utf-8", errors="replace"))
    if kind == "semgrep":
        found = []
        for row in data.get("results", []):
            extra = row.get("extra", {})
            meta = extra.get("metadata", {})
            severity = str(extra.get("severity", "unknown")).lower()
            found.append(finding(spec["id"], extra.get("message", row.get("check_id", "Code finding")), {"error": "high", "warning": "medium", "info": "low"}.get(severity, severity), f"{row.get('path', '')}:{row.get('start', {}).get('line', '')}", row.get("check_id", "Rule matched source code"), meta.get("fix", "Review the highlighted code and rule guidance, change the unsafe pattern, then rescan."), row.get("check_id", "")))
        return found, {"observed": len(data.get("results", [])), "errors": len(data.get("errors", [])), "files_scanned": len(data.get("paths", {}).get("scanned", []))}
    if kind == "gitleaks":
        found = []
        for row in data:
            found.append(finding(spec["id"], row.get("Description", "Potential secret"), "high", f"{row.get('File', '')}:{row.get('StartLine', '')}", "Secret value redacted. Rule: " + row.get("RuleID", ""), "Rotate or revoke the credential, remove it from the current files and Git history where appropriate, then rescan.", row.get("RuleID", "")))
        return found, {"observed": len(data)}
    if kind == "osv":
        found = []
        packages = 0
        for source in data.get("results", []):
            source_path = source.get("source", {}).get("path", "")
            for item in source.get("packages", []):
                package = item.get("package", {})
                packages += 1
                for advisory in item.get("vulnerabilities", []):
                    fixes = sorted({event["fixed"] for affected in advisory.get("affected", []) for scope in affected.get("ranges", []) for event in scope.get("events", []) if event.get("fixed")})
                    advisory_id = advisory.get("id", "unknown advisory")
                    title = advisory.get("summary") or advisory_id
                    component = f"{package.get('ecosystem', 'unknown')}/{package.get('name', 'unknown')}@{package.get('version', 'unknown')}"
                    raw_severity = str(advisory.get("database_specific", {}).get("severity", "unknown")).lower()
                    severity = "medium" if raw_severity == "moderate" else raw_severity if raw_severity in {"critical", "high", "medium", "low"} else "unknown"
                    remedy = f"Upgrade to a fixed release (reported: {', '.join(fixes)}), confirm compatibility, and rescan." if fixes else "Review the advisory for a patched version or mitigation, update the dependency, and rescan."
                    found.append(finding(spec["id"], title, severity, source_path, f"{component}: {advisory_id}", remedy, advisory_id, "dependency-match"))
        return found, {"observed": len(found), "packages": packages}
    if kind == "browser":
        return [], {"observed": len(data.get("pages", [])), "pages": data.get("pages", []), "forms": data.get("forms", []), "api_endpoints": data.get("api_endpoints", []), "errors": data.get("errors", []), "pending_count": data.get("pending_count", 0), "page_limit": data.get("page_limit")}
    if kind == "journey":
        found = []
        for item in data.get("journeys", []):
            for issue in item.get("issues", []):
                if issue.get("type") == "cookie_flags":
                    missing = ", ".join(issue.get("missing", []))
                    found.append(finding(spec["id"], f"Session cookie {issue['cookie']} lacks required flags", "medium", item.get("final_url") or "", f"Configured journey {item['name']} observed cookie {issue['cookie']} without {missing}.", f"Set {missing} on the session cookie where appropriate, then rerun the configured journey.", "auth:cookie_flags", "observed"))
        return found, {"observed": len(data.get("journeys", [])), "journeys": data.get("journeys", []), "failed": data.get("failed", 0)}
    if kind == "zap":
        found = []
        hosts = []
        risk = {"0": "info", "1": "low", "2": "medium", "3": "high"}
        for site in data.get("site", []):
            hosts.append(site.get("@name", ""))
            for alert in site.get("alerts", []):
                instances = alert.get("instances", [])
                example = instances[0] if instances else {}
                solution = html.unescape(re.sub(r"<[^>]+>", " ", alert.get("solution", ""))).strip()
                guidance = re.sub(r"\s+", " ", solution) or "Review the alert guidance, correct the affected application behavior, and rescan."
                evidence = f"ZAP rule {alert.get('alertRef') or alert.get('pluginid', '')}; {len(instances)} observed instance(s); method {example.get('method', 'unknown')}; parameter {example.get('param', '')}"
                found.append(finding(spec["id"], alert.get("name") or alert.get("alert", "Application alert"), risk.get(str(alert.get("riskcode")), "unknown"), example.get("uri") or site.get("@name", ""), evidence, guidance, str(alert.get("alertRef") or alert.get("pluginid", ""))))
        return found, {"observed": len(found), "sites": hosts}
    if kind == "axe":
        found = []
        severity = {"critical": "critical", "serious": "high", "moderate": "medium", "minor": "low"}
        for item in data.get("violations", []):
            selectors = [" ".join(str(part) for part in target) for target in item.get("selectors", [])]
            found.append(finding(spec["id"], item.get("help") or item.get("id", "Accessibility issue"), severity.get(item.get("impact"), "unknown"), item.get("page", ""), f"axe rule {item.get('id', '')}; affected elements: {', '.join(selectors[:5])}", f"Follow the axe rule guidance at {item.get('help_url', '')}, fix the affected elements, and rerun accessibility checks.", str(item.get("id", "")), "observed"))
        return found, {"observed": len(found), "pages": data.get("pages", []), "errors": data.get("errors", []), "pending_count": data.get("pending_count", 0), "page_limit": data.get("page_limit"), "tags": data.get("tags", [])}
    if kind == "lighthouse":
        categories = {key: {"title": value.get("title"), "score": value.get("score")} for key, value in data.get("categories", {}).items()}
        selected = {reference.get("id") for value in data.get("categories", {}).values() for reference in value.get("auditRefs", [])}
        candidates = []
        for audit_id in selected:
            audit = data.get("audits", {}).get(audit_id, {})
            score = audit.get("score")
            if isinstance(score, (int, float)) and score < PERFORMANCE_CONFIG["minimum_audit_score"]:
                candidates.append((score, audit_id, audit))
        candidates.sort(key=lambda item: item[0])
        found = []
        for score, audit_id, audit in candidates[:PERFORMANCE_CONFIG["max_findings"]]:
            found.append(finding(spec["id"], audit.get("title", audit_id), "info", data.get("finalDisplayedUrl") or data.get("requestedUrl", ""), f"Lighthouse score {score:.2f}; {audit.get('displayValue', '')}", audit.get("description", "Review the audit recommendation and rerun Lighthouse after improving the page."), audit_id, "measurement"))
        details = {"observed": len(candidates), "reported": len(found), "categories": categories, "lighthouse_version": data.get("lighthouseVersion"), "requested_url": public_url(data.get("requestedUrl", "")) if data.get("requestedUrl") else None, "final_url": public_url(data.get("finalDisplayedUrl", "")) if data.get("finalDisplayedUrl") else None, "error": data.get("error")}
        return found, details
    if kind == "whatweb":
        rows = data if isinstance(data, list) else [data]
        tech = sorted({name for row in rows for name in row.get("plugins", {}).keys()})
        return [], {"observed": len(tech), "technologies": tech}
    return [], {"observed": 0}


def scan_one(spec: dict, values: dict, work: Path, cancel=None) -> tuple[list[dict], dict, list[dict]]:
    ready = readiness(spec)
    if not ready["ready"]:
        return [], {"id": spec["id"], "label": spec["label"], "state": "skipped", "summary": "Scanner setup incomplete", "source_revision": ready["source_revision"], "source_version": ready["source_version"], "runtime_version": ready["runtime_version"], "runtime_origin": ready["runtime_origin"], "rules_revision": ready["rules_revision"], "rules_dirty": ready["rules_dirty"]}, [gap("scanner_unavailable", "; ".join(ready["limitations"]), ready["resolution"], spec["id"])]
    output = work / f"{spec['id']}.json"
    substitutions = {**values, "source": str(ROOT / spec["source"]), "root": str(ROOT), "output": str(output), "runtime": ready.get("runtime") or "", "zap_home": str(work / "application-home")}
    full = values.get("profile") == "full"
    args_template = spec.get("full_args", spec["args"]) if full else spec["args"]
    oob_issue = None
    if spec["id"] == "templates" and full and values.get("oob_server"):
        server = values["oob_server"]
        if oob_server_reachable(server):
            config_path = work / "template-callback.yaml"
            token_name = values.get("oob_token_env")
            token = os.getenv(token_name) if token_name else None
            if token_name and not token:
                oob_issue = gap("oob_token_missing", f"Callback token environment variable {token_name} is not set.", "Set the token in the local process environment and rerun Full scan.", "templates")
            else:
                args_template = [part for part in args_template if part != "-ni"]
                lines = [f"interactsh-server: {json.dumps(server)}"]
                if token:
                    lines.append(f"interactsh-token: {json.dumps(token)}")
                config_path.write_text("\n".join(lines) + "\n")
                config_path.chmod(0o600)
                args_template = [*args_template, "-config", str(config_path)]
        else:
            oob_issue = gap("oob_server_unreachable", "The configured callback server did not respond from this machine.", "Start the self-hosted callback service, check HTTPS and network access, then rerun Full scan.", "templates")
    timeout = spec.get("full_timeout", spec["timeout"]) if full else spec["timeout"]
    output_spec = {**spec, "inventory_limit": values.get("inventory_limit", FULL_DEFAULTS["inventory_limit"])} if full else spec
    argv = [ready["executable"], *(part.format_map(substitutions) for part in args_template)]
    scanner_env = {**os.environ, **spec.get("env", {}), **({"NMAPDIR": str(ROOT / spec["source"])} if spec["id"] == "ports" else {})}
    try:
        result = run_tool(argv, timeout, cancel, cwd=ROOT, env=scanner_env)
        findings, details = parse_output(output_spec, output)
        extra_issues = []
        if spec["id"] == "ports" and result.returncode == 0 and values.get("url"):
            target_port = urlparse(values["url"]).port
            if target_port and not port_in_ranges(target_port, details.get("scanned_ports", [])):
                extra_output = work / "ports-target.xml"
                extra_values = {**substitutions, "port": str(target_port), "output": str(extra_output)}
                extra_argv = [ready["executable"], *(part.format_map(extra_values) for part in spec["explicit_port_args"])]
                try:
                    extra = run_tool(extra_argv, timeout, cancel, cwd=ROOT, env=scanner_env)
                    if extra.returncode == 0:
                        _, extra_details = parse_output(spec, extra_output)
                        details["ports"] = list({(item["host"], item["protocol"], item["port"]): item for item in details["ports"] + extra_details["ports"]}.values())
                        details["scanned_ports"].extend(extra_details["scanned_ports"])
                        details["aggregate_states"].extend(extra_details["aggregate_states"])
                        details["hosts"].extend(extra_details["hosts"])
                        details["observed"] = len(details["ports"])
                        summarize_port_states(details)
                    else:
                        extra_issues.append(gap("target_port_unscanned", f"The website's explicit port {target_port} could not be scanned.", "Check local network access and retry the port scan.", spec["id"]))
                except (OSError, subprocess.TimeoutExpired, ET.ParseError, ValueError):
                    extra_issues.append(gap("target_port_unscanned", f"The website's explicit port {target_port} could not be scanned.", "Check local network access and retry the port scan.", spec["id"]))
        acceptable = result.returncode == 0 or (spec["id"] in {"secrets", "dependencies"} and result.returncode == 1 and bool(findings))
        if spec["id"] == "application" and not output.is_file():
            acceptable = False
        # A scanner that exits with an error and observed nothing has not partially covered anything.
        state = "completed" if acceptable and not extra_issues else "partial" if output.exists() and (acceptable or details.get("observed")) else "failed"
        if not acceptable:
            details["diagnostic"] = diagnostic(result.stdout, result.stderr)
        issues = extra_issues if acceptable else extra_issues + [gap("scanner_error", f"{spec['label']} exited with code {result.returncode}.", "Read the scanner output shown under this stage on the Coverage page, fix the setup or target access it points to, then retry.", spec["id"])]
        if oob_issue:
            issues.append(oob_issue)
        elif spec["id"] == "templates" and full and values.get("oob_server") and not details.get("oob_interactions"):
            issues.append(gap("oob_target_reachability_unverified", "The callback server responded locally, but target-to-callback reachability was not independently verified.", "Confirm an interaction with a controlled OOB test before treating absent OOB findings as coverage.", "templates"))
        if spec["id"] == "dependencies":
            # OSV-Scanner omits clean packages from its JSON, so the checked lockfiles come from its scan log.
            scanned = re.findall(r"Scanned (.+?) file and found (\d+) package", (result.stdout or "") + (result.stderr or ""))
            details["lockfiles"] = [{"path": path.replace(values.get("repo", "") + os.sep, ""), "packages": int(count)} for path, count in scanned]
            details["files_scanned"] = len(scanned)
            details["packages"] = sum(int(count) for _, count in scanned)
        if acceptable and details.get("files_scanned") == 0 and spec["id"] in {"static", "dependencies"}:
            message, action = ("Source analysis did not analyze any files.", "Check that the folder contains source files in supported languages that are not excluded by .gitignore or .semgrepignore, then rescan.") if spec["id"] == "static" else ("No supported dependency lockfile was found, so dependency vulnerabilities were not assessed.", "Commit a lockfile such as package-lock.json, poetry.lock, go.sum, Cargo.lock, or a pinned requirements.txt, then rescan.")
            issues.append(gap("no_files_analyzed", message, action, spec["id"]))
        if details.get("errors"):
            error_count = len(details["errors"]) if isinstance(details["errors"], list) else details["errors"]
            issues.append(gap("scanner_partial", f"{error_count} target or parser errors were reported.", "Review the stage details and target access, then rerun the scan.", spec["id"]))
        if spec["id"] in {"browser", "accessibility"} and details.get("pending_count"):
            issues.append(gap("browser_page_limit", f"Page-level checks reached their {details['page_limit']} page limit.", "Increase browser_page_limit in Full scan settings and rescan.", spec["id"]))
        if spec["id"] == "journeys" and details.get("failed"):
            issues.append(gap("journey_incomplete", f"{details['failed']} configured browser journey(s) did not complete their expected steps.", "Review the journey step results and selectors, correct the application or configuration, then retry.", spec["id"]))
        if spec["id"] == "performance" and details.get("observed", 0) > details.get("reported", 0):
            issues.append(gap("performance_findings_truncated", "Some measured Lighthouse opportunities were omitted from the report display.", "Increase max_findings in config/performance.json and rescan.", spec["id"]))
        if details.get("inventory_truncated"):
            issues.append(gap("inventory_truncated", "The discovered endpoint inventory exceeded the report display limit.", "Increase the Full scan inventory limit and rescan.", spec["id"]))
        if issues and state == "completed":
            state = "skipped" if details.get("files_scanned") == 0 else "partial"
        summary = f"{details.get('state_counts', {}).get('open', 0)} open of {details.get('scanned_count', 0)} scanned" if spec["id"] == "ports" else f"{details.get('observed', 0)} observed" + (f" in {details['files_scanned']} file{'' if details['files_scanned'] == 1 else 's'}" if "files_scanned" in details else "") + (f" ({details['packages']} packages)" if spec["id"] == "dependencies" else "")
        return findings, {"id": spec["id"], "label": spec["label"], "state": state, "summary": summary, "details": details, "exit_code": result.returncode, "source_revision": ready["source_revision"], "source_version": ready["source_version"], "runtime_version": ready["runtime_version"], "runtime_origin": ready["runtime_origin"], "rules_revision": ready["rules_revision"], "rules_dirty": ready["rules_dirty"], "profile": values.get("profile", "standard")}, issues
    except subprocess.TimeoutExpired:
        return [], {"id": spec["id"], "label": spec["label"], "state": "failed", "summary": "Time limit reached"}, [gap("timeout", f"{spec['label']} reached its {timeout} second limit.", "Narrow the scope or increase the scanner timeout in configuration, then retry.", spec["id"])]
    except (OSError, ValueError, json.JSONDecodeError, ET.ParseError, KeyError) as exc:
        return [], {"id": spec["id"], "label": spec["label"], "state": "failed", "summary": "Output could not be processed"}, [gap("invalid_output", f"{spec['label']}: {type(exc).__name__}", "Check scanner version and output format, then retry.", spec["id"])]


def response_signal_gaps(stages: list[dict]) -> list[dict]:
    """Report throttling and blocking from HTTP statuses the stages actually observed."""
    observed: dict[str, Counter] = {}
    for stage in stages:
        details = stage.get("details") or {}
        counts = Counter(details.get("status_counts", {}))
        counts.update(str(page["status"]) for page in details.get("pages", []) if isinstance(page, dict) and page.get("status"))
        if stage["id"] == "surface" and details.get("status"):
            counts[str(details["status"])] += 1
        for status, count in counts.items():
            observed.setdefault(status, Counter())[stage["id"]] += count
    issues = []
    for status, signal in COVERAGE["response_signals"].items():
        if by_stage := observed.get(status):
            issues.append(gap(signal["code"], signal["message"].format(count=sum(by_stage.values())), signal["resolution"], ", ".join(sorted(by_stage))))
    return issues


def execute_scan(request: dict, progress, cancel=None) -> dict:
    from app.infra_probe import inspect_infrastructure
    from app.web_probe import inspect_website
    from app.tls_probe import inspect_tls
    from app.tls_config_probe import inspect_tls_config
    from app.api_spec_probe import inspect_api_spec

    started = time.time()
    if request.get("profile") == "full" and request.get("url") and not request.get("authorized_intrusive"):
        raise ValueError("Full scan requires explicit authorization for intrusive checks.")
    full_options = full_scan_options(request) if request.get("profile") == "full" else FULL_DEFAULTS
    url, host = validate_target_url(request["url"]) if request.get("url") else (None, None)
    repo_url = validate_repo_url(request["repo_url"]) if request.get("repo_url") else None
    local_path = Path(request["local_path"]).expanduser().resolve() if request.get("local_path") else None
    journey_file = Path(request["journey_file"]).expanduser().resolve() if request.get("journey_file") else None
    oob_server = validate_oob_server(request["oob_server"]) if request.get("oob_server") else None
    oob_token_env = request.get("oob_token_env")
    if oob_token_env and (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", oob_token_env) or not oob_server):
        raise ValueError("OOB token must name a local environment variable and requires an OOB server.")
    if oob_server and (not url or request.get("profile") != "full"):
        raise ValueError("OOB callback server requires a Full website scan.")
    api_spec_file = Path(request["api_spec_file"]).expanduser().resolve() if request.get("api_spec_file") else None
    if repo_url and local_path:
        raise ValueError("Choose either a public GitHub repository or a local source folder for one scan.")
    if not (url or repo_url or local_path):
        raise ValueError("Provide a website URL, public GitHub URL, or local source folder.")
    if local_path and not local_path.is_dir():
        raise ValueError("Local source folder does not exist.")
    if journey_file and (not url or request.get("profile") != "full" or not journey_file.is_file()):
        raise ValueError("Journey file requires a Full website scan and an existing local JSON file.")
    if api_spec_file and (not url or not api_spec_file.is_file()):
        raise ValueError("API specification requires a website URL and an existing local JSON or YAML file.")
    findings, stages, limitations = [], [], []
    profile = request.get("profile", "standard")
    selected = [s for s in specs() if ((s["kind"] in {"web", "network"} and url) or (s["kind"] == "code" and (repo_url or local_path))) and (s["id"] != "templates" or profile in {"deep", "full"}) and (not s.get("full_only") or profile == "full") and (not s.get("requires_journey_file") or journey_file)]
    steps = [{"id": "clone", "label": "Clone public repository"}] if repo_url else []
    if url:
        steps += [{"id": "surface", "label": "HTTP surface"}, {"id": "tls", "label": "TLS certificate and connection"}]
        if profile == "full":
            steps.append({"id": "tls_config", "label": "TLS protocol and cipher configuration"})
        steps.append({"id": "infra", "label": "Infrastructure and stack"})
    steps += [{"id": spec["id"], "label": spec["label"]} for spec in selected]
    if api_spec_file:
        steps.append({"id": "api_spec", "label": "OpenAPI contract comparison"})
    for step in steps:
        step.update(state="pending", summary="")

    def begin(step_id: str, message: str) -> None:
        if cancel is not None and cancel.is_set():
            raise ScanCancelled
        next(step for step in steps if step["id"] == step_id).update(state="running", started_at=time.time())
        progress(message, steps)

    def finish(step_id: str, state: str, summary: str) -> None:
        next(step for step in steps if step["id"] == step_id).update(state=state, summary=summary, finished_at=time.time())

    def record(found: list[dict], stage: dict, issues: list[dict]) -> None:
        finish(stage["id"], stage["state"], stage.get("summary", ""))
        findings.extend(found)
        stages.append(stage)
        limitations.extend(issues)

    cancelled = False
    with tempfile.TemporaryDirectory(prefix="projectn-") as temp:
        work = Path(temp)
        repo = local_path
        commit = None
        if url and profile not in {"deep", "full"}:
            limitations.append(gap("deep_checks_not_selected", "Template-based vulnerability checks were not selected for this scan.", "Choose Deep scan for an authorized target to run those checks."))
        if url and not (repo_url or local_path):
            limitations.append(gap("source_not_provided", "Source code and Git history were not assessed.", "Add a public GitHub URL or local source folder to this project."))
        if not url:
            limitations.append(gap("website_not_provided", "The live website and its network exposure were not assessed.", "Add a website URL to this project."))
        try:
            if repo_url:
                begin("clone", "Cloning public repository")
                repo = work / "source"
                try:
                    clone_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
                    cloned = run_tool(["git", "clone", "--depth", "1", "--single-branch", "--no-recurse-submodules", "--", repo_url, str(repo)], 180, cancel, env=clone_env)
                    if cloned.returncode:
                        raise subprocess.CalledProcessError(cloned.returncode, "git clone")
                    limitations.append(gap("repository_history_shallow", "Only the public repository's default-branch tip was cloned; earlier Git history was not assessed.", "Use a local full-history clone if historical secret coverage is required."))
                    finish("clone", "completed", "Default-branch tip cloned")
                except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    repo = None
                    finish("clone", "failed", "Repository could not be cloned")
                    limitations.append(gap("repository_unavailable", "Public repository could not be cloned.", "Check the GitHub URL, network access, repository visibility, and size, then retry."))
            if repo:
                revision = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10, shell=False)
                commit = revision.stdout.strip() if revision.returncode == 0 else None
            values = {"url": url or "", "host": host or "", "repo": str(repo) if repo else "", "journey_file": str(journey_file) if journey_file else "", "oob_server": oob_server or "", "oob_token_env": oob_token_env or "", "profile": profile, "port_range": full_options["port_range"], "port_flag": full_options.get("port_flag", "--top-ports"), "port_value": full_options.get("port_value", "1000"), "crawl_depth": str(full_options["crawl_depth"]), "crawl_duration": f"{full_options['crawl_duration_minutes']}m", "template_rate": str(full_options["template_rate"]), "inventory_limit": full_options["inventory_limit"], "browser_page_limit": str(full_options["browser_page_limit"])}
            if url:
                begin("surface", "Inspecting HTTP surface")
                found, stage, issues, surface_body = inspect_website(url, host)
                stage.update(source_revision=builtin_revision("app/web_probe.py", "config/web_probe.json"), rules_dirty=False)
                surface_headers = stage.get("details", {}).get("headers", {})
                record(found, stage, issues)
                begin("tls", "Inspecting TLS connection")
                found, stage, issues = inspect_tls(url, host)
                stage.update(source_revision=builtin_revision("app/tls_probe.py", "config/web_probe.json"), rules_dirty=False)
                record(found, stage, issues)
                if profile == "full":
                    begin("tls_config", "Enumerating TLS protocols and cipher suites")
                    record(*inspect_tls_config(url, host, cancel))
                begin("infra", "Profiling hosting, backend, and frontend signals")
                found, stage, issues = inspect_infrastructure(surface_headers, surface_body)
                stage.update(source_revision=builtin_revision("app/infra_probe.py", "config/infra_signals.json"), rules_dirty=False)
                record(found, stage, issues)
            runnable = [spec for spec in selected if spec["kind"] != "code" or repo]
            for spec in runnable:
                begin(spec["id"], f"Running {spec['label']}")
                record(*scan_one(spec, values, work, cancel))
            if api_spec_file:
                begin("api_spec", "Comparing OpenAPI contract with observed routes")
                observed = []
                for stage in stages:
                    if stage["id"] in {"crawler", "browser"}:
                        observed.extend(stage.get("details", {}).get("api_endpoints", []))
                found, stage, issues = inspect_api_spec(api_spec_file, url, observed)
                stage.update(source_revision=builtin_revision("app/api_spec_probe.py"), rules_revision=stage.get("details", {}).get("spec_sha256"), rules_dirty=False)
                record(found, stage, issues)
        except ScanCancelled:
            cancelled = True
            for step in steps:
                if step["state"] == "running":
                    step.update(state="cancelled", summary="Stopped by user", finished_at=time.time())
            unfinished = sum(step["state"] in {"pending", "cancelled"} for step in steps)
            limitations.append(gap("scan_cancelled", f"The scan was stopped by the user; {unfinished} of {len(steps)} steps did not finish.", "Start a new scan of the same target to assess the remaining steps."))
        for step in steps:
            if step["state"] == "pending":
                step["state"] = "not_run" if cancelled else "skipped"
        limitations.extend(response_signal_gaps(stages))
        completed_stages = {stage["id"] for stage in stages if stage["state"] == "completed"}
        if "journeys" in completed_stages:
            journey_stage = next(stage for stage in stages if stage["id"] == "journeys")
            exercised = {capability for item in journey_stage.get("details", {}).get("journeys", []) if item.get("passed") for capability in item.get("covers", [])}
            for capability in JOURNEY_COVERAGE["required"]:
                if capability["id"] not in exercised:
                    limitations.append(gap("journey_capability_not_assessed", capability["message"], "Add a scoped journey with controlled accounts and mark its covers field after verifying its assertions.", "journeys"))
        if request.get("profile") in {"deep", "full"} and "templates" in completed_stages:
            for policy in COVERAGE["deep_profile_limits"]:
                if request.get("profile") == "full" and policy["code"] == "intrusive_templates_excluded":
                    continue
                limitations.append(gap(policy["code"], policy["message"], policy["resolution"], "templates"))
        step_states = {step["id"]: step["state"] for step in steps}
        stage_states = {stage["id"]: stage["state"] for stage in stages}
        configured = {spec["id"]: spec for spec in specs()}
        reasons = COVERAGE["not_assessed_resolutions"]
        for category, enabled in (("website", bool(url)), ("code", bool(repo))):
            if enabled:
                for capability in COVERAGE[category]:
                    stage_id = capability["stage"]
                    # A stage that ran already reported its own limitation with a specific cause and next step.
                    if stage_id in completed_stages or (stage_id in stage_states and any(item["scanner"] == stage_id for item in limitations)):
                        continue
                    spec = configured.get(stage_id, {})
                    if step_states.get(stage_id) == "not_run":
                        resolution = reasons["stopped"]
                    elif stage_id not in step_states and spec.get("full_only") and not spec.get("requires_journey_file") and profile != "full":
                        resolution = reasons["full_profile"]
                    elif stage_states.get(stage_id) in {"failed", "partial"}:
                        resolution = reasons["unfinished"]
                    else:
                        resolution = capability["resolution"]
                    limitations.append(gap("capability_not_assessed", capability["message"], resolution, stage_id))
        for item in findings:
            if repo and item["scanner"] in {"static", "secrets", "dependencies"}:
                item["location"] = item["location"].replace(str(repo) + os.sep, "")
            if item["location"].startswith(("http://", "https://")):
                item["location"] = public_url(item["location"])
            identity = json.dumps([item["scanner"], item["rule"], item["location"], item["title"]], separators=(",", ":"))
            item["fingerprint"] = hashlib.sha256(identity.encode()).hexdigest()[:24]
    return {"target": {"url": public_url(url) if url else None, "host": host, "repo_url": repo_url, "local_path": str(local_path) if local_path else None, "commit": commit, "profile": profile, "full_options": full_options if profile == "full" else None}, "started_at": started, "finished_at": time.time(), "cancelled": cancelled, "steps": steps, "findings": findings, "stages": stages, "limitations": limitations, "summary": {"findings": len(findings), "completed": sum(s["state"] == "completed" for s in stages), "incomplete": sum(s["state"] != "completed" for s in stages)}}


def compare_reports(previous: dict, current: dict) -> dict:
    old = {item["fingerprint"]: item for item in previous["findings"] if item.get("fingerprint")}
    new = {item["fingerprint"]: item for item in current["findings"] if item.get("fingerprint")}
    old_stages = {item["id"]: item for item in previous["stages"]}
    new_stages = {item["id"]: item for item in current["stages"]}
    result = {"still_present": [], "not_observed_on_rescan": [], "not_verifiable": [], "new": []}
    for fingerprint, item in old.items():
        if fingerprint in new:
            result["still_present"].append(new[fingerprint])
            continue
        prior_stage = old_stages.get(item["scanner"], {})
        next_stage = new_stages.get(item["scanner"], {})
        same_engine = (prior_stage.get("source_revision") == next_stage.get("source_revision") and prior_stage.get("rules_revision") == next_stage.get("rules_revision") and prior_stage.get("runtime_version") == next_stage.get("runtime_version") and prior_stage.get("rules_dirty") is False and next_stage.get("rules_dirty") is False)
        if next_stage.get("state") == "completed" and same_engine:
            result["not_observed_on_rescan"].append(item)
        else:
            result["not_verifiable"].append(item)
    result["new"] = [item for fingerprint, item in new.items() if fingerprint not in old]
    result["summary"] = {key: len(value) for key, value in result.items()}
    return result
