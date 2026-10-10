"""Test whether a Firebase Realtime Database discovered on the page is readable without authentication.

This is an active check: it only runs in Full scope, where execute_scan already requires explicit scan-time
authorization before anything starts. It only queries the Firebase project discovered on the target's own
page (never an arbitrary URL), and makes a single request using Firebase's own `shallow=true` option, which
returns only top-level key names (true/false per key), never the actual nested values underneath them.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from app.core import finding, gap

CONFIG = json.loads((Path(__file__).resolve().parent.parent / "config" / "firebase_probe.json").read_text(encoding="utf-8"))
PROJECT_RE = re.compile(r"([a-z0-9][a-z0-9-]{3,30})\.(?:firebaseio\.com|firebaseapp\.com)")


def discover_project(body: str) -> str | None:
    """A Firebase project id referenced on the page, from either its database or app hosting domain."""
    match = PROJECT_RE.search(body)
    return match.group(1) if match else None


def request_json(url: str, timeout: float):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout) as response:
            status, body = response.status, response.read(CONFIG["max_response_bytes"] + 1)
    except urllib.error.HTTPError as exc:
        with exc:
            status, body = exc.code, (exc.read(CONFIG["max_response_bytes"] + 1) if exc.fp else b"")
    except (OSError, ValueError):
        return None, None
    if len(body) > CONFIG["max_response_bytes"]:
        return status, None
    try:
        return status, json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return status, None


def inspect_firebase(body: str, cancel=None) -> tuple[list[dict], dict, list[dict]]:
    label = "Firebase database exposure"
    project_id = discover_project(body)
    if not project_id:
        return [], {"id": "firebase", "label": label, "state": "skipped", "summary": "No Firebase project was found on the page"}, [
            gap("firebase_not_detected", "No Firebase project was found on the page, so database exposure was not tested.", "This check only runs against a Firebase project discovered in the page's own HTML; it does not apply if the site does not use Firebase.", "firebase")
        ]
    if cancel is not None and cancel.is_set():
        return [], {"id": "firebase", "label": label, "state": "partial", "summary": "Stopped before the database could be checked", "details": {"project_id": project_id}}, [
            gap("scan_cancelled", "The Firebase check was stopped by the user before it ran.", "Start a new Full scan of the same target to check it.", "firebase")
        ]
    url = f"https://{project_id}.firebaseio.com/.json?shallow=true"
    status, data = request_json(url, CONFIG["timeout_seconds"])
    found, issues = [], []
    exposed = status == 200 and isinstance(data, dict) and data
    if exposed:
        keys = sorted(str(key) for key in data.keys())
        sensitive = any(word in key.lower() for key in keys for word in CONFIG["sensitive_key_words"])
        found.append(finding(
            "firebase",
            "Firebase Realtime Database is readable without authentication",
            "critical" if sensitive else "high",
            url,
            f"GET {url} returned data without authentication. This used Firebase's shallow option, which lists only top-level "
            f"key names, never their contents. Top-level keys present: {', '.join(keys)}.",
            "Set Firebase Realtime Database security rules to require authentication for read access (the default `.read: true` "
            "or a blank ruleset both expose all data), confirm an unauthenticated request is now denied, then rescan.",
            "firebase:open-rtdb",
            "observed",
        ))
    elif status is None:
        issues.append(gap("firebase_unreachable", f"The Firebase Realtime Database at {project_id}.firebaseio.com did not respond.", "Check that the project id was read correctly and that the database exists, then rescan.", "firebase"))
    summary = "Realtime Database is readable without authentication" if exposed else "Realtime Database is not readable without authentication"
    details = {"project_id": project_id, "database_url": f"https://{project_id}.firebaseio.com", "exposed": exposed}
    return found, {"id": "firebase", "label": label, "state": "completed", "summary": summary, "details": details}, issues
