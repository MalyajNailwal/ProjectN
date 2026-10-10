"""Test whether GraphQL schema introspection is enabled at common endpoint paths on the target.

This is an active check: it only runs in Full scope, where execute_scan already requires explicit scan-time
authorization before anything starts. It sends a single, standard, read-only introspection query (the kind any
GraphQL client sends) to a short, fixed list of conventional endpoint paths on the target's own base URL --
never an unbounded search, never a mutation. If a GraphQL endpoint answers it, the full schema (type and field
names) is disclosed to anyone, including fields and mutations not linked from the app itself.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

from app.core import finding, gap

CONFIG = json.loads((Path(__file__).resolve().parent.parent / "config" / "graphql_probe.json").read_text(encoding="utf-8"))
INTROSPECTION_QUERY = {"query": "query IntrospectionProbe { __schema { queryType { name } types { name } } }"}


def post_json(url: str, payload: dict, timeout: float):
    data = json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, body = response.status, response.read(CONFIG["max_response_bytes"] + 1)
    except urllib.error.HTTPError as exc:
        with exc:
            status = exc.code
            try:
                body = exc.read(CONFIG["max_response_bytes"] + 1) if exc.fp else b""
            except OSError:
                body = b""
    except (OSError, ValueError):
        return None, None
    if len(body) > CONFIG["max_response_bytes"]:
        return status, None
    try:
        return status, json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return status, None


def inspect_graphql(url: str, cancel=None) -> tuple[list[dict], dict, list[dict]]:
    label = "GraphQL introspection"
    base = url.rstrip("/")
    paths = CONFIG["candidate_paths"]
    exposed_endpoint, type_count, checked, interrupted = None, 0, 0, False
    for path in paths:
        if cancel is not None and cancel.is_set():
            interrupted = True
            break
        checked += 1
        endpoint = base + path
        status, data = post_json(endpoint, INTROSPECTION_QUERY, CONFIG["timeout_seconds"])
        if status == 200 and isinstance(data, dict):
            schema = (data.get("data") or {}).get("__schema") if isinstance(data.get("data"), dict) else None
            types = schema.get("types") if isinstance(schema, dict) else None
            if isinstance(types, list) and types:
                exposed_endpoint, type_count = endpoint, len(types)
                break
    found = []
    if exposed_endpoint:
        found.append(finding(
            "graphql",
            "GraphQL schema introspection is enabled",
            "medium",
            exposed_endpoint,
            f"POST {exposed_endpoint} with a standard introspection query returned the full schema: {type_count} type(s). "
            "This reveals the entire API surface, including fields and mutations not linked from the app itself.",
            "Disable introspection in production (most GraphQL server libraries have a single config flag for this), "
            "or require authentication before it is served, then rescan.",
            "graphql:introspection-enabled",
            "observed",
        ))
    issues = []
    if interrupted:
        issues.append(gap("scan_cancelled", f"The GraphQL check was stopped by the user after {checked} of {len(paths)} path(s).", "Start a new Full scan of the same target to check the remaining paths.", "graphql"))
    summary = f"Introspection enabled at {exposed_endpoint}" if exposed_endpoint else f"No introspection on {checked} checked path(s)"
    state = "partial" if interrupted else "completed"
    details = {"checked_paths": checked, "introspection_endpoint": exposed_endpoint, "type_count": type_count}
    return found, {"id": "graphql", "label": label, "state": state, "summary": summary, "details": details}, issues
