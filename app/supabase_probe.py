"""Test whether tables and storage buckets behind a Supabase project discovered on the page are exposed.

This is an active check: it only runs in Full scope, where execute_scan already requires explicit scan-time
authorization before anything starts. It only queries the Supabase project discovered on the target's own
page (never an arbitrary URL), tries that project's own PostgREST schema first, and otherwise tries a short,
fixed list of common table-name guesses -- never an unbounded or growing search. It never stores actual row
values in the report: only the table name, its column names, and the fact that at least one row came back.
Storage buckets are checked with a single metadata-only request (no file listing or download).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from app.core import finding, gap

CONFIG = json.loads((Path(__file__).resolve().parent.parent / "config" / "supabase_probe.json").read_text(encoding="utf-8"))
PROJECT_RE = re.compile(r"https://([a-z0-9]{20})\.supabase\.co")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def discover_project(body: str) -> tuple[str, str] | None:
    """A Supabase project URL and a JWT found together on the page; the client-side anon key, or whatever key was shipped."""
    project = PROJECT_RE.search(body)
    key = JWT_RE.search(body)
    if not project or not key:
        return None
    return f"https://{project.group(1)}.supabase.co", key.group(0)


def request_json(url: str, api_key: str, accept: str, timeout: float):
    request = urllib.request.Request(url, headers={"apikey": api_key, "Authorization": f"Bearer {api_key}", "Accept": accept})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
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


def candidate_tables(base_url: str, api_key: str, timeout: float) -> tuple[list[str], bool]:
    """The project's own PostgREST (Swagger) schema names when it will say, otherwise a short fixed guess list."""
    status, doc = request_json(f"{base_url}/rest/v1/", api_key, "application/openapi+json", timeout)
    if status == 200 and isinstance(doc, dict) and isinstance(doc.get("definitions"), dict) and doc["definitions"]:
        return list(doc["definitions"])[: CONFIG["max_tables"]], True
    return CONFIG["common_table_guesses"][: CONFIG["max_tables"]], False


def public_storage_buckets(base_url: str, api_key: str, timeout: float) -> list[str]:
    """Bucket names the project's own Storage API itself marks public=true; no file listing or download."""
    status, buckets = request_json(f"{base_url}/storage/v1/bucket", api_key, "application/json", timeout)
    if status != 200 or not isinstance(buckets, list):
        return []
    return [item["name"] for item in buckets if isinstance(item, dict) and item.get("public") is True and isinstance(item.get("name"), str)]


def inspect_supabase(body: str, cancel=None) -> tuple[list[dict], dict, list[dict]]:
    label = "Supabase exposure"
    discovered = discover_project(body)
    if not discovered:
        return [], {"id": "supabase", "label": label, "state": "skipped", "summary": "No Supabase project was found on the page"}, [
            gap("supabase_not_detected", "No Supabase project URL and key were found on the page, so table-level exposure was not tested.", "This check only runs against a Supabase project discovered in the page's own HTML; it does not apply if the site does not call Supabase from the browser.", "supabase")
        ]
    base_url, api_key = discovered
    timeout = CONFIG["timeout_seconds"]
    tables, schema_readable = candidate_tables(base_url, api_key, timeout)
    exposed, checked, interrupted = [], 0, False
    for table in tables:
        if cancel is not None and cancel.is_set():
            interrupted = True
            break
        checked += 1
        status, rows = request_json(f"{base_url}/rest/v1/{table}?select=*&limit=1", api_key, "application/json", timeout)
        if status == 200 and isinstance(rows, list) and rows and isinstance(rows[0], dict):
            exposed.append({"table": table, "columns": sorted(rows[0].keys())})
    found = []
    for item in exposed:
        sensitive = any(word in item["table"].lower() for word in CONFIG["sensitive_table_words"])
        found.append(finding(
            "supabase",
            f"Supabase table '{item['table']}' is readable without authentication",
            "critical" if sensitive else "high",
            base_url,
            f"GET {base_url}/rest/v1/{item['table']}?select=*&limit=1 with the key found on the page returned a row. Columns: {', '.join(item['columns']) or '(none)'}. Row values are not stored in this report.",
            "Add a Row Level Security policy on this table that denies anonymous reads unless intended, confirm the anon key can no longer read it, then rescan.",
            "supabase:rls-missing",
            "observed",
        ))
    public_buckets = [] if interrupted else public_storage_buckets(base_url, api_key, timeout)
    for bucket in public_buckets:
        found.append(finding(
            "supabase",
            f"Supabase storage bucket '{bucket}' is public",
            "medium",
            base_url,
            f"GET {base_url}/storage/v1/bucket lists '{bucket}' with public=true: anyone can read files in it without authentication. "
            "This is sometimes intentional (such as product images or avatars); files were not listed or downloaded.",
            "If this bucket should not be public, set it to private in the Supabase dashboard (Storage) and add storage RLS policies, then rescan.",
            "supabase:public-storage-bucket",
            "needs-review",
        ))
    issues = []
    if not schema_readable and checked:
        issues.append(gap("supabase_guess_list_only", f"Only {checked} common table name(s) were tried; the project did not expose its own schema.", "Table names outside this fixed list were not tested; this is not proof those tables are protected.", "supabase"))
    if interrupted:
        issues.append(gap("scan_cancelled", f"The Supabase check was stopped by the user after {checked} of {len(tables)} table(s); storage buckets were not checked.", "Start a new Full scan of the same target to check the remaining tables and storage buckets.", "supabase"))
    summary = f"{len(exposed)} of {checked} table(s) and {len(public_buckets)} storage bucket(s) readable without authentication" if checked else "No tables could be checked"
    state = "partial" if interrupted else "completed" if checked else "failed"
    details = {"project_url": base_url, "tables_checked": checked, "schema_introspectable": schema_readable, "exposed_tables": [item["table"] for item in exposed], "public_buckets": public_buckets}
    return found, {"id": "supabase", "label": label, "state": state, "summary": summary, "details": details}, issues
