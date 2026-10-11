"""Test whether a signup/registration form already discovered by the browser stage rate-limits repeated submissions.

This is an active check: it only runs in Full scope, where execute_scan already requires explicit scan-time
authorization before anything starts. It only tests a form the browser stage already found while rendering the
site (never guesses a URL or submits to a form it has not seen), and every submission uses deliberately invalid
field values (a malformed email, a one-character password) chosen to fail basic validation -- designed so no
account is ever actually created, while still exercising the same request path and volume a real signup
attempt would use. It stops as soon as a rate limit is observed, and is bounded to a small, fixed number of
attempts either way.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from app.core import finding, gap

CONFIG = json.loads((Path(__file__).resolve().parent.parent / "config" / "signup_probe.json").read_text(encoding="utf-8"))
RATE_LIMIT_PHRASES = ("too many", "rate limit", "try again later", "slow down", "temporarily blocked", "temporarily locked")
SKIP_FIELD_TYPES = {"submit", "button", "hidden", "checkbox", "radio", "file"}


def looks_like_signup(form: dict) -> bool:
    if form.get("method") != "POST":
        return False
    field_types = [str(f.get("type", "")).lower() for f in form.get("fields", [])]
    password_count = field_types.count("password")
    haystack = (str(form.get("action", "")) + str(form.get("page", ""))).lower()
    signupish_path = any(word in haystack for word in CONFIG["signup_path_words"])
    return password_count >= 2 or (password_count >= 1 and signupish_path)


def invalid_payload(fields: list[dict]) -> dict[str, str]:
    """Field values chosen to fail validation (so no account is created) while still being well-formed enough
    to exercise the endpoint's normal request path and any rate limiting in front of it."""
    payload = {}
    for field in fields:
        name = field.get("name")
        kind = str(field.get("type", "")).lower()
        if not name or kind in SKIP_FIELD_TYPES:
            continue
        payload[name] = "not-an-email" if kind == "email" else "x" if kind == "password" else "test"
    return payload


def post_form(url: str, payload: dict, timeout: float) -> tuple[int | None, bytes]:
    data = urllib.parse.urlencode(payload).encode()
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
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
        return None, b""
    return status, body[: CONFIG["max_response_bytes"]]


def inspect_signup_rate_limit(forms: list[dict], cancel=None) -> tuple[list[dict], dict, list[dict]]:
    label = "Signup rate limiting"
    candidate = next((item for item in forms if looks_like_signup(item)), None)
    if not candidate:
        return [], {"id": "signup_limits", "label": label, "state": "skipped", "summary": "No signup-shaped form was discovered"}, [
            gap("signup_form_not_found", "No form matching a signup/registration pattern (two password fields, or one password field with a signup-like URL) was discovered on the rendered pages.", "This check only runs against a form the browser stage already found; it does not apply if no such form was in the crawled pages.", "signup_limits")
        ]
    payload = invalid_payload(candidate["fields"])
    attempts = CONFIG["max_attempts"]
    statuses, limited, checked, interrupted = [], False, 0, False
    for _ in range(attempts):
        if cancel is not None and cancel.is_set():
            interrupted = True
            break
        checked += 1
        status, body = post_form(candidate["action"], payload, CONFIG["timeout_seconds"])
        statuses.append(status)
        text = body.decode("utf-8", errors="replace").lower()
        if status == 429 or any(phrase in text for phrase in RATE_LIMIT_PHRASES):
            limited = True
            break
    found = []
    reachable = any(code is not None for code in statuses)
    if not limited and checked >= attempts and not interrupted and reachable:
        found.append(finding(
            "signup_limits",
            "No rate limiting observed on the signup form after repeated submissions",
            "medium",
            candidate["action"],
            f"Sent {checked} submissions to {candidate['action']} in quick succession, each with deliberately invalid "
            f"field values so no account could be created. Response status codes observed: {statuses}. None indicated "
            "a request-volume limit (no HTTP 429, no rate-limit message in the response). This is not proof no limit "
            "exists at a higher volume -- only that it did not trigger within this bounded test.",
            "Add rate limiting on the signup endpoint (per-IP and/or per-account, a sliding window is typical), and "
            "consider a CAPTCHA after a few rapid attempts, then rescan.",
            "signup:no-rate-limit",
            "needs-review",
        ))
    issues = []
    if interrupted:
        issues.append(gap("scan_cancelled", f"The signup rate-limit check was stopped by the user after {checked} of {attempts} submission(s).", "Start a new Full scan of the same target to finish this check.", "signup_limits"))
    elif checked and not reachable:
        issues.append(gap("signup_endpoint_unreachable", f"{candidate['action']} did not respond to any of {checked} submission(s).", "Check that the form's action URL is correct and reachable, then rescan.", "signup_limits"))
    summary = "Rate limiting observed" if limited else f"No rate limiting observed after {checked} submission(s)" if reachable else "The signup endpoint did not respond"
    state = "partial" if interrupted else "completed" if checked else "failed"
    details = {"endpoint": candidate["action"], "attempts": checked, "rate_limited": limited, "statuses": statuses}
    return found, {"id": "signup_limits", "label": label, "state": state, "summary": summary, "details": details}, issues
