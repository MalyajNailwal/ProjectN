"""Fingerprint hosting/CDN, backend-as-a-service, and frontend framework signals already fetched by the HTTP surface probe.

Makes no network requests of its own outside Full scope. Every match is a count of independent, named signals
observed in the response headers or HTML body (config/infra_signals.json), never a trained or estimated
probability, so the percent shown is always "N of M known signals for this provider", reproducible from the
listed evidence.

In Full scope, backend-as-a-service signals are also checked against a bounded number of same-host scripts the
surface stage already discovered (never a new page fetch, never cross-origin) -- frameworks such as Next.js and
Vite commonly inline a backend-as-a-service project's URL into a bundled script rather than server-rendered
HTML, so a root-page-only search misses it on most modern single-page apps, the same gap the dedicated
Supabase/Firebase checks already account for. Hosting and framework signals do not get this treatment: hosting
comes almost entirely from response headers already in hand, and framework markers (such as a `/_next/static/`
asset path) are themselves literal strings already present in the root HTML's own script tags, not hidden
inside a bundle.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from app.core import fetch_same_host_scripts, gap

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "infra_signals.json"
CONFIG = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
STRONG_THRESHOLD = CONFIG.get("strong_threshold_percent", 60)


def match_category(category: str, headers: dict[str, str], body: str) -> list[dict]:
    lowered_headers = {name.lower(): value for name, value in headers.items()}
    results = []
    for provider in CONFIG.get(category, []):
        total_weight = sum(signal["weight"] for signal in provider["signals"])
        matched_weight = 0
        evidence = []
        for signal in provider["signals"]:
            text = lowered_headers.get(signal.get("name", "").lower(), "") if signal["type"] == "header" else body
            if text and re.search(signal["pattern"], text, re.IGNORECASE):
                matched_weight += signal["weight"]
                evidence.append(signal["evidence"])
        if matched_weight:
            percent = round(matched_weight / total_weight * 100)
            results.append({
                "id": provider["id"],
                "label": provider["label"],
                "match_percent": percent,
                "confidence": "confirmed" if percent >= STRONG_THRESHOLD else "possible",
                "evidence": evidence,
            })
    results.sort(key=lambda item: item["match_percent"], reverse=True)
    return results


def inspect_infrastructure(headers: dict[str, str], body: str, links: list[str] = ()) -> tuple[list[dict], dict, list[dict]]:
    """Detect hosting/CDN, backend-as-a-service, and frontend framework signals from already-fetched data.

    `headers` and `body` come from the HTTP surface stage for the same scan; nothing here is fetched again,
    except for `links` (also already discovered by the surface stage), which the caller passes only in Full
    scope -- see the module docstring for why only the baas category uses it.
    """
    label = "Infrastructure and stack"
    if not headers and not body:
        return [], {"id": "infra", "label": label, "state": "skipped", "summary": "No HTTP response was available to inspect"}, [
            gap("infra_not_assessed", "Hosting, backend, and frontend signals were not inspected.", "This runs only after a successful HTTP surface fetch; rescan once the site responds.", "infra")
        ]

    baas_body = body
    if links:
        script_bodies = fetch_same_host_scripts(links, CONFIG["timeout_seconds"], CONFIG["max_scripts_checked"], CONFIG["max_script_bytes"], CONFIG["priority_script_words"])
        baas_body = "\n".join([body, *script_bodies])

    details = {
        "hosting": match_category("hosting", headers, body),
        "baas": match_category("baas", headers, baas_body),
        "frameworks": match_category("frameworks", headers, body),
    }
    parts = []
    for category_label, key in (("hosting", "hosting"), ("backend", "baas"), ("frontend", "frameworks")):
        names = [item["label"] for item in details[key][:3]]
        if names:
            parts.append(f"{category_label}: {', '.join(names)}")
    summary = "; ".join(parts) if parts else "No known hosting, backend, or framework signals matched"
    issues = []
    if not any(details.values()):
        issues.append(gap("infra_signals_not_matched", "No hosting, CDN, backend-as-a-service, or frontend framework signals matched on the fetched page.", "This covers only the fetched homepage's headers and HTML against a fixed signal list in config/infra_signals.json; an unlisted or custom-built stack is not detected.", "infra"))
    return [], {"id": "infra", "label": label, "state": "completed", "summary": summary, "details": details}, issues
