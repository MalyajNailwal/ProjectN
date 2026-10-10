from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

CONFIG = json.loads((Path(__file__).resolve().parent.parent / "config" / "web_probe.json").read_text(encoding="utf-8"))

# Public response metadata only (never Set-Cookie or anything with a credential in it); used to fingerprint hosting/CDN providers.
INFRA_HEADERS = ("server", "via", "x-powered-by", "cf-ray", "cf-cache-status", "x-vercel-id", "x-vercel-cache", "x-nf-request-id",
    "x-amz-cf-id", "x-amz-cf-pop", "x-azure-ref", "x-served-by", "x-cache", "x-github-request-id", "x-fastly-request-id",
    "fly-request-id", "x-render-origin-server", "x-railway-request-id")


class SurfaceParser(HTMLParser):
    def __init__(self, base_url: str, host: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.host = host
        self.links: set[str] = set()
        self.forms: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag in {"a", "script", "link"}:
            raw = values.get("href") or values.get("src")
            if raw:
                full = urllib.parse.urljoin(self.base_url, raw)
                parsed = urllib.parse.urlparse(full)
                if parsed.scheme in {"http", "https"} and parsed.hostname == self.host:
                    self.links.add(parsed._replace(query="", fragment="").geturl())
        if tag == "form":
            action = urllib.parse.urljoin(self.base_url, values.get("action") or self.base_url)
            parsed = urllib.parse.urlparse(action)
            self.forms.append({"method": (values.get("method") or "get").upper(), "action": parsed._replace(query="", fragment="").geturl(), "in_scope": parsed.hostname == self.host})


class ScopedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, host: str):
        self.host = host
        self.blocked: str | None = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).hostname != self.host:
            self.blocked = newurl
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def inspect_website(url: str, host: str) -> tuple[list[dict], dict, list[dict], str]:
    """Inspect one scoped HTTP response; each check reports observed evidence only.

    The fourth return value is the decoded HTML body for the caller's own in-memory use (such as
    infrastructure fingerprinting); it is not part of the stage details and is never stored in the report.
    """
    from app.core import finding, gap

    redirect = ScopedRedirect(host)
    opener = urllib.request.build_opener(redirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={"User-Agent": CONFIG["user_agent"]})
    try:
        try:
            response = opener.open(request, timeout=CONFIG["timeout_seconds"])
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            final_url = response.geturl()
            status = response.status
            headers = response.headers
            body = response.read(CONFIG["max_body_bytes"] + 1)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        reason = "Redirect left the selected host." if redirect.blocked else f"HTTP request failed: {type(exc).__name__}."
        action = "Add the redirected host to the authorized scope and rescan it separately." if redirect.blocked else "Check DNS, TLS, connectivity, and the target URL, then retry."
        return [], {"id": "surface", "label": "HTTP surface", "state": "failed", "summary": reason}, [gap("http_unavailable", reason, action, "surface")], ""

    display_url = urllib.parse.urlparse(final_url)._replace(query="", fragment="").geturl()
    details: dict = {"observed": 1, "url": display_url, "status": status, "content_type": headers.get_content_type(), "links": [], "forms": [], "response_bytes_read": len(body),
        "headers": {name: headers.get(name) for name in INFRA_HEADERS if headers.get(name)}}
    issues = []
    if redirect.blocked:
        issues.append(gap("out_of_scope_redirect", "The target redirected to another host.", "Add that host to the authorized scope and scan it separately.", "surface"))
    if len(body) > CONFIG["max_body_bytes"]:
        body = body[: CONFIG["max_body_bytes"]]
        issues.append(gap("body_truncated", "The HTTP response exceeded the inspection limit.", "Increase max_body_bytes in config/web_probe.json if this page needs deeper inspection.", "surface"))
    if status >= 400:
        issues.append(gap("http_error", f"The target returned HTTP {status}.", "Check target access and scan an available entry page, then retry.", "surface"))

    html = ""
    if details["content_type"] == "text/html":
        charset = headers.get_content_charset() or "utf-8"
        parser = SurfaceParser(final_url, host)
        try:
            html = body.decode(charset, errors="replace")
        except LookupError:
            html = body.decode("utf-8", errors="replace")
            issues.append(gap("unknown_charset", "The page declared an unsupported character encoding.", "Check the response Content-Type charset and retry.", "surface"))
        parser.feed(html)
        details["links"] = sorted(parser.links)[: CONFIG["max_links"]]
        details["forms"] = parser.forms[: CONFIG["max_links"]]
        if len(parser.links) > CONFIG["max_links"] or len(parser.forms) > CONFIG["max_links"]:
            issues.append(gap("html_inventory_truncated", "HTML link or form inventory reached its limit.", "Increase max_links in config/web_probe.json and rescan.", "surface"))

    found = []
    if 200 <= status < 300:
        rules = list(CONFIG["security_headers"])
        if urllib.parse.urlparse(final_url).scheme == "https":
            rules.append(CONFIG["https_header"])
        for rule in rules:
            if rule.get("content_types") and details["content_type"] not in rule["content_types"]:
                continue
            if not headers.get(rule["name"]):
                found.append(finding("surface", rule["title"], "low", display_url, f"HTTP {status} response has no {rule['name']} header.", rule["remediation"], f"header:{rule['name']}", "observed"))
        for cookie in headers.get_all("Set-Cookie", []):
            name = cookie.split("=", 1)[0].strip() or "cookie"
            attributes = {part.split("=", 1)[0].strip().lower() for part in cookie.split(";")[1:]}
            for attr, applicable in (("secure", final_url.startswith("https://")), ("httponly", True), ("samesite", True)):
                if applicable and attr not in attributes:
                    found.append(finding("surface", f"Cookie {name} lacks {attr} attribute", "low", display_url, f"Observed Set-Cookie for {name} without {attr}; cookie value withheld.", f"Set the {attr} attribute on {name} if compatible with the intended cookie behavior, then rescan.", f"cookie:{attr}", "observed"))
    state = "partial" if redirect.blocked or status >= 400 else "completed"
    return found, {"id": "surface", "label": "HTTP surface", "state": state, "summary": f"HTTP {status}; {len(details['links'])} links; {len(details['forms'])} forms", "details": details}, issues, html
