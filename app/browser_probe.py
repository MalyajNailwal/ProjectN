"""Inventory same-origin rendered pages without submitting forms or storing response bodies."""

from __future__ import annotations

import json
import sys
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

def clean_url(value: str) -> str:
    return urlunparse(urlparse(value)._replace(query="", fragment=""))


def same_origin(value: str, origin: str) -> bool:
    candidate = urlparse(value)
    target = urlparse(origin)
    return candidate.scheme == target.scheme and candidate.netloc == target.netloc


def inspect(start_url: str, page_limit: int) -> dict:
    from playwright.sync_api import sync_playwright

    pages = []
    forms = []
    apis = {}
    errors = []
    pending = deque([start_url])
    seen = set()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=False)
        page = context.new_page()

        def on_response(response):
            if not same_origin(response.url, start_url):
                return
            content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
            if content_type == "application/json" or content_type.endswith("+json"):
                key = clean_url(response.url)
                apis[key] = {"url": key, "status": response.status, "method": response.request.method, "content_type": content_type}

        page.on("response", on_response)
        while pending and len(pages) < page_limit:
            target = clean_url(pending.popleft())
            if target in seen or not same_origin(target, start_url):
                continue
            seen.add(target)
            try:
                response = page.goto(target, wait_until="domcontentloaded", timeout=20000)
                page.wait_for_timeout(750)
                current = clean_url(page.url)
                if not same_origin(current, start_url):
                    continue
                pages.append({"url": current, "title": page.title()[:200], "status": response.status if response else None})
                for item in page.locator("form").all():
                    fields = item.locator("input,select,textarea").evaluate_all("els => els.map(el => ({name: el.name || '', type: el.type || el.tagName.toLowerCase()}))")
                    action = urljoin(current, item.get_attribute("action") or current)
                    forms.append({"page": current, "action": clean_url(action), "method": (item.get_attribute("method") or "GET").upper(), "fields": fields})
                for link in page.locator("a[href]").evaluate_all("els => els.map(el => el.href)"):
                    if same_origin(link, start_url) and clean_url(link) not in seen:
                        pending.append(link)
            except Exception as exc:
                errors.append({"url": target, "type": type(exc).__name__})
        browser.close()
    return {"pages": pages, "forms": forms, "api_endpoints": sorted(apis.values(), key=lambda item: item["url"]), "errors": errors, "pending_count": len(pending), "page_limit": page_limit}


if __name__ == "__main__":
    start, output, limit = sys.argv[1:4]
    result = inspect(start, int(limit))
    Path(output).write_text(json.dumps(result))
    if result["errors"]:
        raise SystemExit(2)
