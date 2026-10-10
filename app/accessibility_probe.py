"""Run the locally built axe engine on same-origin pages in headless Chromium."""

from __future__ import annotations

import json
import sys
from collections import deque
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from playwright.sync_api import sync_playwright


def scoped(value: str, origin: str) -> bool:
    left, right = urlparse(value), urlparse(origin)
    return left.scheme == right.scheme and left.netloc == right.netloc


def clean(value: str) -> str:
    return urlunparse(urlparse(value)._replace(query="", fragment=""))


def inspect(start_url: str, axe_path: Path, page_limit: int, tags: list[str]) -> dict:
    pages, violations, errors = [], [], []
    pending = deque([start_url])
    seen = set()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        while pending and len(pages) < page_limit:
            target = clean(pending.popleft())
            if target in seen or not scoped(target, start_url):
                continue
            seen.add(target)
            try:
                response = page.goto(target, wait_until="domcontentloaded", timeout=20000)
                current = clean(page.url)
                if not scoped(current, start_url):
                    continue
                page.add_script_tag(path=str(axe_path))
                result = page.evaluate("async tags => await axe.run(document, {runOnly: {type: 'tag', values: tags}})", tags)
                pages.append({"url": current, "status": response.status if response else None})
                for item in result.get("violations", []):
                    violations.append({"page": current, "id": item.get("id"), "impact": item.get("impact"), "help": item.get("help"), "help_url": item.get("helpUrl"), "selectors": [node.get("target", []) for node in item.get("nodes", [])]})
                for link in page.locator("a[href]").evaluate_all("els => els.map(el => el.href)"):
                    if scoped(link, start_url) and clean(link) not in seen:
                        pending.append(link)
            except Exception as exc:
                errors.append({"url": target, "type": type(exc).__name__})
        browser.close()
    return {"pages": pages, "violations": violations, "errors": errors, "pending_count": len(pending), "page_limit": page_limit, "tags": tags}


if __name__ == "__main__":
    start, output, script_path, limit, config_path = sys.argv[1:6]
    settings = json.loads(Path(config_path).read_text(encoding="utf-8"))
    result = inspect(start, Path(script_path), int(limit), settings["tags"])
    Path(output).write_text(json.dumps(result))
    if result["errors"]:
        raise SystemExit(2)
