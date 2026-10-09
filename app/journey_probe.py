"""Run user-defined, scoped browser journeys with credentials supplied through environment variables."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

from playwright.sync_api import sync_playwright


def public_url(value: str) -> str:
    return urlunparse(urlparse(value)._replace(query="", fragment=""))


def in_scope(value: str, origin: str) -> bool:
    left, right = urlparse(value), urlparse(origin)
    return left.scheme == right.scheme and left.netloc == right.netloc


def run(start_url: str, definition: dict) -> dict:
    journeys = definition.get("journeys", [])
    if not isinstance(journeys, list):
        raise ValueError("journeys must be a list")
    results = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        for journey in journeys:
            context = browser.new_context(ignore_https_errors=False)
            page = context.new_page()
            record = {"name": str(journey.get("name", "Journey"))[:100], "covers": journey.get("covers", []), "passed": True, "completed_steps": 0, "final_url": None, "issues": []}
            try:
                steps = journey.get("steps", [])
                if not steps or not any(step.get("action", "").startswith("expect_") for step in steps):
                    raise ValueError("Journey needs steps and an observable expectation")
                for index, step in enumerate(steps):
                    action = step.get("action")
                    if action == "goto":
                        destination = urljoin(start_url, step["url"])
                        if not in_scope(destination, start_url):
                            raise ValueError("Journey URL leaves the selected origin")
                        page.goto(destination, wait_until="domcontentloaded", timeout=20000)
                    elif action == "fill":
                        environment_name = step["value_env"]
                        if environment_name not in os.environ:
                            raise ValueError(f"Missing environment variable: {environment_name}")
                        page.locator(step["selector"]).fill(os.environ[environment_name], timeout=10000)
                    elif action == "click":
                        page.locator(step["selector"]).click(timeout=10000)
                    elif action == "expect_text":
                        page.get_by_text(step["text"], exact=bool(step.get("exact", False))).wait_for(timeout=10000)
                    elif action == "expect_url_contains":
                        page.wait_for_url(lambda url: step["text"] in str(url), timeout=10000)
                    elif action == "expect_cookie_flags":
                        cookies = {item["name"]: item for item in context.cookies()}
                        cookie = cookies.get(step["cookie"])
                        if not cookie:
                            raise AssertionError(f"Cookie {step['cookie']} was not observed")
                        required = step.get("required", ["secure", "httpOnly", "sameSite"])
                        missing = [flag for flag in required if not (cookie.get(flag) if flag != "sameSite" else cookie.get("sameSite") in {"Lax", "Strict"})]
                        if missing:
                            record["issues"].append({"step": index + 1, "type": "cookie_flags", "cookie": step["cookie"], "missing": missing})
                    else:
                        raise ValueError(f"Unsupported journey action: {action}")
                    if page.url != "about:blank" and not in_scope(page.url, start_url):
                        raise ValueError("Journey navigation left the selected origin")
                    record["completed_steps"] += 1
            except Exception as exc:
                record["passed"] = False
                record["issues"].append({"step": record["completed_steps"] + 1, "type": type(exc).__name__})
            record["final_url"] = public_url(page.url) if page.url != "about:blank" else None
            if record["issues"]:
                record["passed"] = False
            results.append(record)
            context.close()
        browser.close()
    return {"journeys": results, "observed": len(results), "failed": sum(not item["passed"] for item in results)}


if __name__ == "__main__":
    origin, journey_file, output = sys.argv[1:4]
    report = run(origin, json.loads(Path(journey_file).read_text()))
    Path(output).write_text(json.dumps(report))
    if report["failed"]:
        raise SystemExit(2)
