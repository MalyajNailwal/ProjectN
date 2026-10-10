"""Drive the dashboard in headless Chromium: launch a scan from the form and follow it to the report.

Run by `smoke_local.py --ui` with the browser-journeys runtime, which that script installs when missing.
"""

from __future__ import annotations

import sys

from playwright.sync_api import sync_playwright


def main(base: str, target: str, screenshot: str, timeout_seconds: float) -> int:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        errors: list[str] = []
        page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(base, wait_until="networkidle")
        page.get_by_role("heading", name="Start a scan").wait_for()
        page.fill("#website", target)
        page.get_by_role("button", name="Launch assessment").click()
        page.locator(".steps-section .step").first.wait_for(timeout=60_000)
        page.get_by_role("progressbar", name="Scan progress").wait_for()
        # A scan with few installed scanners can finish before the first poll, so the live controls are checked only while it runs.
        if page.locator(".run-state.running, .run-state.queued").count():
            page.get_by_role("heading", name="What is happening now").wait_for()
            page.get_by_role("button", name="Stop scan").wait_for()
            print("UI: scan launched from the form; live progress, running step list, and Stop control are shown", flush=True)
        else:
            print("UI: scan launched from the form and finished before the first progress poll; step list and progress bar are shown", flush=True)
        page.locator(".run-state.completed").wait_for(timeout=timeout_seconds * 1000)
        percent = page.locator(".run-progress-head strong").inner_text()
        if percent != "100%":
            raise RuntimeError(f"Completed scan shows {percent} instead of 100%")
        page.get_by_role("button", name="Explore report").click()
        page.get_by_role("button", name="Coverage", exact=True).click()
        page.get_by_role("heading", name="Scanner stages").wait_for()
        page.screenshot(path=screenshot, full_page=True)
        browser.close()
    if errors:
        raise RuntimeError("Browser console errors: " + "; ".join(errors[:5]))
    print(f"UI: report and coverage pages rendered without console errors; screenshot at {screenshot}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])))
