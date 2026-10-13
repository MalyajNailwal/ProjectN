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
        if page.locator(".run-card .run-state.running, .run-card .run-state.queued").count():
            page.get_by_role("heading", name="What is happening now").wait_for()
            page.get_by_role("button", name="Stop scan").wait_for()
            print("UI: scan launched from the form; live progress, running step list, and Stop control are shown", flush=True)
        else:
            print("UI: scan launched from the form and finished before the first progress poll; step list and progress bar are shown", flush=True)
        page.locator(".run-card .run-state.completed").wait_for(timeout=timeout_seconds * 1000)
        percent = page.locator(".run-progress-head strong").inner_text()
        if percent != "100%":
            raise RuntimeError(f"Completed scan shows {percent} instead of 100%")
        page.get_by_role("button", name="Explore report").click()
        page.wait_for_url("**/findings")
        # Each page and open finding has a URL, and browser Back and Forward stay inside the dashboard.
        finding = page.locator(".finding-row").first
        if finding.count():
            finding.click()
            page.wait_for_url("**/findings?finding=*")
            page.locator(".finding-drawer").wait_for()
            page.go_back()
            page.wait_for_url("**/findings")
            page.locator(".finding-drawer").wait_for(state="detached")
        page.get_by_role("link", name="Coverage", exact=True).click()
        page.wait_for_url("**/coverage")
        page.get_by_role("heading", name="Scanner stages").wait_for()
        page.go_back()
        page.wait_for_url("**/findings")
        page.locator(".finding-toolbar").wait_for()
        page.go_forward()
        page.wait_for_url("**/coverage")
        page.get_by_role("heading", name="Scanner stages").wait_for()
        print("UI: pages and findings have their own URLs; browser Back and Forward stay inside the dashboard", flush=True)
        page.get_by_role("link", name="Overview", exact=True).click()
        previous_scan_id = page.locator(".run-meta code").inner_text()
        page.get_by_role("button", name="Full scope").click()
        page.get_by_label("I am authorized to run intrusive checks against this website.").check()
        page.get_by_role("button", name="Run again").click()
        if page.locator("#website").input_value() != target:
            raise RuntimeError("Run again did not restore the website target")
        if page.get_by_role("button", name="Standard").get_attribute("aria-pressed") != "true":
            raise RuntimeError("Run again did not restore the scan profile")
        if page.locator(".run-meta code").inner_text() != previous_scan_id:
            raise RuntimeError("Run again started a scan without review")
        page.get_by_role("button", name="Full scope").click()
        if page.get_by_label("I am authorized to run intrusive checks against this website.").is_checked():
            raise RuntimeError("Run again reused intrusive scan authorization")
        print("UI: Run again restores the target and profile without launching or retaining intrusive authorization", flush=True)
        page.screenshot(path=screenshot, full_page=True)
        browser.close()
    if errors:
        raise RuntimeError("Browser console errors: " + "; ".join(errors[:5]))
    print(f"UI: report and coverage pages rendered without console errors; screenshot at {screenshot}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])))
