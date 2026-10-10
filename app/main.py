from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.core import DATA, FULL_DEFAULTS, ROOT, ScanCancelled, compare_reports, execute_scan, full_scan_options, public_url, readiness, specs, validate_repo_url, validate_target_url

DB = DATA / "scans.sqlite3"
# ponytail: one app process per data directory; scans left running by a previous process are marked interrupted at startup.
ACTIVE: dict[str, threading.Event] = {}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    with connection() as db:
        db.execute("UPDATE scans SET status = 'failed', progress = 'Interrupted', error = 'ProjectN stopped before this scan finished. Start a new scan of this target.' WHERE status IN ('queued', 'running')")
        db.commit()
    yield
    for event in list(ACTIVE.values()):
        event.set()
    deadline = time.monotonic() + 10
    while ACTIVE and time.monotonic() < deadline:
        await asyncio.sleep(0.1)


app = FastAPI(title="ProjectN", version="0.1.0", lifespan=lifespan)


def connection():
    DATA.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created REAL NOT NULL, status TEXT NOT NULL, progress TEXT NOT NULL, target TEXT NOT NULL, result TEXT, error TEXT)")
    if "steps" not in {row[1] for row in db.execute("PRAGMA table_info(scans)")}:
        db.execute("ALTER TABLE scans ADD COLUMN steps TEXT")
    db.commit()
    return db


class ScanRequest(BaseModel):
    url: str | None = Field(default=None, max_length=2048)
    repo_url: str | None = Field(default=None, max_length=512)
    local_path: str | None = Field(default=None, max_length=2048)
    journey_file: str | None = Field(default=None, max_length=2048)
    api_spec_file: str | None = Field(default=None, max_length=2048)
    oob_server: str | None = Field(default=None, max_length=2048)
    oob_token_env: str | None = Field(default=None, max_length=128)
    profile: str = Field(default="standard", pattern="^(standard|deep|full)$")
    authorized_intrusive: bool = False
    port_range: str | None = Field(default=None, max_length=1024)
    crawl_depth: int | None = Field(default=None, ge=1)
    crawl_duration_minutes: int | None = Field(default=None, ge=1)
    template_rate: int | None = Field(default=None, ge=1)
    inventory_limit: int | None = Field(default=None, ge=1)
    browser_page_limit: int | None = Field(default=None, ge=1)


class DraftRequest(BaseModel):
    allow_external: bool = False


def update_scan(scan_id: str, **fields):
    with connection() as db:
        values = list(fields.values()) + [scan_id]
        db.execute("UPDATE scans SET " + ", ".join(f"{key} = ?" for key in fields) + " WHERE id = ?", values)
        db.commit()


def run_scan(scan_id: str, request: dict, cancel: threading.Event):
    try:
        update_scan(scan_id, status="running", progress="Preparing scan")
        report = execute_scan(request, lambda status, steps: update_scan(scan_id, progress=status, steps=json.dumps(steps)), cancel)
        stopped = report["cancelled"]
        update_scan(scan_id, status="cancelled" if stopped else "completed", progress="Stopped by user; partial report saved" if stopped else "Scan complete", result=json.dumps(report), steps=json.dumps(report["steps"]))
    except ScanCancelled:
        update_scan(scan_id, status="cancelled", progress="Stopped by user before scanning started")
    except Exception as exc:
        update_scan(scan_id, status="failed", progress="Scan failed", error=f"Scan failed ({type(exc).__name__}). Check target access and local scanner setup.")
    finally:
        ACTIVE.pop(scan_id, None)


@app.get("/api/health")
def health():
    return {"status": "ok", "storage": str(DB), "platform": "local"}


@app.get("/api/scanners")
def scanners():
    return [readiness(spec) for spec in specs()]


@app.get("/api/assistant/status")
def assistant_status():
    from app.assistant import assistant_status as current_status
    return current_status()


@app.get("/api/config/full")
def full_config():
    return FULL_DEFAULTS


@app.get("/api/scans")
def scans():
    with connection() as db:
        return [dict(row) for row in db.execute("SELECT id, created, status, progress, target FROM scans ORDER BY created DESC LIMIT 50")]


@app.post("/api/scans", status_code=202)
def create_scan(request: ScanRequest):
    values = request.model_dump()
    if not any(values.get(key) for key in ("url", "repo_url", "local_path")):
        raise HTTPException(422, "Provide a website URL, GitHub URL, or local folder.")
    if values["repo_url"] and values["local_path"]:
        raise HTTPException(422, "Choose either a public GitHub repository or a local source folder for one scan.")
    if values["profile"] == "full" and values["url"] and not values["authorized_intrusive"]:
        raise HTTPException(422, "Confirm authorization for intrusive checks before launching Full scan.")
    try:
        if values["profile"] == "full":
            full_scan_options(values)
        if values["url"]:
            validate_target_url(values["url"])
        if values["repo_url"]:
            validate_repo_url(values["repo_url"])
        if values["local_path"] and not Path(values["local_path"]).expanduser().is_dir():
            raise ValueError("Local folder does not exist.")
        if values["journey_file"]:
            if not values["url"] or values["profile"] != "full" or not Path(values["journey_file"]).expanduser().is_file():
                raise ValueError("Journey file requires a Full website scan and an existing local JSON file.")
        if values["api_spec_file"] and (not values["url"] or not Path(values["api_spec_file"]).expanduser().is_file()):
            raise ValueError("API specification requires a website URL and an existing local JSON or YAML file.")
        if values["oob_server"]:
            from app.core import validate_oob_server
            if not values["url"] or values["profile"] != "full":
                raise ValueError("OOB callback server requires a Full website scan.")
            validate_oob_server(values["oob_server"])
        if values["oob_token_env"] and not values["oob_server"]:
            raise ValueError("An OOB token environment variable requires an OOB callback server.")
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    scan_id = str(uuid.uuid4())
    with connection() as db:
        stored_target = {**values, "url": public_url(values["url"]) if values["url"] else None}
        db.execute("INSERT INTO scans (id, created, status, progress, target) VALUES (?, ?, ?, ?, ?)", (scan_id, time.time(), "queued", "Waiting to start", json.dumps(stored_target)))
        db.commit()
    ACTIVE[scan_id] = threading.Event()
    threading.Thread(target=run_scan, args=(scan_id, values, ACTIVE[scan_id]), daemon=True).start()
    return {"id": scan_id, "status": "queued"}


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: str):
    with connection() as db:
        row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Scan not found")
    item = dict(row)
    item["target"] = json.loads(item["target"])
    item["result"] = json.loads(item["result"]) if item["result"] else None
    item["steps"] = json.loads(item["steps"]) if item["steps"] else []
    return item


@app.post("/api/scans/{scan_id}/cancel", status_code=202)
def cancel_scan(scan_id: str):
    event = ACTIVE.get(scan_id)
    if event is None:
        scan_detail(scan_id)
        raise HTTPException(409, "This scan is not running in this ProjectN process.")
    event.set()
    update_scan(scan_id, progress="Stopping scan and its scanner processes")
    return {"id": scan_id, "status": "stopping"}


@app.get("/api/scans/{scan_id}/export")
def export_scan(scan_id: str):
    item = scan_detail(scan_id)
    if not item["result"]:
        raise HTTPException(409, "Report is not ready")
    from fastapi.responses import Response
    return Response(json.dumps(item["result"], indent=2), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="projectn-{scan_id}.json"'})


@app.post("/api/scans/{scan_id}/findings/{finding_id}/draft")
def remediation_draft(scan_id: str, finding_id: str, request: DraftRequest):
    from app.assistant import draft_remediation

    report = scan_detail(scan_id)["result"]
    if report is None:
        raise HTTPException(409, "Report is not ready")
    finding = next((item for item in report["findings"] if item["id"] == finding_id), None)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    try:
        return draft_remediation(finding, request.allow_external)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc


@app.get("/api/scans/{scan_id}/compare/{previous_id}")
def compare_scan(scan_id: str, previous_id: str):
    current = scan_detail(scan_id)["result"]
    previous = scan_detail(previous_id)["result"]
    if not current or not previous:
        raise HTTPException(409, "Both scans must be complete before comparison.")
    identity_fields = ("url", "repo_url", "local_path")
    if any(current["target"].get(key) != previous["target"].get(key) for key in identity_fields):
        raise HTTPException(422, "The scans must assess the same target inputs.")
    if any("fingerprint" not in item for item in previous["findings"] + current["findings"]):
        raise HTTPException(409, "One report predates stable finding identities; rerun both scans to compare them.")
    return compare_reports(previous, current)


DIST = ROOT / "web" / "dist"


@app.get("/{path:path}", include_in_schema=False)
def ui(path: str):
    file = (DIST / path).resolve()
    if file.is_file() and file.is_relative_to(DIST.resolve()):
        return FileResponse(file)
    if path.startswith("assets/"):
        raise HTTPException(404, "Dashboard asset not found; reload the page after rebuilding the dashboard.")
    index = DIST / "index.html"
    if index.is_file():
        # Revalidate on every load so a rebuilt dashboard never references deleted hashed assets.
        return FileResponse(index, headers={"Cache-Control": "no-cache"})
    raise HTTPException(404, "UI has not been built. Run npm install and npm run build in web/.")
