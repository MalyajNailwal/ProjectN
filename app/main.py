from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from urllib.parse import urlparse

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


@contextmanager
def connection():
    """Open the history database for one operation and always close it.

    sqlite3's own context manager only commits; an unclosed connection keeps the file locked on Windows.
    """
    DATA.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB, timeout=30)
    try:
        db.row_factory = sqlite3.Row
        # WAL mode lets a reader (a status poll) proceed without waiting on a concurrent writer (a running
        # scan's own progress updates) instead of blocking behind SQLite's default lock; this is what was
        # actually causing a status poll to occasionally outlast its own client-side timeout under load.
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created REAL NOT NULL, status TEXT NOT NULL, progress TEXT NOT NULL, target TEXT NOT NULL, result TEXT, error TEXT)")
        columns = {row[1] for row in db.execute("PRAGMA table_info(scans)")}
        if "steps" not in columns:
            db.execute("ALTER TABLE scans ADD COLUMN steps TEXT")
        if "finished" not in columns:
            db.execute("ALTER TABLE scans ADD COLUMN finished REAL")
            # Scans saved before this column existed keep their end time inside the stored report.
            for row in db.execute("SELECT id, result FROM scans WHERE result IS NOT NULL").fetchall():
                try:
                    finished = json.loads(row["result"]).get("finished_at")
                except (ValueError, AttributeError):
                    finished = None
                if finished:
                    db.execute("UPDATE scans SET finished = ? WHERE id = ?", (finished, row["id"]))
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


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
    port_depth: str | None = Field(default=None, pattern="^(quick|standard|thorough|full|custom)$")
    port_range: str | None = Field(default=None, max_length=1024)
    crawl_depth: int | None = Field(default=None, ge=1)
    crawl_duration_minutes: int | None = Field(default=None, ge=1)
    template_rate: int | None = Field(default=None, ge=1)
    inventory_limit: int | None = Field(default=None, ge=1)
    browser_page_limit: int | None = Field(default=None, ge=1)


class DraftRequest(BaseModel):
    allow_external: bool = False


class RetryRequest(BaseModel):
    step_id: str
    authorized_intrusive: bool = False


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
        update_scan(scan_id, status="cancelled" if stopped else "completed", progress="Stopped by user; partial report saved" if stopped else "Scan complete", result=json.dumps(report), steps=json.dumps(report["steps"]), finished=time.time())
    except ScanCancelled:
        update_scan(scan_id, status="cancelled", progress="Stopped by user before scanning started", finished=time.time())
    except Exception as exc:
        update_scan(scan_id, status="failed", progress="Scan failed", error=f"Scan failed ({type(exc).__name__}). Check target access and local scanner setup.", finished=time.time())
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
        return [dict(row) for row in db.execute("SELECT id, created, finished, status, progress, target, error FROM scans ORDER BY created DESC LIMIT 50")]


@app.post("/api/scans", status_code=202)
def create_scan(request: ScanRequest):
    return queue_scan(request.model_dump())


def queue_scan(values: dict):
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
        stored_target = {**values, "url": public_url(values["url"]) if values["url"] else None, "url_query_removed": bool(values["url"] and urlparse(values["url"]).query)}
        db.execute("INSERT INTO scans (id, created, status, progress, target) VALUES (?, ?, ?, ?, ?)", (scan_id, time.time(), "queued", "Waiting to start", json.dumps(stored_target)))
        db.commit()
    ACTIVE[scan_id] = threading.Event()
    threading.Thread(target=run_scan, args=(scan_id, values, ACTIVE[scan_id]), daemon=True).start()
    return {"id": scan_id, "status": "queued"}


@app.post("/api/scans/{scan_id}/retry", status_code=202)
def retry_scan(scan_id: str, request: RetryRequest):
    previous = scan_detail(scan_id)
    if previous["status"] in {"queued", "running"}:
        raise HTTPException(409, "Stop or finish the current scan before retrying a check.")
    prior_steps = previous["steps"] or (previous["result"] or {}).get("steps", [])
    step = next((item for item in prior_steps if item["id"] == request.step_id), None)
    if step is None or step["state"] not in {"failed", "partial", "not_run", "cancelled"}:
        raise HTTPException(422, "Only an incomplete check from this scan can be retried.")
    if previous["target"].get("url_query_removed"):
        raise HTTPException(409, "The original URL query was withheld from history. Start a new scan with the full URL to repeat this check.")
    values = ScanRequest.model_validate(previous["target"]).model_dump()
    values["authorized_intrusive"] = request.authorized_intrusive
    values["retry_of"] = scan_id
    values["retry_step_ids"] = [request.step_id]
    return queue_scan(values)


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


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str):
    if scan_id in ACTIVE:
        raise HTTPException(409, "Stop this scan before deleting it.")
    with connection() as db:
        deleted = db.execute("DELETE FROM scans WHERE id = ?", (scan_id,)).rowcount
        db.commit()
    if not deleted:
        raise HTTPException(404, "Scan not found")
    return {"deleted": deleted}


@app.delete("/api/scans")
def clear_scans():
    """Delete every scan except those still running in this process, then shrink the database file."""
    running = list(ACTIVE)
    with connection() as db:
        keep = f" WHERE id NOT IN ({','.join('?' * len(running))})" if running else ""
        deleted = db.execute("DELETE FROM scans" + keep, running).rowcount
        db.commit()
        db.execute("VACUUM")
    return {"deleted": deleted, "kept_running": len(running)}


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


@app.get("/api/scans/{scan_id}/findings/{finding_id}/history")
def finding_history(scan_id: str, finding_id: str):
    """When this exact finding (by its stable fingerprint) was first seen on this same target, and in how many scans."""
    report = scan_detail(scan_id)["result"]
    if report is None:
        raise HTTPException(409, "Report is not ready")
    finding = next((item for item in report["findings"] if item["id"] == finding_id), None)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    target_key = (report["target"].get("url") or report["target"].get("repo_url") or report["target"].get("local_path") or "").lower()
    with connection() as db:
        rows = db.execute("SELECT created, target, result FROM scans WHERE status = 'completed' AND result IS NOT NULL ORDER BY created ASC").fetchall()
    first_seen, seen_in = None, 0
    for row in rows:
        other_target = json.loads(row["target"])
        other_key = (other_target.get("url") or other_target.get("repo_url") or other_target.get("local_path") or "").lower()
        if other_key != target_key:
            continue
        if any(item.get("fingerprint") == finding["fingerprint"] for item in json.loads(row["result"]).get("findings", [])):
            seen_in += 1
            if first_seen is None:
                first_seen = row["created"]
    return {"first_seen": first_seen, "seen_in_scans": seen_in}


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
