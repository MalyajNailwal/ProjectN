"""Deleting scan history never removes a scan that is still running."""

import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app import main


class ScanHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        data = Path(self.temp.name)
        self.patches = [patch.object(main, "DATA", data), patch.object(main, "DB", data / "scans.sqlite3"), patch.dict(main.ACTIVE, {}, clear=True)]
        for item in self.patches:
            item.start()
        with main.connection() as db:
            for scan_id, status in (("done-1", "completed"), ("done-2", "failed"), ("live", "running")):
                db.execute("INSERT INTO scans (id, created, status, progress, target) VALUES (?, 0, ?, '', '{}')", (scan_id, status))
            db.commit()
        main.ACTIVE["live"] = threading.Event()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def remaining(self) -> set[str]:
        with main.connection() as db:
            return {row["id"] for row in db.execute("SELECT id FROM scans")}

    def test_delete_one_scan_but_not_a_running_one(self):
        self.assertEqual(main.delete_scan("done-1"), {"deleted": 1})
        with self.assertRaises(HTTPException) as running:
            main.delete_scan("live")
        self.assertEqual(running.exception.status_code, 409)
        with self.assertRaises(HTTPException) as missing:
            main.delete_scan("done-1")
        self.assertEqual(missing.exception.status_code, 404)
        self.assertEqual(self.remaining(), {"done-2", "live"})

    def test_clear_history_keeps_running_scans(self):
        self.assertEqual(main.clear_scans(), {"deleted": 2, "kept_running": 1})
        self.assertEqual(self.remaining(), {"live"})

    def test_end_time_is_recorded_and_copied_for_older_scans(self):
        # A database from before the finished column existed keeps its end time inside the stored report.
        older = Path(self.temp.name) / "older.sqlite3"
        db = sqlite3.connect(older)
        db.execute("CREATE TABLE scans (id TEXT PRIMARY KEY, created REAL NOT NULL, status TEXT NOT NULL, progress TEXT NOT NULL, target TEXT NOT NULL, result TEXT, error TEXT)")
        db.execute("INSERT INTO scans VALUES ('old', 100, 'completed', '', '{}', ?, NULL)", (json.dumps({"finished_at": 160.0}),))
        db.commit()
        db.close()
        with patch.object(main, "DB", older):
            self.assertEqual(main.scans()[0]["finished"], 160.0)
            with main.connection() as db:
                db.execute("INSERT INTO scans (id, created, status, progress, target) VALUES ('new', 200, 'queued', '', '{}')")
            with patch.object(main, "execute_scan", return_value={"cancelled": False, "steps": []}):
                main.run_scan("new", {}, threading.Event())
            finished = {row["id"]: row["finished"] for row in main.scans()}
        self.assertIsInstance(finished["new"], float)
        self.assertGreater(finished["new"], 200)

    def test_retry_accepts_only_incomplete_check_and_requires_fresh_full_authorization(self):
        target = {"url": "https://example.test", "profile": "full", "authorized_intrusive": True}
        steps = [{"id": "browser", "state": "failed"}, {"id": "surface", "state": "completed"}]
        with main.connection() as db:
            db.execute("UPDATE scans SET target = ?, steps = ? WHERE id = 'done-1'", (json.dumps(target), json.dumps(steps)))
        with self.assertRaises(HTTPException) as completed:
            main.retry_scan("done-1", main.RetryRequest(step_id="surface", authorized_intrusive=True))
        self.assertEqual(completed.exception.status_code, 422)
        with self.assertRaises(HTTPException) as no_consent:
            main.retry_scan("done-1", main.RetryRequest(step_id="browser"))
        self.assertEqual(no_consent.exception.status_code, 422)
        with patch.object(main, "queue_scan", return_value={"id": "retry", "status": "queued"}) as queued:
            self.assertEqual(main.retry_scan("done-1", main.RetryRequest(step_id="browser", authorized_intrusive=True))["id"], "retry")
        values = queued.call_args.args[0]
        self.assertEqual(values["retry_step_ids"], ["browser"])
        self.assertEqual(values["retry_of"], "done-1")
        with main.connection() as db:
            db.execute("UPDATE scans SET steps = NULL, result = ? WHERE id = 'done-1'", (json.dumps({"steps": steps}),))
        with patch.object(main, "queue_scan", return_value={"id": "retry", "status": "queued"}):
            self.assertEqual(main.retry_scan("done-1", main.RetryRequest(step_id="browser", authorized_intrusive=True))["id"], "retry")
        target["url_query_removed"] = True
        with main.connection() as db:
            db.execute("UPDATE scans SET target = ? WHERE id = 'done-1'", (json.dumps(target),))
        with self.assertRaises(HTTPException) as lost_query:
            main.retry_scan("done-1", main.RetryRequest(step_id="browser", authorized_intrusive=True))
        self.assertEqual(lost_query.exception.status_code, 409)


if __name__ == "__main__":
    unittest.main()
