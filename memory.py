"""SQLite job history. Stores reports and metadata, never raw submitted source."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import uuid

def now():
    return datetime.now(timezone.utc).isoformat()

class JobStore:
    def __init__(self, workspace=None):
        self.root = Path(workspace or os.getenv("DEBUG_AGENT_WORKSPACE", "workspace")).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.database = self.root / "history.sqlite3"
        with self.connection() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, channel TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                file_count INTEGER NOT NULL, result TEXT)""")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self, channel, count):
        job_id = uuid.uuid4().hex
        with self.connection() as db:
            db.execute("INSERT INTO jobs VALUES (?, ?, 'running', ?, ?, ?, NULL)",
                       (job_id, channel, now(), now(), count))
        return job_id

    def finish(self, job_id, status, result):
        if status not in {"completed", "failed"}:
            raise ValueError("Invalid terminal status.")
        with self.connection() as db:
            db.execute("UPDATE jobs SET status=?, updated_at=?, result=? WHERE id=?",
                       (status, now(), json.dumps(result), job_id))

    def get(self, job_id):
        with self.connection() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["result"] = json.loads(result["result"]) if result["result"] else None
        return result

    def recent(self, limit=20):
        with self.connection() as db:
            return [dict(r) for r in db.execute(
                "SELECT id,channel,status,created_at,updated_at,file_count FROM jobs ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 100)),))]

    def recover(self):
        # One API process only. Do not share its workspace with another API instance.
        with self.connection() as db:
            db.execute("UPDATE jobs SET status='failed', updated_at=?, result=? WHERE status='running' AND channel='api'",
                       (now(), json.dumps({"error": "Service restarted before the job completed."})))

    def delete(self, job_id):
        with self.connection() as db:
            row = db.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                return False
            if row["status"] == "running":
                raise ValueError("Cannot delete a running job.")
            db.execute("DELETE FROM jobs WHERE id=?", (job_id,))
        return True
