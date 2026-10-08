import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone

log = logging.getLogger("wolffy.buffer")


class LocalBuffer:
    def __init__(self, db_path, max_events=50000):
        self.max_events = max(100, int(max_events))
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock, self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS events ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT NOT NULL, "
                "is_alert INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL)"
            )

    def save(self, event):
        payload = json.dumps(event, default=str)
        created = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO events (created, is_alert, data) VALUES (?, ?, ?)",
                (created, 1 if event.get("type") == "alert" else 0, payload),
            )
            self._trim()

    def _trim(self):
        total = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        excess = total - self.max_events
        if excess <= 0:
            return
        self._conn.execute(
            "DELETE FROM events WHERE id IN "
            "(SELECT id FROM events WHERE is_alert = 0 ORDER BY id LIMIT ?)",
            (excess,),
        )
        total = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        excess = total - self.max_events
        if excess > 0:
            self._conn.execute(
                "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT ?)",
                (excess,),
            )
            log.warning("buffer lleno: descartados %d eventos antiguos", excess)

    def fetch_pending(self, limit=200):
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, data FROM events ORDER BY id LIMIT ?", (limit,)
            ).fetchall()
        result, corrupt = [], []
        for row_id, data in rows:
            try:
                result.append((row_id, json.loads(data)))
            except ValueError:
                corrupt.append(row_id)
        if corrupt:
            self.delete(corrupt)
        return result

    def delete(self, ids):
        if not ids:
            return
        marks = ",".join("?" * len(ids))
        with self._lock, self._conn:
            self._conn.execute(f"DELETE FROM events WHERE id IN ({marks})", list(ids))

    def pending_count(self):
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def close(self):
        with self._lock:
            self._conn.close()
