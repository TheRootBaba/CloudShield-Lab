"""SQLite-backed worker leases and low-cardinality operational counters.

The lease table is shared across collector replicas through the shared auth DB.
SQLite is appropriate only while replicas share a reliable local/volume filesystem;
use PostgreSQL or a dedicated queue before multi-host horizontal scaling.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


@contextmanager
def _connect(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path), timeout=15)
    db.execute("PRAGMA busy_timeout=15000")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def ensure_schema(path) -> None:
    with _connect(path) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS worker_leases (
          lease_name TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
          acquired_at TEXT NOT NULL, expires_at TEXT NOT NULL,
          heartbeat_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_worker_lease_expiry ON worker_leases(expires_at);
        CREATE TABLE IF NOT EXISTS worker_heartbeats (
          worker_id TEXT PRIMARY KEY, heartbeat_at TEXT NOT NULL,
          status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS operational_counters (
          metric_name TEXT PRIMARY KEY, metric_value INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL
        );
        """)


def acquire_lease(path, lease_name: str, owner_id: str, ttl_seconds: int = 90) -> bool:
    if not lease_name or not owner_id or not 15 <= int(ttl_seconds) <= 3600:
        raise ValueError("Lease name, owner and a TTL between 15 and 3600 seconds are required")
    ensure_schema(path)
    now = _now()
    expires = _stamp(now + timedelta(seconds=int(ttl_seconds)))
    with _connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT owner_id,expires_at FROM worker_leases WHERE lease_name=?", (lease_name,)).fetchone()
        if row and row[0] != owner_id and row[1] > _stamp(now):
            return False
        db.execute("""INSERT INTO worker_leases VALUES(?,?,?,?,?)
          ON CONFLICT(lease_name) DO UPDATE SET owner_id=excluded.owner_id,
          acquired_at=CASE WHEN worker_leases.owner_id=excluded.owner_id THEN worker_leases.acquired_at ELSE excluded.acquired_at END,
          expires_at=excluded.expires_at,heartbeat_at=excluded.heartbeat_at""",
          (lease_name, owner_id, _stamp(now), expires, _stamp(now)))
        db.execute("""INSERT INTO worker_heartbeats VALUES(?,?, 'running')
          ON CONFLICT(worker_id) DO UPDATE SET heartbeat_at=excluded.heartbeat_at,status='running'""",
          (owner_id, _stamp(now)))
    return True


def renew_lease(path, lease_name: str, owner_id: str, ttl_seconds: int = 90) -> bool:
    if not lease_name or not owner_id or not 15 <= int(ttl_seconds) <= 3600:
        raise ValueError("Lease name, owner and a TTL between 15 and 3600 seconds are required")
    ensure_schema(path)
    now = _now()
    with _connect(path) as db:
        changed = db.execute("""UPDATE worker_leases SET expires_at=?,heartbeat_at=?
          WHERE lease_name=? AND owner_id=? AND expires_at>?""",
          (_stamp(now + timedelta(seconds=int(ttl_seconds))), _stamp(now),
           lease_name, owner_id, _stamp(now))).rowcount
    return changed == 1


def release_lease(path, lease_name: str, owner_id: str) -> bool:
    ensure_schema(path)
    with _connect(path) as db:
        changed = db.execute("DELETE FROM worker_leases WHERE lease_name=? AND owner_id=?",
                             (lease_name, owner_id)).rowcount
    return changed == 1


def record_heartbeat(path, worker_id: str, status: str = "running") -> None:
    if status not in {"running", "stopping", "failed"}:
        raise ValueError("Invalid worker status")
    ensure_schema(path)
    with _connect(path) as db:
        db.execute("""INSERT INTO worker_heartbeats VALUES(?,?,?)
          ON CONFLICT(worker_id) DO UPDATE SET heartbeat_at=excluded.heartbeat_at,status=excluded.status""",
          (worker_id, _stamp(_now()), status))


def increment_counter(path, metric_name: str, amount: int = 1) -> None:
    if not metric_name or not metric_name.replace("_", "").isalnum() or not isinstance(amount, int) or amount < 0:
        raise ValueError("Invalid metric counter")
    ensure_schema(path)
    with _connect(path) as db:
        db.execute("""INSERT INTO operational_counters VALUES(?,?,?)
          ON CONFLICT(metric_name) DO UPDATE SET metric_value=metric_value+excluded.metric_value,
          updated_at=excluded.updated_at""", (metric_name, amount, _stamp(_now())))


def metrics_snapshot(path) -> dict[str, int]:
    ensure_schema(path)
    with _connect(path) as db:
        rows = db.execute("SELECT metric_name,metric_value FROM operational_counters ORDER BY metric_name").fetchall()
    return {name: value for name, value in rows}
