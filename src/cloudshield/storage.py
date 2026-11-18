"""Transactional, idempotent local evidence persistence using SQLite."""
from __future__ import annotations
import hashlib, json, sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from .events import load_events
from .pipeline import analyze_payload

def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)

def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()

class EvidenceStore:
    """Single-user local evidence store; not a multi-tenant production database."""
    def __init__(self, path: str | Path):
        self.path = str(path)
        with self._connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
              event_id TEXT PRIMARY KEY, event_time TEXT NOT NULL, actor TEXT NOT NULL,
              account_id TEXT NOT NULL, payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
              finding_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, rule_id TEXT NOT NULL,
              payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
              FOREIGN KEY(event_id) REFERENCES events(event_id)
            );
            CREATE TABLE IF NOT EXISTS incidents (
              incident_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_actor_time ON events(actor,event_time);
            CREATE INDEX IF NOT EXISTS idx_findings_event ON findings(event_id);
            """)
    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
    def ingest(self, payload: Any) -> dict[str,int]:
        result=analyze_payload(payload)
        events=load_events(payload)
        counts={"events_inserted":0,"findings_inserted":0,"incidents_inserted":0}
        with self._connect() as db:
            for event in events:
                body=event.to_dict()
                cur=db.execute("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)",
                    (event.event_id,event.event_time,event.actor,event.account_id,_canonical(body),_digest(body)))
                counts["events_inserted"]+=cur.rowcount
            for finding in result["findings"]:
                fid=_digest([finding["event_id"],finding["rule_id"]])
                cur=db.execute("INSERT OR IGNORE INTO findings VALUES (?,?,?,?,?)",
                    (fid,finding["event_id"],finding["rule_id"],_canonical(finding),_digest(finding)))
                counts["findings_inserted"]+=cur.rowcount
            for incident in result["incidents"]:
                cur=db.execute("INSERT OR IGNORE INTO incidents VALUES (?,?,?)",
                    (incident["incident_id"],_canonical(incident),_digest(incident)))
                counts["incidents_inserted"]+=cur.rowcount
        return counts
    def timeline(self, actor: str | None=None, account_id: str | None=None) -> list[dict[str,Any]]:
        sql="SELECT payload_json,payload_sha256 FROM events WHERE 1=1"
        args=[]
        if actor is not None: sql+=" AND actor=?"; args.append(actor)
        if account_id is not None: sql+=" AND account_id=?"; args.append(account_id)
        sql+=" ORDER BY event_time,event_id"
        with self._connect() as db: rows=db.execute(sql,args).fetchall()
        return [{"event":json.loads(body),"evidence_sha256":digest} for body,digest in rows]
    def incident(self, incident_id: str) -> dict[str,Any]:
        with self._connect() as db:
            row=db.execute("SELECT payload_json,payload_sha256 FROM incidents WHERE incident_id=?",(incident_id,)).fetchone()
        if row is None: raise KeyError(f"Incident not found: {incident_id}")
        return {"incident":json.loads(row[0]),"evidence_sha256":row[1]}

[executed on device: babam-desktop (5b84c11b-7f66-494f-9e6d-0dd5f16de169)]