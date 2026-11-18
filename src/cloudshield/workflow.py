"""Local incident workflow state and append-only activity history."""
from __future__ import annotations
import json, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATUSES={"new","acknowledged","in_progress","resolved","reopened"}
TRANSITIONS={
 "new":{"acknowledged","in_progress","resolved"},
 "acknowledged":{"in_progress","resolved","reopened"},
 "in_progress":{"acknowledged","resolved","reopened"},
 "resolved":{"reopened"},
 "reopened":{"acknowledged","in_progress","resolved"},
}
PRIORITIES={"P1","P2","P3","P4"}

def _now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
from contextlib import contextmanager
@contextmanager
def _connect(path):
 db=sqlite3.connect(str(path));db.row_factory=sqlite3.Row
 db.execute("PRAGMA foreign_keys=ON")
 try:
  yield db
  db.commit()
 except Exception:
  db.rollback()
  raise
 finally:
  db.close()

def ensure_schema(path):
 Path(path).parent.mkdir(parents=True,exist_ok=True)
 with _connect(path) as db:
  db.executescript("""
  CREATE TABLE IF NOT EXISTS incident_workflow (
   incident_id TEXT PRIMARY KEY, status TEXT NOT NULL, assignee TEXT, priority TEXT NOT NULL,
   updated_at TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
   FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
  );
  CREATE TABLE IF NOT EXISTS incident_activity (
   activity_id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL,
   activity_type TEXT NOT NULL, actor TEXT NOT NULL, details_json TEXT NOT NULL,
   created_at TEXT NOT NULL,
   FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
  );
  CREATE INDEX IF NOT EXISTS idx_incident_activity ON incident_activity(incident_id,activity_id);
  """)

def _exists(db,incident_id):
 return db.execute("SELECT 1 FROM incidents WHERE incident_id=?",(incident_id,)).fetchone() is not None

def _default_priority(db,incident_id):
 row=db.execute("SELECT json_extract(payload_json,'$.severity') FROM incidents WHERE incident_id=?",(incident_id,)).fetchone()
 return {"CRITICAL":"P1","HIGH":"P2","MEDIUM":"P3","LOW":"P4"}.get(str(row[0] if row else "INFO").upper(),"P4")

def _state(db,incident_id):
 row=db.execute("SELECT * FROM incident_workflow WHERE incident_id=?",(incident_id,)).fetchone()
 return dict(row) if row else None

def get_workflow(path,incident_id):
 ensure_schema(path)
 with _connect(path) as db:
  if not _exists(db,incident_id): raise KeyError("Incident not found")
  state=_state(db,incident_id)
  if state is None:
   now=_now();priority=_default_priority(db,incident_id)
   db.execute("INSERT INTO incident_workflow VALUES(?,?,?,?,?,1)",(incident_id,"new",None,priority,now))
   db.execute("INSERT INTO incident_activity(incident_id,activity_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",(incident_id,"created","system",json.dumps({"status":"new","priority":priority},sort_keys=True),now))
   state=_state(db,incident_id)
  activities=db.execute("SELECT activity_id,activity_type,actor,details_json,created_at FROM incident_activity WHERE incident_id=? ORDER BY activity_id",(incident_id,)).fetchall()
 return {"state":state,"activity":[{**dict(a),"details":json.loads(a["details_json"])} for a in activities]}

def update_workflow(path,incident_id,changes,actor="analyst"):
 allowed={"status","assignee","priority"}
 if not isinstance(changes,dict) or set(changes)-allowed: raise ValueError("Only status, assignee, and priority may be updated")
 actor=str(actor or "analyst").strip()[:120] or "analyst"
 ensure_schema(path)
 with _connect(path) as db:
  if not _exists(db,incident_id): raise KeyError("Incident not found")
  current=_state(db,incident_id)
  if current is None:
   now=_now();priority=_default_priority(db,incident_id)
   db.execute("INSERT INTO incident_workflow VALUES(?,?,?,?,?,1)",(incident_id,"new",None,priority,now))
   db.execute("INSERT INTO incident_activity(incident_id,activity_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",(incident_id,"created","system",json.dumps({"status":"new","priority":priority},sort_keys=True),now))
   current=_state(db,incident_id)
  if "status" in changes:
   new=changes["status"]
   if new not in STATUSES: raise ValueError("Invalid status")
   if new!=current["status"] and new not in TRANSITIONS[current["status"]]: raise ValueError(f"Transition not allowed: {current['status']} -> {new}")
  if "priority" in changes and changes["priority"] not in PRIORITIES: raise ValueError("Priority must be P1, P2, P3, or P4")
  if "assignee" in changes:
   assignee=changes["assignee"]
   if assignee is not None and (not isinstance(assignee,str) or len(assignee.strip())>120): raise ValueError("Assignee must be a string of at most 120 characters or null")
   changes["assignee"]=assignee.strip() if assignee else None
  before={k:current[k] for k in ("status","assignee","priority")}
  after={**before,**changes}
  if after!=before:
   now=_now();version=current["version"]+1
   db.execute("UPDATE incident_workflow SET status=?,assignee=?,priority=?,updated_at=?,version=? WHERE incident_id=?",
    (after["status"],after["assignee"],after["priority"],now,version,incident_id))
   db.execute("INSERT INTO incident_activity(incident_id,activity_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",(incident_id,"updated",actor,json.dumps({"before":before,"after":after},sort_keys=True),now))
 return get_workflow(path,incident_id)

def add_note(path,incident_id,note,actor="analyst"):
 if not isinstance(note,str) or not note.strip(): raise ValueError("Note cannot be empty")
 if len(note)>5000: raise ValueError("Note exceeds 5,000 characters")
 actor=str(actor or "analyst").strip()[:120] or "analyst"
 ensure_schema(path)
 with _connect(path) as db:
  if not _exists(db,incident_id): raise KeyError("Incident not found")
  if _state(db,incident_id) is None:
   now=_now();priority=_default_priority(db,incident_id)
   db.execute("INSERT INTO incident_workflow VALUES(?,?,?,?,?,1)",(incident_id,"new",None,priority,now))
   db.execute("INSERT INTO incident_activity(incident_id,activity_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",(incident_id,"created","system",json.dumps({"status":"new","priority":priority},sort_keys=True),now))
  now=_now()
  db.execute("INSERT INTO incident_activity(incident_id,activity_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",(incident_id,"note",actor,json.dumps({"note":note.strip()},ensure_ascii=False),now))
 return get_workflow(path,incident_id)
