"""Portable evidence bundles with SHA-256 integrity verification (not signatures)."""
from __future__ import annotations
import hashlib,json,sqlite3
from datetime import datetime,timezone
from pathlib import Path
from .workflow import ensure_schema,get_workflow

def canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,default=str)
def digest(value): return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()

def build_bundle(path,incident_id):
 ensure_schema(path)
 workflow=get_workflow(path,incident_id)
 db=sqlite3.connect(str(path));db.row_factory=sqlite3.Row
 try:
  inc=db.execute("SELECT payload_json,payload_sha256 FROM incidents WHERE incident_id=?",(incident_id,)).fetchone()
  if not inc: raise KeyError("Incident not found")
  incident=json.loads(inc["payload_json"])
  event_ids=sorted({str(t.get("event_id")) for t in incident.get("timeline",[]) if t.get("event_id")})
  events=[];findings=[]
  for eid in event_ids:
   e=db.execute("SELECT payload_json,payload_sha256 FROM events WHERE event_id=?",(eid,)).fetchone()
   if e: events.append({"event":json.loads(e["payload_json"]),"sha256":e["payload_sha256"]})
   rows=db.execute("SELECT payload_json,payload_sha256 FROM findings WHERE event_id=? ORDER BY rule_id",(eid,)).fetchall()
   findings.extend({"finding":json.loads(r["payload_json"]),"sha256":r["payload_sha256"]} for r in rows)
  activity=workflow
  body={"bundle_version":"1.0","generated_at":datetime.now(timezone.utc).isoformat(timespec="seconds"),"incident":{"data":incident,"sha256":inc["payload_sha256"]},"workflow":activity,"events":events,"findings":findings}
  body["manifest"]={"hash_algorithm":"SHA-256","bundle_sha256":digest(body),"event_count":len(events),"finding_count":len(findings),"activity_count":len(activity["activity"])}
  return body
 finally:db.close()

def verify_bundle(bundle):
 if not isinstance(bundle,dict):return {"valid":False,"errors":["Bundle must be a JSON object"],"checked":{}}
 errors=[]
 manifest=bundle.get("manifest")
 if not isinstance(manifest,dict):return {"valid":False,"errors":["Missing manifest"],"checked":{}}
 if manifest.get("hash_algorithm")!="SHA-256":errors.append("Unsupported hash algorithm")
 body={k:v for k,v in bundle.items() if k!="manifest"}
 if digest(body)!=manifest.get("bundle_sha256"):errors.append("Bundle manifest hash mismatch")
 checks={"incident":False,"events":0,"findings":0,"references":True}
 incident=bundle.get("incident")
 if isinstance(incident,dict) and "data" in incident:
  checks["incident"]=digest(incident["data"])==incident.get("sha256")
  if not checks["incident"]:errors.append("Incident digest mismatch")
 else:errors.append("Incident record missing or malformed")
 for item in bundle.get("events",[]):
  if not isinstance(item,dict) or "event" not in item:errors.append("Malformed event evidence item");continue
  ok=digest(item["event"])==item.get("sha256");checks["events"]+=1
  if not ok:errors.append("Event digest mismatch: "+str(item["event"].get("event_id","unknown")))
 for item in bundle.get("findings",[]):
  if not isinstance(item,dict) or "finding" not in item:errors.append("Malformed finding evidence item");continue
  ok=digest(item["finding"])==item.get("sha256");checks["findings"]+=1
  if not ok:errors.append("Finding digest mismatch: "+str(item["finding"].get("finding_id",item["finding"].get("rule_id","unknown"))))
 timeline_ids=set((t.get("event_id") for t in incident.get("data",{}).get("timeline",[]))) if isinstance(incident,dict) else set()
 event_ids=set((e.get("event",{}).get("event_id") for e in bundle.get("events",[]) if isinstance(e,dict)))
 if not event_ids.issubset(timeline_ids):checks["references"]=False;errors.append("Bundle contains event not referenced by incident timeline")
 if not timeline_ids.issubset(event_ids):checks["references"]=False;errors.append("Incident timeline references missing event evidence")
 return {"valid":not errors,"errors":errors,"checked":checks,"bundle_sha256":manifest.get("bundle_sha256")}
