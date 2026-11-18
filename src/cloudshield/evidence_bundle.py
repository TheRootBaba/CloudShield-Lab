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
 checks={"incident":False,"events":0,"findings":0,"references":True,"workflow":False}
 incident=bundle.get("incident")
 if isinstance(incident,dict) and isinstance(incident.get("data"),dict):
  checks["incident"]=digest(incident["data"])==incident.get("sha256")
  if not checks["incident"]:errors.append("Incident digest mismatch")
 else:errors.append("Incident record missing or malformed")
 events=bundle.get("events",[])
 findings=bundle.get("findings",[])
 if not isinstance(events,list):errors.append("Events must be an array");events=[]
 if not isinstance(findings,list):errors.append("Findings must be an array");findings=[]
 event_ids=set()
 seen_event_ids=set()
 for item in events:
  if not isinstance(item,dict) or not isinstance(item.get("event"),dict):errors.append("Malformed event evidence item");continue
  event=item["event"];ok=digest(event)==item.get("sha256");checks["events"]+=1
  if event.get("event_id"):
   eid=str(event["event_id"])
   if eid in seen_event_ids:errors.append("Duplicate event evidence ID: "+eid)
   seen_event_ids.add(eid);event_ids.add(eid)
  if not ok:errors.append("Event digest mismatch: "+str(event.get("event_id","unknown")))
 for item in findings:
  if not isinstance(item,dict) or not isinstance(item.get("finding"),dict):errors.append("Malformed finding evidence item");continue
  finding=item["finding"];ok=digest(finding)==item.get("sha256");checks["findings"]+=1
  if not ok:errors.append("Finding digest mismatch: "+str(finding.get("finding_id",finding.get("rule_id","unknown"))))
  if finding.get("event_id") and str(finding["event_id"]) not in event_ids:errors.append("Finding references missing event: "+str(finding["event_id"]))
 timeline_ids=set()
 if checks["incident"]:
  timeline=incident["data"].get("timeline",[])
  if not isinstance(timeline,list):errors.append("Incident timeline must be an array");timeline=[]
  timeline_ids={str(t.get("event_id")) for t in timeline if isinstance(t,dict) and t.get("event_id")}
 if event_ids!=timeline_ids:checks["references"]=False;errors.append("Bundle event references do not match incident timeline")
 workflow=bundle.get("workflow")
 if isinstance(workflow,dict) and isinstance(workflow.get("state"),dict) and isinstance(workflow.get("activity"),list):
  checks["workflow"]=True
 else:errors.append("Workflow state or activity history missing/malformed")
 for key,count in (("event_count",len(events)),("finding_count",len(findings)),("activity_count",len(workflow.get("activity",[])) if isinstance(workflow,dict) and isinstance(workflow.get("activity"),list) else -1)):
  if manifest.get(key)!=count:errors.append("Manifest "+key+" mismatch")
 return {"valid":not errors,"errors":errors,"checked":checks,"bundle_sha256":manifest.get("bundle_sha256")}
