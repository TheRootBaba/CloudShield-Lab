import json,tempfile,unittest
from pathlib import Path
from cloudshield.storage import EvidenceStore
from cloudshield.simulator import simulate
from cloudshield.pipeline import analyze_payload
from cloudshield.workflow import get_workflow,update_workflow,add_note
from cloudshield.evidence_bundle import build_bundle,verify_bundle

class IncidentWorkflowTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.db=Path(self.tmp.name)/"db.sqlite"
  payload=simulate("multi-stage-compromise",at="2026-11-18T10:00:00Z")["events"]
  EvidenceStore(self.db).ingest(payload)
  self.incident_id=analyze_payload(payload)["incidents"][0]["incident_id"]
 def tearDown(self):self.tmp.cleanup()
 def test_initial_state_assignment_and_audit(self):
  initial=get_workflow(self.db,self.incident_id)
  self.assertEqual(initial["state"]["status"],"new")
  self.assertEqual(initial["state"]["priority"],"P1")
  updated=update_workflow(self.db,self.incident_id,{"status":"acknowledged","assignee":"blue-team","priority":"P2"},"baba")
  self.assertEqual(updated["state"]["assignee"],"blue-team")
  self.assertEqual(updated["state"]["version"],2)
  self.assertEqual(updated["activity"][-1]["actor"],"baba")
  self.assertEqual(updated["activity"][-1]["details"]["before"]["status"],"new")
 def test_transition_validation_and_note_limits(self):
  with self.assertRaises(ValueError):update_workflow(self.db,self.incident_id,{"status":"closed"})
  with self.assertRaises(ValueError):update_workflow(self.db,self.incident_id,{"priority":"urgent"})
  with self.assertRaises(ValueError):update_workflow(self.db,self.incident_id,{"status":["resolved"]})
  with self.assertRaises(ValueError):update_workflow(self.db,self.incident_id,{"priority":["P1"]})
  with self.assertRaises(ValueError):add_note(self.db,self.incident_id," ")
  with self.assertRaises(ValueError):add_note(self.db,self.incident_id,"x"*5001)
  note=add_note(self.db,self.incident_id,"Need verify CloudTrail context","analyst-1")
  self.assertEqual(note["activity"][-1]["details"]["note"],"Need verify CloudTrail context")
 def test_resolve_reopen_allowed_but_resolved_to_in_progress_not(self):
  update_workflow(self.db,self.incident_id,{"status":"resolved"})
  with self.assertRaises(ValueError):update_workflow(self.db,self.incident_id,{"status":"in_progress"})
  self.assertEqual(update_workflow(self.db,self.incident_id,{"status":"reopened"})["state"]["status"],"reopened")
 def test_missing_incident_raises(self):
  with self.assertRaises(KeyError):get_workflow(self.db,"missing")

class EvidenceBundleTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.db=Path(self.tmp.name)/"db.sqlite"
  payload=simulate("multi-stage-compromise",at="2026-11-18T10:00:00Z")["events"
  ]
  EvidenceStore(self.db).ingest(payload)
  self.incident_id=analyze_payload(payload)["incidents"][0]["incident_id"]
 def tearDown(self):self.tmp.cleanup()
 def test_bundle_verifies_and_contains_referenced_records(self):
  bundle=build_bundle(self.db,self.incident_id)
  self.assertEqual(4,len(bundle["events"]))
  self.assertEqual(4,len(bundle["findings"]))
  self.assertEqual("1.1",bundle["bundle_version"])
  self.assertEqual(4,bundle["collection_metadata"]["event_count"])
  self.assertTrue(bundle["collection_metadata"]["source_formats"])
  self.assertTrue(verify_bundle(bundle)["valid"])
 def test_tampering_is_detected(self):
  bundle=build_bundle(self.db,self.incident_id)
  bundle["events"][0]["event"]["event_name"]="TAMPERED"
  result=verify_bundle(bundle)
  self.assertFalse(result["valid"])
  self.assertTrue(any("Event digest mismatch" in e for e in result["errors"]))
  self.assertTrue(any("manifest hash mismatch" in e for e in result["errors"]))
 def test_missing_or_unreferenced_event_detected(self):
  bundle=build_bundle(self.db,self.incident_id)
  bundle["events"].pop()
  bundle["manifest"]["bundle_sha256"]="wrong"
  result=verify_bundle(bundle)
  self.assertFalse(result["valid"])
  self.assertFalse(result["checked"]["references"])
 def test_malformed_bundle(self):
  self.assertFalse(verify_bundle({})["valid"])
  bundle=build_bundle(self.db,self.incident_id);bundle["events"]="not-an-array"
  self.assertFalse(verify_bundle(bundle)["valid"])
 def test_unknown_version_and_missing_provenance_are_rejected(self):
  bundle=build_bundle(self.db,self.incident_id);bundle["bundle_version"]="99.0"
  self.assertFalse(verify_bundle(bundle)["valid"])
  bundle=build_bundle(self.db,self.incident_id);bundle.pop("collection_metadata")
  self.assertFalse(verify_bundle(bundle)["valid"])
  bundle=build_bundle(self.db,self.incident_id);bundle["events"]=None
  self.assertFalse(verify_bundle(bundle)["valid"])
  bundle=build_bundle(self.db,self.incident_id);bundle["generated_at"]="not-a-timestamp"
  self.assertFalse(verify_bundle(bundle)["valid"])
 def test_duplicate_event_records_detected(self):
  bundle=build_bundle(self.db,self.incident_id);bundle["events"].append(bundle["events"][0])
  result=verify_bundle(bundle)
  self.assertFalse(result["valid"])
  self.assertTrue(any("Duplicate event evidence ID" in e for e in result["errors"]))
if __name__=="__main__":unittest.main()
