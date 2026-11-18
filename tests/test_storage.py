import tempfile, unittest
from pathlib import Path
from cloudshield.storage import EvidenceStore
from cloudshield.simulator import simulate

class EvidenceStoreTests(unittest.TestCase):
    def test_ingest_is_idempotent_and_persists_incident(self):
        payload=simulate("public-s3-policy",at="2026-11-18T10:00:00Z")["events"]
        with tempfile.TemporaryDirectory() as tmp:
            store=EvidenceStore(Path(tmp)/"evidence.sqlite3")
            first=store.ingest(payload)
            second=store.ingest(payload)
            self.assertEqual(first,{"events_inserted":1,"findings_inserted":1,"incidents_inserted":1})
            self.assertEqual(second,{"events_inserted":0,"findings_inserted":0,"incidents_inserted":0})
            rows=store.timeline()
            self.assertEqual(len(rows),1)
            self.assertEqual(len(rows[0]["evidence_sha256"]),64)
    def test_incident_lookup_and_missing_incident(self):
        payload=simulate("iam-policy-escalation",at="2026-11-18T10:00:00Z")["events"]
        with tempfile.TemporaryDirectory() as tmp:
            store=EvidenceStore(Path(tmp)/"evidence.sqlite3")
            store.ingest(payload)
            from cloudshield.pipeline import analyze_payload
            incident_id=analyze_payload(payload)["incidents"][0]["incident_id"]
            self.assertEqual(store.incident(incident_id)["incident"]["finding_count"],1)
            with self.assertRaises(KeyError): store.incident("not-found")
    def test_actor_filter(self):
        rows=simulate("iam-policy-escalation",at="2026-11-18T10:00:00Z")["events"]
        with tempfile.TemporaryDirectory() as tmp:
            store=EvidenceStore(Path(tmp)/"evidence.sqlite3")
            store.ingest(rows)
            self.assertEqual(len(store.timeline(actor="arn:aws:iam::000000000000:user/lab-operator")),1)
            self.assertEqual(store.timeline(actor="not-an-actor"),[])

if __name__=="__main__": unittest.main()
