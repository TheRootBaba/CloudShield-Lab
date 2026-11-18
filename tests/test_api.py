import json, tempfile, threading, unittest
from pathlib import Path
from urllib.request import Request, urlopen
from http.server import ThreadingHTTPServer
from cloudshield import api

class ApiIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.original=api.DB_PATH
        api.DB_PATH=Path(self.tmp.name)/"api.sqlite3"
        self.server=ThreadingHTTPServer(("127.0.0.1",0),api.Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.base=f"http://127.0.0.1:{self.server.server_port}"
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
        api.DB_PATH=self.original; self.tmp.cleanup()
    def get(self,path):
        with urlopen(self.base+path,timeout=3) as response: return json.loads(response.read())
    def post(self,path,payload):
        request=Request(self.base+path,data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"},method="POST")
        with urlopen(request,timeout=3) as response: return json.loads(response.read())
    def patch(self,path,payload):
        request=Request(self.base+path,data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"},method="PATCH")
        with urlopen(request,timeout=3) as response: return json.loads(response.read())
    def test_health_and_static_app(self):
        self.assertTrue(self.get("/api/health")["ok"])
        self.assertEqual(self.get("/api/dashboard")["events_total"],0)
        with urlopen(self.base+"/",timeout=3) as response:
            self.assertIn(b"CloudShield",response.read())
    def test_simulation_incident_graph_and_source_provenance(self):
        result=self.post("/api/simulate",{"scenario":"multi-stage-compromise"})
        self.assertEqual(result["execution"],"offline-synthetic")
        self.assertEqual(result["events_inserted"],4)
        self.assertEqual(result["findings_inserted"],4)
        dashboard=self.get("/api/dashboard")
        self.assertEqual(dashboard["events_total"],4)
        self.assertEqual(dashboard["data_mode"],"synthetic")
        incidents=self.get("/api/incidents")
        self.assertEqual(len(incidents),1)
        detail=self.get("/api/incidents/"+incidents[0]["incident_id"])
        self.assertEqual(len(detail["attack_path"]["event_nodes"]),4)
        self.assertEqual(len(detail["attack_path"]["sequence_edges"]),3)
        events=self.get("/api/events")
        self.assertTrue(all(event["source_format"]=="synthetic" for event in events))
        self.assertTrue(all(len(event["fingerprint"])==64 for event in events))
    def test_incident_workflow_and_export_verify_endpoints(self):
        self.post("/api/simulate",{"scenario":"multi-stage-compromise"})
        incident=self.get("/api/incidents")[0]
        iid=incident["incident_id"]
        self.assertEqual("new",incident["workflow"]["status"])
        self.assertEqual("P1",incident["workflow"]["priority"])
        self.assertEqual(0,incident["workflow"]["version"])
        workflow=self.get("/api/incidents/"+iid+"/workflow")
        self.assertEqual(workflow["state"]["status"],"new")
        changed=self.patch("/api/incidents/"+iid+"/workflow",{"changes":{"status":"acknowledged","assignee":"triage","priority":"P2"},"actor":"test-analyst"})
        self.assertEqual(changed["state"]["assignee"],"triage")
        note=self.post("/api/incidents/"+iid+"/notes",{"note":"Review source events","actor":"test-analyst"})
        self.assertEqual(note["activity"][-1]["details"]["note"],"Review source events")
        bundle=self.get("/api/incidents/"+iid+"/export")
        self.assertEqual(4,len(bundle["events"]))
        self.assertTrue(self.post("/api/evidence/verify",bundle)["valid"])
        bundle["events"][0]["event"]["event_name"]="modified"
        self.assertFalse(self.post("/api/evidence/verify",bundle)["valid"])
    def test_rule_inventory_endpoint(self):
        rules=self.get("/api/rules")
        self.assertGreaterEqual(len(rules),10)
if __name__=="__main__": unittest.main()