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
    def test_bind_host_must_be_loopback(self):
        api.validate_bind_host("127.0.0.1")
        api.validate_bind_host("::1")
        with self.assertRaises(RuntimeError):
            api.validate_bind_host("0.0.0.0")
        with self.assertRaises(RuntimeError):
            api.validate_bind_host("192.0.2.10")
        with self.assertRaises(RuntimeError):
            api.validate_bind_host("localhost")

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
    def test_analytics_asset_inventory_and_attack_mapping_endpoints(self):
        self.post("/api/simulate", {"scenario": "all"})
        analytics = self.get("/api/analytics?window=24h")
        self.assertEqual(7, analytics["events_total"])
        self.assertEqual(7, analytics["findings_total"])
        self.assertEqual(12, len(analytics["series"]))
        assets = self.get("/api/assets")
        self.assertGreaterEqual(len(assets), 1)
        self.assertTrue(assets)
        graph = self.get("/api/asset-graph")
        self.assertTrue(graph["nodes"])
        self.assertIn("edges", graph)
        rules = self.get("/api/rules")
        self.assertTrue(any(rule["attack_techniques"] for rule in rules))

    def test_configured_role_tokens_gate_api_and_audit_mutations(self):
        import os
        from urllib.error import HTTPError
        admin="A"*40; responder="R"*40; analyst="V"*40
        old={key:os.environ.get(key) for key in ("CLOUDSHIELD_ADMIN_TOKEN","CLOUDSHIELD_RESPONDER_TOKEN","CLOUDSHIELD_ANALYST_TOKEN")}
        try:
            os.environ["CLOUDSHIELD_ADMIN_TOKEN"]=admin
            os.environ["CLOUDSHIELD_RESPONDER_TOKEN"]=responder
            os.environ["CLOUDSHIELD_ANALYST_TOKEN"]=analyst
            with self.assertRaises(HTTPError) as denied:
                self.get("/api/dashboard")
            self.assertEqual(401,denied.exception.code)
            denied.exception.close()
            request=Request(self.base+"/api/dashboard",headers={"Authorization":"Bearer "+analyst})
            with urlopen(request,timeout=3) as response:
                self.assertEqual(200,response.status)
            payload=json.dumps({"scenario":"multi-stage-compromise"}).encode()
            request=Request(self.base+"/api/simulate",data=payload,headers={"Content-Type":"application/json","Authorization":"Bearer "+analyst},method="POST")
            with self.assertRaises(HTTPError) as forbidden:
                urlopen(request,timeout=3)
            self.assertEqual(403,forbidden.exception.code)
            forbidden.exception.close()
            request=Request(self.base+"/api/simulate",data=payload,headers={"Content-Type":"application/json","Authorization":"Bearer "+responder},method="POST")
            with urlopen(request,timeout=3) as response:
                self.assertEqual(200,response.status)
            import sqlite3
            db=sqlite3.connect(api.DB_PATH)
            try:
                actor,action=db.execute("SELECT actor,action FROM security_audit ORDER BY audit_id DESC LIMIT 1").fetchone()
            finally:
                db.close()
            self.assertEqual(("responder","simulation.run"),(actor,action))
            request=Request(self.base+"/api/incidents",headers={"Authorization":"Bearer "+responder})
            with urlopen(request,timeout=3) as response:
                incident=json.loads(response.read())[0]
            patch=Request(self.base+"/api/incidents/"+incident["incident_id"]+"/workflow",data=json.dumps({"changes":{"status":"acknowledged"},"actor":"admin"}).encode(),headers={"Content-Type":"application/json","Authorization":"Bearer "+responder},method="PATCH")
            with urlopen(patch,timeout=3) as response:
                activity=json.loads(response.read())["activity"][-1]
            self.assertEqual("responder",activity["actor"])
        finally:
            for key,value in old.items():
                if value is None: os.environ.pop(key,None)
                else: os.environ[key]=value

    def test_rule_inventory_endpoint(self):
        rules=self.get("/api/rules")
        self.assertGreaterEqual(len(rules),10)
if __name__=="__main__": unittest.main()
