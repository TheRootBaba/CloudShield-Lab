"""Local-first HTTP API and static web server for CloudShield Command Center."""
from __future__ import annotations
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from typing import Any
from .pipeline import analyze_payload
from .simulator import SCENARIOS, simulate, simulate_all
from .storage import EvidenceStore
from .graph import build_attack_path
from .workflow import ensure_schema, get_workflow, update_workflow, add_note
from .evidence_bundle import build_bundle, verify_bundle

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
DB_PATH = Path(os.environ.get("CLOUDSHIELD_DB", str(ROOT / "artifacts" / "evidence.sqlite3")))
MAX_BODY = 2 * 1024 * 1024

@contextmanager
def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(DB_PATH))
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def _ensure_store():
    EvidenceStore(DB_PATH)
    ensure_schema(DB_PATH)

def _rows(table: str, limit: int = 200):
    _ensure_store()
    if table not in {"events", "findings", "incidents"}:
        raise ValueError("Invalid table")
    with _connect() as db:
        records = db.execute(f"SELECT payload_json,payload_sha256 FROM {table} ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
    return [{"data": json.loads(body), "sha256": digest} for body, digest in records]

def _dashboard():
    _ensure_store()
    with _connect() as db:
        events_total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        findings_total = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        incidents_total = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        critical_incidents = db.execute("SELECT COUNT(*) FROM incidents WHERE json_extract(payload_json, '$.severity')='CRITICAL'").fetchone()[0]
        severity_rows = db.execute("SELECT json_extract(payload_json, '$.severity'), COUNT(*) FROM findings GROUP BY 1").fetchall()
        source_rows = db.execute("SELECT json_extract(payload_json, '$.source_format'), COUNT(*) FROM events GROUP BY 1").fetchall()
    severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for severity, count in severity_rows:
        key = str(severity or "INFO").upper()
        severities[key] = severities.get(key, 0) + count
    sources = {str(source or "unknown"): count for source, count in source_rows}
    incidents = _rows("incidents", 6)
    findings = _rows("findings", 8)
    events = _rows("events", 8)
    return {
        "events_total": events_total,
        "findings_total": findings_total,
        "incidents_total": incidents_total,
        "critical_incidents": critical_incidents,
        "severity": severities,
        "sources": sources,
        "recent_incidents": [row["data"] for row in incidents],
        "recent_findings": [row["data"] for row in findings],
        "recent_events": [row["data"] for row in events],
        "data_mode": "empty" if not events_total else ("mixed" if len(sources) > 1 else next(iter(sources))),
    }

def _incident(incident_id: str):
    _ensure_store()
    with _connect() as db:
        row = db.execute("SELECT payload_json,payload_sha256 FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
    if not row:
        return None
    data = json.loads(row[0])
    return {"incident": data, "evidence_sha256": row[1], "attack_path": build_attack_path(data)}

class Handler(BaseHTTPRequestHandler):
    server_version = "CloudShieldLocal/1.0"
    def log_message(self, fmt, *args):
        if os.environ.get("CLOUDSHIELD_HTTP_LOG", "0") == "1":
            super().log_message(fmt, *args)
    def _send(self, status: int, payload: Any, content_type="application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else (json.dumps(payload, ensure_ascii=False, default=str).encode() if content_type.startswith("application/json") else str(payload).encode())
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)
    def _body(self):
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("Content-Type must be application/json")
        origin = self.headers.get("Origin")
        if origin and origin != "http://" + self.headers.get("Host", ""):
            raise PermissionError("Cross-origin requests are not allowed")
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > MAX_BODY:
            raise ValueError("Request body exceeds 2 MiB limit")
        raw = self.rfile.read(length)
        return json.loads(raw) if raw else {}
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/health":
                return self._send(200, {"ok": True, "service": "cloudshield-local-api", "database": str(DB_PATH), "aws_collector_enabled": os.environ.get("CLOUDSHIELD_ENABLE_AWS_COLLECTOR") == "1"})
            if path == "/api/dashboard":
                return self._send(200, _dashboard())
            if path == "/api/incidents":
                return self._send(200, [row["data"] for row in _rows("incidents", 500)])
            if path.startswith("/api/incidents/") and path.endswith("/workflow"):
                incident_id=path[len("/api/incidents/"):-len("/workflow")]
                return self._send(200,get_workflow(DB_PATH,incident_id))
            if path.startswith("/api/incidents/") and path.endswith("/export"):
                incident_id=path[len("/api/incidents/"):-len("/export")]
                return self._send(200,build_bundle(DB_PATH,incident_id))
            if path.startswith("/api/incidents/"):
                item = _incident(path.rsplit("/", 1)[-1])
                return self._send(200, item) if item else self._send(404, {"error": "Incident not found"})
            if path == "/api/findings":
                return self._send(200, [row["data"] for row in _rows("findings", 500)])
            if path == "/api/events":
                return self._send(200, [{**row["data"], "fingerprint": row["sha256"]} for row in _rows("events", 500)])
            if path.startswith("/api/evidence/"):
                _ensure_store()
                event_id = path.rsplit("/", 1)[-1]
                with _connect() as db:
                    event = db.execute("SELECT payload_json,payload_sha256 FROM events WHERE event_id=?", (event_id,)).fetchone()
                    findings = db.execute("SELECT payload_json,payload_sha256 FROM findings WHERE event_id=?", (event_id,)).fetchall()
                if not event:
                    return self._send(404, {"error": "Evidence not found"})
                return self._send(200, {"event": json.loads(event[0]), "sha256": event[1], "findings": [{"finding": json.loads(r[0]), "sha256": r[1]} for r in findings]})
            if path == "/api/rules":
                from .detector import RULE_CATALOG
                return self._send(200, RULE_CATALOG)
            if path == "/api/collector/status":
                try:
                    import boto3
                    sdk = True
                    credentials = bool(boto3.Session().get_credentials())
                except ImportError:
                    sdk, credentials = False, False
                return self._send(200, {"enabled": os.environ.get("CLOUDSHIELD_ENABLE_AWS_COLLECTOR") == "1", "sdk_installed": sdk, "credentials_detected": credentials, "mode": "read-only CloudTrail LookupEvents; one-shot, user initiated"})
            if path == "/" or path.startswith("/"):
                safe = "index.html" if path == "/" else path.lstrip("/")
                target = (WEB / safe).resolve()
                if WEB.resolve() not in target.parents and target != WEB / "index.html":
                    return self._send(403, "Forbidden", "text/plain; charset=utf-8")
                if not target.is_file():
                    return self._send(404, "Not found", "text/plain; charset=utf-8")
                mime = "text/html; charset=utf-8" if target.suffix == ".html" else ("text/css; charset=utf-8" if target.suffix == ".css" else "text/javascript; charset=utf-8")
                return self._send(200, target.read_bytes(), mime)
            return self._send(404, {"error": "Not found"})
        except KeyError as exc:
            return self._send(404, {"error": str(exc).strip("'")})
        except (sqlite3.Error, OSError, ValueError) as exc:
            return self._send(500, {"error": str(exc)})
    def do_PATCH(self):
        try:
            body=self._body()
            if self.path.startswith("/api/incidents/") and self.path.endswith("/workflow"):
                incident_id=self.path[len("/api/incidents/"):-len("/workflow")]
                return self._send(200,update_workflow(DB_PATH,incident_id,body.get("changes",body),body.get("actor","analyst")))
            return self._send(404,{"error":"Not found"})
        except KeyError as exc:
            return self._send(404,{"error":str(exc).strip("'")})
        except ValueError as exc:
            return self._send(400,{"error":str(exc)})
        except Exception as exc:
            return self._send(500,{"error":f"{type(exc).__name__}: {exc}"})
    def do_POST(self):
        try:
            body = self._body()
            if self.path == "/api/evidence/verify":
                return self._send(200,verify_bundle(body))
            if self.path.startswith("/api/incidents/") and self.path.endswith("/notes"):
                incident_id=self.path[len("/api/incidents/"):-len("/notes")]
                result=add_note(DB_PATH,incident_id,body.get("note"),body.get("actor","analyst"))
                return self._send(200,result)
            if self.path == "/api/ingest":
                result = EvidenceStore(DB_PATH).ingest(body)
                return self._send(200, {"ok": True, "source": "user-upload", **result})
            if self.path == "/api/simulate":
                scenario = body.get("scenario", "all")
                payload = simulate_all() if scenario == "all" else simulate(scenario)
                scenarios = payload.get("scenarios", [payload])
                total = {"events_inserted": 0, "findings_inserted": 0, "incidents_inserted": 0}
                for item in scenarios:
                    counts = EvidenceStore(DB_PATH).ingest(item["events"])
                    for key, value in counts.items():
                        total[key] += value
                return self._send(200, {"ok": True, "execution": "offline-synthetic", "cloud_api_calls": 0, "scenarios": [s["scenario"] for s in scenarios], **total})
            if self.path == "/api/collector/aws":
                if os.environ.get("CLOUDSHIELD_ENABLE_AWS_COLLECTOR") != "1":
                    return self._send(403, {"error": "Live collector disabled. Set CLOUDSHIELD_ENABLE_AWS_COLLECTOR=1 and restart the local server."})
                region = str(body.get("region", "us-east-1"))
                if not re.fullmatch(r"^[a-z]{2}(?:-[a-z0-9]+)+-\d$", region):
                    return self._send(400, {"error": "Invalid AWS region format"})
                from .collector import collect_cloudtrail
                result = collect_cloudtrail(region, int(body.get("lookback_minutes", 60)), int(body.get("max_pages", 5)))
                counts = EvidenceStore(DB_PATH).ingest(result["events"]) if result["events"] else {"events_inserted": 0, "findings_inserted": 0, "incidents_inserted": 0}
                return self._send(200, {"ok": True, **{k:v for k,v in result.items() if k != "events"}, "events_returned": len(result["events"]), **counts})
            return self._send(404, {"error": "Not found"})
        except PermissionError as exc:
            return self._send(403, {"error": str(exc)})
        except KeyError as exc:
            return self._send(404, {"error": str(exc).strip("'")})
        except (ValueError, json.JSONDecodeError) as exc:
            return self._send(400, {"error": str(exc)})
        except Exception as exc:
            return self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

def main():
    host = os.environ.get("CLOUDSHIELD_HOST", "127.0.0.1")
    port = int(os.environ.get("CLOUDSHIELD_PORT", "8765"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"CloudShield Command Center: http://{host}:{port}")
    print(f"Evidence database: {DB_PATH}")
    server.serve_forever()

if __name__ == "__main__":
    main()