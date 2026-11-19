"""Local-first HTTP API and static web server for CloudShield Command Center."""
from __future__ import annotations
import json
import os
import re
import ipaddress
import sqlite3
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from typing import Any
from .pipeline import analyze_payload
from .simulator import SCENARIOS, simulate, simulate_all
from .storage import EvidenceStore
from .graph import build_attack_path
from .assets import inventory, relationship_graph
from .attack_techniques import catalog as technique_catalog
from .workflow import ensure_schema, get_workflow, update_workflow, add_note
from .evidence_bundle import build_bundle, verify_bundle
from .security import SlidingWindowLimiter, authenticate, role_allowed, audit

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
DB_PATH = Path(os.environ.get("CLOUDSHIELD_DB", str(ROOT / "artifacts" / "evidence.sqlite3")))
MAX_BODY = 2 * 1024 * 1024
_READ_LIMITER = SlidingWindowLimiter(120)
_WRITE_LIMITER = SlidingWindowLimiter(30)

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
    queries = {
        "events": "SELECT payload_json,payload_sha256 FROM events ORDER BY rowid DESC LIMIT ?",
        "findings": "SELECT payload_json,payload_sha256 FROM findings ORDER BY rowid DESC LIMIT ?",
        "incidents": "SELECT payload_json,payload_sha256 FROM incidents ORDER BY rowid DESC LIMIT ?",
    }
    with _connect() as db:
        records = db.execute(queries[table], (limit,)).fetchall()
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


def _analytics(window: str = "24h"):
    """Aggregate the local evidence store into bounded chart series."""
    durations = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7)}
    if window not in {*durations, "all"}:
        raise ValueError("Unsupported analytics window")
    _ensure_store()
    with _connect() as db:
        event_values = [row[0] for row in db.execute("SELECT json_extract(payload_json, '$.event_time') FROM events").fetchall()]
        finding_values = [row[0] for row in db.execute("SELECT json_extract(payload_json, '$.event_time') FROM findings").fetchall()]
        top_rules = db.execute("SELECT json_extract(payload_json, '$.rule_id'), COUNT(*) FROM findings GROUP BY 1 ORDER BY 2 DESC LIMIT 6").fetchall()

    def parse_time(value):
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return None

    event_times = [t for t in (parse_time(v) for v in event_values) if t]
    finding_times = [t for t in (parse_time(v) for v in finding_values) if t]
    observed = event_times + finding_times
    now = max([datetime.now(timezone.utc), *observed])
    if window == "all":
        start = min(observed) if observed else now - timedelta(hours=24)
        bucket_count = 16
    else:
        start = now - durations[window]
        bucket_count = 12 if window in {"1h", "24h"} else 14
    span = max((now - start).total_seconds(), 1)
    step = span / bucket_count
    buckets = [{"time": start + timedelta(seconds=step * i), "events": 0, "findings": 0} for i in range(bucket_count)]

    def add_times(values, key):
        for stamp in values:
            if stamp < start or stamp > now:
                continue
            index = min(bucket_count - 1, int((stamp - start).total_seconds() / step))
            buckets[index][key] += 1

    add_times(event_times, "events")
    add_times(finding_times, "findings")
    label_format = "%H:%M" if window in {"1h", "24h"} else "%b %d"
    return {
        "window": window,
        "events_total": sum(b["events"] for b in buckets),
        "findings_total": sum(b["findings"] for b in buckets),
        "series": [{"label": b["time"].strftime(label_format), "events": b["events"], "findings": b["findings"]} for b in buckets],
        "top_rules": [{"rule": str(rule or "Unknown"), "count": count} for rule, count in top_rules],
        "scope": "Aggregated across all records in the local SQLite evidence store",
    }


def _incident(incident_id: str):
    _ensure_store()
    with _connect() as db:
        row = db.execute("SELECT payload_json,payload_sha256 FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
    if not row:
        return None
    data = json.loads(row[0])
    return {"incident": data, "evidence_sha256": row[1], "attack_path": build_attack_path(data), "workflow": get_workflow(DB_PATH, incident_id)}

class Handler(BaseHTTPRequestHandler):
    server_version = "CloudShieldLocal/1.0"
    def log_message(self, fmt, *args):
        if os.environ.get("CLOUDSHIELD_HTTP_LOG", "0") == "1":
            super().log_message(fmt, *args)
    def _drain_rejected_body(self):
        """Consume a bounded rejected request body before closing, avoiding TCP reset on unread bytes."""
        raw_length = self.headers.get("Content-Length", "0")
        if raw_length.isdigit() and 0 <= int(raw_length) <= MAX_BODY:
            if int(raw_length):
                self.rfile.read(int(raw_length))
        else:
            self.close_connection = True

    def _authorize(self, method: str, path: str) -> bool:
        if path == "/api/health":
            return True
        if not path.startswith("/api/"):
            return True
        remote = self.client_address[0]
        limiter = _READ_LIMITER if method == "GET" else _WRITE_LIMITER
        if not limiter.allow(remote):
            self.close_connection = True
            self._send(429, {"error": "Request rate limit exceeded"})
            return False
        try:
            role = authenticate(self.headers.get("Authorization"))
        except RuntimeError as exc:
            self.close_connection = True
            self._send(503, {"error": str(exc)})
            return False
        if role is None:
            if method in {"POST", "PATCH", "PUT"}:
                self._drain_rejected_body()
            self.close_connection = True
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return False
        if not role_allowed(role, method, path):
            if method in {"POST", "PATCH", "PUT"}:
                self._drain_rejected_body()
            self.close_connection = True
            self._send(403, {"error": "Insufficient role"})
            return False
        self._cloudshield_role = role
        return True

    def _audit_mutation(self, action: str, resource: str):
        role = getattr(self, "_cloudshield_role", "local")
        audit(DB_PATH, role, action, resource, self.client_address[0])

    def _send(self, status: int, payload: Any, content_type="application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else (json.dumps(payload, ensure_ascii=False, default=str).encode() if content_type.startswith("application/json") else str(payload).encode())
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)
    def _body(self):
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("Content-Type must be application/json")
        origin = self.headers.get("Origin")
        if origin and origin != "http://" + self.headers.get("Host", ""):
            raise PermissionError("Cross-origin requests are not allowed")
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Transfer-Encoding is not supported")
        raw_length = self.headers.get("Content-Length", "0")
        if not raw_length.isdigit():
            raise ValueError("Invalid Content-Length")
        length = int(raw_length)
        if length < 0 or length > MAX_BODY:
            raise ValueError("Request body exceeds 2 MiB limit")
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body must contain valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object")
        return value
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if not self._authorize("GET", path): return
            if path == "/api/health":
                return self._send(200, {"ok": True, "service": "cloudshield-local-api", "database": str(DB_PATH), "aws_collector_enabled": os.environ.get("CLOUDSHIELD_ENABLE_AWS_COLLECTOR") == "1"})
            if path == "/api/analytics":
                window = parse_qs(parsed.query).get("window", ["24h"])[0]
                return self._send(200, _analytics(window))
            if path == "/api/dashboard":
                return self._send(200, _dashboard())
            if path == "/api/incidents":
                _ensure_store()
                with _connect() as db:
                    rows=db.execute("SELECT i.payload_json,w.status,w.assignee,w.priority,w.updated_at,w.version FROM incidents i LEFT JOIN incident_workflow w ON w.incident_id=i.incident_id ORDER BY i.rowid DESC LIMIT 500").fetchall()
                incidents=[]
                for row in rows:
                    item=json.loads(row[0]);severity=str(item.get("severity","INFO")).upper()
                    item["workflow"]={"status":row[1] or "new","assignee":row[2],"priority":row[3] or {"CRITICAL":"P1","HIGH":"P2","MEDIUM":"P3","LOW":"P4"}.get(severity,"P4"),"updated_at":row[4],"version":row[5] or 0}
                    incidents.append(item)
                return self._send(200,incidents)
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
                return self._send(200, technique_catalog())
            if path == "/api/assets":
                _ensure_store()
                with _connect() as db:
                    event_rows = db.execute("SELECT payload_json FROM events ORDER BY event_time,event_id").fetchall()
                    finding_rows = db.execute("SELECT payload_json FROM findings").fetchall()
                assets = inventory([json.loads(r[0]) for r in event_rows], [json.loads(r[0]) for r in finding_rows])
                return self._send(200, assets)
            if path == "/api/asset-graph":
                _ensure_store()
                with _connect() as db:
                    event_rows = db.execute("SELECT payload_json FROM events ORDER BY event_time,event_id").fetchall()
                    finding_rows = db.execute("SELECT payload_json FROM findings").fetchall()
                events = [json.loads(r[0]) for r in event_rows]
                findings = [json.loads(r[0]) for r in finding_rows]
                assets = inventory(events, findings)
                return self._send(200, relationship_graph(events, assets))
            if path in {"/api/collector/status", "/api/providers"}:
                try:
                    import boto3
                    aws_sdk = True
                    aws_credentials = bool(boto3.Session().get_credentials())
                except ImportError:
                    aws_sdk, aws_credentials = False, False
                try:
                    import importlib.util
                    azure_sdk = all(importlib.util.find_spec(name) is not None for name in ("azure.identity", "azure.mgmt.resource", "azure.mgmt.monitor"))
                except (ImportError, ModuleNotFoundError, ValueError):
                    azure_sdk = False
                return self._send(200, {
                    "providers": [
                        {"id":"aws", "name":"Amazon Web Services", "sdk_installed":aws_sdk, "credentials_detected":aws_credentials, "enabled":os.environ.get("CLOUDSHIELD_ENABLE_AWS_COLLECTOR") == "1" or os.environ.get("CLOUDSHIELD_ENABLE_AWS_INVENTORY") == "1", "capabilities":["CloudTrail management event lookup", "bounded EC2/security-group/S3-name/IAM metadata inventory"]},
                        {"id":"azure", "name":"Microsoft Azure", "sdk_installed":azure_sdk, "environment_credentials_configured":bool(os.environ.get("AZURE_CLIENT_ID") and os.environ.get("AZURE_TENANT_ID") and os.environ.get("AZURE_CLIENT_SECRET")), "subscription_configured":bool(os.environ.get("AZURE_SUBSCRIPTION_ID")), "credential_chain":"DefaultAzureCredential (environment, workload/managed identity, developer tools)", "enabled":os.environ.get("CLOUDSHIELD_ENABLE_AZURE_COLLECTION") == "1", "capabilities":["Azure Activity Log control-plane events", "bounded Azure Resource Manager metadata inventory"]}
                    ],
                    "mode":"explicitly enabled, bounded, read-only, user-initiated collection"
                })
            if path == "/" or path.startswith("/"):
                safe = "index.html" if path == "/" else path.lstrip("/")
                target = (WEB / safe).resolve()
                if WEB.resolve() not in target.parents and target != WEB / "index.html":
                    return self._send(403, "Forbidden", "text/plain; charset=utf-8")
                if not target.is_file():
                    return self._send(404, "Not found", "text/plain; charset=utf-8")
                mime_types = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".svg": "image/svg+xml", ".woff": "font/woff", ".woff2": "font/woff2", ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp", ".json": "application/json; charset=utf-8"}
                mime = mime_types.get(target.suffix.lower(), "application/octet-stream")
                return self._send(200, target.read_bytes(), mime)
            return self._send(404, {"error": "Not found"})
        except KeyError as exc:
            return self._send(404, {"error": str(exc).strip("'")})
        except ValueError as exc:
            return self._send(400, {"error": str(exc)})
        except (sqlite3.Error, OSError) as exc:
            return self._send(500, {"error": str(exc)})
    def do_PATCH(self):
        try:
            if not self._authorize("PATCH", urlparse(self.path).path): return
            body=self._body()
            if self.path.startswith("/api/incidents/") and self.path.endswith("/workflow"):
                incident_id=self.path[len("/api/incidents/"):-len("/workflow")]
                role=getattr(self,"_cloudshield_role","local")
                actor=body.get("actor","analyst") if role == "local" else role
                result=update_workflow(DB_PATH,incident_id,body.get("changes",body),actor)
                self._audit_mutation("workflow.update", incident_id)
                return self._send(200,result)
            return self._send(404,{"error":"Not found"})
        except PermissionError as exc:
            return self._send(403,{"error":str(exc)})
        except KeyError as exc:
            return self._send(404,{"error":str(exc).strip("'")})
        except ValueError as exc:
            return self._send(400,{"error":str(exc)})
        except Exception as exc:
            return self._send(500,{"error":f"{type(exc).__name__}: {exc}"})
    def do_POST(self):
        try:
            if not self._authorize("POST", urlparse(self.path).path): return
            body = self._body()
            if self.path == "/api/evidence/verify":
                return self._send(200,verify_bundle(body))
            if self.path.startswith("/api/incidents/") and self.path.endswith("/notes"):
                incident_id=self.path[len("/api/incidents/"):-len("/notes")]
                role=getattr(self,"_cloudshield_role","local")
                actor=body.get("actor","analyst") if role == "local" else role
                result=add_note(DB_PATH,incident_id,body.get("note"),actor)
                self._audit_mutation("incident.note", incident_id)
                return self._send(200,result)
            if self.path == "/api/ingest":
                result = EvidenceStore(DB_PATH).ingest(body)
                self._audit_mutation("evidence.ingest", "user-upload")
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
                self._audit_mutation("simulation.run", str(scenario))
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
                self._audit_mutation("aws.collect", region)
                return self._send(200, {"ok": True, **{k:v for k,v in result.items() if k != "events"}, "events_returned": len(result["events"]), **counts})
            if self.path in {"/api/collector/azure/activity-logs", "/api/collector/azure/inventory"}:
                if os.environ.get("CLOUDSHIELD_ENABLE_AZURE_COLLECTION") != "1":
                    return self._send(403, {"error": "Azure collection disabled. Set CLOUDSHIELD_ENABLE_AZURE_COLLECTION=1 and restart the local server."})
                subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
                if not subscription_id:
                    return self._send(400, {"error": "Set AZURE_SUBSCRIPTION_ID in the server environment."})
                from . import azure_provider
                if self.path.endswith("/activity-logs"):
                    result = azure_provider.collect_activity_logs(subscription_id, int(body.get("lookback_hours", 24)), int(body.get("max_pages", 10)), int(body.get("max_records", 2000)))
                    counts = EvidenceStore(DB_PATH).ingest(result["events"]) if result["events"] else {"events_inserted":0,"findings_inserted":0,"incidents_inserted":0}
                    self._audit_mutation("azure.activity_logs.collect", subscription_id)
                    return self._send(200, {"ok":True, **{k:v for k,v in result.items() if k != "events"}, "events_returned":len(result["events"]), **counts})
                result = azure_provider.collect_inventory(subscription_id, int(body.get("max_pages", 10)), int(body.get("max_records", 2000)))
                self._audit_mutation("azure.inventory.collect", subscription_id)
                return self._send(200, result)
            return self._send(404, {"error": "Not found"})
        except PermissionError as exc:
            return self._send(403, {"error": str(exc)})
        except KeyError as exc:
            return self._send(404, {"error": str(exc).strip("'")})
        except (ValueError, json.JSONDecodeError) as exc:
            return self._send(400, {"error": str(exc)})
        except Exception as exc:
            return self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

def validate_bind_host(host: str, container_mode: bool = False) -> None:
    """Keep native runs on loopback; allow wildcard bind only inside an explicitly configured container."""
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = False
    # Require both the explicit profile flag and a container runtime marker; Compose maps host port to 127.0.0.1 only.
    in_container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    if not is_loopback and not (container_mode and in_container and host == "0.0.0.0"):  # nosec B104
        raise RuntimeError(
            "CloudShield may bind only to loopback unless CLOUDSHIELD_CONTAINER_MODE=1 is set inside the supplied container. "
            "The container must publish its host port on 127.0.0.1 only; this app is single-tenant and not approved for public exposure."
        )


def main():
    host = os.environ.get("CLOUDSHIELD_HOST", "127.0.0.1")
    container_mode = os.environ.get("CLOUDSHIELD_CONTAINER_MODE") == "1"
    validate_bind_host(host, container_mode=container_mode)
    port = int(os.environ.get("CLOUDSHIELD_PORT", "8765"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"CloudShield Command Center: http://{host}:{port}")
    print(f"Evidence database: {DB_PATH}")
    server.serve_forever()

if __name__ == "__main__":
    main()