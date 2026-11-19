"""Local-first HTTP API and static web server for CloudShield Command Center."""
from __future__ import annotations
import json
import os
import secrets
from contextvars import ContextVar
from http.cookies import SimpleCookie
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
from .auth import AuthStore, cookie_header

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
DB_PATH = Path(os.environ.get("CLOUDSHIELD_DB", str(ROOT / "artifacts" / "evidence.sqlite3")))
_CURRENT_DB = ContextVar("cloudshield_tenant_db", default=None)
_AUTH_STORE = None
_FIREBASE_APP = None

def _db_path():
    return _CURRENT_DB.get() or DB_PATH

def _auth_enabled():
    return os.environ.get("CLOUDSHIELD_AUTH_MODE", "").lower() == "multi_user"

def _auth_store():
    global _AUTH_STORE
    if _AUTH_STORE is None:
        auth_db = Path(os.environ.get("CLOUDSHIELD_AUTH_DB", str(ROOT / "artifacts" / "auth.sqlite3")))
        tenant_root = Path(os.environ.get("CLOUDSHIELD_TENANT_DIR", str(ROOT / "artifacts" / "tenants")))
        _AUTH_STORE = AuthStore(auth_db, tenant_root)
    return _AUTH_STORE

def _firebase_public_config():
    provider = os.environ.get("CLOUDSHIELD_AUTH_PROVIDER", "local").strip().lower()
    return {
        "provider": provider,
        "firebase": {
            "apiKey": os.environ.get("CLOUDSHIELD_FIREBASE_API_KEY", ""),
            "authDomain": os.environ.get("CLOUDSHIELD_FIREBASE_AUTH_DOMAIN", ""),
            "projectId": os.environ.get("CLOUDSHIELD_FIREBASE_PROJECT_ID", ""),
            "appId": os.environ.get("CLOUDSHIELD_FIREBASE_APP_ID", ""),
            "messagingSenderId": os.environ.get("CLOUDSHIELD_FIREBASE_MESSAGING_SENDER_ID", ""),
        },
    }


def _verify_firebase_id_token(id_token: str) -> dict:
    """Verify Firebase-issued browser ID tokens; never trust client-supplied identity fields."""
    global _FIREBASE_APP
    if not isinstance(id_token, str) or not id_token or len(id_token) > 16_384:
        raise PermissionError("A valid Firebase sign-in token is required")
    project_id = os.environ.get("CLOUDSHIELD_FIREBASE_PROJECT_ID", "").strip()
    credential_path = (os.environ.get("CLOUDSHIELD_FIREBASE_CREDENTIALS")
                       or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")).strip()
    if not project_id or not credential_path:
        raise RuntimeError("Firebase authentication is not configured on this server")
    try:
        import firebase_admin
        from firebase_admin import auth as firebase_auth, credentials
        if _FIREBASE_APP is None:
            try:
                _FIREBASE_APP = firebase_admin.get_app("cloudshield")
            except ValueError:
                credential = credentials.Certificate(credential_path)
                _FIREBASE_APP = firebase_admin.initialize_app(
                    credential, {"projectId": project_id}, name="cloudshield")
        return firebase_auth.verify_id_token(id_token, app=_FIREBASE_APP, check_revoked=True)
    except RuntimeError:
        raise
    except Exception as exc:
        # Keep provider diagnostics out of the public response.
        raise PermissionError("Firebase sign-in could not be verified. Sign in again.") from exc


def _client_ip(handler):
    """Use the TCP peer for rate limiting and audit attribution.

    Forwarding headers are client-controlled unless a separately verified trusted-proxy
    chain is configured. The production proxy is the only public ingress; using its peer
    address conservatively applies the login limiter to the whole proxy rather than
    allowing attackers to bypass it with a forged X-Forwarded-For value.
    """
    try:
        return str(ipaddress.ip_address(handler.client_address[0]))
    except (ValueError, TypeError, IndexError):
        return "unknown"

def _cookies(handler):
    jar = SimpleCookie()
    try:
        jar.load(handler.headers.get("Cookie", ""))
    except Exception:
        return None, None
    return (jar.get("cloudshield_session").value if jar.get("cloudshield_session") else None,
            jar.get("cloudshield_csrf").value if jar.get("cloudshield_csrf") else None)

MAX_BODY = 2 * 1024 * 1024
_READ_LIMITER = SlidingWindowLimiter(120)
_WRITE_LIMITER = SlidingWindowLimiter(30)
_AUTH_LIMITER = SlidingWindowLimiter(30)

@contextmanager
def _connect():
    _db_path().parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(_db_path()))
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def _ensure_store():
    EvidenceStore(_db_path())
    ensure_schema(_db_path())

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
        "scope": "Aggregated across all records in the current workspace SQLite evidence store",
    }


def _incident(incident_id: str):
    _ensure_store()
    with _connect() as db:
        row = db.execute("SELECT payload_json,payload_sha256 FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
    if not row:
        return None
    data = json.loads(row[0])
    return {"incident": data, "evidence_sha256": row[1], "attack_path": build_attack_path(data), "workflow": get_workflow(_db_path(), incident_id)}

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
        remote = _client_ip(self)
        limiter = _READ_LIMITER if method == "GET" else _WRITE_LIMITER
        if not limiter.allow(remote):
            self.close_connection = True
            self._send(429, {"error": "Request rate limit exceeded"})
            return False
        if _auth_enabled():
            session = getattr(self, "_cloudshield_session", None)
            if session is None:
                self.close_connection = True
                self._send(401, {"error": "Sign in is required"})
                return False
            role = session.role
        else:
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
        audit(_db_path(), role, action, resource, _client_ip(self))

    def _send(self, status: int, payload: Any, content_type="application/json; charset=utf-8", extra_headers=None):
        body = payload if isinstance(payload, bytes) else (json.dumps(payload, ensure_ascii=False, default=str).encode() if content_type.startswith("application/json") else str(payload).encode())
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:; connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://www.googleapis.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        for name, value in (extra_headers or []): self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)
    def _body(self):
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("Content-Type must be application/json")
        origin = self.headers.get("Origin")
        if origin:
            parsed_origin = urlparse(origin)
            allowed_schemes = {"https"} if os.environ.get("CLOUDSHIELD_COOKIE_SECURE") == "1" else {"http", "https"}
            if parsed_origin.scheme not in allowed_schemes or parsed_origin.netloc != self.headers.get("Host", "") or parsed_origin.path not in {"", "/"}:
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

    def _auth_response(self, user, csrf=None, token=None):
        secure = os.environ.get("CLOUDSHIELD_COOKIE_SECURE") == "1"
        headers = []
        if token:
            headers.append(("Set-Cookie", cookie_header("cloudshield_session", token, secure=secure, max_age=12*60*60, http_only=True)))
        if csrf:
            headers.append(("Set-Cookie", cookie_header("cloudshield_csrf", csrf, secure=secure, max_age=12*60*60, http_only=False)))
        return self._send(200, {"ok": True, "user": user, "csrf_token": csrf}, extra_headers=headers)

    def _auth_get(self, path):
        store = _auth_store()
        if path == "/api/auth/config":
            config = _firebase_public_config()
            firebase = config["firebase"]
            configured = all(firebase.values())
            return self._send(200, {"provider": config["provider"], "firebase": firebase,
                                    "configured": configured if config["provider"] == "firebase" else True})
        if path == "/api/auth/status":
            bootstrap_required = store.bootstrap_required()
            return self._send(200, {"enabled": True, "bootstrap_required": bootstrap_required,
                                   "bootstrap_token_required": bootstrap_required and bool(os.environ.get("CLOUDSHIELD_BOOTSTRAP_TOKEN"))})
        token, csrf = _cookies(self)
        session = store.get_session(token)
        if path == "/api/auth/me":
            if not session: return self._send(401, {"error": "Not signed in"})
            return self._send(200, {"user": {"user_id":session.user_id,"tenant_id":session.tenant_id,"email":session.email,"display_name":session.display_name,"role":session.role,"expires_at":session.expires_at}})
        if path == "/api/team/members":
            if not session or session.role != "admin": return self._send(403, {"error":"Workspace administrator access required"})
            return self._send(200, {"members":store.members(session)})
        return self._send(404, {"error":"Not found"})

    def _auth_post(self, path):
        store = _auth_store()
        if path in {"/api/auth/login", "/api/auth/register", "/api/auth/firebase"} and not _AUTH_LIMITER.allow(_client_ip(self)):
            return self._send(429, {"error":"Too many authentication attempts; try again later"})
        body = self._body()
        provider = os.environ.get("CLOUDSHIELD_AUTH_PROVIDER", "local").strip().lower()
        if provider == "firebase" and path in {"/api/auth/login", "/api/auth/register"}:
            return self._send(403, {"error": "Password authentication is disabled; use Firebase Authentication"})
        if path == "/api/auth/firebase":
            if os.environ.get("CLOUDSHIELD_AUTH_PROVIDER", "local").strip().lower() != "firebase":
                return self._send(404, {"error": "Firebase authentication is not enabled"})
            claims = _verify_firebase_id_token(body.get("id_token", ""))
            if claims.get("email_verified") is not True:
                return self._send(403, {"error": "Verify your email address before accessing CloudShield"})
            uid, email = claims.get("uid"), claims.get("email")
            if not isinstance(uid, str) or not isinstance(email, str):
                return self._send(403, {"error": "Firebase identity is missing a verified email"})
            store = _auth_store()
            if store.bootstrap_required():
                bootstrap_token = os.environ.get("CLOUDSHIELD_BOOTSTRAP_TOKEN", "")
                provided = body.get("bootstrap_token", "")
                if bootstrap_token and (not isinstance(provided, str) or len(provided) > 128
                        or not provided.isascii() or not bootstrap_token.isascii()
                        or not secrets.compare_digest(provided, bootstrap_token)):
                    return self._send(403, {"error": "A valid initial administrator setup key is required"})
            display_name = body.get("display_name") or claims.get("name") or email.split("@", 1)[0]
            user = store.register_firebase(uid, email, display_name, body.get("tenant_name", ""), body.get("invite_code", ""))
            EvidenceStore(store.tenant_path(user["tenant_id"]))
            session, token = store.login_firebase(uid)
            store.record_audit(session, "firebase.session.created", session.email)
            response_user = {"user_id":session.user_id,"tenant_id":session.tenant_id,"email":session.email,
                             "display_name":session.display_name,"role":session.role,"expires_at":session.expires_at}
            return self._auth_response(response_user, session.csrf_token, token)
        if path == "/api/auth/register":
            bootstrap_token = os.environ.get("CLOUDSHIELD_BOOTSTRAP_TOKEN", "")
            provided_bootstrap = body.get("bootstrap_token", "")
            if store.bootstrap_required() and bootstrap_token and (
                not isinstance(provided_bootstrap, str) or len(provided_bootstrap) > 128
                or not provided_bootstrap.isascii() or not bootstrap_token.isascii()
                or not secrets.compare_digest(provided_bootstrap, bootstrap_token)
            ):
                return self._send(403, {"error": "A valid initial administrator setup key is required"})
            user = store.register(body.get("email"), body.get("display_name"), body.get("password"),
                                  body.get("tenant_name", ""), body.get("invite_code", ""))
            EvidenceStore(store.tenant_path(user["tenant_id"]))
            session, token = store.login(body.get("email"), body.get("password"))
            store.record_audit(session, "account.registered", session.email)
            return self._auth_response(user, session.csrf_token, token)
        if path == "/api/auth/login":
            session, token = store.login(body.get("email"), body.get("password"))
            store.record_audit(session, "session.created", session.email)
            user = {"user_id":session.user_id,"tenant_id":session.tenant_id,"email":session.email,
                    "display_name":session.display_name,"role":session.role,"expires_at":session.expires_at}
            return self._auth_response(user, session.csrf_token, token)
        token, csrf = _cookies(self)
        session = store.get_session(token)
        if not session: return self._send(401, {"error":"Not signed in"})
        if not store.csrf_valid(session, csrf, self.headers.get("X-CSRF-Token")):
            return self._send(403, {"error":"CSRF validation failed"})
        if path == "/api/auth/logout":
            store.record_audit(session, "session.revoked", session.email)
            store.logout(token)
            secure = os.environ.get("CLOUDSHIELD_COOKIE_SECURE") == "1"
            return self._send(200, {"ok":True}, extra_headers=[
                ("Set-Cookie", cookie_header("cloudshield_session", "", secure=secure, max_age=0, http_only=True)),
                ("Set-Cookie", cookie_header("cloudshield_csrf", "", secure=secure, max_age=0, http_only=False))])
        if path == "/api/team/invites":
            result = store.create_invite(session, body.get("role", "analyst"))
            store.record_audit(session, "member.invited", result["role"])
            return self._send(201, result)
        if path == "/api/team/workspace-invites":
            result = store.create_workspace_invite(session, body.get("workspace_name", ""))
            store.record_audit(session, "workspace.invited", result["workspace_name"])
            return self._send(201, result)
        if path.startswith("/api/team/members/") and path.endswith("/disable"):
            user_id = path[len("/api/team/members/"):-len("/disable")]
            store.disable_member(session, user_id)
            return self._send(200, {"ok":True})
        return self._send(404, {"error":"Not found"})

    def _dispatch_auth(self, method):
        path = urlparse(self.path).path
        if path == "/api/auth/status" and method == "GET":
            enabled = _auth_enabled()
            bootstrap_required = _auth_store().bootstrap_required() if enabled else False
            self._send(200, {"enabled":enabled, "bootstrap_required":bootstrap_required,
                             "bootstrap_token_required":bootstrap_required and bool(os.environ.get("CLOUDSHIELD_BOOTSTRAP_TOKEN"))})
            return True
        if not _auth_enabled() or not (path.startswith("/api/auth/") or path.startswith("/api/team/")):
            return False
        try:
            if method == "GET": self._auth_get(path)
            elif method == "POST": self._auth_post(path)
            else: self._send(405, {"error":"Method not allowed"})
        except PermissionError as exc:
            self._send(403, {"error":str(exc)})
        except ValueError as exc:
            self._send(400, {"error":str(exc)})
        except RuntimeError as exc:
            self._send(503, {"error":str(exc)})
        except sqlite3.Error:
            self._send(503, {"error":"Authentication storage is temporarily unavailable"})
        return True

    def _with_tenant(self, method, handler):
        path = urlparse(self.path).path
        if self._dispatch_auth(method):
            return
        if not _auth_enabled() or not path.startswith("/api/") or path == "/api/health":
            return handler()
        token, csrf = _cookies(self)
        session = _auth_store().get_session(token)
        if not session:
            return self._send(401, {"error":"Sign in required"})
        if method in {"POST","PATCH","PUT","DELETE"}:
            if not _auth_store().csrf_valid(session, csrf, self.headers.get("X-CSRF-Token")):
                return self._send(403, {"error":"CSRF validation failed"})
        tenant_db = _auth_store().tenant_path(session.tenant_id)
        context = _CURRENT_DB.set(tenant_db)
        self._cloudshield_session = session
        self._cloudshield_role = session.role
        try:
            return handler()
        finally:
            _CURRENT_DB.reset(context)

    def do_GET(self): return self._with_tenant("GET", self._do_GET)
    def do_POST(self): return self._with_tenant("POST", self._do_POST)
    def do_PATCH(self): return self._with_tenant("PATCH", self._do_PATCH)

    def _do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if not self._authorize("GET", path): return
            if path == "/api/health":
                if _auth_enabled():
                    return self._send(200, {"ok": True, "service": "cloudshield-api"})
                return self._send(200, {"ok": True, "service": "cloudshield-local-api", "database": str(_db_path()), "aws_collector_enabled": os.environ.get("CLOUDSHIELD_ENABLE_AWS_COLLECTOR") == "1"})
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
                return self._send(200,get_workflow(_db_path(),incident_id))
            if path.startswith("/api/incidents/") and path.endswith("/export"):
                incident_id=path[len("/api/incidents/"):-len("/export")]
                return self._send(200,build_bundle(_db_path(),incident_id))
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
                    aws_credentials = False if _auth_enabled() else bool(boto3.Session().get_credentials())
                except ImportError:
                    aws_sdk, aws_credentials = False, False
                try:
                    import importlib.util
                    azure_sdk = all(importlib.util.find_spec(name) is not None for name in ("azure.identity", "azure.mgmt.resource", "azure.mgmt.monitor"))
                except (ImportError, ModuleNotFoundError, ValueError):
                    azure_sdk = False
                if _auth_enabled():
                    return self._send(200, {
                        "providers": [
                            {"id":"aws", "name":"Amazon Web Services", "sdk_installed":aws_sdk, "credentials_detected":False, "enabled":False, "capabilities":["Cloud collection unavailable in shared multi-user mode; tenant-scoped identities are required"]},
                            {"id":"azure", "name":"Microsoft Azure", "sdk_installed":azure_sdk, "environment_credentials_configured":False, "subscription_configured":False, "enabled":False, "capabilities":["Cloud collection unavailable in shared multi-user mode; tenant-scoped identities are required"]}
                        ],
                        "mode":"disabled in shared multi-user mode until provider identities are tenant-scoped"
                    })
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
    def _do_PATCH(self):
        try:
            if not self._authorize("PATCH", urlparse(self.path).path): return
            body=self._body()
            if self.path.startswith("/api/incidents/") and self.path.endswith("/workflow"):
                incident_id=self.path[len("/api/incidents/"):-len("/workflow")]
                role=getattr(self,"_cloudshield_role","local")
                actor=body.get("actor","analyst") if role == "local" else role
                result=update_workflow(_db_path(),incident_id,body.get("changes",body),actor)
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
    def _do_POST(self):
        try:
            if not self._authorize("POST", urlparse(self.path).path): return
            body = self._body()
            if self.path == "/api/evidence/verify":
                return self._send(200,verify_bundle(body))
            if self.path.startswith("/api/incidents/") and self.path.endswith("/notes"):
                incident_id=self.path[len("/api/incidents/"):-len("/notes")]
                role=getattr(self,"_cloudshield_role","local")
                actor=body.get("actor","analyst") if role == "local" else role
                result=add_note(_db_path(),incident_id,body.get("note"),actor)
                self._audit_mutation("incident.note", incident_id)
                return self._send(200,result)
            if self.path == "/api/ingest":
                result = EvidenceStore(_db_path()).ingest(body)
                self._audit_mutation("evidence.ingest", "user-upload")
                return self._send(200, {"ok": True, "source": "user-upload", **result})
            if self.path == "/api/simulate":
                scenario = body.get("scenario", "all")
                payload = simulate_all() if scenario == "all" else simulate(scenario)
                scenarios = payload.get("scenarios", [payload])
                total = {"events_inserted": 0, "findings_inserted": 0, "incidents_inserted": 0}
                for item in scenarios:
                    counts = EvidenceStore(_db_path()).ingest(item["events"])
                    for key, value in counts.items():
                        total[key] += value
                self._audit_mutation("simulation.run", str(scenario))
                return self._send(200, {"ok": True, "execution": "offline-synthetic", "cloud_api_calls": 0, "scenarios": [s["scenario"] for s in scenarios], **total})
            if self.path == "/api/collector/aws":
                if _auth_enabled():
                    return self._send(403, {"error":"Cloud collection is disabled in shared multi-user mode until provider credentials are tenant-scoped."})
                if os.environ.get("CLOUDSHIELD_ENABLE_AWS_COLLECTOR") != "1":
                    return self._send(403, {"error": "Live collector disabled. Set CLOUDSHIELD_ENABLE_AWS_COLLECTOR=1 and restart the local server."})
                region = str(body.get("region", "us-east-1"))
                if not re.fullmatch(r"^[a-z]{2}(?:-[a-z0-9]+)+-\d$", region):
                    return self._send(400, {"error": "Invalid AWS region format"})
                from .collector import collect_cloudtrail
                result = collect_cloudtrail(region, int(body.get("lookback_minutes", 60)), int(body.get("max_pages", 5)))
                counts = EvidenceStore(_db_path()).ingest(result["events"]) if result["events"] else {"events_inserted": 0, "findings_inserted": 0, "incidents_inserted": 0}
                self._audit_mutation("aws.collect", region)
                return self._send(200, {"ok": True, **{k:v for k,v in result.items() if k != "events"}, "events_returned": len(result["events"]), **counts})
            if self.path in {"/api/collector/azure/activity-logs", "/api/collector/azure/inventory"}:
                if _auth_enabled():
                    return self._send(403, {"error":"Cloud collection is disabled in shared multi-user mode until provider credentials are tenant-scoped."})
                if os.environ.get("CLOUDSHIELD_ENABLE_AZURE_COLLECTION") != "1":
                    return self._send(403, {"error": "Azure collection disabled. Set CLOUDSHIELD_ENABLE_AZURE_COLLECTION=1 and restart the local server."})
                subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
                if not subscription_id:
                    return self._send(400, {"error": "Set AZURE_SUBSCRIPTION_ID in the server environment."})
                from . import azure_provider
                if self.path.endswith("/activity-logs"):
                    result = azure_provider.collect_activity_logs(subscription_id, int(body.get("lookback_hours", 24)), int(body.get("max_pages", 10)), int(body.get("max_records", 2000)))
                    counts = EvidenceStore(_db_path()).ingest(result["events"]) if result["events"] else {"events_inserted":0,"findings_inserted":0,"incidents_inserted":0}
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


def validate_deployment_security(host: str) -> None:
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback and not _auth_enabled():
        raise RuntimeError("Non-loopback deployments require CLOUDSHIELD_AUTH_MODE=multi_user.")
    if not is_loopback and os.environ.get("CLOUDSHIELD_COOKIE_SECURE") != "1":
        raise RuntimeError("Non-loopback deployments require Secure browser cookies (CLOUDSHIELD_COOKIE_SECURE=1) behind HTTPS.")
    if not is_loopback:
        bootstrap_token = os.environ.get("CLOUDSHIELD_BOOTSTRAP_TOKEN", "")
        if len(bootstrap_token) < 32 or not bootstrap_token.isascii() or bootstrap_token.lower().startswith("replace_"):
            raise RuntimeError("Non-loopback deployments require a unique CLOUDSHIELD_BOOTSTRAP_TOKEN of at least 32 characters to protect first-admin registration.")


def main():
    host = os.environ.get("CLOUDSHIELD_HOST", "127.0.0.1")
    container_mode = os.environ.get("CLOUDSHIELD_CONTAINER_MODE") == "1"
    validate_bind_host(host, container_mode=container_mode)
    validate_deployment_security(host)
    port = int(os.environ.get("CLOUDSHIELD_PORT", "8765"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"CloudShield Command Center: http://{host}:{port}")
    if _auth_enabled():
        print("Authentication: multi-user browser sessions; evidence stores are workspace-isolated")
    else:
        print(f"Evidence database: {_db_path()}")
    server.serve_forever()

if __name__ == "__main__":
    main()