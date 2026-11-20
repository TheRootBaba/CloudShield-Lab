"""Tenant-local cloud connection registry, alerting and approval-gated response workflows.

Provider credentials are never accepted or persisted by CloudShield. AWS uses an
STS AssumeRole trust relationship with a workspace-specific external ID. Azure
uses DefaultAzureCredential/workload or managed identity scoped to one subscription.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import smtplib
import ssl
from email.message import EmailMessage
from datetime import timedelta
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROVIDERS = {"aws", "azure"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def _connect(path: str | Path):
    db = sqlite3.connect(str(path), timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def ensure_schema(path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with _connect(path) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS cloud_connections (
          provider TEXT PRIMARY KEY CHECK(provider IN ('aws','azure')),
          config_json TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
          status TEXT NOT NULL DEFAULT 'not_tested',
          last_checked_at TEXT,
          last_collected_at TEXT,
          last_error TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS collection_runs (
          run_id TEXT PRIMARY KEY, provider TEXT NOT NULL, started_at TEXT NOT NULL,
          finished_at TEXT, status TEXT NOT NULL, events_seen INTEGER NOT NULL DEFAULT 0,
          pages_read INTEGER NOT NULL DEFAULT 0, truncated INTEGER NOT NULL DEFAULT 0,
          error TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
          alert_id TEXT PRIMARY KEY, finding_id TEXT NOT NULL UNIQUE,
          severity TEXT NOT NULL, title TEXT NOT NULL, summary TEXT NOT NULL,
          created_at TEXT NOT NULL, acknowledged_at TEXT, acknowledged_by TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
        CREATE TABLE IF NOT EXISTS cloud_inventory (
          provider TEXT NOT NULL, resource_id TEXT NOT NULL, payload_json TEXT NOT NULL,
          observed_at TEXT NOT NULL, PRIMARY KEY(provider,resource_id)
        );
        CREATE TABLE IF NOT EXISTS response_requests (
          request_id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, action TEXT NOT NULL,
          rationale TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
          requested_by TEXT NOT NULL, requested_at TEXT NOT NULL,
          decided_by TEXT, decided_at TEXT, decision_note TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_response_status ON response_requests(status, requested_at);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_response_pending_unique ON response_requests(finding_id,action) WHERE status='pending';
        CREATE TABLE IF NOT EXISTS notification_outbox (
          notification_id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL,
          user_id TEXT NOT NULL, email TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL,
          last_error TEXT, delivered_at TEXT, UNIQUE(alert_id,user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_notification_pending ON notification_outbox(status,next_attempt_at);
        """)
        db.commit()


def configure_aws(path: str | Path, role_arn: str, region: str, actor: str, *,
                  auth_db_path: str | Path | None = None, tenant_id: str | None = None) -> dict[str, Any]:
    if not isinstance(role_arn, str) or not re.fullmatch(
        r"arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}", role_arn
    ):
        raise ValueError("Enter a valid AWS IAM role ARN for the target account")
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-\d", region):
        raise ValueError("Enter a valid AWS region")
    if (auth_db_path is None) != (tenant_id is None):
        raise ValueError("Both auth database path and tenant ID are required for workspace binding")
    if auth_db_path is not None:
        reserve_workspace_identity(auth_db_path, tenant_id, "aws", role_arn)
    external_id = secrets.token_urlsafe(36)
    config = {"role_arn": role_arn, "region": region, "external_id": external_id,
              "configured_by": str(actor)[:128]}
    _save(path, "aws", config)
    return {"provider": "aws", "role_arn": role_arn, "region": region,
            "external_id": external_id, "enabled": False,
            "trust_policy_hint": "Allow sts:AssumeRole only from the CloudShield deployment principal and require this ExternalId. Grant cloudtrail:LookupEvents and the documented read-only inventory actions only."}


def configure_azure(path: str | Path, tenant_id: str, subscription_id: str,
                    managed_identity_client_id: str | None, actor: str, *,
                    auth_db_path: str | Path | None = None, workspace_id: str | None = None) -> dict[str, Any]:
    if not isinstance(managed_identity_client_id, str) or not managed_identity_client_id.strip():
        raise ValueError("A workspace-specific Azure managed/workload identity client ID is required")
    try:
        tenant_id = str(uuid.UUID(str(tenant_id)))
        subscription_id = str(uuid.UUID(str(subscription_id)))
        if managed_identity_client_id:
            managed_identity_client_id = str(uuid.UUID(str(managed_identity_client_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Azure tenant, subscription and optional managed identity client IDs must be UUIDs") from exc
    if (auth_db_path is None) != (workspace_id is None):
        raise ValueError("Both auth database path and workspace ID are required for workspace binding")
    identity_key = ":".join((tenant_id, subscription_id, managed_identity_client_id))
    if auth_db_path is not None:
        reserve_workspace_identity(auth_db_path, workspace_id, "azure", identity_key)
    config = {"tenant_id": tenant_id, "subscription_id": subscription_id,
              "managed_identity_client_id": managed_identity_client_id,
              "configured_by": str(actor)[:128]}
    _save(path, "azure", config)
    return {"provider": "azure", "tenant_id": tenant_id, "subscription_id": subscription_id,
            "managed_identity_client_id": managed_identity_client_id, "enabled": False,
            "permissions_required": ["Microsoft.Insights/eventtypes/values/read",
                                     "Microsoft.Resources/subscriptions/read",
                                     "Microsoft.Resources/subscriptions/resources/read"]}


def _save(path: str | Path, provider: str, config: dict[str, Any]) -> None:
    ensure_schema(path)
    now = _now()
    with _connect(path) as db:
        db.execute("""INSERT INTO cloud_connections(provider,config_json,enabled,status,created_at,updated_at)
          VALUES(?,?,0,'not_tested',?,?)
          ON CONFLICT(provider) DO UPDATE SET config_json=excluded.config_json,enabled=0,
          status='not_tested',last_error=NULL,updated_at=excluded.updated_at""",
          (provider, json.dumps(config, sort_keys=True), now, now))
        db.commit()



def reserve_workspace_identity(auth_db_path: str | Path, tenant_id: str, provider: str, identity_key: str) -> None:
    """Enforce one unique provider identity per workspace across all tenants."""
    if provider not in PROVIDERS or not tenant_id or not isinstance(identity_key, str) or not identity_key:
        raise ValueError("Invalid workspace provider identity")
    import sqlite3
    from contextlib import closing
    Path(auth_db_path).parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(auth_db_path), timeout=10)) as db:
        db.execute("CREATE TABLE IF NOT EXISTS workspace_provider_bindings (provider TEXT NOT NULL, identity_key TEXT NOT NULL, tenant_id TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(provider,identity_key), UNIQUE(provider,tenant_id))")
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute("SELECT tenant_id FROM workspace_provider_bindings WHERE provider=? AND identity_key=?", (provider, identity_key)).fetchone()
        if existing and existing[0] != tenant_id:
            raise PermissionError("This cloud identity is already assigned to another CloudShield workspace")
        db.execute("DELETE FROM workspace_provider_bindings WHERE provider=? AND tenant_id=?", (provider, tenant_id))
        db.execute("INSERT INTO workspace_provider_bindings(provider,identity_key,tenant_id,updated_at) VALUES(?,?,?,?)",
                   (provider, identity_key, tenant_id, _now()))
        db.commit()

def get_connection(path: str | Path, provider: str) -> dict[str, Any] | None:
    if provider not in PROVIDERS:
        raise ValueError("Unsupported provider")
    ensure_schema(path)
    with _connect(path) as db:
        row = db.execute("SELECT * FROM cloud_connections WHERE provider=?", (provider,)).fetchone()
    if not row:
        return None
    config = json.loads(row["config_json"])
    # The AWS external ID is a trust-policy value; reveal it only through the one-time
    # configure response, never in routine status responses.
    config.pop("external_id", None)
    return {"provider": provider, **config, "enabled": bool(row["enabled"]),
            "status": row["status"], "last_checked_at": row["last_checked_at"],
            "last_collected_at": row["last_collected_at"], "last_error": row["last_error"]}


def _raw_connection(path: str | Path, provider: str) -> tuple[dict[str, Any], bool]:
    ensure_schema(path)
    with _connect(path) as db:
        row = db.execute("SELECT config_json,enabled FROM cloud_connections WHERE provider=?", (provider,)).fetchone()
    if not row:
        raise ValueError(f"{provider.upper()} connection is not configured for this workspace")
    return json.loads(row["config_json"]), bool(row["enabled"])


def set_enabled(path: str | Path, provider: str, enabled: bool) -> dict[str, Any]:
    if provider not in PROVIDERS or not isinstance(enabled, bool):
        raise ValueError("Invalid provider or enabled flag")
    ensure_schema(path)
    with _connect(path) as db:
        row = db.execute("SELECT status FROM cloud_connections WHERE provider=?", (provider,)).fetchone()
        if not row:
            raise ValueError(f"{provider.upper()} connection is not configured")
        if enabled and row["status"] != "connected":
            raise PermissionError("Test the workspace cloud identity successfully before enabling collection")
        changed = db.execute("UPDATE cloud_connections SET enabled=?,updated_at=? WHERE provider=?",
            (int(enabled), _now(), provider)).rowcount
        db.commit()
    if changed != 1:
        raise ValueError(f"{provider.upper()} connection is not configured")
    return get_connection(path, provider) or {}


def aws_session(path: str | Path, *, sts_client=None, session_factory=None, allow_disabled: bool = False):
    config, enabled = _raw_connection(path, "aws")
    if not enabled and not allow_disabled:
        raise PermissionError("AWS collection is disabled for this workspace")
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise RuntimeError("Install CloudShield AWS extras before connecting AWS") from exc
    retry_config = Config(retries={"mode":"standard","total_max_attempts":4})
    if sts_client is None:
        sts_client = boto3.client("sts", config=retry_config)
    response = sts_client.assume_role(RoleArn=config["role_arn"],
        RoleSessionName="CloudShieldWorkspace", ExternalId=config["external_id"], DurationSeconds=3600)
    creds = response["Credentials"]
    factory = session_factory or boto3.Session
    session = factory(aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"], region_name=config["region"])
    identity = session.client("sts", config=retry_config).get_caller_identity()
    expected = config["role_arn"].split(":")[4]
    if identity.get("Account") != expected:
        raise PermissionError("AWS assumed role account does not match the configured account")
    return session, config


def azure_credential(path: str | Path, *, allow_disabled: bool = False):
    config, enabled = _raw_connection(path, "azure")
    if not enabled and not allow_disabled:
        raise PermissionError("Azure collection is disabled for this workspace")
    try:
        from azure.identity import ManagedIdentityCredential, WorkloadIdentityCredential
    except ImportError as exc:
        raise RuntimeError("Install CloudShield Azure extras before connecting Azure") from exc
    import os
    token_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE", "").strip()
    client_id = config.get("managed_identity_client_id") or os.environ.get("AZURE_CLIENT_ID", "").strip()
    if token_file:
        if not client_id:
            raise RuntimeError("Azure workload identity requires an explicit client ID for this workspace")
        credential = WorkloadIdentityCredential(tenant_id=config["tenant_id"], client_id=client_id,
                                                token_file_path=token_file)
    else:
        # Do not fall back to a shared developer/CLI credential chain in a multi-tenant service.
        if not client_id:
            raise RuntimeError("Configure a workspace-specific Azure managed identity client ID or workload identity federation")
        credential = ManagedIdentityCredential(client_id=client_id)
    return credential, config


def mark_provider(path: str | Path, provider: str, *, status: str,
                  error: str | None = None, collected: bool = False) -> None:
    ensure_schema(path)
    now = _now()
    with _connect(path) as db:
        db.execute("""UPDATE cloud_connections SET status=?,last_checked_at=?,
          last_collected_at=CASE WHEN ? THEN ? ELSE last_collected_at END,
          last_error=?,updated_at=? WHERE provider=?""",
          (status, now, int(collected), now, str(error)[:500] if error else None, now, provider))
        db.commit()


def sync_alerts(path: str | Path, findings: list[dict[str, Any]]) -> int:
    ensure_schema(path)
    inserted = 0
    with _connect(path) as db:
        for finding in findings:
            severity = str(finding.get("severity", "INFO")).upper()
            if severity not in {"CRITICAL", "HIGH"}:
                continue
            finding_id = str(finding.get("finding_id") or finding.get("id") or "")
            if not finding_id and finding.get("event_id") and finding.get("rule_id"):
                canonical = json.dumps([finding["event_id"], finding["rule_id"]], sort_keys=True, separators=(",", ":"))
                finding_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if not finding_id:
                continue
            title = str(finding.get("title") or finding.get("rule_name") or finding.get("rule_id") or "High severity finding")[:200]
            summary = str(finding.get("rationale") or finding.get("description") or "Review the associated evidence.")[:1000]
            cursor = db.execute("""INSERT OR IGNORE INTO alerts
              (alert_id,finding_id,severity,title,summary,created_at) VALUES(?,?,?,?,?,?)""",
              (secrets.token_urlsafe(18), finding_id, severity, title, summary, _now()))
            inserted += cursor.rowcount
        db.commit()
    return inserted


def list_alerts(path: str | Path, limit: int = 100) -> list[dict[str, Any]]:
    if not 1 <= int(limit) <= 500:
        raise ValueError("Alert limit must be 1–500")
    ensure_schema(path)
    with _connect(path) as db:
        rows = db.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (int(limit),)).fetchall()
    return [dict(row) for row in rows]


def acknowledge_alert(path: str | Path, alert_id: str, actor: str) -> dict[str, Any]:
    ensure_schema(path)
    with _connect(path) as db:
        changed = db.execute("UPDATE alerts SET acknowledged_at=?,acknowledged_by=? WHERE alert_id=? AND acknowledged_at IS NULL",
            (_now(), str(actor)[:128], alert_id)).rowcount
        row = db.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
        db.commit()
    if not row:
        raise KeyError("Alert not found")
    return dict(row)



def store_inventory(path: str | Path, provider: str, resources: list[dict[str, Any]]) -> int:
    if provider not in PROVIDERS or not isinstance(resources, list):
        raise ValueError("Invalid inventory payload")
    ensure_schema(path)
    now = _now()
    stored = 0
    with _connect(path) as db:
        for resource in resources[:10000]:
            resource_id = resource.get("resource_id") or resource.get("id")
            if not isinstance(resource_id, str) or not resource_id.strip():
                continue
            db.execute("""INSERT INTO cloud_inventory(provider,resource_id,payload_json,observed_at)
              VALUES(?,?,?,?) ON CONFLICT(provider,resource_id) DO UPDATE SET
              payload_json=excluded.payload_json,observed_at=excluded.observed_at""",
              (provider, resource_id[:1024], json.dumps(resource, sort_keys=True, default=str), now))
            stored += 1
        db.commit()
    return stored


def list_inventory(path: str | Path, provider: str | None = None, limit: int = 2000) -> list[dict[str, Any]]:
    if provider is not None and provider not in PROVIDERS:
        raise ValueError("Unsupported provider")
    ensure_schema(path)
    with _connect(path) as db:
        if provider:
            rows = db.execute("SELECT provider,payload_json,observed_at FROM cloud_inventory WHERE provider=? ORDER BY observed_at DESC LIMIT ?", (provider, max(1,min(int(limit),10000)))).fetchall()
        else:
            rows = db.execute("SELECT provider,payload_json,observed_at FROM cloud_inventory ORDER BY observed_at DESC LIMIT ?", (max(1,min(int(limit),10000)),)).fetchall()
    return [{"provider":row[0], **json.loads(row[1]), "observed_at":row[2]} for row in rows]

def recommendations(finding: dict[str, Any]) -> list[dict[str, str]]:
    """Return conservative, human-reviewed suggestions; never call cloud write APIs."""
    rule = str(finding.get("rule_id", "")).lower()
    suggestions = [
      {"action":"review_and_revoke_suspicious_credentials","title":"Review and revoke suspicious credentials",
       "rationale":"Confirm the actor and credential owner, preserve audit evidence, then revoke only the confirmed compromised credential."},
      {"action":"restrict_exposed_network_rule","title":"Restrict exposed network access",
       "rationale":"Validate business ownership and dependencies, then narrow the affected ingress rule to approved source ranges."},
      {"action":"restore_audit_logging","title":"Restore and protect audit logging",
       "rationale":"Confirm the logging gap and restore the approved trail/configuration without overwriting retained evidence."},
    ]
    if "s3" in rule:
        return [{"action":"remove_unintended_public_access","title":"Remove unintended public access",
          "rationale":"Confirm intended sharing and dependencies, then restore account and bucket public-access guardrails."}]
    if "ingress" in rule or "network" in rule or "security_group" in rule:
        return [suggestions[1]]
    if "iam" in rule or "credential" in rule or "access_key" in rule:
        return [suggestions[0]]
    if "cloudtrail" in rule or "logging" in rule:
        return [suggestions[2]]
    return suggestions


def request_response(path: str | Path, finding_id: str, action: str, rationale: str, actor: str) -> dict[str, Any]:
    if not all(isinstance(v, str) and v.strip() for v in (finding_id, action, rationale, actor)):
        raise ValueError("Finding, action, rationale and requester are required")
    if len(finding_id) > 160 or len(action) > 100 or len(rationale) > 2000:
        raise ValueError("Response request exceeds allowed length")
    allowed = {"review_and_revoke_suspicious_credentials", "restrict_exposed_network_rule",
               "restore_audit_logging", "remove_unintended_public_access"}
    # Action IDs are selected from the fixed reviewed catalogue, not arbitrary API input.
    if action not in allowed:
        raise ValueError("Action is not in the reviewed response catalogue")
    ensure_schema(path)
    request_id = secrets.token_urlsafe(18)
    with _connect(path) as db:
        rows = db.execute("SELECT event_id,rule_id,payload_json FROM findings").fetchall()
        matching = next((row for row in rows if hashlib.sha256(
            json.dumps([row[0], row[1]], sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() == finding_id), None)
        if not matching:
            raise KeyError("Finding not found in this workspace")
        finding = json.loads(matching[2])
        if action not in {item["action"] for item in recommendations(finding)}:
            raise ValueError("Action is not recommended for this finding")
        if db.execute("SELECT 1 FROM response_requests WHERE finding_id=? AND action=? AND status='pending'", (finding_id, action)).fetchone():
            raise ValueError("A pending request already exists for this finding and action")
        db.execute("""INSERT INTO response_requests
          (request_id,finding_id,action,rationale,status,requested_by,requested_at)
          VALUES(?,?,?,?, 'pending',?,?)""",
          (request_id, finding_id, action, rationale.strip(), str(actor)[:128], _now()))
        db.commit()
        row = db.execute("SELECT * FROM response_requests WHERE request_id=?", (request_id,)).fetchone()
    return dict(row)


def decide_response(path: str | Path, request_id: str, actor: str, approve: bool, note: str = "") -> dict[str, Any]:
    if not isinstance(approve, bool) or not isinstance(note, str) or len(note) > 1000:
        raise ValueError("Invalid approval decision")
    ensure_schema(path)
    with _connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM response_requests WHERE request_id=?", (request_id,)).fetchone()
        if not row:
            raise KeyError("Response request not found")
        if row["status"] != "pending":
            raise ValueError("Response request has already been decided")
        if row["requested_by"] == actor:
            raise PermissionError("A different workspace member must approve or reject this request")
        db.execute("""UPDATE response_requests SET status=?,decided_by=?,decided_at=?,decision_note=?
          WHERE request_id=? AND status='pending'""",
          ("approved" if approve else "rejected", str(actor)[:128], _now(), note.strip(), request_id))
        db.commit()
        updated = db.execute("SELECT * FROM response_requests WHERE request_id=?", (request_id,)).fetchone()
    return dict(updated)


def list_responses(path: str | Path, limit: int = 100) -> list[dict[str, Any]]:
    ensure_schema(path)
    with _connect(path) as db:
        rows = db.execute("SELECT * FROM response_requests ORDER BY requested_at DESC LIMIT ?", (max(1,min(int(limit),500)),)).fetchall()
    return [dict(row) for row in rows]



def deliver_alert_notifications(path: str | Path, auth_db_path: str | Path, tenant_id: str,
                                *, smtp_factory=None) -> dict[str, Any]:
    """Email unacknowledged HIGH/CRITICAL alerts to active workspace admins/responders.

    SMTP is optional but must use STARTTLS and authenticated relay credentials. Secrets
    are read from a mounted file, never stored in the tenant database or audit payload.
    """
    import sqlite3
    from contextlib import closing
    ensure_schema(path)
    with closing(sqlite3.connect(str(auth_db_path))) as auth_db:
        recipients = auth_db.execute("SELECT user_id,email FROM users WHERE tenant_id=? AND active=1 AND role IN ('admin','responder')", (tenant_id,)).fetchall()
    now = datetime.now(timezone.utc)
    with _connect(path) as db:
        alerts = db.execute("SELECT alert_id,severity,title FROM alerts WHERE acknowledged_at IS NULL").fetchall()
        queued = 0
        for alert in alerts:
            for user_id, email in recipients:
                queued += db.execute("INSERT OR IGNORE INTO notification_outbox(alert_id,user_id,email,status,next_attempt_at) VALUES(?,?,?,'pending',?)",
                    (alert[0], user_id, email, _now())).rowcount
        pending = db.execute("SELECT notification_id,alert_id,email,attempts,user_id FROM notification_outbox WHERE status='pending' AND attempts<5 AND next_attempt_at<=? ORDER BY notification_id LIMIT 100", (_now(),)).fetchall()
        db.commit()
    host = os.environ.get("CLOUDSHIELD_SMTP_HOST", "").strip()
    username = os.environ.get("CLOUDSHIELD_SMTP_USERNAME", "").strip()
    password_file = os.environ.get("CLOUDSHIELD_SMTP_PASSWORD_FILE", "").strip()
    sender = os.environ.get("CLOUDSHIELD_SMTP_FROM", "").strip()
    if not (host and username and password_file and sender):
        return {"configured":False, "queued":queued, "sent":0, "pending":len(pending),
                "message":"SMTP relay is not configured; in-app alerts remain available."}
    try:
        password = Path(password_file).read_text(encoding="utf-8").strip()
        port = int(os.environ.get("CLOUDSHIELD_SMTP_PORT", "587"))
        if not password or not 1 <= port <= 65535:
            raise ValueError("Invalid SMTP password file or port")
    except (OSError, ValueError) as exc:
        return {"configured":False, "queued":queued, "sent":0, "pending":len(pending), "error":type(exc).__name__}
    factory = smtp_factory or smtplib.SMTP
    client = None
    sent = failed = cancelled = 0
    try:
        client = factory(host, port, timeout=10)
        client.ehlo()
        client.starttls(context=ssl.create_default_context())
        client.ehlo()
        client.login(username, password)
        for notification_id, alert_id, email, attempts, user_id in pending:
            with closing(sqlite3.connect(str(auth_db_path))) as auth_db:
                member = auth_db.execute("SELECT email FROM users WHERE user_id=? AND tenant_id=? AND active=1 AND role IN ('admin','responder')",
                                         (user_id, tenant_id)).fetchone()
            if not member:
                with _connect(path) as db:
                    db.execute("UPDATE notification_outbox SET status='cancelled',last_error='recipient_no_longer_active' WHERE notification_id=?", (notification_id,))
                cancelled += 1
                continue
            email = member[0]
            with _connect(path) as db:
                alert = db.execute("SELECT severity,title FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
            if not alert:
                continue
            message = EmailMessage()
            message["Subject"] = f"CloudShield {alert[0]} security alert"
            message["From"] = sender
            message["To"] = email
            base_url = os.environ.get("CLOUDSHIELD_PUBLIC_URL", "").rstrip("/")
            message.set_content(f"A {alert[0]} severity finding requires workspace review.\n\n{alert[1]}\n\nAlert reference: {alert_id}\n{base_url}\n\nThis message contains no credentials or raw event payload.")
            try:
                client.send_message(message)
                with _connect(path) as db:
                    db.execute("UPDATE notification_outbox SET status='delivered',attempts=attempts+1,delivered_at=?,last_error=NULL WHERE notification_id=?", (_now(), notification_id))
                sent += 1
            except Exception as exc:
                delay = min(3600, 60 * (2 ** attempts))
                retry_at = (now + timedelta(seconds=delay)).isoformat(timespec="seconds")
                with _connect(path) as db:
                    db.execute("UPDATE notification_outbox SET attempts=attempts+1,next_attempt_at=?,last_error=? WHERE notification_id=?",
                               (retry_at, type(exc).__name__, notification_id))
                failed += 1
    except Exception as exc:
        # Authentication/connection failure: bounded retry for every pending row.
        delay = 300
        retry_at = (now + timedelta(seconds=delay)).isoformat(timespec="seconds")
        with _connect(path) as db:
            for row in pending:
                db.execute("UPDATE notification_outbox SET attempts=attempts+1,next_attempt_at=?,last_error=? WHERE notification_id=?",
                           (retry_at, type(exc).__name__, row[0]))
        failed += len(pending)
    finally:
        if client is not None:
            try:
                client.quit()
            except Exception as exc:
                logging.getLogger(__name__).debug("SMTP client cleanup failed (%s)", type(exc).__name__)
    return {"configured":True, "queued":queued, "sent":sent, "failed":failed, "cancelled":cancelled,
            "pending":max(0,len(pending)-sent-failed-cancelled)}

def execute_response(*_args, **_kwargs):
    """Fail closed until a provider-specific write adapter receives a security review."""
    raise RuntimeError("Cloud response execution is not enabled. Approval records intent only; no cloud write action is implemented.")
