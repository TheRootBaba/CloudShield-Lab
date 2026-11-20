"""Guarded response planning and execution controls.

Plans are deterministic and non-mutating. Actual cloud mutation requires an
explicitly installed provider adapter, a successful approval quorum, a matching
plan digest, an idempotency key, and both runtime and database kill switches
to be enabled. No provider adapter is bundled by default.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import cloud_ops

ACTION_POLICY = {
    "review_and_revoke_suspicious_credentials": {
        "provider": "aws", "permission": "iam:UpdateAccessKey",
        "quorum": 2, "reversible": False, "risk": "critical",
    },
    "restrict_exposed_network_rule": {
        "provider": "aws", "permission": "ec2:RevokeSecurityGroupIngress",
        "quorum": 2, "reversible": True, "risk": "high",
    },
    "restore_audit_logging": {
        "provider": "aws", "permission": "cloudtrail:StartLogging",
        "quorum": 2, "reversible": True, "risk": "high",
    },
    "remove_unintended_public_access": {
        "provider": "aws", "permission": "s3:PutBucketPublicAccessBlock",
        "quorum": 2, "reversible": True, "risk": "critical",
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def _db(path: str | Path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_control_schema(path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with _db(path) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS response_control (
          control_key TEXT PRIMARY KEY, control_value TEXT NOT NULL, updated_at TEXT NOT NULL,
          updated_by TEXT NOT NULL
        )""")
        db.execute("""INSERT OR IGNORE INTO response_control(control_key,control_value,updated_at,updated_by)
          VALUES('kill_switch','enabled',?,'system')""", (_now(),))


def ensure_schema(path: str | Path) -> None:
    cloud_ops.ensure_schema(path)
    with _db(path) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS response_plans (
          request_id TEXT PRIMARY KEY, plan_json TEXT NOT NULL, plan_sha256 TEXT NOT NULL,
          created_at TEXT NOT NULL, expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS response_execution_approvals (
          request_id TEXT NOT NULL, actor TEXT NOT NULL, approved_at TEXT NOT NULL,
          plan_sha256 TEXT NOT NULL, PRIMARY KEY(request_id,actor)
        );
        CREATE TABLE IF NOT EXISTS response_executions (
          request_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
          plan_sha256 TEXT NOT NULL, status TEXT NOT NULL,
          started_at TEXT NOT NULL, finished_at TEXT, result_json TEXT,
          rollback_json TEXT, error_code TEXT
        );
        CREATE TABLE IF NOT EXISTS response_control (
          control_key TEXT PRIMARY KEY, control_value TEXT NOT NULL, updated_at TEXT NOT NULL,
          updated_by TEXT NOT NULL
        );
        INSERT OR IGNORE INTO response_control(control_key,control_value,updated_at,updated_by)
          VALUES('kill_switch','enabled',CURRENT_TIMESTAMP,'system');
        """)


def _finding(db: sqlite3.Connection, finding_id: str) -> dict[str, Any]:
    rows = db.execute("SELECT event_id,rule_id,payload_json FROM findings").fetchall()
    for row in rows:
        digest = hashlib.sha256(json.dumps(
            [row["event_id"], row["rule_id"]], sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()
        if secrets.compare_digest(digest, finding_id):
            return json.loads(row["payload_json"])
    raise KeyError("Finding not found in this workspace")


def dry_run(path: str | Path, request_id: str, *, ttl_seconds: int = 900) -> dict[str, Any]:
    """Build and persist a deterministic preview; this function never calls a provider."""
    ensure_schema(path)
    with _db(path) as db:
        request = db.execute("SELECT * FROM response_requests WHERE request_id=?", (request_id,)).fetchone()
        if not request:
            raise KeyError("Response request not found")
        if request["status"] != "approved":
            raise PermissionError("A response must be independently approved before dry-run planning")
        finding = _finding(db, request["finding_id"])
        policy = ACTION_POLICY.get(request["action"])
        if not policy:
            raise ValueError("No reviewed policy exists for this action")
        evidence = finding.get("evidence") or {}
        if not isinstance(evidence, dict):
            raise ValueError("Finding evidence must be an object")
        request_parameters = evidence.get("request_parameters") or {}
        response_elements = evidence.get("response_elements") or {}
        if not isinstance(request_parameters, dict):
            request_parameters = {}
        if not isinstance(response_elements, dict):
            response_elements = {}
        access_key_data = response_elements.get("accessKey")
        access_key = access_key_data.get("accessKeyId") if isinstance(access_key_data, dict) else None
        action_parameters = {
            "review_and_revoke_suspicious_credentials": {
                "user_name": evidence.get("user_name") or request_parameters.get("userName"),
                "access_key_id": evidence.get("access_key_id") or access_key,
            },
            "restrict_exposed_network_rule": {
                "group_id": evidence.get("group_id"),
                "ip_permissions": evidence.get("ip_permissions") or [],
            },
            "restore_audit_logging": {
                "trail_name": evidence.get("trail_name") or request_parameters.get("name") or request_parameters.get("trailName"),
            },
            "remove_unintended_public_access": {
                "bucket_name": evidence.get("bucket_name"),
            },
        }.get(request["action"], {})
        required = {
            "review_and_revoke_suspicious_credentials": ("user_name", "access_key_id"),
            "restrict_exposed_network_rule": ("group_id", "ip_permissions"),
            "restore_audit_logging": ("trail_name",),
            "remove_unintended_public_access": ("bucket_name",),
        }[request["action"]]
        missing_parameters = [key for key in required if not action_parameters.get(key)]
        if request["action"] == "restrict_exposed_network_rule" and not isinstance(action_parameters.get("ip_permissions"), list):
            missing_parameters.append("ip_permissions")
        raw_resource_ids = evidence.get("resource_ids") or []
        resource_ids = list(raw_resource_ids) if isinstance(raw_resource_ids, list) else []
        for key in ("resource_id", "instance_id", "group_id", "bucket_name", "access_key_id", "trail_name"):
            value = evidence.get(key) or action_parameters.get(key) or finding.get(key)
            if isinstance(value, str) and value:
                resource_ids.append(value)
        resource_ids = sorted({item.strip()[:1024] for item in resource_ids if isinstance(item, str) and item.strip()})
        inventory_rows = db.execute(
            "SELECT resource_id,payload_json FROM cloud_inventory WHERE provider=? ORDER BY resource_id",
            (policy["provider"],),
        ).fetchall()
        targets = []
        for row in inventory_rows:
            if row["resource_id"] in resource_ids:
                targets.append({"resource_id": row["resource_id"], "resource": json.loads(row["payload_json"])})
        plan = {
            "request_id": request_id,
            "action": request["action"],
            "provider": policy["provider"],
            "required_permission": policy["permission"],
            "risk": policy["risk"],
            "approval_quorum": policy["quorum"],
            "reversible": policy["reversible"],
            "resource_ids": resource_ids,
            "action_parameters": action_parameters,
            "missing_action_parameters": missing_parameters,
            "preconditions_met": not missing_parameters and bool(resource_ids),
            "matched_inventory": targets,
            "blast_radius": {
                "explicit_targets": len(resource_ids),
                "inventory_matches": len(targets),
                "unresolved_targets": max(1 if not resource_ids else 0, len(resource_ids) - len(targets)),
                "scope": "explicit resource IDs only; no account-wide discovery or mutation",
            },
            "execution": "not_performed",
            "warnings": [
                "Dry run is a plan only and does not call AWS or Azure.",
                "No provider adapter is enabled by default.",
                "Unresolved targets must be manually reconciled before execution.",
            ],
        }
        encoded = json.dumps(plan, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        now = datetime.now(timezone.utc)
        expires = (now.timestamp() + max(60, min(int(ttl_seconds), 3600)))
        expires_at = datetime.fromtimestamp(expires, timezone.utc).isoformat(timespec="seconds")
        db.execute("""INSERT INTO response_plans VALUES(?,?,?,?,?)
          ON CONFLICT(request_id) DO UPDATE SET plan_json=excluded.plan_json,
          plan_sha256=excluded.plan_sha256,created_at=excluded.created_at,expires_at=excluded.expires_at""",
          (request_id, encoded, digest, now.isoformat(timespec="seconds"), expires_at))
    return {**plan, "plan_sha256": digest, "expires_at": expires_at}


def approve_execution(path: str | Path, request_id: str, actor: str) -> dict[str, Any]:
    if not isinstance(actor, str) or not actor.strip() or len(actor) > 256:
        raise ValueError("Approver identity is required")
    actor_key = actor.strip().casefold()[:128]
    ensure_schema(path)
    with _db(path) as db:
        request = db.execute("SELECT * FROM response_requests WHERE request_id=?", (request_id,)).fetchone()
        plan = db.execute("SELECT * FROM response_plans WHERE request_id=?", (request_id,)).fetchone()
        if not request or not plan:
            raise KeyError("Approved request and current dry-run plan are required")
        if request["status"] != "approved":
            raise PermissionError("Response request is not approved")
        if (str(request["requested_by"] or "").strip().casefold() == actor_key
                or str(request["decided_by"] or "").strip().casefold() == actor_key):
            raise PermissionError("Requester and initial approver cannot approve execution")
        if datetime.fromisoformat(plan["expires_at"]) <= datetime.now(timezone.utc):
            raise PermissionError("Dry-run plan expired; generate a fresh plan")
        db.execute("INSERT OR IGNORE INTO response_execution_approvals VALUES(?,?,?,?)",
                   (request_id, actor_key, _now(), plan["plan_sha256"]))
        count = db.execute("SELECT COUNT(*) FROM response_execution_approvals WHERE request_id=? AND plan_sha256=?",
                           (request_id, plan["plan_sha256"])).fetchone()[0]
        required = ACTION_POLICY[request["action"]]["quorum"]
    return {"request_id": request_id, "approvals": count, "required": required, "quorum_met": count >= required}


def set_kill_switch(path: str | Path, enabled: bool, actor: str, *, allow_disable: bool = False) -> dict[str, Any]:
    if not isinstance(enabled, bool) or not isinstance(actor, str) or not actor.strip():
        raise ValueError("A boolean switch value and actor are required")
    if enabled is False and not allow_disable:
        raise PermissionError("Only a local deployment operator may disable the service-wide kill switch")
    ensure_control_schema(path)
    value = "enabled" if enabled else "disabled"
    with _db(path) as db:
        db.execute("""INSERT INTO response_control VALUES('kill_switch',?,?,?)
          ON CONFLICT(control_key) DO UPDATE SET control_value=excluded.control_value,
          updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
          (value, _now(), actor.strip()[:128]))
    return {"kill_switch": value, "updated_by": actor.strip()[:128]}


def kill_switch_state(path: str | Path) -> bool:
    ensure_control_schema(path)
    with _db(path) as db:
        row = db.execute("SELECT control_value FROM response_control WHERE control_key='kill_switch'").fetchone()
    return not row or row[0] != "disabled"


def execute(path: str | Path, request_id: str, idempotency_key: str, plan_sha256: str,
            *, adapter: Callable[..., dict[str, Any]] | None = None,
            control_path: str | Path | None = None) -> dict[str, Any]:
    """Execute only a previously planned, quorum-approved action via an injected adapter."""
    if not isinstance(idempotency_key, str) or not (16 <= len(idempotency_key) <= 128):
        raise ValueError("A caller-generated idempotency key of 16–128 characters is required")
    if os.environ.get("CLOUDSHIELD_RESPONSE_EXECUTION_ENABLED") != "1":
        raise PermissionError("Cloud response execution is disabled by deployment policy")
    if not isinstance(plan_sha256, str) or len(plan_sha256) != 64:
        raise ValueError("A valid dry-run plan digest is required")
    ensure_schema(path)
    with _db(path) as db:
        db.execute("BEGIN IMMEDIATE")
        control_db_path = control_path or path
        if Path(control_db_path).resolve() != Path(path).resolve():
            ensure_control_schema(control_db_path)
        if Path(control_db_path).resolve() == Path(path).resolve():
            switch = db.execute("SELECT control_value FROM response_control WHERE control_key='kill_switch'").fetchone()
        else:
            with _db(control_db_path) as control_db:
                switch = control_db.execute("SELECT control_value FROM response_control WHERE control_key='kill_switch'").fetchone()
        if not switch or switch[0] != "disabled":
            raise PermissionError("Emergency response kill switch is enabled")
        request = db.execute("SELECT * FROM response_requests WHERE request_id=?", (request_id,)).fetchone()
        plan = db.execute("SELECT * FROM response_plans WHERE request_id=?", (request_id,)).fetchone()
        if not request or request["status"] != "approved" or not plan:
            raise PermissionError("An approved request and dry-run plan are required")
        if not secrets.compare_digest(plan["plan_sha256"], plan_sha256):
            raise PermissionError("Dry-run plan changed; execution is blocked")
        if datetime.fromisoformat(plan["expires_at"]) <= datetime.now(timezone.utc):
            raise PermissionError("Dry-run plan expired")
        policy = ACTION_POLICY[request["action"]]
        approvals = db.execute("SELECT COUNT(*) FROM response_execution_approvals WHERE request_id=? AND plan_sha256=?",
                               (request_id, plan_sha256)).fetchone()[0]
        if approvals < policy["quorum"]:
            raise PermissionError("Execution approval quorum has not been met")
        if db.execute("SELECT 1 FROM response_executions WHERE request_id=?", (request_id,)).fetchone():
            raise ValueError("This response request has already been executed or attempted")
        if adapter is None or not callable(adapter):
            raise RuntimeError("No reviewed provider adapter is installed for this action")
        db.execute("""INSERT INTO response_executions(request_id,idempotency_key,plan_sha256,status,started_at)
          VALUES(?,?,?,'running',?)""", (request_id, idempotency_key, plan_sha256, _now()))
    try:
        plan_data = json.loads(plan["plan_json"])
        if not plan_data.get("preconditions_met") or plan_data["blast_radius"]["unresolved_targets"]:
            raise PermissionError("Missing action parameters or unresolved resource targets block execution")
        result = adapter(plan=plan_data, idempotency_key=idempotency_key)
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise RuntimeError("Provider adapter did not confirm a successful action")
        rollback = result.get("rollback")
        with _db(path) as db:
            db.execute("""UPDATE response_executions SET status='succeeded',finished_at=?,
              result_json=?,rollback_json=? WHERE request_id=? AND status='running'""",
              (_now(), json.dumps({k:v for k,v in result.items() if k != "rollback"}, sort_keys=True, default=str),
               json.dumps(rollback, sort_keys=True, default=str) if rollback is not None else None, request_id))
        return {"request_id": request_id, "status": "succeeded", "result": {k:v for k,v in result.items() if k != "rollback"},
                "rollback_available": rollback is not None}
    except Exception as exc:
        with _db(path) as db:
            db.execute("""UPDATE response_executions SET status='failed',finished_at=?,error_code=?
              WHERE request_id=? AND status='running'""", (_now(), type(exc).__name__, request_id))
        raise


def execution_history(path: str | Path, request_id: str) -> dict[str, Any] | None:
    ensure_schema(path)
    with _db(path) as db:
        row = db.execute("SELECT * FROM response_executions WHERE request_id=?", (request_id,)).fetchone()
    return dict(row) if row else None
