"""Scheduled, bounded, read-only provider collection worker.

Run as a separate process. Each workspace is discovered from the auth database and
uses only its own tenant-local provider configuration and evidence database.
"""
from __future__ import annotations

import os
import signal
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from .auth import AuthStore
from .storage import EvidenceStore
from . import cloud_ops
from .collector import collect_cloudtrail
from .aws_inventory import collect_inventory as collect_aws_inventory
from .azure_provider import collect_activity_logs, collect_inventory as collect_azure_inventory

_STOP = False


def _stop(*_args):
    global _STOP
    _STOP = True


def _tenant_databases(auth_db: Path, tenant_root: Path):
    store = AuthStore(auth_db, tenant_root)
    with closing(sqlite3.connect(str(auth_db))) as db:
        tenant_ids = [row[0] for row in db.execute("SELECT tenant_id FROM tenants")]
    return [(tenant_id, store.tenant_path(tenant_id)) for tenant_id in tenant_ids]


def _inventory_due(db_path: Path, provider: str) -> bool:
    with closing(sqlite3.connect(str(db_path))) as db:
        db.execute("CREATE TABLE IF NOT EXISTS worker_state (state_key TEXT PRIMARY KEY, state_value TEXT NOT NULL)")
        row = db.execute("SELECT state_value FROM worker_state WHERE state_key=?", (provider + '_last_inventory_at',)).fetchone()
    if not row:
        return True
    from datetime import datetime, timezone, timedelta
    try:
        last = datetime.fromisoformat(row[0])
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - last >= timedelta(hours=6)
    except ValueError:
        return True


def _mark_inventory(db_path: Path, provider: str) -> None:
    with closing(sqlite3.connect(str(db_path))) as db:
        db.execute("CREATE TABLE IF NOT EXISTS worker_state (state_key TEXT PRIMARY KEY, state_value TEXT NOT NULL)")
        db.execute("INSERT INTO worker_state VALUES(?,?) ON CONFLICT(state_key) DO UPDATE SET state_value=excluded.state_value",
                   (provider + '_last_inventory_at', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())))
        db.commit()


def collect_workspace(db_path: str | Path, interval_seconds: int = 300, *, lease_heartbeat=None) -> dict:
    """Collect one bounded interval for one workspace; provider and inventory errors are isolated."""
    db_path = Path(db_path)
    results = {}

    def renew_lease():
        if lease_heartbeat is not None and not lease_heartbeat():
            raise RuntimeError("Workspace collection lease was lost; stopping provider work")
    aws = cloud_ops.get_connection(db_path, "aws")
    if aws and aws["enabled"]:
        try:
            renew_lease()
            session, config = cloud_ops.aws_session(db_path)
            lookback_minutes = max(15, min(1440, (int(interval_seconds) + 59) // 60 + 5))
            events = collect_cloudtrail(config["region"], lookback_minutes=lookback_minutes, max_pages=5, session=session)
            renew_lease()
            counts = EvidenceStore(db_path).ingest(events["events"]) if events["events"] else {}
            cloud_ops.sync_alerts(db_path, _findings(db_path))
            cloud_ops.mark_provider(db_path, "aws", status="connected", collected=True)
            results["aws"] = {"ok": True, "events": len(events["events"]), "complete": events["complete"], **counts}
        except Exception as exc:
            cloud_ops.mark_provider(db_path, "aws", status="error", error=type(exc).__name__ + ": " + str(exc))
            results["aws"] = {"ok": False, "error": type(exc).__name__}
        else:
            if _inventory_due(db_path, "aws"):
                try:
                    renew_lease()
                    inventory = collect_aws_inventory([config["region"]], max_pages=1, session=session)
                    renew_lease()
                    inventory["stored_resources"] = cloud_ops.store_inventory(db_path, "aws", inventory.get("resources", []))
                    results["aws_inventory"] = {"resources":inventory.get("resource_count",0),
                        "complete":inventory.get("collection_complete", inventory.get("complete",False))}
                    _mark_inventory(db_path, "aws")
                except Exception as exc:
                    cloud_ops.mark_provider(db_path, "aws", status="partial", error="Inventory: " + type(exc).__name__, collected=True)
                    results["aws_inventory"] = {"ok":False, "error":type(exc).__name__}

    azure = cloud_ops.get_connection(db_path, "azure")
    if azure and azure["enabled"]:
        credential = None
        try:
            renew_lease()
            credential, config = cloud_ops.azure_credential(db_path)
            from azure.mgmt.monitor import MonitorManagementClient
            monitor = MonitorManagementClient(credential, config["subscription_id"],
                retry_total=3, retry_backoff_factor=0.8, retry_backoff_max=8)
            lookback_hours = max(1, min(24, (int(interval_seconds) + 3599) // 3600 + 1))
            events = collect_activity_logs(config["subscription_id"], lookback_hours=lookback_hours,
                max_pages=5, max_records=1000, monitor_client=monitor)
            renew_lease()
            counts = EvidenceStore(db_path).ingest(events["events"]) if events["events"] else {}
            cloud_ops.sync_alerts(db_path, _findings(db_path))
            cloud_ops.mark_provider(db_path, "azure", status="connected", collected=True)
            results["azure"] = {"ok": True, "events": len(events["events"]), "complete": events["complete"], **counts}
        except Exception as exc:
            cloud_ops.mark_provider(db_path, "azure", status="error", error=type(exc).__name__ + ": " + str(exc))
            results["azure"] = {"ok": False, "error": type(exc).__name__}
        else:
            if _inventory_due(db_path, "azure"):
                try:
                    renew_lease()
                    from azure.mgmt.resource import ResourceManagementClient
                    resource_client = ResourceManagementClient(credential, config["subscription_id"],
                        retry_total=3, retry_backoff_factor=0.8, retry_backoff_max=8)
                    inventory = collect_azure_inventory(config["subscription_id"], max_pages=5,
                        max_records=1000, resource_client=resource_client)
                    renew_lease()
                    inventory["stored_resources"] = cloud_ops.store_inventory(db_path, "azure", inventory.get("resources", []))
                    results["azure_inventory"] = {"resources":inventory.get("resource_count",0),
                        "complete":inventory.get("complete",False)}
                    _mark_inventory(db_path, "azure")
                except Exception as exc:
                    cloud_ops.mark_provider(db_path, "azure", status="partial", error="Inventory: " + type(exc).__name__, collected=True)
                    results["azure_inventory"] = {"ok":False, "error":type(exc).__name__}
        finally:
            if credential is not None:
                credential.close()
    return results


def _findings(db_path: Path) -> list[dict]:
    with closing(sqlite3.connect(str(db_path))) as db:
        rows = db.execute("SELECT payload_json FROM findings ORDER BY rowid DESC LIMIT 1000").fetchall()
    import json
    return [json.loads(row[0]) for row in rows]



def _record_heartbeat(auth_db: Path, worker_id: str = "primary", status: str = "running") -> None:
    from .worker_coordination import record_heartbeat
    record_heartbeat(auth_db, worker_id, status)

def run_forever() -> None:
    auth_db = Path(os.environ.get("CLOUDSHIELD_AUTH_DB", "/data/auth.sqlite3"))
    tenant_root = Path(os.environ.get("CLOUDSHIELD_TENANT_DIR", "/data/tenants"))
    interval = int(os.environ.get("CLOUDSHIELD_COLLECTION_INTERVAL_SECONDS", "300"))
    if not 60 <= interval <= 3600:
        raise RuntimeError("CLOUDSHIELD_COLLECTION_INTERVAL_SECONDS must be 60–3600")
    import socket
    import uuid
    from .worker_coordination import acquire_lease, renew_lease, release_lease, increment_counter
    worker_id = (os.environ.get("CLOUDSHIELD_WORKER_ID") or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}")[:128]
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    print(f"CloudShield collection worker started; id={worker_id}; interval={interval}s")
    while not _STOP:
        started = time.monotonic()
        try:
            _record_heartbeat(auth_db, worker_id)
            for tenant_id, tenant_db in _tenant_databases(auth_db, tenant_root):
                if _STOP:
                    break
                if not tenant_db.exists():
                    continue
                lease_name = f"collect:{tenant_id}"
                lease_ttl = min(3600, max(90, interval + 60))
                if not acquire_lease(auth_db, lease_name, worker_id, ttl_seconds=lease_ttl):
                    increment_counter(auth_db, "worker_lease_contention_total")
                    continue
                try:
                    result = collect_workspace(
                        tenant_db, interval_seconds=interval,
                        lease_heartbeat=lambda: renew_lease(auth_db, lease_name, worker_id, ttl_seconds=lease_ttl),
                    )
                    notifications = cloud_ops.deliver_alert_notifications(tenant_db, auth_db, tenant_id)
                    increment_counter(auth_db, "worker_workspace_cycles_total")
                    if result or notifications.get("queued") or notifications.get("sent") or notifications.get("failed"):
                        print(f"Workspace {tenant_db.stem[:12]}: collection={result}; notifications={notifications}")
                except Exception:
                    increment_counter(auth_db, "worker_workspace_errors_total")
                    raise
                finally:
                    release_lease(auth_db, lease_name, worker_id)
        except Exception as exc:
            # A worker-level error is visible in container logs; the next cycle retries.
            print(f"Worker cycle failed: {type(exc).__name__}: {exc}")
            increment_counter(auth_db, "worker_cycle_errors_total")
        remaining = max(1, interval - int(time.monotonic() - started))
        for _ in range(remaining):
            if _STOP:
                break
            time.sleep(1)
    _record_heartbeat(auth_db, worker_id, "stopping")


if __name__ == "__main__":
    run_forever()
