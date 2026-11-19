"""Opt-in, bounded, read-only Azure inventory and Activity Log adapter."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
MAX_PAGES = 20
MAX_RECORDS = 5000


def _validate(subscription_id: str, max_pages: int, max_records: int) -> None:
    if not isinstance(subscription_id, str) or not _UUID.fullmatch(subscription_id):
        raise ValueError("A valid Azure subscription UUID is required")
    if not isinstance(max_pages, int) or not 1 <= max_pages <= MAX_PAGES:
        raise ValueError(f"max_pages must be between 1 and {MAX_PAGES}")
    if not isinstance(max_records, int) or not 1 <= max_records <= MAX_RECORDS:
        raise ValueError(f"max_records must be between 1 and {MAX_RECORDS}")


def _value(obj: Any, *names: str, default=None):
    for name in names:
        value = obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)
        if value is not None:
            return value
    return default


def _nested(obj: Any, *names: str, default=None):
    value = obj
    for name in names:
        value = _value(value, name)
        if value is None:
            return default
    return value


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _clients(subscription_id: str):
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resource import ResourceManagementClient
        from azure.mgmt.monitor import MonitorManagementClient
    except ImportError as exc:
        raise RuntimeError("Azure support requires azure-identity, azure-mgmt-resource and azure-mgmt-monitor. Install with: pip install -e .[azure]") from exc
    credential = DefaultAzureCredential()
    retry = {"retry_total": 3, "retry_backoff_factor": 0.8, "retry_backoff_max": 8}
    return (
        ResourceManagementClient(credential, subscription_id, **retry),
        MonitorManagementClient(credential, subscription_id, **retry),
        credential,
    )


def _bounded_pages(paged: Any, max_pages: int, max_records: int):
    """Read a bounded Azure ItemPaged response; SDK retry policy handles transient HTTP errors."""
    records, pages, truncated, failure = [], 0, False, None
    iterator = paged.by_page() if hasattr(paged, "by_page") else iter([paged])
    try:
        while pages < max_pages and len(records) < max_records:
            try:
                page = next(iterator)
            except StopIteration:
                break
            pages += 1
            if isinstance(page, (dict, str, bytes)):
                page = [page]
            for item in page:
                if len(records) >= max_records:
                    truncated = True
                    break
                records.append(item)
            if len(records) >= max_records:
                truncated = True
                break
        else:
            truncated = True
        if pages >= max_pages and getattr(iterator, "continuation_token", None):
            truncated = True
    except Exception as exc:  # preserve already retrieved pages and report partial failure
        failure = {"type": type(exc).__name__, "message": str(exc)[:500]}
    return records, pages, truncated, failure


def collect_inventory(subscription_id: str, max_pages: int = 10, max_records: int = 2000, resource_client=None) -> dict[str, Any]:
    """List ARM resource metadata only. No resource write APIs are called."""
    _validate(subscription_id, max_pages, max_records)
    credential = None
    if resource_client is None:
        resource_client, _, credential = _clients(subscription_id)
    started = datetime.now(timezone.utc)
    try:
        paged = resource_client.resources.list()
        resources, pages, truncated, failure = _bounded_pages(paged, max_pages, max_records)
    finally:
        if credential is not None:
            credential.close()
    rows = []
    for resource in resources:
        resource_id = _value(resource, "id")
        group_match = re.search(r"/resourceGroups/([^/]+)", str(resource_id or ""), re.IGNORECASE)
        rows.append({
            "resource_type": str(_value(resource, "type", default="unknown")).lower(),
            "resource_id": resource_id,
            "name": _value(resource, "name"),
            "region": _value(resource, "location"),
            "resource_group": _value(resource, "resource_group", "resourceGroup") or (group_match.group(1) if group_match else None),
            "tags": _value(resource, "tags", default={}) or {},
        })
    failures = ([{"operation": "resources.list", **failure}] if failure else [])
    return {
        "provider": "azure", "subscription_id": subscription_id,
        "execution": "live-read-only", "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "collection_started_at": started.isoformat(timespec="seconds"),
        "resources": rows, "resource_count": len(rows), "pages_read": pages,
        "api_calls": pages, "api_call_count_semantics":"successful logical SDK page operations; internal SDK retries are not counted",
        "retry_policy":"Azure SDK retry_total=3 with capped backoff for transient responses",
        "truncated": truncated, "partial_failures": failures,
        "complete": not truncated and not failures,
        "permissions_required": ["Microsoft.Resources/subscriptions/resources/read"],
        "limitations": ["ARM resource metadata only; this does not enumerate data-plane objects or prove effective security configuration.",
                        "A complete flag applies only to this bounded ARM resource-list operation, not all Azure assets or services.",
                        "No Azure resource creation, modification or deletion APIs are called."],
    }


def _activity_event(item: Any, subscription_id: str) -> dict[str, Any]:
    operation_obj = _value(item, "operation_name", "operationName")
    operation = _value(operation_obj, "value", default=operation_obj) or "unknown"
    event_id = _value(item, "event_data_id", "eventDataId", "id") or _value(item, "correlation_id", "correlationId") or "unknown"
    caller = _value(item, "caller", default="unknown")
    resource_id = _value(item, "resource_id", "resourceId")
    category = _nested(item, "category", "value") or "Administrative"
    authorization = _value(item, "authorization", default={}) or {}
    http_request = _value(item, "http_request", "httpRequest", default={}) or {}
    properties = _value(item, "properties", default={}) or {}
    status = _nested(item, "status", "value") or _value(item, "status", default="unknown")
    event_time = _iso(_value(item, "event_timestamp", "eventTimestamp", "submission_timestamp", "submissionTimestamp")) or "unknown"
    return {
        "eventID": str(event_id), "eventTime": event_time,
        "eventSource": "azure.activitylogs", "eventName": str(operation),
        "recipientAccountId": subscription_id,
        "region": str(_value(item, "resource_location", "resourceLocation", default="unknown")),
        "sourceIPAddress": str(_value(http_request, "client_ip_address", "clientIpAddress", default="unknown")),
        "userIdentity": {"type": "AzurePrincipal", "principalId": str(caller)},
        "resources": ([{"id": str(resource_id)}] if resource_id else []),
        "requestParameters": {"authorization": authorization, "category": category, "status": str(status), "properties": properties},
        "responseElements": {"status": str(status)},
        "cloudshield_provider": "azure", "cloudshield_source_format": "azure_activity_log",
    }


def collect_activity_logs(subscription_id: str, lookback_hours: int = 24, max_pages: int = 10, max_records: int = 2000, monitor_client=None) -> dict[str, Any]:
    """Read Azure subscription Activity Logs over a bounded UTC window."""
    _validate(subscription_id, max_pages, max_records)
    if not isinstance(lookback_hours, int) or not 1 <= lookback_hours <= 168:
        raise ValueError("lookback_hours must be between 1 and 168")
    credential = None
    if monitor_client is None:
        _, monitor_client, credential = _clients(subscription_id)
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=lookback_hours)
    filter_value = f"eventTimestamp ge '{start.isoformat()}' and eventTimestamp le '{end.isoformat()}'"
    try:
        paged = monitor_client.activity_logs.list(filter=filter_value)
        items, pages, truncated, failure = _bounded_pages(paged, max_pages, max_records)
    finally:
        if credential is not None:
            credential.close()
    events = [_activity_event(item, subscription_id) for item in items]
    failures = ([{"operation": "activity_logs.list", **failure}] if failure else [])
    return {
        "provider": "azure", "source": "azure-activity-logs", "subscription_id": subscription_id,
        "execution": "live-read-only", "lookback_hours": lookback_hours,
        "collection_started_at": start.isoformat(timespec="seconds"), "collection_ended_at": end.isoformat(timespec="seconds"),
        "events": events, "event_count": len(events), "pages_read": pages, "api_calls": pages,
        "api_call_count_semantics":"successful logical SDK page operations; internal SDK retries are not counted",
        "retry_policy":"Azure SDK retry_total=3 with capped backoff for transient responses",
        "truncated": truncated, "partial_failures": failures, "complete": not truncated and not failures,
        "permissions_required": ["Microsoft.Insights/eventtypes/values/read"],
        "limitations": ["Azure Activity Logs cover control-plane operations and are not a substitute for resource data-plane logs or Microsoft Defender alerts.",
                        "A complete flag applies only to the requested bounded Activity Log window.",
                        "No Azure resource creation, modification or deletion APIs are called."],
    }
