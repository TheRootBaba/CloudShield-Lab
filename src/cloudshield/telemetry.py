from __future__ import annotations

from typing import Any, Iterable


def normalize_cloudtrail(events: Iterable[dict[str, Any]] | dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize CloudTrail events into stable telemetry records."""
    if isinstance(events, dict):
        events = events.get("Records") or events.get("events") or events.get("Events") or []
    if not isinstance(events, list):
        return []
    normalized: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        detail = event.get("detail") if isinstance(event.get("detail"), dict) else event
        normalized.append({
            "event_name": str(detail.get("eventName") or detail.get("EventName") or detail.get("event_name") or ""),
            "event_source": str(detail.get("eventSource") or detail.get("EventSource") or detail.get("event_source") or ""),
            "event_time": str(detail.get("eventTime") or detail.get("EventTime") or detail.get("event_time") or ""),
            "actor": str(detail.get("userIdentity", {}).get("arn", "") if isinstance(detail.get("userIdentity"), dict)
                         else detail.get("actor") or ""),
            "source_ip": str(detail.get("sourceIPAddress") or detail.get("SourceIPAddress") or detail.get("source_ip") or ""),
            "response": str(detail.get("errorCode") or detail.get("responseElements") or "success"),
        })
    return normalized


def normalize_security_hub(findings: Iterable[dict[str, Any]] | dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize AWS Security Hub findings for cross-source processing."""
    if isinstance(findings, dict):
        findings = findings.get("Findings") or []
    if not isinstance(findings, list):
        return []
    normalized: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = finding.get("Severity", {})
        label = severity.get("Label") if isinstance(severity, dict) else severity
        resources = finding.get("Resources") or []
        resource_id = ""
        if isinstance(resources, list) and resources and isinstance(resources[0], dict):
            resource_id = str(resources[0].get("Id") or "")
        normalized.append({
            "id": str(finding.get("Id") or ""),
            "title": str(finding.get("Title") or ""),
            "severity": str(label or finding.get("severity") or "INFORMATIONAL").lower(),
            "status": str(finding.get("RecordState") or finding.get("status") or "UNKNOWN"),
            "resource": resource_id,
            "description": str(finding.get("Description") or ""),
        })
    return normalized
