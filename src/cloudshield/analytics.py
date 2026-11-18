"""Deterministic time-window correlation, incident timelines and evidence manifests."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any
from .events import CloudEvent
from .detector import Finding

SEVERITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def _parse_time(value: str):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return None

def _time(value: str) -> str:
    parsed = _parse_time(value)
    return parsed.isoformat().replace("+00:00", "Z") if parsed else value

def build_incidents(events: list[CloudEvent], findings: list[Finding], window_minutes: int = 30) -> list[dict[str, Any]]:
    """Group findings for the same actor/account while adjacent activity is within the window."""
    if window_minutes < 0:
        raise ValueError("window_minutes must be non-negative")
    by_id = {event.event_id: event for event in events}
    grouped: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        event = by_id.get(finding.event_id)
        grouped[(finding.actor, event.account_id if event else "unknown")].append(finding)

    incidents: list[dict[str, Any]] = []
    for (actor, account), items in sorted(grouped.items()):
        items.sort(key=lambda f: (_parse_time(f.event_time) or datetime.min.replace(tzinfo=timezone.utc), f.event_id, f.rule_id))
        clusters: list[list[Finding]] = []
        for finding in items:
            current_time = _parse_time(finding.event_time)
            if not clusters:
                clusters.append([finding])
                continue
            previous_time = _parse_time(clusters[-1][-1].event_time)
            within_window = (current_time is None or previous_time is None or
                             (current_time - previous_time).total_seconds() <= window_minutes * 60)
            if within_window:
                clusters[-1].append(finding)
            else:
                clusters.append([finding])
        for cluster in clusters:
            timeline = []
            for finding in cluster:
                event = by_id.get(finding.event_id)
                timeline.append({
                    "timestamp": _time(finding.event_time),
                    "event_id": finding.event_id,
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "source_ip": finding.source_ip,
                    "event_name": event.event_name if event else "unknown",
                    "resources": list(event.resource_ids) if event else [],
                    "evidence": finding.evidence,
                })
            canonical = json.dumps(timeline, sort_keys=True, separators=(",", ":"), default=str)
            incidents.append({
                "incident_id": "inc-" + sha256((actor + "|" + account + "|" + canonical).encode()).hexdigest()[:12],
                "actor": actor,
                "account_id": account,
                "finding_count": len(cluster),
                "severity": max((f.severity for f in cluster), key=lambda s: SEVERITY.get(s, 0)),
                "first_seen": timeline[0]["timestamp"],
                "last_seen": timeline[-1]["timestamp"],
                "rule_ids": sorted({f.rule_id for f in cluster}),
                "correlation": {"method": "same_actor_and_account_within_window", "window_minutes": window_minutes},
                "timeline": timeline,
                "evidence_sha256": sha256(canonical.encode()).hexdigest(),
            })
    return incidents

def investigation(event_id: str, events: list[CloudEvent], findings: list[Finding]) -> dict[str, Any]:
    matches = [event for event in events if event.event_id == event_id]
    if not matches:
        raise KeyError(f"Event not found: {event_id}")
    event = matches[0]
    related = [finding.to_dict() for finding in findings if finding.event_id == event_id]
    raw = json.dumps(event.raw, sort_keys=True, separators=(",", ":"), default=str)
    return {
        "event": event.to_dict(),
        "findings": related,
        "evidence": {
            "sha256": sha256(raw.encode()).hexdigest(),
            "raw_event": event.raw,
            "integrity_note": "SHA-256 covers canonicalized raw event JSON; it is an integrity fingerprint, not a digital signature or proof of origin.",
        },
    }

[executed on device: babam-desktop (5b84c11b-7f66-494f-9e6d-0dd5f16de169)]