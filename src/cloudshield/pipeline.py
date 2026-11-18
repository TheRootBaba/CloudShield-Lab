"""End-to-end local verification pipeline."""
from __future__ import annotations
from typing import Any
from .events import load_events
from .detector import analyze_event
from .analytics import build_incidents

def analyze_payload(payload: Any) -> dict[str,Any]:
    events=load_events(payload)
    findings=[f for event in events for f in analyze_event(event)]
    incidents=build_incidents(events,findings)
    return {"schema_version":"1.0","events_analyzed":len(events),"findings_count":len(findings),"incidents_count":len(incidents),"events":[e.to_dict() for e in events],"findings":[f.to_dict() for f in findings],"incidents":incidents}

[executed on device: babam-desktop (5b84c11b-7f66-494f-9e6d-0dd5f16de169)]