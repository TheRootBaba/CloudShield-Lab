"""Explainable relationship graph. Correlation edges are hypotheses, never causal proof."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

MAX_CORRELATION_GAP_SECONDS = 24 * 60 * 60


def _parse(value: Any):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _node_id(kind: str, value: str) -> str:
    return f"{kind}:" + sha256(value.encode("utf-8")).hexdigest()[:12]


def build_attack_path(incident: dict[str, Any]) -> dict[str, Any]:
    """Build an explainable, bounded correlation graph from an incident timeline.

    This deliberately does not infer exploitability, privilege reachability, or
    causation. Consecutive events are linked only when there is a concrete
    correlation signal and their timestamps are within the configured window.
    """
    raw_timeline = incident.get("timeline", [])
    timeline = raw_timeline if isinstance(raw_timeline, list) else []
    timeline = [item for item in timeline if isinstance(item, dict)]

    actor = str(incident.get("actor") or "unknown")
    account = str(incident.get("account_id") or "unknown")
    actor_id = _node_id("actor", actor)
    account_node_id = _node_id("account", account)
    nodes = [
        {"id": actor_id, "kind": "actor", "label": actor},
        {"id": account_node_id, "kind": "account", "label": account},
    ]
    edges = []
    resource_nodes: set[str] = set()
    event_ids: list[str] = []
    normalized: list[dict[str, Any]] = []

    for index, item in enumerate(timeline):
        event_id = str(item.get("event_id") or f"event-{index}")
        # Duplicate IDs make graph references ambiguous; retain deterministic unique IDs.
        if event_id in event_ids:
            event_id = f"{event_id}#{index}"
        event_ids.append(event_id)
        resources_value = item.get("resources", [])
        resources = sorted({str(value) for value in resources_value if value is not None}) if isinstance(resources_value, (list, tuple, set)) else []
        normalized.append({**item, "event_id": event_id, "resources": resources})

        nodes.append({
            "id": event_id,
            "kind": "finding",
            "label": item.get("title") or item.get("rule_id") or "Security finding",
            "rule_id": item.get("rule_id"),
            "severity": item.get("severity"),
            "timestamp": item.get("timestamp"),
            "resources": resources,
        })
        edges.append({
            "source": event_id, "target": actor_id,
            "relationship": "attributed_to_incident_actor",
            "evidence": ["incident_actor_attribution"],
            "confidence": "incident_context",
        })
        edges.append({
            "source": event_id, "target": account_node_id,
            "relationship": "occurred_in_incident_account",
            "evidence": ["incident_account_attribution"],
            "confidence": "incident_context",
        })
        for resource in resources:
            resource_id = _node_id("resource", resource)
            if resource_id not in resource_nodes:
                nodes.append({"id": resource_id, "kind": "resource", "label": resource})
                resource_nodes.add(resource_id)
            edges.append({
                "source": event_id, "target": resource_id,
                "relationship": "references_resource",
                "evidence": ["event_resource_identifier"],
                "confidence": "observed_context",
            })

    sequence_edges = []
    for previous, current in zip(normalized, normalized[1:]):
        reasons = []
        shared = sorted(set(previous["resources"]).intersection(current["resources"]))
        if shared:
            reasons.append("shared_resource")
        previous_actor = str(previous.get("actor") or "")
        current_actor = str(current.get("actor") or "")
        if previous_actor and current_actor and previous_actor == current_actor:
            reasons.append("same_event_actor")
        elif actor != "unknown":
            # This is weaker than per-event actor equality; make the provenance explicit.
            reasons.append("same_incident_actor_attribution")

        start, end = _parse(previous.get("timestamp")), _parse(current.get("timestamp"))
        gap = (end - start).total_seconds() if start and end and end >= start else None
        if gap is not None and gap > MAX_CORRELATION_GAP_SECONDS:
            reasons = []
        if not reasons:
            continue

        edge = {
            "source": previous["event_id"],
            "target": current["event_id"],
            "relationship": "correlated_sequence_hypothesis",
            "evidence": reasons,
            "shared_resources": shared,
            "time_gap_seconds": gap,
            "confidence": "moderate" if shared and gap is not None else "low",
            "causal": False,
        }
        sequence_edges.append(edge)
        edges.append(edge)

    return {
        "model": "explainable-temporal-resource-graph-v2",
        "semantics": (
            "Correlation hypotheses based on incident actor attribution, "
            "per-event actor equality, shared resource identifiers and event time. "
            "Edges do not establish causality, exploitability or privilege reachability."
        ),
        "correlation_window_seconds": MAX_CORRELATION_GAP_SECONDS,
        "nodes": nodes,
        "event_nodes": [node for node in nodes if node["kind"] == "finding"],
        "edges": edges,
        "sequence_edges": sequence_edges,
        "complete": False,
        "limitations": [
            "Only the incident timeline is analyzed; no authoritative IAM or network reachability is inferred.",
            "Incident-level actor attribution is weaker than matching actor fields on both events.",
            "Missing or invalid timestamps reduce temporal confidence; gaps over 24 hours are not linked.",
            "A shared resource or actor does not prove one event caused another.",
        ],
    }
