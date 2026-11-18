"""Explainable relationship graph. Edges are hypotheses, never causal proof."""
from __future__ import annotations
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

def _parse(value: str):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None

def build_attack_path(incident: dict[str, Any]) -> dict[str, Any]:
    timeline = incident.get("timeline", [])
    nodes = []
    edges = []
    actor = str(incident.get("actor", "unknown"))
    account = str(incident.get("account_id", "unknown"))
    actor_id = "actor:" + sha256(actor.encode("utf-8")).hexdigest()[:12]
    account_node_id = "account:" + sha256(account.encode("utf-8")).hexdigest()[:12]
    nodes.extend([
        {"id": actor_id, "kind": "actor", "label": actor},
        {"id": account_node_id, "kind": "account", "label": account},
    ])
    resource_nodes = set()
    for index, item in enumerate(timeline):
        event_node_id = item.get("event_id", f"event-{index}")
        nodes.append({
            "id": event_node_id,
            "kind": "finding",
            "label": item.get("title", item.get("rule_id", "Security finding")),
            "rule_id": item.get("rule_id"),
            "severity": item.get("severity"),
            "timestamp": item.get("timestamp"),
            "resources": item.get("resources", []),
        })
        edges.append({"source": event_node_id, "target": actor_id, "relationship": "performed_by", "evidence": ["incident_actor_attribution"], "confidence": "observed_context"})
        edges.append({"source": event_node_id, "target": account_node_id, "relationship": "occurred_in_account", "evidence": ["normalized_account_id"], "confidence": "observed_context"})
        for resource in item.get("resources", []):
            resource = str(resource)
            resource_id = "resource:" + sha256(resource.encode("utf-8")).hexdigest()[:12]
            if resource_id not in resource_nodes:
                nodes.append({"id": resource_id, "kind": "resource", "label": resource})
                resource_nodes.add(resource_id)
            edges.append({"source": event_node_id, "target": resource_id, "relationship": "references_resource", "evidence": ["event_resource_identifier"], "confidence": "observed_context"})
        if index == 0:
            continue
        previous = timeline[index - 1]
        current = item
        reasons = []
        if previous.get("actor") == current.get("actor") or incident.get("actor"):
            reasons.append("same_incident_actor")
        prev_resources = set(previous.get("resources", []))
        curr_resources = set(current.get("resources", []))
        shared = sorted(prev_resources.intersection(curr_resources))
        if shared:
            reasons.append("shared_resource")
        a, b = _parse(previous.get("timestamp")), _parse(current.get("timestamp"))
        gap = abs((b - a).total_seconds()) if a and b else None
        edges.append({
            "source": previous.get("event_id", f"event-{index-1}"),
            "target": current.get("event_id", f"event-{index}"),
            "relationship": "temporal_and_actor_correlation",
            "evidence": reasons or ["same_incident_cluster"],
            "shared_resources": shared,
            "time_gap_seconds": gap,
            "confidence": "moderate" if shared else "low",
        })
    return {
        "model": "explainable-temporal-resource-graph-v1",
        "semantics": "Hypothesis graph built from observed actor, time and resource overlap. Edges do not establish causality.",
        "nodes": nodes,
        "event_nodes": [node for node in nodes if node["kind"] == "finding"],
        "edges": edges,
        "sequence_edges": [edge for edge in edges if edge["relationship"] == "temporal_and_actor_correlation"],
        "complete": False,
    }