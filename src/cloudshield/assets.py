"""Derived, local-only AWS asset inventory and observed relationship graph."""
from __future__ import annotations
from collections import defaultdict
from hashlib import sha256
from typing import Any
import json

def classify_resource(resource_id: str) -> str:
    value = str(resource_id or "")
    if value.startswith("arn:"):
        parts = value.split(":", 5)
        service = parts[2] if len(parts) > 2 else "unknown"
        tail = parts[5] if len(parts) > 5 else ""
        if service == "s3":
            return "s3-bucket"
        if service == "iam":
            return "iam-role" if tail.startswith("role/") else "iam-user" if tail.startswith("user/") else "iam-policy"
        if service == "ec2":
            prefix = tail.split("/", 1)[0]
            return {"instance": "ec2-instance", "security-group": "security-group", "snapshot": "ebs-snapshot", "volume": "ebs-volume"}.get(prefix, f"ec2-{prefix or 'resource'}")
        if service == "rds":
            return "rds-resource"
        if service == "lambda":
            return "lambda-function"
        if service == "kms":
            return "kms-key"
        return f"{service}-resource"
    if value.startswith("sg-"): return "security-group"
    if value.startswith("i-"): return "ec2-instance"
    if value.startswith("snap-"): return "ebs-snapshot"
    if value.startswith("arn:aws:s3:::"): return "s3-bucket"
    return "unknown-resource"

def _asset_id(account: str, region: str, resource: str) -> str:
    return "asset:" + sha256(f"{account}|{region}|{resource}".encode()).hexdigest()[:16]

def inventory(events: list[dict], findings: list[dict]) -> list[dict]:
    """Build inventory from observed event identifiers; never imply unseen assets."""
    by_resource: dict[tuple[str, str, str], dict[str, Any]] = {}
    finding_by_event: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        finding_by_event[str(f.get("event_id", ""))].append(f)
    for event in events:
        account = str(event.get("account_id") or "unknown")
        region = str(event.get("region") or "unknown")
        actor = str(event.get("actor") or "unknown")
        stamp = str(event.get("event_time") or "unknown")
        event_id = str(event.get("event_id") or "")
        resources = event.get("resource_ids") or []
        if not resources:
            resources = _extract_resource_ids(event)
        service = str(event.get("event_source") or "").split(".",1)[0]
        for resource in resources:
            resource = str(resource)
            kind = classify_resource(resource)
            if kind == "unknown-resource":
                kind = {"s3":"s3-bucket","iam":"iam-resource","ec2":"ec2-resource","rds":"rds-resource","lambda":"lambda-function","kms":"kms-key"}.get(service,kind)
            key = (account, region, resource)
            item = by_resource.setdefault(key, {
                "id": _asset_id(account, region, resource),
                "resource_id": resource,
                "resource_type": kind,
                "account_id": account,
                "region": region,
                "first_seen": stamp,
                "last_seen": stamp,
                "event_count": 0,
                "actors": set(),
                "event_ids": set(),
                "findings": [],
            })
            if stamp < item["first_seen"]: item["first_seen"] = stamp
            if stamp > item["last_seen"]: item["last_seen"] = stamp
            item["event_count"] += 1
            item["actors"].add(actor)
            item["event_ids"].add(event_id)
            item["findings"].extend(finding_by_event.get(event_id, []))
    result=[]
    for item in by_resource.values():
        severities=sorted({str(f.get("severity","INFO")).upper() for f in item["findings"]}, key=lambda s: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(s,5))
        item["actors"]=sorted(item["actors"])
        item["event_ids"]=sorted(item["event_ids"])
        item["finding_count"]=len(item["findings"])
        item["severities"]=severities
        item["findings"]=[{"rule_id":f.get("rule_id"),"title":f.get("title"),"severity":f.get("severity"),"event_id":f.get("event_id")} for f in item["findings"]]
        result.append(item)
    return sorted(result, key=lambda a: (a["account_id"],a["region"],a["resource_type"],a["resource_id"]))

def _extract_resource_ids(event: dict) -> list[str]:
    raw=event.get("raw") or {}
    detail=raw.get("detail") if isinstance(raw.get("detail"),dict) else raw
    values=[]
    for r in detail.get("resources") or []:
        if isinstance(r,dict):
            rid=r.get("ARN") or r.get("arn") or r.get("id")
            if rid: values.append(str(rid))
        elif isinstance(r,str): values.append(r)
    params=event.get("request_parameters") or {}
    for key in ("bucketName","groupId","roleName","userName","policyArn","functionName","snapshotId","dBSnapshotIdentifier","keyId","trailName"):
        val=params.get(key)
        if val: values.append(str(val))
    return sorted(set(values))

def relationship_graph(events: list[dict], assets: list[dict]) -> dict:
    """Observed identity-to-asset edges, labeled as contextual rather than causal."""
    actors={}
    event_lookup={}
    asset_ids={a["resource_id"]:a["id"] for a in assets}
    edges=[]
    for event in events:
        actor=str(event.get("actor") or "unknown")
        account=str(event.get("account_id") or "unknown")
        actor_id="actor:"+sha256(actor.encode()).hexdigest()[:12]
        account_id="account:"+sha256(account.encode()).hexdigest()[:12]
        actors[actor_id]={"id":actor_id,"kind":"identity","label":actor}
        event_lookup[event.get("event_id")]=event
        edges.append({"source":actor_id,"target":account_id,"relationship":"observed_in_account","evidence":["event_actor_and_account"],"confidence":"observed_context"})
        for resource in event.get("resource_ids") or _extract_resource_ids(event):
            target=asset_ids.get(str(resource))
            if target:
                edges.append({"source":actor_id,"target":target,"relationship":"actor_touched_resource","event_id":event.get("event_id"),"timestamp":event.get("event_time"),"evidence":["normalized_event_resource"],"confidence":"observed_context"})
                edges.append({"source":account_id,"target":target,"relationship":"resource_observed_in_account","event_id":event.get("event_id"),"evidence":["normalized_account_id","resource_identifier"],"confidence":"observed_context"})
    accounts={}
    for a in assets:
        aid="account:"+sha256(a["account_id"].encode()).hexdigest()[:12]
        accounts[aid]={"id":aid,"kind":"account","label":a["account_id"]}
    nodes=[*actors.values(),*accounts.values(),*({"id":a["id"],"kind":"asset","label":a["resource_id"],"resource_type":a["resource_type"],"account_id":a["account_id"],"region":a["region"],"finding_count":a["finding_count"]} for a in assets)]
    return {"model":"observed-asset-relationship-graph-v1","semantics":"Edges represent observed event context, not causal attack paths or complete inventory.","nodes":nodes,"edges":edges,"complete":False}
