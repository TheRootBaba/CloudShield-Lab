"""Normalized, immutable audit-event model with CloudTrail and Security Hub adapters."""
from __future__ import annotations
from dataclasses import dataclass, asdict, replace
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any
import re

def _stable(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)

@dataclass(frozen=True)
class CloudEvent:
    event_id: str
    event_time: str
    event_source: str
    event_name: str
    actor: str
    source_ip: str
    region: str
    account_id: str
    resource_ids: tuple[str, ...]
    request_parameters: dict[str, Any]
    response_elements: dict[str, Any]
    raw: dict[str, Any]
    source_format: str = "cloudtrail"
    @property
    def fingerprint(self) -> str:
        return sha256(_stable(self.to_dict()).encode()).hexdigest()
    @classmethod
    def from_dict(cls, p: dict[str, Any]) -> "CloudEvent":
        if not isinstance(p, dict): raise ValueError("Each event must be a JSON object")
        detail = p.get("detail") if isinstance(p.get("detail"), dict) else p
        identity = detail.get("userIdentity") or detail.get("user") or {}
        session = identity.get("sessionContext") or {}
        issuer = session.get("sessionIssuer") or {}
        actor = identity.get("arn") or issuer.get("arn") or identity.get("principalId") or identity.get("type") or detail.get("actor") or "unknown"
        resources = detail.get("resources") or []
        ids = []
        for r in resources:
            if isinstance(r, dict):
                rid = r.get("ARN") or r.get("arn") or r.get("id")
                if rid: ids.append(str(rid))
            elif isinstance(r, str): ids.append(r)
        rp = detail.get("requestParameters") or detail.get("request_parameters") or {}
        for key in ("bucketName", "groupId", "roleName", "userName", "policyArn"):
            if rp.get(key): ids.append(str(rp[key]))
        event_name = detail.get("eventName") or detail.get("name") or detail.get("type") or "unknown"
        event_source = detail.get("eventSource") or detail.get("source") or ""
        if event_source and "." not in event_source and event_source.endswith(".amazonaws.com") is False:
            event_source = event_source.replace("aws.", "") + ".amazonaws.com"
        event_id = str(detail.get("eventID") or detail.get("id") or detail.get("findingId") or sha256(_stable(detail).encode()).hexdigest()[:16])
        time = str(detail.get("eventTime") or detail.get("time") or p.get("time") or "unknown")
        actor_text = str(actor)
        account_match = re.search(r"arn:[^:]+:[^:]*::(\d{12}):", actor_text)
        account_id = detail.get("recipientAccountId") or detail.get("accountId") or (account_match.group(1) if account_match else "unknown")
        return cls(event_id,time,str(event_source or "unknown"),str(event_name),actor_text,str(detail.get("sourceIPAddress") or detail.get("sourceIp") or "unknown"),str(detail.get("awsRegion") or detail.get("region") or "unknown"),str(account_id),tuple(sorted(set(ids))),rp,detail.get("responseElements") or {},p,"synthetic" if isinstance(p.get("cloudshield_lab"), dict) else ("securityhub" if "findings" in p or "AwsAccountId" in detail else "cloudtrail"))
    def to_dict(self) -> dict[str, Any]:
        result=asdict(self); result["resource_ids"]=list(self.resource_ids); return result

def _securityhub_event(finding: dict[str, Any]) -> CloudEvent:
    severity = finding.get("Severity") or {}
    if isinstance(severity, dict):
        severity = severity.get("Label") or severity.get("Normalized") or "UNKNOWN"
    resources = finding.get("Resources") or []
    event = CloudEvent.from_dict({
        "eventID": finding.get("Id") or finding.get("FindingId") or "securityhub-unknown",
        "eventTime": finding.get("UpdatedAt") or finding.get("CreatedAt") or "unknown",
        "eventSource": "securityhub.amazonaws.com",
        "eventName": "SecurityHubFinding",
        "recipientAccountId": finding.get("AwsAccountId") or "unknown",
        "awsRegion": finding.get("Region") or "unknown",
        "sourceIPAddress": "unknown",
        "userIdentity": {"type": "SecurityHub", "principalId": "securityhub"},
        "resources": resources,
        "requestParameters": {"severity": str(severity), "title": finding.get("Title", ""), "types": finding.get("Types", [])},
    })
    return replace(event, raw=finding, source_format="securityhub")

def load_events(payload: Any) -> list[CloudEvent]:
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict) and isinstance(payload.get("Records"), list):
        rows = payload["Records"]
    elif isinstance(payload, dict) and isinstance(payload.get("events"), list):
        rows = payload["events"]
    elif isinstance(payload, dict) and isinstance(payload.get("Findings"), list):
        return [_securityhub_event(row) for row in payload["Findings"]]
    elif isinstance(payload, dict) and isinstance((payload.get("detail") or {}).get("findings"), list):
        return [_securityhub_event(row) for row in payload["detail"]["findings"]]
    elif isinstance(payload, dict):
        rows = [payload]
    else:
        raise ValueError("Input must be an event object, a list, or a CloudTrail Records document")
    return [CloudEvent.from_dict(row) for row in rows]