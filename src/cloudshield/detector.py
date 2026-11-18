"""Explainable, intentionally conservative cloud audit-event detection rules."""

from dataclasses import asdict, dataclass
from typing import Any

from .events import CloudEvent


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    rationale: str
    event_id: str
    event_time: str
    actor: str
    source_ip: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


IAM_MUTATION_EVENTS = {
    "PutRolePolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "AttachUserPolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "UpdateAssumeRolePolicy",
}


def _is_public_bucket_policy(params: dict[str, Any]) -> bool:
    policy = params.get("policyDocument")
    if isinstance(policy, str):
        # CloudTrail may encode the policy document as JSON text.
        import json
        try:
            policy = json.loads(policy)
        except (TypeError, ValueError):
            return False
    if not isinstance(policy, dict):
        return False
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        principal = statement.get("Principal")
        action = statement.get("Action")
        public_principal = principal == "*" or (
            isinstance(principal, dict)
            and any(value == "*" or (isinstance(value, list) and "*" in value)
                    for value in principal.values())
        )
        actions = action if isinstance(action, list) else [action]
        broad_read = "*" in actions or "s3:*" in actions or "s3:GetObject" in actions
        if public_principal and broad_read and statement.get("Effect", "Allow") == "Allow":
            return True
    return False


def _exposes_admin_port(params: dict[str, Any]) -> bool:
    permissions = params.get("ipPermissions") or []
    if isinstance(permissions, dict):
        permissions = [permissions]
    for permission in permissions:
        if not isinstance(permission, dict):
            continue
        protocol = str(permission.get("ipProtocol", ""))
        from_port = permission.get("fromPort")
        to_port = permission.get("toPort")
        admin_port = protocol == "-1" or (
            isinstance(from_port, int)
            and isinstance(to_port, int)
            and from_port <= 22 <= to_port
        ) or (
            isinstance(from_port, int)
            and isinstance(to_port, int)
            and from_port <= 3389 <= to_port
        )
        ranges = permission.get("ipRanges") or []
        if isinstance(ranges, dict):
            ranges = [ranges]
        ipv6_ranges = permission.get("ipv6Ranges") or []
        if isinstance(ipv6_ranges, dict):
            ipv6_ranges = [ipv6_ranges]
        internet_open = any(
            item.get("cidrIp") == "0.0.0.0/0" for item in ranges if isinstance(item, dict)
        ) or any(
            item.get("cidrIpv6") == "::/0" for item in ipv6_ranges if isinstance(item, dict)
        )
        if admin_port and internet_open:
            return True
    return False


def analyze_event(event: CloudEvent) -> list[Finding]:
    """Return zero or more findings for one normalized audit event."""
    findings: list[Finding] = []
    base = {
        "event_id": event.event_id,
        "event_time": event.event_time,
        "actor": event.actor,
        "source_ip": event.source_ip,
    }

    if event.event_source == "securityhub.amazonaws.com" and event.event_name == "SecurityHubFinding":
        label = str(event.request_parameters.get("severity", "UNKNOWN")).upper()
        mapped = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFORMATIONAL": "INFO", "INFO": "INFO"}.get(label)
        if mapped:
            findings.append(Finding(
                rule_id="CS-SH-001",
                title=str(event.request_parameters.get("title") or "AWS Security Hub finding"),
                severity=mapped,
                rationale="Imported AWS Security Hub finding. Review the original provider context and affected resources.",
                evidence={"source": "securityhub", "severity_label": label, "types": event.request_parameters.get("types", []), "resources": list(event.resource_ids)},
                **base,
            ))

    if event.event_source == "iam.amazonaws.com" and event.event_name in IAM_MUTATION_EVENTS:
        findings.append(Finding(
            rule_id="CS-IAM-001",
            title="IAM trust or permission policy modified",
            severity="HIGH",
            rationale=(
                "An identity policy or role trust relationship changed. "
                "Validate the actor, change ticket, affected principal and resulting permissions."
            ),
            evidence={"event_name": event.event_name, "request_parameters": event.request_parameters},
            **base,
        ))

    if event.event_source == "s3.amazonaws.com" and event.event_name == "PutBucketPolicy":
        if _is_public_bucket_policy(event.request_parameters):
            findings.append(Finding(
                rule_id="CS-S3-001",
                title="Bucket policy grants access to a public principal",
                severity="CRITICAL",
                rationale=(
                    "The policy allows a public principal to read objects or grants wildcard actions. "
                    "Confirm whether public access is explicitly intended."
                ),
                evidence={"bucket_name": event.request_parameters.get("bucketName"),
                          "policy_document": event.request_parameters.get("policyDocument")},
                **base,
            ))

    if (event.event_source == "ec2.amazonaws.com"
            and event.event_name == "AuthorizeSecurityGroupIngress"
            and _exposes_admin_port(event.request_parameters)):
        findings.append(Finding(
            rule_id="CS-NET-001",
            title="Administrative port exposed to the public internet",
            severity="CRITICAL",
            rationale=(
                "An inbound security-group rule exposes SSH, RDP or all protocols to 0.0.0.0/0. "
                "Restrict the source to an approved management range."
            ),
            evidence={"group_id": event.request_parameters.get("groupId"),
                      "ip_permissions": event.request_parameters.get("ipPermissions")},
            **base,
        ))

    return findings

[executed on device: babam-desktop (5b84c11b-7f66-494f-9e6d-0dd5f16de169)]