from __future__ import annotations

from typing import Any, Iterable

from .models import Change, Finding


def parse_plan(plan: dict[str, Any]) -> list[Change]:
    """Convert a Terraform JSON plan into normalized resource changes."""
    changes: list[Change] = []
    root = plan.get("resource_changes", []) if isinstance(plan, dict) else []
    if not isinstance(root, list):
        return changes
    for item in root:
        if not isinstance(item, dict):
            continue
        actions = item.get("change", {}).get("actions", [])
        action = "+".join(actions) if isinstance(actions, list) else str(actions)
        if action == "create":
            action = "create"
        elif action == "delete":
            action = "delete"
        elif action in ("update", "update"):
            action = "update"
        elif action == "replace" or "create" in action and "delete" in action:
            action = "replace"
        elif action == "no-op":
            action = "no-op"
        else:
            action = action or "unknown"
        change = item.get("change", {})
        changes.append(Change(
            address=str(item.get("address", "")),
            action=action,
            type=str(item.get("type", "")),
            after=dict(change.get("after") or {}) if isinstance(change.get("after"), dict) else {},
            before=dict(change.get("before") or {}) if isinstance(change.get("before"), dict) else {},
        ))
    return changes


def detect_risky_changes(plan_or_changes: Any) -> list[Finding]:
    """Detect common infrastructure risks without contacting AWS."""
    changes = parse_plan(plan_or_changes) if isinstance(plan_or_changes, dict) else [
        item for item in plan_or_changes if isinstance(item, Change)
    ] if isinstance(plan_or_changes, list) else []
    findings: list[Finding] = []
    for change in changes:
        if change.action == "no-op" or change.action == "delete":
            continue
        config = change.after
        if change.type in ("aws_security_group", "aws_vpc_security_group_ingress_rule"):
            cidrs = _egress_cidrs(config)
            for cidr in cidrs:
                if cidr in ("0.0.0.0/0", "::/0"):
                    findings.append(Finding(
                        id=f"public-ingress:{change.address}",
                        severity="high",
                        title="Security group allows ingress from the internet",
                        resource=change.address,
                        evidence={"cidr": cidr},
                        remediation="Restrict ingress to approved CIDR ranges.",
                    ))
        if change.type == "aws_s3_bucket":
            if config.get("acl") == "public-read" or config.get("acl") == "public-read-write":
                findings.append(Finding(
                    id=f"public-s3:{change.address}",
                    severity="critical",
                    title="S3 bucket permits public access",
                    resource=change.address,
                    evidence={"acl": config.get("acl")},
                    remediation="Set a private ACL and enable a public access block.",
                ))
        if change.type in ("aws_cloudtrail", "aws_s3_bucket") and "logging" in change.type:
            pass
        if change.type == "aws_cloudtrail" and config.get("enable_logging") is False:
            findings.append(Finding(
                id=f"cloudtrail-disabled:{change.address}",
                severity="critical",
                title="CloudTrail logging is disabled",
                resource=change.address,
                evidence={"enable_logging": False},
                remediation="Enable CloudTrail logging.",
            ))
    return findings


def _egress_cidrs(config: dict[str, Any]) -> list[str]:
    cidrs: list[str] = []
    for key in ("cidr_blocks", "ipv6_cidr_blocks"):
        value = config.get(key)
        if isinstance(value, list):
            cidrs.extend(str(item) for item in value)
    if isinstance(config.get("cidr_ipv4"), str):
        cidrs.append(config["cidr_ipv4"])
    if isinstance(config.get("cidr_ipv6"), str):
        cidrs.append(config["cidr_ipv6"])
    for ingress in config.get("ingress", []) if isinstance(config.get("ingress"), list) else []:
        if isinstance(ingress, dict):
            cidrs.extend(_egress_cidrs(ingress))
    return cidrs
