from __future__ import annotations

from typing import Iterable

from .models import Finding, Remediation


APPROVED_ACTIONS = {
    "Restrict ingress to approved CIDR ranges.",
    "Set a private ACL and enable a public access block.",
    "Enable CloudTrail logging.",
}


def propose_remediation(findings: Finding | Iterable[Finding]) -> list[Remediation]:
    if isinstance(findings, Finding):
        findings = [findings]
    return [
        Remediation(
            finding_id=finding.id,
            action=finding.remediation,
            target=finding.resource,
            approved=False,
            applied=False,
            dry_run=True,
        )
        for finding in findings
        if isinstance(finding, Finding)
    ]


def apply_guarded_remediation(
    remediation: Remediation,
    *,
    approved: bool = False,
    allowlist: Iterable[str] | None = None,
    executor=None,
) -> Remediation:
    allowed = set(allowlist) if allowlist is not None else APPROVED_ACTIONS
    if remediation.action not in allowed:
        remediation.applied = False
        remediation.approved = False
        remediation.dry_run = True
        return remediation
    remediation.approved = bool(approved)
    remediation.dry_run = not approved
    if approved:
        if executor is not None:
            executor(remediation.target, remediation.action)
        remediation.applied = True
    else:
        remediation.applied = False
    return remediation
