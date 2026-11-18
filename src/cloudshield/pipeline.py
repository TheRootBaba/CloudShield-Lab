from __future__ import annotations

from typing import Any, Callable

from .terraform import detect_risky_changes
from .remediation import propose_remediation
from .validation import validate_fix


def verify_change(plan: dict[str, Any], recheck: Callable | None = None) -> dict[str, Any]:
    findings = detect_risky_changes(plan)
    remediation = propose_remediation(findings)
    validation = validate_fix(findings, recheck)
    return {
        "findings": [finding.to_dict() for finding in findings],
        "remediation": [item.to_dict() for item in remediation],
        "validation": [item.to_dict() for item in validation],
    }
