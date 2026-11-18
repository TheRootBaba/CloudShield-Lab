from __future__ import annotations

from typing import Callable, Iterable

from .models import Finding, ValidationResult


def validate_fix(
    findings: Finding | Iterable[Finding],
    recheck: Callable[[Finding], bool] | None = None,
) -> list[ValidationResult]:
    if isinstance(findings, Finding):
        findings = [findings]
    results: list[ValidationResult] = []
    for finding in findings:
        passed = bool(recheck(finding)) if recheck is not None else False
        results.append(ValidationResult(
            finding_id=finding.id,
            passed=passed,
            evidence={"recheck": "passed" if passed else "failed"},
        ))
    return results
