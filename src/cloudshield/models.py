from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable


def _json_dict(value: dict[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items()}


@dataclass
class Change:
    address: str
    action: str
    type: str
    after: dict[str, Any] = field(default_factory=dict)
    before: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    resource: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Remediation:
    finding_id: str
    action: str
    target: str
    approved: bool = False
    applied: bool = False
    dry_run: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationResult:
    finding_id: str
    passed: bool
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
