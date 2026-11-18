"""CloudShield Lab public API."""

from .graph import AttackGraph, build_attack_graph, find_attack_paths
from .models import Change, Finding, Remediation, ValidationResult
from .pipeline import verify_change
from .remediation import apply_guarded_remediation, propose_remediation
from .telemetry import normalize_cloudtrail, normalize_security_hub
from .terraform import detect_risky_changes, parse_plan
from .validation import validate_fix

__all__ = [
    "AttackGraph",
    "Change",
    "Finding",
    "Remediation",
    "ValidationResult",
    "apply_guarded_remediation",
    "build_attack_graph",
    "detect_risky_changes",
    "find_attack_paths",
    "normalize_cloudtrail",
    "normalize_security_hub",
    "parse_plan",
    "propose_remediation",
    "validate_fix",
    "verify_change",
]
