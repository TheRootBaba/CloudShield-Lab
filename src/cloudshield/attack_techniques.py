"""Curated MITRE ATT&CK mappings for CloudShield's selected detections.

Mappings are intentionally conservative and reviewed as hypotheses about technique
coverage, not proof that a technique occurred.
"""
from __future__ import annotations

RULE_TECHNIQUES = {
    "CS-IAM-001": [{"id": "T1098", "name": "Account Manipulation", "url": "https://attack.mitre.org/techniques/T1098/"}],
    "CS-IAM-002": [{"id": "T1098.001", "name": "Additional Cloud Credentials", "url": "https://attack.mitre.org/techniques/T1098/001/"}],
    "CS-IAM-003": [{"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts", "url": "https://attack.mitre.org/techniques/T1078/004/"}],
    "CS-S3-001": [],
    "CS-S3-002": [],
    "CS-NET-001": [],
    "CS-NET-002": [],
    "CS-CT-001": [{"id": "T1562.008", "name": "Disable Cloud Logs", "url": "https://attack.mitre.org/techniques/T1562/008/"}],
    "CS-KMS-001": [],
    "CS-EC2-001": [],
    "CS-LAMBDA-001": [],
    "CS-RDS-001": [],
    "CS-SH-001": [],
    "CS-AZ-IAM-001": [{"id": "T1098.003", "name": "Additional Cloud Roles", "url": "https://attack.mitre.org/techniques/T1098/003/"}],
    "CS-AZ-AUDIT-001": [{"id": "T1562.008", "name": "Disable Cloud Logs", "url": "https://attack.mitre.org/techniques/T1562/008/"}],
    "CS-AZ-NET-001": [],
    "CS-AZ-STO-001": [],
    "CS-AZ-GOV-001": [],
    "CS-AZ-KV-001": [],
}

def techniques_for_rule(rule_id: str) -> list[dict]:
    """Return a copy so callers cannot mutate the curated mapping."""
    return [dict(item) for item in RULE_TECHNIQUES.get(rule_id, [])]

def catalog() -> list[dict]:
    from .detector import RULE_CATALOG
    return [{**rule, "attack_techniques": techniques_for_rule(rule["id"])} for rule in RULE_CATALOG]
