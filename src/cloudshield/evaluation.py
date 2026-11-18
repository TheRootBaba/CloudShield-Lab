"""Deterministic detection evaluation against explicitly labelled fixtures.

Metrics describe only the supplied corpus. They are not estimates of production
false-positive or false-negative rates.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .detector import RULE_CATALOG, analyze_event
from .events import CloudEvent


def evaluate_cases(cases: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(cases, list) or not cases:
        raise ValueError("Evaluation corpus must be a non-empty list")
    rule_ids = [str(rule["id"]) for rule in RULE_CATALOG]
    counts = {rule_id: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for rule_id in rule_ids}
    case_results = []
    seen_ids = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"Case {index} must be an object")
        case_id = str(case.get("id", "")).strip()
        if not case_id or case_id in seen_ids:
            raise ValueError(f"Case {index} has a missing or duplicate id")
        seen_ids.add(case_id)
        label = case.get("label")
        if label not in {"positive", "negative"}:
            raise ValueError(f"Case {case_id} label must be positive or negative")
        event = case.get("event")
        if not isinstance(event, dict):
            raise ValueError(f"Case {case_id} event must be an object")
        raw_expected = case.get("expected_rule_ids", [])
        if not isinstance(raw_expected, list) or any(not isinstance(item, str) for item in raw_expected):
            raise ValueError(f"Case {case_id} expected_rule_ids must be a list of strings")
        expected = set(raw_expected)
        unknown = expected - set(rule_ids)
        if unknown:
            raise ValueError(f"Case {case_id} contains unknown expected rules: {sorted(unknown)}")
        predicted = {finding.rule_id for finding in analyze_event(CloudEvent.from_dict(event))}
        # Each fixture labels all catalogued rules for that event as positive or negative.
        if label == "negative" and expected:
            raise ValueError(f"Negative case {case_id} cannot declare expected rules")
        if label == "positive" and not expected:
            raise ValueError(f"Positive case {case_id} must declare expected rules")
        for rule_id in rule_ids:
            actual = rule_id in expected
            found = rule_id in predicted
            key = "tp" if actual and found else "fn" if actual else "fp" if found else "tn"
            counts[rule_id][key] += 1
        missed = sorted(expected - predicted)
        unexpected = sorted(predicted - expected)
        case_results.append({
            "id": case_id,
            "label": label,
            "expected_rule_ids": sorted(expected),
            "predicted_rule_ids": sorted(predicted),
            "missed_rule_ids": missed,
            "unexpected_rule_ids": unexpected,
            "pass": not missed and not unexpected,
        })

    per_rule = {}
    totals = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for rule_id, values in counts.items():
        tp, fp, fn, tn = (values[k] for k in ("tp", "fp", "fn", "tn"))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        specificity = tn / (tn + fp) if tn + fp else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_rule[rule_id] = {
            **values,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "f1": round(f1, 4),
        }
        for key in totals:
            totals[key] += values[key]
    tp, fp, fn, tn = (totals[k] for k in ("tp", "fp", "fn", "tn"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "evaluation_version": "1.0",
        "corpus_scope": "curated deterministic fixtures only; not representative production telemetry",
        "case_count": len(cases),
        "rule_count": len(rule_ids),
        "case_pass_count": sum(1 for item in case_results if item["pass"]),
        "case_fail_count": sum(1 for item in case_results if not item["pass"]),
        "micro_average": {
            **totals,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "f1": round(f1, 4),
        },
        "per_rule": per_rule,
        "cases": case_results,
        "limitations": [
            "Labels are hand-authored and cover only selected event shapes.",
            "Fixture metrics do not estimate production false-positive or false-negative rates.",
            "A negative fixture is not proof that an event is benign in every context.",
        ],
    }


def evaluate_file(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read evaluation corpus: {exc}") from exc
    if isinstance(payload, dict):
        payload = payload.get("cases")
    return evaluate_cases(payload)
