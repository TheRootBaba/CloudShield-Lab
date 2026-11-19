# Detection evaluation methodology

## Scope

The versioned fixture corpus (`fixtures/detection_evaluation.json`) labels positive and negative AWS/Azure provider event shapes for the 15 catalogued detection rules. Evaluation is deterministic and reports per-rule and micro-averaged TP/FP/FN/TN, precision, recall, specificity and F1. Every rule change must add or update a positive, negative and relevant adversarial fixture before merge.

## Reproduction

```powershell
cloudshield evaluate fixtures/detection_evaluation.json --output artifacts/detection-evaluation-report.json
python -m unittest discover -s tests -v
```

The current corpus is a hand-authored regression set, not a random sample. Its 30/30 pass result and 1.0 fixture metrics must never be presented as production precision/recall. The sample does not estimate prevalence, base rates, analyst disposition, alert fatigue, cross-account drift or missed data-plane activity.

## Robustness coverage

- Duplicate event IDs are normalized to unambiguous identifiers and tested in correlation.
- Missing/malformed timeline values are handled without asserting unsupported edges.
- Out-of-order timestamps are sorted before relationship construction; time gaps over 24 hours are not linked.
- Private IPv4/IPv6 ingress, private bucket policies and denied policy statements are negative/adversarial cases.
- Bundle verification covers duplicate/missing/unreferenced events and digest changes.

## Severity and confidence semantics

Severity remains a rule/provider classification, not a calibrated loss estimate. CRITICAL indicates a potentially high-impact exposure or key/snapshot condition; HIGH indicates material identity, audit or configuration change; provider-imported severity is retained only when recognized. Analysts must validate effective resource state, business context and compensating controls.

Each finding now includes `confidence` and `confidence_rationale`. HIGH means the event payload contains a comparatively explicit indicator (for example, a wildcard public principal or successful root login); MEDIUM means an event-name/provider signal requires more context. Confidence is a deterministic evidence-strength tier, not a probability, statistical calibration or guarantee that compromise occurred. The rationale explicitly requires contextual review.

## Real-world label process (future gate)

When independently approved telemetry becomes available: preserve raw source records; de-identify only with documented transformation; have two reviewers independently label rule applicability and severity; adjudicate disagreements; record source coverage and sampling method; separate tuning and holdout periods; version the corpus and label guide; report per-rule metrics with confidence intervals and class prevalence; monitor drift; and retain false-positive/false-negative case reviews. Do not mix synthetic and production metrics.


Azure-specific regression cases now include RBAC role-assignment writes and diagnostic-setting deletion, with benign read/write cases to reduce obvious false positives. These are event-pattern rules; they do not validate effective Azure permissions or prove that log export has actually stopped.
