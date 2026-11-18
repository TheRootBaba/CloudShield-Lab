# Phase 11 — detection evaluation harness

## What is included
- `fixtures/detection_evaluation.json` contains 26 hand-labelled positive/negative event-shape cases.
- All 13 catalogued rules are represented by at least one positive case; negative cases exercise nearby benign or non-matching conditions.
- `cloudshield evaluate` produces per-case match results and per-rule plus micro-averaged TP/FP/FN/TN, precision, recall, specificity and F1.
- CI runs the evaluation module's regression tests through the Python test suite.

## Run
```powershell
python -m cloudshield.cli evaluate fixtures/detection_evaluation.json
python -m cloudshield.cli evaluate fixtures/detection_evaluation.json --output artifacts/detection-evaluation-report.json
```

## Current fixture result
- 26 / 26 cases pass.
- 13 / 13 expected rule matches.
- Fixture micro precision, recall, specificity and F1 are each 1.0000.

## Important interpretation
These values describe only this curated deterministic fixture corpus. The fixtures are not sampled from production, do not reflect real base rates, and do not establish operational false-positive or false-negative rates. Expand the corpus with independently labelled, representative telemetry before using metrics to tune or claim real-world accuracy.
