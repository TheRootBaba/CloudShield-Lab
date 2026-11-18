# Phase 7 — Detection validation & ATT&CK alignment

## Implemented
- Curated MITRE ATT&CK technique references attached to selected rule IDs.
- Rule catalog and findings expose ATT&CK metadata; detection cards link to technique references.
- Positive detection, negative boundary and adversarial fixture tests validate expected behavior.
- Mappings are intentionally sparse. Configuration/exposure findings that do not demonstrate technique execution remain unmapped.

## Validation
The fixture suite checks expected behavior against handcrafted examples, not real-world prevalence. It does not measure production false-positive or false-negative rates. Mapping references should be reviewed when rules or ATT&CK versions change.

## Scope limits
Detection logic remains selected CloudTrail request-pattern checks, not behavior analytics or comprehensive ATT&CK coverage. No live cloud telemetry or production tuning was performed.
