# Threat model (initial)

## Purpose

CloudShield Lab is a defensive learning environment for validating detections against cloud audit events. The initial implementation processes local, synthetic JSON fixtures only.

## Assets to protect

- Integrity of detection rules and test fixtures.
- Confidentiality of any future imported audit logs.
- Integrity of any future remediation actions.
- Availability and cost boundaries of any optional cloud sandbox.

## Threats considered

- A privileged identity changes a role or user policy to expand access.
- A bucket policy accidentally or deliberately grants public read access.
- A security-group change exposes SSH/RDP or all protocols to the internet.
- A future remediation routine makes an unsafe change or acts on the wrong resource.
- Sensitive account identifiers, tokens or production logs are accidentally committed.

## Safety controls

- Synthetic account IDs, IP addresses and resource names in committed fixtures.
- No AWS credentials or cloud API calls in the initial release.
- No automatic remediation in the initial release.
- Future remediation must use explicit allowlists, dry-run mode, approval, audit logging and rollback design.
- Secrets and raw customer logs must never be committed.

## Limitations

The current rules are demonstrations, not a complete threat-detection system. An IAM policy change may be legitimate; public access may be intentional; network exposure needs business context. Findings require human investigation.
