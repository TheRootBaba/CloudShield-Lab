# Detection coverage and limitations

This inventory describes implemented event-pattern rules. It is not a statement of exhaustive AWS threat coverage. Rule behavior depends on expected CloudTrail request fields being present.

| Rule | Service | Event patterns | Intent |
|---|---|---|---|
| CS-IAM-001 | IAM | PutRolePolicy, AttachRolePolicy, PutUserPolicy, AttachUserPolicy, CreatePolicyVersion, SetDefaultPolicyVersion, UpdateAssumeRolePolicy | Permission/trust mutation |
| CS-IAM-002 | IAM | CreateAccessKey, CreateLoginProfile, UpdateLoginProfile | Credential lifecycle change |
| CS-IAM-003 | Sign-in | Root ConsoleLogin success | Root console use |
| CS-S3-001 | S3 | PutBucketPolicy | Wildcard public principal in bucket policy |
| CS-S3-002 | S3 | PutBucketAcl | AllUsers / AuthenticatedUsers ACL grant |
| CS-NET-001 | EC2 | AuthorizeSecurityGroupIngress | Public SSH, RDP or all-protocol ingress |
| CS-NET-002 | EC2 | AuthorizeSecurityGroupIngress | Other public IPv4/IPv6 ingress |
| CS-CT-001 | CloudTrail | StopLogging, DeleteTrail, UpdateTrail | Audit trail disruption/change |
| CS-KMS-001 | KMS | DisableKey, ScheduleKeyDeletion | Key availability/destruction risk |
| CS-EC2-001 | EC2 | ModifySnapshotAttribute | EBS snapshot shared with all |
| CS-LAMBDA-001 | Lambda | AddPermission | Wildcard Lambda invocation principal |
| CS-RDS-001 | RDS | ModifyDBSnapshotAttribute | RDS snapshot shared with all |
| CS-SH-001 | Security Hub | Imported finding records | Provider finding normalization |

## Validation status

- Curated ATT&CK references are attached to selected rules; mappings are coverage hypotheses, not proof of technique execution.
- The Phase 11 evaluation corpus includes 26 hand-labelled positive/negative event shapes. All 26 currently pass against the 13 catalogued rules.
- Fixture-only metrics are perfect on this small corpus by construction and must not be represented as production precision, recall or accuracy.

## Known blind spots

- No exhaustive service coverage, suppression tuning, behavioral baselines, anomaly detection, threat intelligence or production false-positive measurement.
- No complete IAM privilege graph, effective-permission evaluation, network reachability analysis or cloud configuration scanner.
- Some rules depend on exact CloudTrail request parameter shapes. New AWS API versions and alternate wrappers require fixture coverage.
- No multi-account organization discovery or broad data-plane event coverage.
- No automatic response or remediation.

Add independently labelled fixtures and tests before describing a rule as production-ready. A clean scan means only that the currently enabled rules did not match the ingested records.
