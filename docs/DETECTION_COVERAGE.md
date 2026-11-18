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

## Known blind spots

- No exhaustive service coverage, ATT&CK mapping validation, suppression tuning, detection-as-code corpus or production false-positive measurement.
- No complete IAM privilege graph, effective-permission evaluation, asset inventory, network reachability analysis or cloud configuration scanner.
- Some rules depend on exact CloudTrail request parameter shapes. New AWS API versions and alternate wrappers require fixture coverage.
- No behavioral baselines, anomaly detection, threat intelligence, identity risk scoring, multi-account organization discovery or data-plane event coverage.
- No automatic response or remediation.

Add fixtures and tests before describing a rule as production-ready. A clean scan means only that the currently enabled rules did not match the ingested records.