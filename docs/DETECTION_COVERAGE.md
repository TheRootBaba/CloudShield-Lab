# Detection coverage and limitations

This inventory describes implemented event-pattern rules across AWS and Azure. It is not a statement of exhaustive cloud threat coverage. Rule behavior depends on provider event fields being present.

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
| CS-AZ-IAM-001 | Azure Activity Log | Microsoft.Authorization/roleAssignments/write | Azure RBAC role assignment mutation |
| CS-AZ-AUDIT-001 | Azure Activity Log | Microsoft.Insights/diagnosticSettings/delete | Diagnostic/audit export setting deletion |
| CS-AZ-NET-001 | Azure Activity Log | Microsoft.Network/networkSecurityGroups/securityRules/write | Internet source to SSH/RDP/all ports |
| CS-AZ-STO-001 | Azure Activity Log | Microsoft.Storage/storageAccounts/write | Anonymous blob access setting enabled |
| CS-AZ-GOV-001 | Azure Activity Log | Microsoft.Authorization/policyAssignments/delete | Governance policy assignment removed |
| CS-AZ-KV-001 | Azure Activity Log | Microsoft.KeyVault/vaults/write | Key Vault network ACL default action set to Allow |

## Validation status

- Curated ATT&CK references are attached to selected rules; mappings are coverage hypotheses, not proof of technique execution.
- The current evaluation corpus includes 40 hand-labelled AWS/Azure positive/negative event shapes. All 40 currently pass against the 19 catalogued rules.
- Fixture-only metrics are perfect on this small corpus by construction and must not be represented as production precision, recall or accuracy.

## Known blind spots

- No exhaustive service coverage, suppression tuning, behavioral baselines, anomaly detection, threat intelligence or production false-positive measurement.
- No complete IAM privilege graph, effective-permission evaluation, network reachability analysis or cloud configuration scanner.
- Some rules depend on exact CloudTrail request parameter shapes. New AWS API versions and alternate wrappers require fixture coverage.
- Azure coverage is limited to subscription ARM resource metadata and Activity Logs; no Defender for Cloud alerts, Entra ID sign-in/audit events, data-plane logs or management-group discovery.
- No multi-account organization discovery or broad data-plane event coverage.
- No automatic response or remediation.

Add independently labelled fixtures and tests before describing a rule as production-ready. A clean scan means only that the currently enabled rules did not match the ingested records.
