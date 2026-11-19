"""Explainable cloud audit detections. Rules are explicit, versioned and intentionally conservative."""
from dataclasses import asdict, dataclass
from typing import Any
from .events import CloudEvent

@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    rationale: str
    event_id: str
    event_time: str
    actor: str
    source_ip: str
    evidence: dict[str, Any]
    confidence: str = "MEDIUM"
    confidence_rationale: str = "The event pattern matched a documented rule; contextual validation is still required."
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

RULE_CATALOG = [
 {"id":"CS-IAM-001","title":"IAM trust or permission policy modified","severity":"HIGH","service":"IAM","events":["PutRolePolicy","AttachRolePolicy","PutUserPolicy","AttachUserPolicy","CreatePolicyVersion","SetDefaultPolicyVersion","UpdateAssumeRolePolicy"],"description":"Identity permissions or trust relationships changed."},
 {"id":"CS-IAM-002","title":"New IAM credential or console password created","severity":"HIGH","service":"IAM","events":["CreateAccessKey","CreateLoginProfile","UpdateLoginProfile"],"description":"A potentially persistent authentication method was created or changed."},
 {"id":"CS-IAM-003","title":"Root account console login succeeded","severity":"HIGH","service":"Sign-in","events":["ConsoleLogin"],"description":"Root account console access succeeded."},
 {"id":"CS-S3-001","title":"Bucket policy grants public access","severity":"CRITICAL","service":"S3","events":["PutBucketPolicy"],"description":"A bucket policy grants wildcard principal access."},
 {"id":"CS-S3-002","title":"Bucket ACL grants public access","severity":"HIGH","service":"S3","events":["PutBucketAcl"],"description":"An S3 ACL grants access to AllUsers or AuthenticatedUsers."},
 {"id":"CS-NET-001","title":"Administrative port exposed publicly","severity":"CRITICAL","service":"EC2","events":["AuthorizeSecurityGroupIngress"],"description":"SSH, RDP or all protocols are open to the internet."},
 {"id":"CS-NET-002","title":"Security group ingress open to the internet","severity":"HIGH","service":"EC2","events":["AuthorizeSecurityGroupIngress"],"description":"An ingress rule allows any IPv4/IPv6 source, regardless of port."},
 {"id":"CS-CT-001","title":"CloudTrail logging weakened or stopped","severity":"HIGH","service":"CloudTrail","events":["StopLogging","DeleteTrail","UpdateTrail"],"description":"Audit logging may have been disabled or redirected."},
 {"id":"CS-KMS-001","title":"KMS key disabled or scheduled for deletion","severity":"CRITICAL","service":"KMS","events":["DisableKey","ScheduleKeyDeletion"],"description":"Encryption key availability or recoverability may be impacted."},
 {"id":"CS-EC2-001","title":"EBS snapshot made public","severity":"CRITICAL","service":"EC2","events":["ModifySnapshotAttribute"],"description":"A snapshot permission may expose stored data publicly."},
 {"id":"CS-LAMBDA-001","title":"Lambda function permission granted to public principal","severity":"HIGH","service":"Lambda","events":["AddPermission"],"description":"A Lambda resource policy may allow invocation by any principal."},
 {"id":"CS-RDS-001","title":"RDS snapshot shared publicly","severity":"CRITICAL","service":"RDS","events":["ModifyDBSnapshotAttribute"],"description":"A database snapshot may have been shared with all AWS accounts."},
 {"id":"CS-SH-001","title":"AWS Security Hub finding imported","severity":"Provider","service":"Security Hub","events":["SecurityHubFinding"],"description":"Provider finding normalized into CloudShield."},
 {"id":"CS-AZ-IAM-001","title":"Azure role assignment changed","severity":"HIGH","service":"Azure RBAC","events":["Microsoft.Authorization/roleAssignments/write"],"description":"An Azure role assignment was created or updated; validate principal, role definition and scope."},
 {"id":"CS-AZ-AUDIT-001","title":"Azure Activity Log diagnostic settings deleted","severity":"HIGH","service":"Azure Monitor","events":["Microsoft.Insights/diagnosticSettings/delete"],"description":"A diagnostic setting was deleted; validate whether audit export coverage was weakened."},
]
IAM_MUTATION_EVENTS = set(RULE_CATALOG[0]["events"])
def _as_list(value):
    if value is None: return []
    return value if isinstance(value, list) else [value]
def _public_principal(value):
    if value == "*": return True
    if isinstance(value, dict):
        return any(v == "*" or (isinstance(v, list) and "*" in v) for v in value.values())
    return False
def _is_public_bucket_policy(params):
    import json
    policy = params.get("policyDocument")
    if isinstance(policy, str):
        try: policy = json.loads(policy)
        except (TypeError, ValueError): return False
    if not isinstance(policy, dict): return False
    for statement in _as_list(policy.get("Statement")):
        if not isinstance(statement, dict): continue
        actions = _as_list(statement.get("Action"))
        broad = any(a in ("*", "s3:*", "s3:GetObject", "s3:ListBucket") for a in actions)
        if statement.get("Effect", "Allow") == "Allow" and _public_principal(statement.get("Principal")) and broad:
            return True
    return False
def _permissions(params):
    return _as_list(params.get("ipPermissions") or params.get("ipPermissionsEgress"))
def _internet_open(permission):
    return (any(isinstance(x, dict) and x.get("cidrIp") == "0.0.0.0/0" for x in _as_list(permission.get("ipRanges"))) or
            any(isinstance(x, dict) and x.get("cidrIpv6") == "::/0" for x in _as_list(permission.get("ipv6Ranges"))))
def _admin_port(permission):
    protocol = str(permission.get("ipProtocol", ""))
    start, end = permission.get("fromPort"), permission.get("toPort")
    return protocol == "-1" or (isinstance(start, int) and isinstance(end, int) and
        ((start <= 22 <= end) or (start <= 3389 <= end)))
def _public_acl(params):
    policy = params.get("accessControlPolicy") or {}
    acl = policy.get("accessControlList") or {}
    for grant in _as_list(acl.get("grant")):
        grantee = grant.get("grantee") or {}
        uri = grantee.get("uri", "")
        if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"): return True
    return False
def _make(event, rule_id, title, severity, rationale, evidence):
    explicit = {"CS-S3-001", "CS-S3-002", "CS-NET-001", "CS-NET-002", "CS-KMS-001", "CS-EC2-001", "CS-LAMBDA-001", "CS-RDS-001", "CS-IAM-003"}
    confidence = "HIGH" if rule_id in explicit else "MEDIUM"
    explanation = ("The event contains an explicit public/exposure or successful-root-login indicator; validate the resource's effective state."
                  if confidence == "HIGH" else
                  "The event name or provider finding matches a documented signal; authorization, impact and surrounding context require analyst review.")
    return Finding(rule_id,title,severity,rationale,event.event_id,event.event_time,event.actor,event.source_ip,evidence,confidence,explanation)

def analyze_event(event: CloudEvent) -> list[Finding]:
    findings=[]
    source,name,params=event.event_source,event.event_name,event.request_parameters or {}
    if source == "azure.activitylogs":
        operation = name.lower()
        if operation.endswith("microsoft.authorization/roleassignments/write") or operation.endswith("/roleassignments/write"):
            findings.append(_make(event,"CS-AZ-IAM-001","Azure role assignment changed","HIGH",
                "An Azure RBAC role assignment was created or updated. Confirm the principal, role definition, scope, approval and resulting effective permissions.",
                {"operation":name,"resource_ids":list(event.resource_ids),"authorization":params.get("authorization",{}),"status":params.get("status")}))
        if operation.endswith("microsoft.insights/diagnosticsettings/delete") or operation.endswith("/diagnosticsettings/delete"):
            findings.append(_make(event,"CS-AZ-AUDIT-001","Azure Activity Log diagnostic settings deleted","HIGH",
                "A diagnostic setting was deleted. Verify whether subscription activity logs or resource logs have lost their export destination and restore approved coverage.",
                {"operation":name,"resource_ids":list(event.resource_ids),"status":params.get("status")}))
    if source == "securityhub.amazonaws.com" and name == "SecurityHubFinding":
        label=str(params.get("severity","UNKNOWN")).upper()
        mapped={"CRITICAL":"CRITICAL","HIGH":"HIGH","MEDIUM":"MEDIUM","LOW":"LOW","INFORMATIONAL":"INFO","INFO":"INFO"}.get(label)
        if mapped:
            findings.append(_make(event,"CS-SH-001",str(params.get("title") or "AWS Security Hub finding"),mapped,
                "Imported AWS Security Hub finding. Review the original provider context and affected resources.",
                {"source":"securityhub","severity_label":label,"types":params.get("types",[]),"resources":list(event.resource_ids)}))
    if source == "iam.amazonaws.com" and name in IAM_MUTATION_EVENTS:
        findings.append(_make(event,"CS-IAM-001","IAM trust or permission policy modified","HIGH",
            "An identity policy or role trust relationship changed. Validate the actor, change ticket, affected principal and resulting permissions.",
            {"event_name":name,"request_parameters":params}))
    if source == "iam.amazonaws.com" and name in {"CreateAccessKey","CreateLoginProfile","UpdateLoginProfile"}:
        findings.append(_make(event,"CS-IAM-002","New IAM credential or console password created","HIGH",
            "A new long-lived credential or console password was created or changed. Confirm the request was authorized and rotate unexpected credentials.",
            {"event_name":name,"request_parameters":params}))
    if source == "s3.amazonaws.com" and name == "PutBucketPolicy" and _is_public_bucket_policy(params):
        findings.append(_make(event,"CS-S3-001","Bucket policy grants access to a public principal","CRITICAL",
            "The policy allows a public principal to read objects or grants wildcard actions. Confirm whether public access is explicitly intended.",
            {"bucket_name":params.get("bucketName"),"policy_document":params.get("policyDocument")}))
    if source == "s3.amazonaws.com" and name == "PutBucketAcl" and _public_acl(params):
        findings.append(_make(event,"CS-S3-002","Bucket ACL grants public access","HIGH",
            "The bucket ACL contains an AllUsers or AuthenticatedUsers grant. Inspect object exposure and remove unintended grants.",
            {"bucket_name":params.get("bucketName"),"access_control_policy":params.get("accessControlPolicy")}))
    if source == "ec2.amazonaws.com" and name == "AuthorizeSecurityGroupIngress":
        exposed=[p for p in _permissions(params) if _internet_open(p)]
        admin=[p for p in exposed if _admin_port(p)]
        if admin:
            findings.append(_make(event,"CS-NET-001","Administrative port exposed to the public internet","CRITICAL",
                "An inbound security-group rule exposes SSH, RDP or all protocols to 0.0.0.0/0 or ::/0. Restrict the source to an approved management range.",
                {"group_id":params.get("groupId"),"ip_permissions":admin}))
        elif exposed:
            findings.append(_make(event,"CS-NET-002","Security group ingress open to the internet","HIGH",
                "An inbound security-group rule allows a public IPv4 or IPv6 source. Validate the port, protocol and business need.",
                {"group_id":params.get("groupId"),"ip_permissions":exposed}))
    if source == "cloudtrail.amazonaws.com" and name in {"StopLogging","DeleteTrail","UpdateTrail"}:
        findings.append(_make(event,"CS-CT-001","CloudTrail logging weakened or stopped","HIGH",
            "A trail was stopped, deleted or modified. Verify logging coverage and preserve independent audit evidence.",
            {"event_name":name,"request_parameters":params}))
    if source == "kms.amazonaws.com" and name in {"DisableKey","ScheduleKeyDeletion"}:
        findings.append(_make(event,"CS-KMS-001","KMS key disabled or scheduled for deletion","CRITICAL",
            "A KMS key state change may interrupt decryption or make protected data unrecoverable. Confirm key ownership and recovery procedures.",
            {"event_name":name,"request_parameters":params}))
    if source == "ec2.amazonaws.com" and name == "ModifySnapshotAttribute":
        values=params.get("createVolumePermission") or {}
        if any(str(x.get("group","")).lower()=="all" for x in _as_list(values.get("add")) if isinstance(x,dict)):
            findings.append(_make(event,"CS-EC2-001","EBS snapshot made public","CRITICAL",
                "The snapshot create-volume permission includes the all group. Treat the snapshot contents as potentially exposed.",
                {"snapshot_id":params.get("snapshotId"),"create_volume_permission":values}))
    if source == "lambda.amazonaws.com" and name == "AddPermission" and str(params.get("principal","")) == "*":
        findings.append(_make(event,"CS-LAMBDA-001","Lambda function permission granted to public principal","HIGH",
            "A Lambda resource policy was changed to allow a wildcard principal. Confirm the function is intentionally public and constrained by conditions.",
            {"function_name":params.get("functionName"),"principal":params.get("principal"),"action":params.get("action")}))
    if source == "rds.amazonaws.com" and name == "ModifyDBSnapshotAttribute":
        values=params.get("valuesToAdd") or []
        if any(str(v).lower()=="all" for v in _as_list(values)):
            findings.append(_make(event,"CS-RDS-001","RDS snapshot shared publicly","CRITICAL",
                "The snapshot attribute includes the all value, which can expose the snapshot to every AWS account.",
                {"snapshot_id":params.get("dBSnapshotIdentifier"),"values_to_add":values}))
    identity=(event.raw.get("userIdentity") or (event.raw.get("detail") or {}).get("userIdentity") or {})
    if identity.get("type") == "Root" and name == "ConsoleLogin":
        response=event.raw.get("responseElements") or {}
        if response.get("ConsoleLogin") == "Success":
            findings.append(_make(event,"CS-IAM-003","Root account console login succeeded","HIGH",
                "The AWS root identity signed in successfully. Confirm emergency access use and ensure root MFA and access controls are enforced.",
                {"user_identity_type":"Root","response_elements":response}))
    return findings