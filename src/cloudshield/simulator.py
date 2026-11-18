"""Safe, offline attack-scenario simulator. Emits synthetic CloudTrail-shaped events only."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

SCENARIOS={
 "iam-policy-escalation":"A privileged identity policy is attached (synthetic event).",
 "public-s3-policy":"A bucket policy grants public object reads (synthetic event).",
 "public-admin-ingress":"A security group exposes SSH to the internet (synthetic event).",
}
def simulate(name: str, at: str|None=None) -> dict[str,Any]:
    if name not in SCENARIOS: raise ValueError(f"Unknown scenario {name!r}; choose from: {', '.join(SCENARIOS)}")
    stamp=at or datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
    common={"eventTime":stamp,"awsRegion":"us-east-1","recipientAccountId":"000000000000","sourceIPAddress":"198.51.100.42","userIdentity":{"type":"IAMUser","principalId":"SYNTHETIC:operator","arn":"arn:aws:iam::000000000000:user/lab-operator"}}
    if name=="iam-policy-escalation":
        row={**common,"eventID":"sim-iam-001","eventSource":"iam.amazonaws.com","eventName":"AttachUserPolicy","requestParameters":{"userName":"lab-operator","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}}
    elif name=="public-s3-policy":
        row={**common,"eventID":"sim-s3-001","eventSource":"s3.amazonaws.com","eventName":"PutBucketPolicy","requestParameters":{"bucketName":"cloudshield-lab-synthetic","policyDocument":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::cloudshield-lab-synthetic/*"}]}}}
    else:
        row={**common,"eventID":"sim-net-001","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","requestParameters":{"groupId":"sg-synthetic","ipPermissions":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":[{"cidrIp":"0.0.0.0/0"}]}]}}
    return {"scenario":name,"description":SCENARIOS[name],"execution":"offline-synthetic","cloud_api_calls":0,"events":[row]}
def simulate_all() -> dict[str,Any]:
    return {"execution":"offline-synthetic","cloud_api_calls":0,"scenarios":[simulate(n) for n in SCENARIOS]}
