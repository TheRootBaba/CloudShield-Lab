"""Safe, offline attack-scenario simulator. Emits synthetic CloudTrail-shaped events only."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from typing import Any

SCENARIOS = {
 "iam-policy-escalation": "A privileged identity policy is attached (synthetic event).",
 "public-s3-policy": "A bucket policy grants public object reads (synthetic event).",
 "public-admin-ingress": "A security group exposes SSH to the internet (synthetic event).",
 "multi-stage-compromise": "A synthetic sequence links privilege change, credential creation, audit disruption and public network exposure.",
}
def _common(stamp, actor="SYNTHETIC:operator"):
    return {"eventTime":stamp,"awsRegion":"us-east-1","recipientAccountId":"000000000000","sourceIPAddress":"198.51.100.42",
        "userIdentity":{"type":"IAMUser","principalId":actor,"arn":"arn:aws:iam::000000000000:user/lab-operator"}}
def _event_id(name, stamp, index=1):
    return f"sim-{name}-{sha256(stamp.encode()).hexdigest()[:8]}-{index:02d}"
def simulate(name: str, at: str|None=None) -> dict[str,Any]:
    if name not in SCENARIOS: raise ValueError(f"Unknown scenario {name!r}; choose from: {', '.join(SCENARIOS)}")
    stamp=at or datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
    if name == "multi-stage-compromise":
        base=datetime.fromisoformat(stamp.replace("Z","+00:00"))
        specs=[
          ("iam.amazonaws.com","AttachUserPolicy",{"userName":"lab-operator","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}),
          ("iam.amazonaws.com","CreateAccessKey",{"userName":"lab-operator","accessKeyId":"SYNTHETIC-KEY"}),
          ("cloudtrail.amazonaws.com","StopLogging",{"name":"organization-trail"}),
          ("ec2.amazonaws.com","AuthorizeSecurityGroupIngress",{"groupId":"sg-synthetic","ipPermissions":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":[{"cidrIp":"0.0.0.0/0"}]}]}),
        ]
        events=[]
        for index,(source,event_name,params) in enumerate(specs,1):
            event_time=(base+timedelta(minutes=(index-1)*3)).isoformat().replace("+00:00","Z")
            events.append({**_common(event_time),"eventID":_event_id(name,stamp,index),"eventSource":source,"eventName":event_name,"requestParameters":params})
    elif name == "iam-policy-escalation":
        events=[{**_common(stamp),"eventID":_event_id(name,stamp),"eventSource":"iam.amazonaws.com","eventName":"AttachUserPolicy","requestParameters":{"userName":"lab-operator","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}}]
    elif name == "public-s3-policy":
        events=[{**_common(stamp),"eventID":_event_id(name,stamp),"eventSource":"s3.amazonaws.com","eventName":"PutBucketPolicy","requestParameters":{"bucketName":"cloudshield-lab-synthetic","policyDocument":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::cloudshield-lab-synthetic/*"}]}}}]
    else:
        events=[{**_common(stamp),"eventID":_event_id(name,stamp),"eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","requestParameters":{"groupId":"sg-synthetic","ipPermissions":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":[{"cidrIp":"0.0.0.0/0"}]}]}}]
    for event in events:
        event["cloudshield_lab"]={"execution":"offline-synthetic","scenario":name}
    return {"scenario":name,"description":SCENARIOS[name],"execution":"offline-synthetic","cloud_api_calls":0,"events":events}
def simulate_all() -> dict[str,Any]:
    return {"execution":"offline-synthetic","cloud_api_calls":0,"scenarios":[simulate(n) for n in SCENARIOS]}