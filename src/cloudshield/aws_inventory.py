"""Explicitly enabled, bounded, read-only AWS resource inventory."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

_REGION = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-\d$")
MAX_REGIONS = 5
MAX_PAGES = 2


def _pages(client, operation: str, result_key: str, max_pages: int, **params):
    records = []
    token = None
    pages = 0
    truncated = False
    while pages < max_pages:
        request = dict(params)
        if token:
            request["NextToken"] = token
        response = getattr(client, operation)(**request)
        pages += 1
        records.extend(response.get(result_key, []))
        token = response.get("NextToken")
        if not token:
            break
    else:
        truncated = bool(token)
    return records, pages, truncated


def _iam_pages(client, operation: str, result_key: str, max_pages: int):
    records = []
    marker = None
    pages = 0
    truncated = False
    while pages < max_pages:
        request = {"MaxItems": 1000}
        if marker:
            request["Marker"] = marker
        response = getattr(client, operation)(**request)
        pages += 1
        records.extend(response.get(result_key, []))
        marker = response.get("Marker")
        if not response.get("IsTruncated"):
            break
    else:
        truncated = bool(marker)
    return records, pages, truncated


def collect_inventory(regions: list[str], max_pages: int = 1, session=None) -> dict[str, Any]:
    """Collect names and metadata only; never creates, modifies or deletes AWS resources."""
    if not isinstance(regions, list) or not regions:
        raise ValueError("At least one explicit AWS region is required")
    if len(regions) > MAX_REGIONS or len(set(regions)) != len(regions):
        raise ValueError(f"Provide 1-{MAX_REGIONS} unique regions")
    if any(not isinstance(region, str) or not _REGION.fullmatch(region) for region in regions):
        raise ValueError("One or more AWS region identifiers are invalid")
    if not isinstance(max_pages, int) or not 1 <= max_pages <= MAX_PAGES:
        raise ValueError(f"max_pages must be between 1 and {MAX_PAGES}")
    if session is None:
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("AWS inventory requires boto3. Install with: pip install -e .[aws]") from exc
        session = boto3.Session()

    calls = 0
    truncated = False
    resources = []
    permissions = {
        "ec2": ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"],
        "s3": ["s3:ListAllMyBuckets"],
        "iam": ["iam:ListRoles", "iam:ListUsers"],
    }
    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        instances, count, cut = _pages(ec2, "describe_instances", "Reservations", max_pages, MaxResults=1000)
        calls += count
        truncated = truncated or cut
        for reservation in instances:
            for instance in reservation.get("Instances", []):
                resources.append({
                    "resource_type": "ec2-instance",
                    "resource_id": instance.get("InstanceId"),
                    "region": region,
                    "state": (instance.get("State") or {}).get("Name"),
                    "instance_type": instance.get("InstanceType"),
                    "vpc_id": instance.get("VpcId"),
                    "subnet_id": instance.get("SubnetId"),
                    "private_ip": instance.get("PrivateIpAddress"),
                    "public_ip": instance.get("PublicIpAddress"),
                    "security_group_ids": sorted(g.get("GroupId", "") for g in instance.get("SecurityGroups", []) if g.get("GroupId")),
                    "name": next((tag.get("Value") for tag in instance.get("Tags", []) if tag.get("Key") == "Name"), None),
                })
        groups, count, cut = _pages(ec2, "describe_security_groups", "SecurityGroups", max_pages, MaxResults=1000)
        calls += count
        truncated = truncated or cut
        for group in groups:
            resources.append({
                "resource_type": "security-group",
                "resource_id": group.get("GroupId"),
                "region": region,
                "name": group.get("GroupName"),
                "description": group.get("Description"),
                "vpc_id": group.get("VpcId"),
                "inbound_rule_count": len(group.get("IpPermissions", [])),
                "outbound_rule_count": len(group.get("IpPermissionsEgress", [])),
            })

    s3 = session.client("s3")
    bucket_response = s3.list_buckets(MaxBuckets=1000)
    calls += 1
    truncated = truncated or bool(bucket_response.get("IsTruncated"))
    for bucket in bucket_response.get("Buckets", []):
        resources.append({
            "resource_type": "s3-bucket",
            "resource_id": bucket.get("Name"),
            "created_at": bucket.get("CreationDate").isoformat() if bucket.get("CreationDate") else None,
            "region": "global-location-not-enumerated",
        })

    iam = session.client("iam")
    roles, count, cut = _iam_pages(iam, "list_roles", "Roles", max_pages)
    calls += count
    truncated = truncated or cut
    for role in roles:
        resources.append({
            "resource_type": "iam-role",
            "resource_id": role.get("Arn"),
            "name": role.get("RoleName"),
            "created_at": role.get("CreateDate").isoformat() if role.get("CreateDate") else None,
        })
    users, count, cut = _iam_pages(iam, "list_users", "Users", max_pages)
    calls += count
    truncated = truncated or cut
    for user in users:
        resources.append({
            "resource_type": "iam-user",
            "resource_id": user.get("Arn"),
            "name": user.get("UserName"),
            "created_at": user.get("CreateDate").isoformat() if user.get("CreateDate") else None,
        })

    return {
        "inventory_version": "1.0",
        "execution": "live-read-only",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "regions_requested": list(regions),
        "resources": resources,
        "resource_count": len(resources),
        "api_calls": calls,
        "truncated": truncated,
        "complete": False,
        "permissions_required": permissions,
        "limitations": [
            "This is a bounded inventory of EC2 instances/security groups, S3 bucket names, IAM role names and IAM user names only.",
            "S3 bucket regions, policies, ACLs, objects, effective IAM permissions and organization-wide account discovery are not queried.",
            "A truncated response is incomplete; even an untruncated response is not a complete AWS asset or configuration inventory.",
            "No AWS resource creation, modification or deletion APIs are called.",
        ],
    }
