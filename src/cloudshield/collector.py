"""Opt-in, read-only AWS CloudTrail LookupEvents collector."""
from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone
from typing import Any

def collect_cloudtrail(region: str = "us-east-1", lookback_minutes: int = 60, max_pages: int = 5) -> dict[str, Any]:
    if not 1 <= int(lookback_minutes) <= 1440:
        raise ValueError("lookback_minutes must be between 1 and 1440")
    if not 1 <= int(max_pages) <= 20:
        raise ValueError("max_pages must be between 1 and 20")
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("AWS collector dependency missing. Install with: pip install -e .[aws]") from exc
    now = datetime.now(timezone.utc)
    client = boto3.client("cloudtrail", region_name=region)
    events = []
    token = None
    pages = 0
    while pages < max_pages:
        params = {
            "StartTime": now - timedelta(minutes=int(lookback_minutes)),
            "EndTime": now,
            "MaxResults": 50,
        }
        if token:
            params["NextToken"] = token
        response = client.lookup_events(**params)
        pages += 1
        for item in response.get("Events", []):
            raw = item.get("CloudTrailEvent")
            if not raw:
                continue
            try:
                event = json.loads(raw) if isinstance(raw, str) else raw
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(event, dict):
                events.append(event)
        token = response.get("NextToken")
        if not token:
            break
    return {
        "source": "aws-cloudtrail",
        "execution": "live-read-only",
        "region": region,
        "lookback_minutes": int(lookback_minutes),
        "pages_read": pages,
        "events": events,
        "cloud_api_calls": pages,
        "permissions_required": ["cloudtrail:LookupEvents"],
    }