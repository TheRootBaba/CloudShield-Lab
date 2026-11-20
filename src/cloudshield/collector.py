"""Opt-in, read-only AWS CloudTrail LookupEvents collector."""
from __future__ import annotations
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

def collect_cloudtrail(region: str = "us-east-1", lookback_minutes: int = 60, max_pages: int = 5, session=None) -> dict[str, Any]:
    if not 1 <= int(lookback_minutes) <= 1440:
        raise ValueError("lookback_minutes must be between 1 and 1440")
    if not 1 <= int(max_pages) <= 20:
        raise ValueError("max_pages must be between 1 and 20")
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-\d", region):
        raise ValueError("Invalid AWS region identifier")
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise RuntimeError("AWS collector dependency missing. Install with: pip install -e .[aws]") from exc
    now = datetime.now(timezone.utc)
    client = (session or boto3).client("cloudtrail", region_name=region, config=Config(retries={"mode":"standard", "total_max_attempts":4}))
    events = []
    token = None
    seen_tokens = set()
    pages = 0
    partial_failures = []
    while pages < max_pages:
        params = {
            "StartTime": now - timedelta(minutes=int(lookback_minutes)),
            "EndTime": now,
            "MaxResults": 50,
        }
        if token:
            params["NextToken"] = token
        try:
            response = client.lookup_events(**params)
        except Exception as exc:
            partial_failures.append({"operation":"lookup_events", "type":type(exc).__name__, "message":str(exc)[:500]})
            break
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
        if token in seen_tokens:
            partial_failures.append({"operation":"lookup_events", "type":"RepeatedContinuationToken", "message":"Provider repeated a continuation token; pagination stopped safely."})
            break
        seen_tokens.add(token)
    truncated = bool(token and pages >= max_pages)
    return {
        "source": "aws-cloudtrail",
        "execution": "live-read-only",
        "region": region,
        "lookback_minutes": int(lookback_minutes),
        "pages_read": pages,
        "events": events,
        "cloud_api_calls": pages,
        "api_call_count_semantics":"successful logical SDK page operations; internal botocore retry attempts are not counted",
        "retry_policy":"botocore standard mode with total_max_attempts=4",
        "truncated": truncated,
        "partial_failures": partial_failures,
        "complete": not truncated and not partial_failures,
        "permissions_required": ["cloudtrail:LookupEvents"],
    }