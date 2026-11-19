"""Small, dependency-free API security primitives for the single-process local service."""
from __future__ import annotations

import hmac
import os
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] >= self.window_seconds:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


def configured_tokens() -> dict[str, str]:
    tokens = {}
    for role, variable in (("admin", "CLOUDSHIELD_ADMIN_TOKEN"), ("responder", "CLOUDSHIELD_RESPONDER_TOKEN"), ("analyst", "CLOUDSHIELD_ANALYST_TOKEN")):
        token = os.environ.get(variable, "")
        if token:
            if len(token) < 32:
                raise RuntimeError(f"{variable} must contain at least 32 characters")
            tokens[role] = token
    if len(set(tokens.values())) != len(tokens):
        raise RuntimeError("Each configured role token must be unique")
    return tokens


def authenticate(header: str | None) -> str | None:
    tokens = configured_tokens()
    if not tokens:
        return "local"
    if not isinstance(header, str) or not header.startswith("Bearer "):
        return None
    supplied = header[7:]
    for role, expected in tokens.items():
        if hmac.compare_digest(supplied, expected):
            return role
    return None


def role_allowed(role: str, method: str, path: str) -> bool:
    if role == "local":
        return True
    if method == "GET":
        return True
    if method == "POST" and path == "/api/evidence/verify":
        return True
    if path == "/api/collector/aws":
        return role == "admin"
    return role in {"admin", "responder"}


def audit(path: str | Path, actor: str, action: str, resource: str, remote: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(target))
    try:
        db.execute("""CREATE TABLE IF NOT EXISTS security_audit (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            occurred_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            remote_address TEXT NOT NULL
        )""")
        db.execute("INSERT INTO security_audit(occurred_at,actor,action,resource,remote_address) VALUES(?,?,?,?,?)",
                   (datetime.now(timezone.utc).isoformat(), actor, action, resource[:300], remote[:80]))
        db.commit()
    finally:
        db.close()
