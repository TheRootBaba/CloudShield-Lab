"""Multi-user browser authentication with tenant-isolated SQLite workspaces.

Passwords use scrypt; browser sessions are opaque, hashed server-side, expiring,
revocable and protected by SameSite cookies plus a synchronizer CSRF token.
Each tenant receives a separate evidence database file.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

SESSION_HOURS = 12
INVITE_HOURS = 24
PASSWORD_MIN = 12
ROLES = {"admin", "responder", "analyst"}


def _now():
    return datetime.now(timezone.utc)


def _stamp(value):
    return value.isoformat(timespec="seconds")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return "scrypt$16384$8$1$" + salt.hex() + "$" + digest.hex()


def _password_ok(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, expected = encoded.split("$")
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p), dklen=64)
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


@contextmanager
def _connect(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path), timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=10000")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@dataclass(frozen=True)
class Session:
    user_id: str
    tenant_id: str
    email: str
    display_name: str
    role: str
    csrf_token: str
    expires_at: str


class AuthStore:
    def __init__(self, path: str | Path, tenant_root: str | Path):
        self.path = Path(path)
        self.tenant_root = Path(tenant_root)
        self.tenant_root.mkdir(parents=True, exist_ok=True)
        with _connect(self.path) as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS tenants (
              tenant_id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
              user_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
              display_name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL,
              active INTEGER NOT NULL DEFAULT 1, failed_attempts INTEGER NOT NULL DEFAULT 0,
              locked_until TEXT, created_at TEXT NOT NULL,
              FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
            );
            CREATE TABLE IF NOT EXISTS sessions (
              session_hash TEXT PRIMARY KEY, csrf_hash TEXT NOT NULL, user_id TEXT NOT NULL,
              expires_at TEXT NOT NULL, created_at TEXT NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS invites (
              invite_hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, role TEXT NOT NULL,
              created_by TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT,
              FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
            );
            CREATE TABLE IF NOT EXISTS auth_audit (
              audit_id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
              actor_user_id TEXT, tenant_id TEXT, action TEXT NOT NULL, target TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
            """)
            db.commit()

    def bootstrap_required(self) -> bool:
        with _connect(self.path) as db:
            return db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0

    def register(self, email: str, display_name: str, password: str, tenant_name: str = "", invite: str = "") -> dict:
        if not isinstance(email, str) or not isinstance(display_name, str) or not isinstance(tenant_name, str):
            raise ValueError("Email, display name and workspace name must be text")
        email = email.strip().lower()
        display_name = display_name.strip()
        local_part, separator, domain = email.partition("@")
        if (len(email) > 254 or not separator or not local_part or len(local_part) > 64
                or not domain or "@" in domain or "." not in domain
                or domain.startswith(".") or domain.endswith(".")
                or any(character.isspace() for character in email)):
            raise ValueError("Enter a valid email address")
        if not display_name or len(display_name) > 80:
            raise ValueError("Display name must be 1–80 characters")
        if not isinstance(password, str) or len(password) < PASSWORD_MIN or len(password) > 256:
            raise ValueError(f"Password must be {PASSWORD_MIN}–256 characters")
        if invite is not None and not isinstance(invite, str):
            raise ValueError("Invitation code must be text")
        now = _now()
        user_id = secrets.token_urlsafe(18)
        with _connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                raise ValueError("An account with this email already exists")
            if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
                tenant_id = secrets.token_urlsafe(18)
                clean_tenant = str(tenant_name or "").strip()[:80] or (display_name + "'s workspace")
                db.execute("INSERT INTO tenants VALUES(?,?,?)", (tenant_id, clean_tenant, _stamp(now)))
                role = "admin"
            else:
                if not invite or len(invite) > 128:
                    raise PermissionError("A valid workspace invitation is required")
                invite_row = db.execute("SELECT * FROM invites WHERE invite_hash=? AND used_at IS NULL AND expires_at>?",
                                        (_hash(invite), _stamp(now))).fetchone()
                if not invite_row:
                    raise PermissionError("Invitation is invalid, expired or already used")
                tenant_id, role = invite_row["tenant_id"], invite_row["role"]
                changed = db.execute("UPDATE invites SET used_at=? WHERE invite_hash=? AND used_at IS NULL", (_stamp(now), _hash(invite))).rowcount
                if changed != 1:
                    raise PermissionError("Invitation has already been used")
            db.execute("INSERT INTO users(user_id,tenant_id,email,display_name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
                       (user_id, tenant_id, email, display_name, _password_hash(password), role, _stamp(now)))
            db.commit()
        self.tenant_path(tenant_id).parent.mkdir(parents=True, exist_ok=True)
        return {"user_id": user_id, "tenant_id": tenant_id, "email": email, "display_name": display_name, "role": role}

    def login(self, email: str, password: str) -> tuple[Session, str]:
        email = str(email or "").strip().lower()
        if len(email) > 254:
            email = ""
        # Bound attacker-controlled input before the deliberately expensive scrypt operation.
        password = password if isinstance(password, str) and len(password) <= 256 else ""
        now = _now()
        with _connect(self.path) as db:
            row = db.execute("SELECT * FROM users WHERE email=? AND active=1", (email,)).fetchone()
            if not row:
                # Fixed dummy work factor for unknown users; never hash unbounded attacker input.
                _password_hash("dummy-password")
                raise PermissionError("Email or password is incorrect")
            if row["locked_until"] and row["locked_until"] > _stamp(now):
                raise PermissionError("Account temporarily locked. Try again later.")
            if not _password_ok(str(password or ""), row["password_hash"]):
                failures = row["failed_attempts"] + 1
                locked = _stamp(now + timedelta(minutes=15)) if failures >= 8 else None
                db.execute("UPDATE users SET failed_attempts=?,locked_until=? WHERE user_id=?", (failures, locked, row["user_id"]))
                db.commit()
                raise PermissionError("Email or password is incorrect")
            db.execute("UPDATE users SET failed_attempts=0,locked_until=NULL WHERE user_id=?", (row["user_id"],))
            session_token, csrf = secrets.token_urlsafe(40), secrets.token_urlsafe(32)
            expires = _stamp(now + timedelta(hours=SESSION_HOURS))
            db.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (_hash(session_token), _hash(csrf), row["user_id"], expires, _stamp(now)))
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (_stamp(now),))
            db.commit()
            session = Session(row["user_id"], row["tenant_id"], row["email"], row["display_name"], row["role"], csrf, expires)
            return session, session_token

    def get_session(self, token: str | None) -> Session | None:
        if not token or len(token) > 256:
            return None
        now = _stamp(_now())
        with _connect(self.path) as db:
            row = db.execute("""SELECT s.csrf_hash,s.expires_at,u.user_id,u.tenant_id,u.email,u.display_name,u.role
                FROM sessions s JOIN users u ON u.user_id=s.user_id
                WHERE s.session_hash=? AND s.expires_at>? AND u.active=1""", (_hash(token), now)).fetchone()
        if not row:
            return None
        # The raw CSRF token is intentionally returned only by login; on refresh the browser
        # supplies the readable csrf cookie and the API validates it against this stored hash.
        return Session(row["user_id"], row["tenant_id"], row["email"], row["display_name"], row["role"], row["csrf_hash"], row["expires_at"])

    def csrf_valid(self, session: Session, cookie_value: str | None, header_value: str | None) -> bool:
        return bool(cookie_value and header_value and hmac.compare_digest(cookie_value, header_value)
                    and hmac.compare_digest(_hash(cookie_value), session.csrf_token))

    def logout(self, token: str | None):
        if token:
            with _connect(self.path) as db:
                db.execute("DELETE FROM sessions WHERE session_hash=?", (_hash(token),))
                db.commit()

    def create_invite(self, session: Session, role: str) -> dict:
        if session.role != "admin":
            raise PermissionError("Only workspace administrators can invite members")
        if not isinstance(role, str) or role not in {"analyst", "responder"}:
            raise ValueError("Invitations may grant analyst or responder roles only")
        token = secrets.token_urlsafe(32)
        expires = _stamp(_now() + timedelta(hours=INVITE_HOURS))
        with _connect(self.path) as db:
            db.execute("INSERT INTO invites VALUES(?,?,?,?,?,NULL)", (_hash(token), session.tenant_id, role, session.user_id, expires))
            db.commit()
        return {"invite_code": token, "role": role, "expires_at": expires}

    def create_workspace_invite(self, session: Session, workspace_name: str) -> dict:
        if session.role != "admin":
            raise PermissionError("Only workspace administrators can create workspaces")
        if not isinstance(workspace_name, str):
            raise ValueError("Workspace name must be text")
        name = workspace_name.strip()
        if not name or len(name) > 80:
            raise ValueError("Workspace name must be 1–80 characters")
        tenant_id = secrets.token_urlsafe(18)
        token = secrets.token_urlsafe(32)
        expires = _stamp(_now() + timedelta(hours=INVITE_HOURS))
        with _connect(self.path) as db:
            db.execute("INSERT INTO tenants VALUES(?,?,?)", (tenant_id, name, _stamp(_now())))
            db.execute("INSERT INTO invites VALUES(?,?,?,?,?,NULL)", (_hash(token), tenant_id, "admin", session.user_id, expires))
            db.commit()
        return {"invite_code": token, "workspace_name": name, "role": "admin", "expires_at": expires}

    def members(self, session: Session) -> list[dict]:
        if session.role != "admin":
            raise PermissionError("Only workspace administrators can view workspace members")
        with _connect(self.path) as db:
            rows = db.execute("SELECT user_id,email,display_name,role,active,created_at FROM users WHERE tenant_id=? ORDER BY created_at",
                              (session.tenant_id,)).fetchall()
        return [dict(row) for row in rows]

    def record_audit(self, session: Session | None, action: str, target: str = ""):
        with _connect(self.path) as db:
            db.execute("INSERT INTO auth_audit(occurred_at,actor_user_id,tenant_id,action,target) VALUES(?,?,?,?,?)",
                       (_stamp(_now()), session.user_id if session else None, session.tenant_id if session else None,
                        str(action)[:80], str(target)[:200]))
            db.commit()

    def disable_member(self, session: Session, user_id: str):
        if session.role != "admin":
            raise PermissionError("Only workspace administrators can manage members")
        if user_id == session.user_id:
            raise ValueError("You cannot disable your own administrator account")
        with _connect(self.path) as db:
            changed = db.execute("UPDATE users SET active=0 WHERE user_id=? AND tenant_id=? AND active=1",
                                 (user_id, session.tenant_id)).rowcount
            if changed != 1:
                raise ValueError("Member not found or already disabled")
            db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            db.execute("INSERT INTO auth_audit(occurred_at,actor_user_id,tenant_id,action,target) VALUES(?,?,?,?,?)",
                       (_stamp(_now()), session.user_id, session.tenant_id, "member.disabled", user_id))
            db.commit()

    def tenant_path(self, tenant_id: str) -> Path:
        safe = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
        return self.tenant_root / (safe + ".sqlite3")


def cookie_header(name: str, value: str, *, secure: bool, max_age: int, http_only: bool) -> str:
    parts = [f"{name}={value}", "Path=/", f"Max-Age={max_age}", "SameSite=Strict"]
    if http_only:
        parts.append("HttpOnly")
    if secure:
        parts.append("Secure")
    return "; ".join(parts)
