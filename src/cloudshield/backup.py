"""Verified SQLite online backup and safe restore helpers."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _integrity(path: Path) -> str:
    db = sqlite3.connect(f"file:{quote(str(path.resolve()))}?mode=ro", uri=True)
    try:
        row = db.execute("PRAGMA integrity_check").fetchone()
        return str(row[0] if row else "unknown")
    finally:
        db.close()


def backup_database(source: str | Path, destination: str | Path) -> dict:
    source, destination = Path(source), Path(destination)
    manifest = Path(str(destination) + ".manifest.json")
    if not source.is_file():
        raise FileNotFoundError(f"Source database does not exist: {source}")
    if destination.exists() or manifest.exists():
        raise FileExistsError("Backup database or manifest already exists; refusing to overwrite")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_db = sqlite3.connect(f"file:{quote(str(source.resolve()))}?mode=ro", uri=True)
    target_db = sqlite3.connect(str(destination))
    try:
        source_db.backup(target_db)
        integrity = target_db.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"Backup integrity check failed: {integrity}")
    except Exception:
        target_db.close()
        source_db.close()
        destination.unlink(missing_ok=True)
        raise
    else:
        target_db.close()
        source_db.close()
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass
    record = {
        "manifest_version": "1.0", "database_file": destination.name,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "size_bytes": destination.stat().st_size, "sha256": _digest(destination),
        "sqlite_integrity_check": "ok", "source_database": source.name,
        "note": "Manifest and backup are stored together; sign or copy the manifest to an independent trusted location for stronger chain of custody.",
    }
    try:
        with manifest.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except Exception:
        manifest.unlink(missing_ok=True)
        destination.unlink(missing_ok=True)
        raise
    try:
        os.chmod(manifest, 0o600)
    except OSError:
        pass
    return {**record, "manifest_file": str(manifest), "backup_file": str(destination)}


def verify_backup(backup: str | Path, manifest: str | Path | None = None) -> dict:
    backup = Path(backup)
    manifest = Path(manifest) if manifest else Path(str(backup) + ".manifest.json")
    if not backup.is_file() or not manifest.is_file():
        return {"valid": False, "errors": ["Backup database or manifest is missing"]}
    try:
        record = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"valid": False, "errors": ["Backup manifest is unreadable or invalid JSON"]}
    if not isinstance(record, dict):
        return {"valid": False, "errors": ["Backup manifest must be a JSON object"]}
    errors = []
    if record.get("manifest_version") != "1.0": errors.append("Unsupported manifest version")
    if record.get("database_file") != backup.name: errors.append("Manifest database filename mismatch")
    if record.get("size_bytes") != backup.stat().st_size: errors.append("Backup size mismatch")
    if record.get("sha256") != _digest(backup): errors.append("Backup SHA-256 mismatch")
    integrity = _integrity(backup)
    if integrity != "ok": errors.append(f"SQLite integrity check failed: {integrity}")
    return {"valid": not errors, "errors": errors, "sha256": _digest(backup), "sqlite_integrity_check": integrity, "manifest": record}


def restore_backup(backup: str | Path, destination: str | Path, manifest: str | Path | None = None) -> dict:
    backup, destination = Path(backup), Path(destination)
    verification = verify_backup(backup, manifest)
    if not verification["valid"]:
        raise ValueError("Backup verification failed: " + "; ".join(verification["errors"]))
    if destination.exists():
        raise FileExistsError("Restore destination already exists; refusing to overwrite")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copyfile(backup, destination)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
        integrity = _integrity(destination)
        if integrity != "ok":
            raise RuntimeError(f"Restored database integrity check failed: {integrity}")
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return {"restored": True, "destination": str(destination), "sha256": _digest(destination), "sqlite_integrity_check": integrity}
