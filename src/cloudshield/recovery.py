"""Verified, tenant-aware workspace-set backup and restore.

Callers should quiesce application writes for a consistent multi-database snapshot.
The archive and sidecar manifest should be copied to independent protected storage.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import zipfile
from urllib.parse import quote
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .backup import backup_database

VERSION = "1.0"
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024 * 1024
MAX_DATABASE_BYTES = 8 * 1024 * 1024 * 1024
MAX_DATABASES = 5000
MAX_MANIFEST_BYTES = 2 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _integrity(path: Path) -> str:
    db = sqlite3.connect(f"file:{quote(str(path.resolve()))}?mode=ro", uri=True)
    try:
        return str(db.execute("PRAGMA integrity_check").fetchone()[0])
    finally:
        db.close()


def _safe_archive_member(name: str) -> bool:
    """Allow only the exact workspace database layout on every host OS."""
    if not isinstance(name, str) or not name or len(name) > 160:
        return False
    if chr(92) in name or ":" in name or chr(0) in name:
        return False
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name or any(part in {"", ".", ".."} for part in path.parts):
        return False
    if name == "auth.sqlite3":
        return True
    return (
        len(path.parts) == 2
        and path.parts[0] == "tenants"
        and re.fullmatch("[a-f0-9]{64}[.]sqlite3", path.parts[1]) is not None
    )


def backup_workspace_set(auth_database: str | Path, tenant_directory: str | Path, destination: str | Path) -> dict:
    auth_database, tenant_directory, destination = Path(auth_database), Path(tenant_directory), Path(destination)
    manifest_path = Path(str(destination) + ".manifest.json")
    if not auth_database.is_file():
        raise FileNotFoundError("Authentication database does not exist")
    if not tenant_directory.is_dir():
        raise FileNotFoundError("Tenant database directory does not exist")
    if destination.exists() or manifest_path.exists():
        raise FileExistsError("Workspace backup or manifest already exists")
    tenants = sorted(tenant_directory.glob("*.sqlite3"))
    if not tenants:
        raise ValueError("No tenant databases found; refusing to create an incomplete workspace backup")
    if len(tenants) + 1 > MAX_DATABASES:
        raise ValueError("Workspace count exceeds the configured backup safety limit")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cloudshield-recovery-") as temp:
        stage = Path(temp)
        sources = [("auth.sqlite3", auth_database)] + [(f"tenants/{p.name}", p) for p in tenants]
        records = []
        for archive_name, source in sources:
            target = stage / archive_name
            backup_database(source, target)
            records.append({"path": archive_name, "size_bytes": target.stat().st_size, "sha256": _sha256(target), "sqlite_integrity_check": _integrity(target)})
        outer = {"manifest_version": VERSION, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "database_count": len(records), "files": records}
        (stage / "workspace-manifest.json").write_text(json.dumps(outer, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                for record in records:
                    file = stage / record["path"]
                    archive.write(file, record["path"])
                archive.write(stage / "workspace-manifest.json", "workspace-manifest.json")
            os.chmod(destination, 0o600)
            sidecar = {"manifest_version": VERSION, "archive_file": destination.name, "size_bytes": destination.stat().st_size,
                       "sha256": _sha256(destination), "generated_at": outer["generated_at"], "database_count": len(records)}
            with manifest_path.open("x", encoding="utf-8") as stream:
                json.dump(sidecar, stream, indent=2, sort_keys=True)
                stream.write("\n")
            os.chmod(manifest_path, 0o600)
        except Exception:
            destination.unlink(missing_ok=True)
            manifest_path.unlink(missing_ok=True)
            raise
    return {**sidecar, "archive": str(destination), "manifest": str(manifest_path), "files": records}


def verify_workspace_backup(archive_path: str | Path, manifest_path: str | Path | None = None) -> dict:
    archive_path = Path(archive_path)
    manifest_path = Path(manifest_path) if manifest_path else Path(str(archive_path) + ".manifest.json")
    errors = []
    if not archive_path.is_file() or not manifest_path.is_file():
        return {"valid": False, "errors": ["Workspace archive or sidecar manifest is missing"]}
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES or manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        return {"valid": False, "errors": ["Workspace archive or sidecar manifest exceeds the configured safety limit"]}
    try:
        sidecar = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"valid": False, "errors": ["Workspace sidecar manifest is unreadable"]}
    if not isinstance(sidecar, dict) or sidecar.get("manifest_version") != VERSION:
        return {"valid": False, "errors": ["Unsupported workspace manifest"]}
    if sidecar.get("archive_file") != archive_path.name:
        errors.append("Archive filename mismatch")
    if sidecar.get("size_bytes") != archive_path.stat().st_size:
        errors.append("Archive size mismatch")
    if sidecar.get("sha256") != _sha256(archive_path):
        errors.append("Archive SHA-256 mismatch")
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) > MAX_DATABASES + 1:
                errors.append("Archive contains too many entries")
            if len(names) != len(set(names)):
                errors.append("Archive contains duplicate paths")
            for info in infos:
                if info.filename == "workspace-manifest.json":
                    continue
                if not _safe_archive_member(info.filename):
                    errors.append("Archive contains an unsafe or unexpected path")
                    break
            if any(info.file_size > MAX_DATABASE_BYTES for info in infos):
                errors.append("Archive contains a database larger than the configured safety limit")
            if sum(info.file_size for info in infos) > MAX_ARCHIVE_BYTES * 2:
                errors.append("Archive expands beyond the configured total safety limit")
            if "workspace-manifest.json" not in names:
                errors.append("Internal workspace manifest is missing")
            elif archive.getinfo("workspace-manifest.json").file_size > MAX_MANIFEST_BYTES:
                errors.append("Internal workspace manifest exceeds the configured safety limit")
            else:
                internal = json.loads(archive.read("workspace-manifest.json"))
                if internal.get("manifest_version") != VERSION or not isinstance(internal.get("files"), list):
                    errors.append("Internal workspace manifest is invalid")
                else:
                    entries = internal["files"]
                    valid_entries = (
                        all(isinstance(entry, dict) and isinstance(entry.get("path"), str) for entry in entries)
                        and len({entry["path"] for entry in entries}) == len(entries)
                        and all(_safe_archive_member(entry["path"]) for entry in entries)
                        and any(entry["path"] == "auth.sqlite3" for entry in entries)
                    )
                    if not valid_entries:
                        errors.append("Internal workspace manifest contains unsafe or duplicate database paths")
                    expected = {entry["path"]: entry for entry in entries if isinstance(entry, dict) and isinstance(entry.get("path"), str)}
                    actual = set(names) - {"workspace-manifest.json"}
                    if actual != set(expected):
                        errors.append("Archive file list does not match internal manifest")
                    if valid_entries:
                        with tempfile.TemporaryDirectory(prefix="cloudshield-verify-") as temp:
                            for name, record in expected.items():
                                if name not in actual:
                                    continue
                                target = Path(temp).joinpath(*PurePosixPath(name).parts)
                                target.parent.mkdir(parents=True, exist_ok=True)
                                with archive.open(name, "r") as source, target.open("xb") as output:
                                    shutil.copyfileobj(source, output, length=1024 * 1024)
                                if target.stat().st_size != record.get("size_bytes") or _sha256(target) != record.get("sha256"):
                                    errors.append(f"File digest/size mismatch: {name}")
                                if _integrity(target) != "ok":
                                    errors.append(f"SQLite integrity failure: {name}")
                    if sidecar.get("database_count") != len(expected):
                        errors.append("Database count mismatch")
    except (OSError, sqlite3.Error, zipfile.BadZipFile, KeyError, json.JSONDecodeError, RuntimeError, AttributeError) as exc:
        errors.append(f"Archive verification failed: {type(exc).__name__}")
    return {"valid": not errors, "errors": errors, "sha256": _sha256(archive_path), "database_count": sidecar.get("database_count")}


def restore_workspace_set(archive_path: str | Path, destination: str | Path, manifest_path: str | Path | None = None) -> dict:
    archive_path, destination = Path(archive_path), Path(destination)
    verification = verify_workspace_backup(archive_path, manifest_path)
    if not verification["valid"]:
        raise ValueError("Workspace backup verification failed: " + "; ".join(verification["errors"]))
    if destination.exists():
        raise FileExistsError("Restore destination already exists; refusing to overwrite")
    destination.mkdir(parents=True)
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            for name in archive.namelist():
                path = PurePosixPath(name)
                allowed = name == "workspace-manifest.json" or _safe_archive_member(name)
                if not allowed:
                    raise ValueError("Unsafe or unexpected archive path")
                target = destination.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(name) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                try:
                    os.chmod(target, 0o600)
                except OSError:
                    pass
        manifest = json.loads((destination / "workspace-manifest.json").read_text(encoding="utf-8"))
        for record in manifest["files"]:
            target = destination.joinpath(*PurePosixPath(record["path"]).parts)
            if _sha256(target) != record["sha256"] or _integrity(target) != "ok":
                raise RuntimeError(f"Restored database failed verification: {record['path']}")
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return {"restored": True, "destination": str(destination), "database_count": verification["database_count"], "sqlite_integrity_check": "ok"}
