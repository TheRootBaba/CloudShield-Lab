#!/usr/bin/env python3
"""Run a secret-safe local release verification and write a compact JSON record.

This runner performs local tests/build checks only. It never loads .env files,
contacts cloud APIs, provisions resources, or prints environment variable values.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


def run_check(name: str, command: list[str], cwd: Path) -> dict[str, object]:
    started = dt.datetime.now(dt.timezone.utc)
    try:
        proc = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=900)
        output = (proc.stdout + "\n" + proc.stderr).strip()
        return {
            "name": name,
            "command": command,
            "status": "passed" if proc.returncode == 0 else "failed",
            "exit_code": proc.returncode,
            "duration_seconds": round((dt.datetime.now(dt.timezone.utc) - started).total_seconds(), 2),
            "summary": output[-1200:],
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "name": name,
            "command": command,
            "status": "error",
            "exit_code": None,
            "duration_seconds": round((dt.datetime.now(dt.timezone.utc) - started).total_seconds(), 2),
            "summary": type(exc).__name__,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="evidence/acceptance/local-verification.json")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    npm = "npm.cmd" if os.name == "nt" else "npm"
    commands = [
        ("python-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"]),
        ("python-compile", [sys.executable, "-m", "compileall", "-q", "src", "tests"]),
        ("bandit", [sys.executable, "-m", "bandit", "-q", "-r", "src"]),
        ("detection-evaluation", [sys.executable, "-m", "cloudshield.cli", "evaluate", "fixtures/detection_evaluation.json"]),
        ("npm-production-audit", [npm, "audit", "--omit=dev", "--audit-level=low"]),
        ("web-production-build", [npm, "run", "build"]),
    ]
    checks = [run_check(name, command, root) for name, command in commands]
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = None
    record = {
        "schema_version": 1,
        "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "commit": commit,
        "platform": platform.platform(),
        "scope": "local software verification only; no live cloud, IdP, SMTP, backup-provider, or production-host acceptance",
        "checks": checks,
        "passed": sum(item["status"] == "passed" for item in checks),
        "failed": sum(item["status"] != "passed" for item in checks),
    }
    destination = (root / args.output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: record[key] for key in ("commit", "passed", "failed", "scope")}, indent=2))
    print(f"Evidence record: {destination.relative_to(root)}")
    return 0 if record["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
