from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pipeline import verify_change


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cloudshield", description="Verify Terraform infrastructure changes")
    parser.add_argument("plan", help="Path to a Terraform plan JSON file")
    args = parser.parse_args(argv)
    try:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(verify_change(plan), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
