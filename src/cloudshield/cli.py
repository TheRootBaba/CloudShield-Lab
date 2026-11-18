"""CloudShield command-line interface."""
import argparse
import getpass
import json
import os
from pathlib import Path

from .events import load_events
from .detector import analyze_event
from .analytics import investigation
from .simulator import SCENARIOS, simulate, simulate_all
from .pipeline import analyze_payload
from .storage import EvidenceStore
from .evaluation import evaluate_file
from .evidence_signing import generate_keypair, sign_bundle_file, verify_signature_files


def _read(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Input error: {exc}")


def analyze_file(path: Path):
    """Normalize, detect and correlate an event file."""
    result = analyze_payload(_read(path))
    result["input_file"] = Path(path).name
    return result


def main(argv=None):
    p = argparse.ArgumentParser(prog="cloudshield", description="Local-first cloud security verification lab")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze", help="Normalize, detect and correlate events")
    a.add_argument("file")
    s = sub.add_parser("simulate", help="Emit safe synthetic attack telemetry")
    s.add_argument("scenario", choices=[*SCENARIOS, "all"], nargs="?", default="all")
    s.add_argument("--output")
    i = sub.add_parser("investigate", help="Investigate an event from an input file")
    i.add_argument("file")
    i.add_argument("event_id")
    st = sub.add_parser("store", help="Analyze and persist evidence locally")
    st.add_argument("file")
    st.add_argument("--database", default="artifacts/evidence.sqlite3")
    tl = sub.add_parser("timeline", help="Read the persisted event timeline")
    tl.add_argument("--database", default="artifacts/evidence.sqlite3")
    tl.add_argument("--actor")
    tl.add_argument("--account-id")
    inc = sub.add_parser("incident", help="Retrieve a persisted incident by ID")
    inc.add_argument("incident_id")
    inc.add_argument("--database", default="artifacts/evidence.sqlite3")
    ev = sub.add_parser("evaluate", help="Evaluate detections against a labelled fixture corpus")
    ev.add_argument("file", nargs="?", default="fixtures/detection_evaluation.json")
    ev.add_argument("--output")
    kg = sub.add_parser("keygen", help="Generate an encrypted Ed25519 evidence-signing key pair")
    kg.add_argument("--private-key", required=True)
    kg.add_argument("--public-key", required=True)
    sb = sub.add_parser("sign-bundle", help="Sign a valid evidence bundle with Ed25519")
    sb.add_argument("file")
    sb.add_argument("--private-key", required=True)
    sb.add_argument("--signature")
    vs = sub.add_parser("verify-signature", help="Verify a detached Ed25519 evidence signature")
    vs.add_argument("file")
    vs.add_argument("--public-key", required=True)
    vs.add_argument("--signature")
    aws = sub.add_parser("aws-inventory", help="Run a bounded, opt-in read-only AWS inventory")
    aws.add_argument("--regions", nargs="+", required=True)
    aws.add_argument("--max-pages", type=int, default=1)
    aws.add_argument("--output")
    args = p.parse_args(argv)

    if args.command == "analyze":
        result = analyze_file(args.file)
    elif args.command == "simulate":
        result = simulate_all() if args.scenario == "all" else simulate(args.scenario)
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    elif args.command == "investigate":
        events = load_events(_read(args.file))
        findings = [f for e in events for f in analyze_event(e)]
        try:
            result = investigation(args.event_id, events, findings)
        except KeyError as exc:
            raise SystemExit(str(exc))
    elif args.command == "store":
        db = Path(args.database)
        db.parent.mkdir(parents=True, exist_ok=True)
        result = EvidenceStore(db).ingest(_read(args.file))
    elif args.command == "timeline":
        result = EvidenceStore(args.database).timeline(args.actor, args.account_id)
    elif args.command == "incident":
        try:
            result = EvidenceStore(args.database).incident(args.incident_id)
        except KeyError as exc:
            raise SystemExit(str(exc))
    elif args.command == "evaluate":
        result = evaluate_file(args.file)
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    elif args.command == "keygen":
        password = getpass.getpass("New private-key password (minimum 12 characters): ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise SystemExit("Passwords do not match")
        result = generate_keypair(args.private_key, args.public_key, password)
    elif args.command == "sign-bundle":
        password = getpass.getpass("Private-key password: ")
        signature_path = args.signature or (args.file + ".sig.json")
        result = sign_bundle_file(args.file, args.private_key, signature_path, password)
        result["signature_file"] = signature_path
    elif args.command == "verify-signature":
        signature_path = args.signature or (args.file + ".sig.json")
        result = verify_signature_files(args.file, signature_path, args.public_key)
        if not result["valid"]:
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1
    elif args.command == "aws-inventory":
        if os.environ.get("CLOUDSHIELD_ENABLE_AWS_INVENTORY") != "1":
            raise SystemExit("AWS inventory is disabled. Set CLOUDSHIELD_ENABLE_AWS_INVENTORY=1 to explicitly opt in.")
        from .aws_inventory import collect_inventory
        result = collect_inventory(args.regions, args.max_pages)
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
    else:
        raise SystemExit("Unsupported command")

    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
