"""CloudShield command-line interface."""
import argparse, json
from pathlib import Path
from .events import load_events
from .detector import analyze_event
from .analytics import investigation
from .simulator import SCENARIOS, simulate, simulate_all
from .pipeline import analyze_payload
from .storage import EvidenceStore

def _read(path):
    try: return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc: raise SystemExit(f"Input error: {exc}")

def analyze_file(path: Path):
    """Normalize, detect and correlate an event file."""
    result=analyze_payload(_read(path))
    result["input_file"]=Path(path).name
    return result

def main(argv=None):
    p=argparse.ArgumentParser(prog="cloudshield",description="Local-first cloud security verification lab")
    sub=p.add_subparsers(dest="command",required=True)
    a=sub.add_parser("analyze",help="Normalize, detect and correlate events"); a.add_argument("file")
    s=sub.add_parser("simulate",help="Emit safe synthetic attack telemetry"); s.add_argument("scenario",choices=[*SCENARIOS,"all"],nargs="?",default="all"); s.add_argument("--output")
    i=sub.add_parser("investigate",help="Investigate an event from an input file"); i.add_argument("file"); i.add_argument("event_id")
    st=sub.add_parser("store",help="Analyze and persist evidence locally"); st.add_argument("file"); st.add_argument("--database",default="artifacts/evidence.sqlite3")
    tl=sub.add_parser("timeline",help="Read the persisted event timeline"); tl.add_argument("--database",default="artifacts/evidence.sqlite3"); tl.add_argument("--actor"); tl.add_argument("--account-id")
    inc=sub.add_parser("incident",help="Retrieve a persisted incident by ID"); inc.add_argument("incident_id"); inc.add_argument("--database",default="artifacts/evidence.sqlite3")
    args=p.parse_args(argv)
    if args.command=="analyze": result=analyze_file(args.file)
    elif args.command=="simulate":
        result=simulate_all() if args.scenario=="all" else simulate(args.scenario)
        if args.output:
            output_path=Path(args.output)
            output_path.parent.mkdir(parents=True,exist_ok=True)
            output_path.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    elif args.command=="investigate":
        events=load_events(_read(args.file)); findings=[f for e in events for f in analyze_event(e)]
        try: result=investigation(args.event_id,events,findings)
        except KeyError as exc: raise SystemExit(str(exc))
    elif args.command=="store":
        db=Path(args.database); db.parent.mkdir(parents=True,exist_ok=True)
        result=EvidenceStore(db).ingest(_read(args.file))
    elif args.command=="timeline":
        result=EvidenceStore(args.database).timeline(args.actor,args.account_id)
    else:
        try: result=EvidenceStore(args.database).incident(args.incident_id)
        except KeyError as exc: raise SystemExit(str(exc))
    print(json.dumps(result,indent=2,sort_keys=True,default=str))
    return 0
if __name__=="__main__": raise SystemExit(main())
