import argparse
import json
import sys
from pathlib import Path
from .reproducer import verify
from .utils import OSS_IMG
from .Locator import report

def cli_reproduce(localId):
    res = verify(localId, False)
    if res:
        out = OSS_IMG / f"{localId}"
        print(f"[+] Successfully reproduced {localId=}, see: {out}")
        return out
    else:
        print("[-] Failed to Reproduce")
        return False

def cli_report(localId):
    target = Path(f"./Reports/{localId}.json")
    if target.exists():
        print(f"[+] Report exists: {target}")
        return json.loads(target.read_text())
    res = report(localId)
    if res:
        print(f"[+] Generated report: {target}")
        return json.loads(target.read_text())
    else:
        print("[-] Failed to Report")
        return False

def main():
    parser = argparse.ArgumentParser(prog="arvo", description="ARVO CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # reproduce
    p_reproduce = subparsers.add_parser("reproduce", help="Reproduce a bug")
    p_reproduce.add_argument("localId", type=int)

    # report
    p_report = subparsers.add_parser("report", help="Generate a report")
    p_report.add_argument("localId", type=int)

    args = parser.parse_args()

    if args.command == "reproduce":
        cli_reproduce(args.localId)
    elif args.command == "report":
        cli_report(args.localId)

if __name__ == "__main__":
    main()
