import argparse
import json
import sys
from pathlib import Path
from .reproducer import verify
from .utils import *
from .Locator import report
from .utils_log import *

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
def cli_list(pname):
    res = listProject(pname)
    if not res:
        WARN(f"Not found, check the provided project name {pname=}")
    else:
        print(res)
def cli_check(localId):
    reproduciable = True if localId in getDone() else False
    patch_located = True if localId in getReports() else False
    pname = getPname(localId)
    INFO(f"{pname=} {localId=}")
    if reproduciable:
        SUCCESS("Reproduced: \tTrue")
    else:
        WARN("Reproduced: \tFalse")
    if patch_located:
        SUCCESS("Patch Located: \tTrue")
    else:
        WARN("Patch Located: \tFalse")

def main():
    parser = argparse.ArgumentParser(prog="arvo", description="ARVO CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # reproduce
    p_reproduce = subparsers.add_parser("reproduce", help="Reproduce a bug")
    p_reproduce.add_argument("localId", type=int)

    # report
    p_report = subparsers.add_parser("report", help="Generate a report")
    p_report.add_argument("localId", type=int)

    # list
    p_list = subparsers.add_parser("list", help="List the localIds belong to a specific project in meta")
    p_list.add_argument("pname", type=str)

    # check status
    p_check = subparsers.add_parser("check", help="Check the reproducing status of a localId")
    p_check.add_argument("localId", type=int)

    args = parser.parse_args()

    if args.command == "reproduce":
        cli_reproduce(args.localId)
    elif args.command == "report":
        cli_report(args.localId)
    elif args.command == "list":
        cli_list(args.pname)
    elif args.command == "check":
        cli_check(args.localId)

if __name__ == "__main__":
    main()
