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
    res = report(localId,False)
    print(res)
def cli_list(pname):
    res = listProject(pname)
    if not res:
        WARN(f"Not found, check the provided project name {pname=}")
    else:
        print(res)
def cli_check_localId(localId,verbose=False):
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
    if verbose and (not reproduciable or not patch_located):
        INFO("Reasons:")
        possible_image_err   = ARVO / "CrashLog" / f"{localId}_Image.log"
        possible_compile_err = ARVO / "CrashLog" / f"{localId}_Compile.log"
        log_file = ARVO / "Log" / "_Event.log"
        crash_file = ARVO / "_CrashLOGs"
        if possible_image_err.exists():
            os.system(f"tail -n 100 {possible_image_err}")
        if possible_compile_err.exists():
            os.system(f"tail -n 100 {possible_compile_err}")
        INFO("[Event Log]")
        os.system(f"grep -r {localId} {log_file}")
        INFO("[Crash Log]")
        os.system(f"grep -r {localId} {crash_file}")
        
def cli_check(localId_project):
    if localId_project.isdigit():
        localId = int(localId_project)
        cli_check_localId(localId,True)
    else:
        pname = localId_project
        for x in listProject(pname):
            cli_check_localId(x)
    
def cli_show(localId):
    res = getReport(localId)
    if not res:
        WARN(f"No Report Found for {localId=}")
    else:
        print(json.dumps(res,indent=4))
def cli_summary():
    pass
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
    p_check = subparsers.add_parser("check", help="Check the reproducing status")
    p_check.add_argument("localId_project", type=str)

    # show report
    p_show = subparsers.add_parser("show", help="Print the report")
    p_show.add_argument("localId", type=int)

    # summary
    p_summary = subparsers.add_parser("summary", help="Print the summary of current reproducing process")

    args = parser.parse_args()

    if args.command == "reproduce":
        cli_reproduce(args.localId)
    elif args.command == "report":
        cli_report(args.localId)
    elif args.command == "list":
        cli_list(args.pname)
    elif args.command == "check":
        cli_check(args.localId_project)
    elif args.command == "show":
        cli_show(args.localId)
    elif args.command == 'summary':
        cli_summary()

if __name__ == "__main__":
    main()
