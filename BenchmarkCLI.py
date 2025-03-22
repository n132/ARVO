from fx import *
from pathlib import Path
from unitTest import *
import sys
from cli import cli_report
def usage():
    print("[+] Usage:")
    print("[+]      python3 BenchmarkCLI.py [Command] [LocalId] <InputFile>")
    print("[+]      Command: <getMeta, tryFix>")
    print("[+]      LocalId: a number identifier for the issue in OSS-Fuzz")
def cli_getMeta(localId):
    vulcode = getGetVulCode(localId)
    if vulcode==False:
        print(f"[-] Failed to get the metadata for case {localId}")
        return False
    return {"Vulnerable Codes":vulcode}, cli_report(localId) 
def cli_tryFix(localId,infile):
    with open(infile,'rb') as f:
        res = BenchMarkAPI(localId,f.read())
    return res
if __name__ == "__main__":
    if len(sys.argv) not in [3,4]:
        usage()
    else:
        command = sys.argv[1]
        localId = int(sys.argv[2])
        if command == "getMeta":
            res = cli_getMeta(localId)
            if res != False:
                vulcode, report_info = res
                print(vulcode)
                print(report_info)
        elif command == "tryFix":
            if len(sys.argv) != 4:
                print("[-] Please provide the InputFile including the fix")
                exit(1)
            infile  = Path(sys.argv[3])
            if not infile.exists():
                print("[-] Please provide a json file as input")
                exit(1)
            res = cli_tryFix(localId,infile)
            print(res)
        else:
            usage()
            
        
