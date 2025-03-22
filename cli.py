# command line interface
from reproducer import *
from utils import *
from Locator import report
import sys
def usage():
    print("[+] Usage:")
    print("[+]      python3 cli.py [Command] [LocalId]")
    print("[+]      Command: <reproduce, report>")
    print("[+]      LocalId: a number identifier for the issue in OSS-Fuzz")
def cli_reproduce(localId):
    res = verify(localId,False) # Verify and save the image
    if res==True:
        print(f"[+] Successfully reproduced the case, where {localId=}, check your reproducing result at {OSS_IMG}/{localId} directory." )
        return OSS_IMG/f"{localId}"
    else:
        print(f"[-] Failed to Reproduce")
        return False
def cli_report(localId):
    target = Path(f"./Reports/{localId}.json")
    if target.exists():
        print(f"[+] Report exists at ./Reports/{localId}.json")
        return json.loads(open(Path(f"./Reports/{localId}.json")).read())
    res = report(localId)
    if res==True:
        print(f"[+] Successfully generated the report, where {localId=}, check your result at ./Reports/{localId}.json." )
        return json.loads(open(Path(f"./Reports/{localId}.json")).read())
    else:
        print(f"[-] Failed to Report")
        return False
if __name__ == "__main__":
    if len(sys.argv)!= 3:
        usage()
    else:
        command = sys.argv[1]
        localId = int(sys.argv[2])
        print(command,localId)
        if command == "reproduce":
            cli_reproduce(localId)
        elif command == "report":
            cli_report(localId)
        else:
            usage()
            