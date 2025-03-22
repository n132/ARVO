from utils import *
import sys
def reproduceProb(localId):
    def leave(res):
        docker_rmi(f"n132/arvo:{localId}-vul")
        docker_rmi(f"n132/arvo:{localId}-fix")
        return res
    print(f"[+] Checking image {localId=}")
    target = OSS_IMG / str(localId)
    if not target.exists():
        return leave(False)
    # Vul
    if docker_load(open(target/f"{localId}-vul.tar"))!=True:
        return leave(False)
    ret_code = execute_ret(["bash","arvo_vul.sh"],target)
    if ret_code == 0:
        return leave(False)
    # Fix 
    if docker_load(open(target/f"{localId}-fix.tar"))!=True:
        return leave(False)
    ret_code = execute_ret(["bash","arvo_fix.sh"],target)
    if ret_code == 0:
        return leave(True)
    return leave(False)
def parseArvoScript(filePath):
    with open(filePath) as f:
        cmdline = f.read().strip().split(" ")
    return cmdline

def recompileProb(localId):
    def leave(res):
        docker_rmi(f"n132/arvo:{localId}-vul")
        docker_rmi(f"n132/arvo:{localId}-fix")
        return res
    print(f"[+] Checking image {localId=}")
    target = OSS_IMG / str(localId)
    if not target.exists():
        return leave(False)
    # Vul Compile
    if docker_load(open(target/f"{localId}-vul.tar"))!=True:
        return leave(False)
    cmdline = parseArvoScript(target/"arvo_vul.sh")
    subcmd = " ".join(cmdline[-2:])
    cmdline = cmdline[:-2] + ["sh", "-c", f'(compile || exit 132) && {subcmd}']
    print(" ".join(cmdline))
    ret_code = execute_ret(cmdline,target)
    if ret_code == 132 or ret_code == 0:
        # not perfect not enough to checking
        return leave(False)
    # Fix Compile
    if docker_load(open(target/f"{localId}-fix.tar"))!=True:
        return leave(False)
    cmdline = parseArvoScript(target/"arvo_fix.sh")
    subcmd = " ".join(cmdline[-2:])
    cmdline = cmdline[:-2] + ["sh", "-c", f'compile && {subcmd}']
    print(" ".join(cmdline))

    ret_code = execute_ret(cmdline,target)
    if ret_code == 0:
        return leave(True)
    return leave(False)

def reproduceAll():
    failed = []
    for i in OSS_IMG.iterdir():
        localId = int(i.name)
        res = reproduceProb(localId)
        if res !=True:
            failed.append(localId)
            eventLog(f"[-] ImageVerify: Failed to Reproduce {localId}.")
        print(f"{failed=}")
        exit(1)
    print(f"Failed to reproduce:")
    print(failed)

def recompileAll():
    failed = []
    for i in OSS_IMG.iterdir():
        localId = int(i.name)
        res = recompileProb(localId)
        print(res)
        if res !=True:
            failed.append(localId)
            eventLog(f"[-] ImageVerify: Failed to Recompile {localId}.")
    print(f"Failed to recompile:")
    print(failed)


def usage():
    print("Usage:")
    print("\tpython3 imageVerify.py [recompile|reproduce]")
if __name__ == "__main__":
    pass
