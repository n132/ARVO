from .utils_experiments import *
from .utils_GPT import GPTLabeler
import time
from glob           import glob

def patchDesc(localId,update=False):
    if not update and Path(f"./PatchDesc/{localId}.log").exists():
        return 
    
    patch_desc = GPTLabeler(localId)
    if patch_desc == False:
        eventLog(f"[-] patchDesc: Faild to analysis the pacth: {localId=}")
        return
    with open(f"./PatchDesc/{localId}.log","w") as f:
        f.write(patch_desc)
    print("Sleeping to cool-down...")
    time.sleep(10)
    return
def desc_allPatches(ids=None,update=False):
    if ids != None:
        pass
    else:
        ids = get_all_single_mods()
    for x in ids:
        print(f"[+] Generating the Desc for issue: {x}")
        patchDesc(x,update)
    return 
def get_test_dataset():
    filter1 = "This model's maximum context length"
    fs = glob("./PatchDesc/*")
    res = []
    for fname in fs:
        with open(fname,'r') as f:
            if filter1 not in f.read():
                res.append(int(fname.split("/")[-1][:-4]))
    return res