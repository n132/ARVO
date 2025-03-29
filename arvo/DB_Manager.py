from pathlib import Path
from ._profile import *
import json
import shutil
from time import sleep
from base58 import b58encode
OSS_DB      = Path(OSS_DB_DIR)
OSS_DB_MAP  = OSS_DB/"map"
OSS_DB_LOCK = OSS_DB/"map.lock"
RETRY       = 4
from filelock import FileLock
LOG = Path(ARVO_DIR) / "Log"

if not LOG.exists():
    LOG.mkdir(exist_ok=True)

def eventLog(s):
    logFilelock = LOG/"_Event.log.lock"
    logFile = LOG/"_Event.log"
    lock = FileLock(logFilelock)
    with lock:
        with open(logFile,'a') as f:
            f.write(s+"\n")
def updateCrashLog(result,log_file,perm='a'):
    logFilelock = LOG/f"{log_file}.lock"
    logFile = LOG/f"{log_file}"
    lock = FileLock(logFilelock)
    with lock:
        with open(logFile,perm) as f:
            f.write(result+"\n")
def DB_DUMP(rec):
    ct = 0 
    while ct < RETRY:
        try:
            lock = FileLock(OSS_DB_LOCK)
            with lock:
                with open(OSS_DB_MAP,'w') as f:
                    f.write(json.dumps(rec,indent=4))
            return True
        except:
            sleep(0.3)
            ct+=1
    return False
def DB_INSERT(url,orig):
    if not orig.exists():
        return False
    rec = DB_MAP()
    if url in rec.keys():
        del rec[url]
    dest = OSS_DB /  b58encode(url).decode()        
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir()
    try:
        shutil.copytree(orig,dest/orig.name,symlinks=True)
    except:
        return False
    rec[url] = str(dest/orig.name)
    if not DB_DUMP(rec):
        eventLog("[!] DB_INSERT: OSS_DB is polluted")
        exit(1)
    else:
        return True


def DB_CHECK(url):
    map = DB_MAP()
    if url in map.keys():
        res = Path(map[url])
        if res.exists():
            return res
        else:
            DB_remove(url,res)
            return False
    else:
        return False
def DB_MAP():
    ct = 0 
    while ct < RETRY*2:
        try:
            with open(OSS_DB_MAP) as f:
                res = json.loads(f.read())
            return res
        except:
            sleep(0.3)
            ct+=1
    eventLog("[!] DM_MAP: Failed to get DB MAP")
    exit(1)
def DB_remove(url,path):
    if path.exists():
        shutil.rmtree(path)
    data = DB_MAP()
    try:
        del data[url]
    except:
        pass
    DB_DUMP(data)
    