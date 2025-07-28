import sqlite3
from .utils import *
from .dev import *
from .reproducer import verify
import zipfile

Database_PATH = ARVO / "upstream_false_positives.db"
OSS_Fuzz_Arch = OSS_TMP / "OSS_Fuzz_Arch"

def fp_init():
    with sqlite3.connect(Database_PATH) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS upstream_false_positives (
            localId INTEGER PRIMARY KEY,
            reason TEXT,
            log    TEXT
        )
        """)
        conn.commit()
    with sqlite3.connect(Database_PATH) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS upstream_true_positives (
            localId INTEGER PRIMARY KEY,
            reason TEXT,
            log    TEXT
        )
        """)
        conn.commit()
def fp_insert(data):
    conn = sqlite3.connect(Database_PATH, timeout=30, isolation_level="EXCLUSIVE")
    conn.execute("BEGIN EXCLUSIVE")
    conn.execute("""
    INSERT INTO upstream_false_positives (
        localId, reason, log
    ) VALUES (?, ?, ?)
    """, data)
    conn.commit()
    conn.close()
    return True

def tp_insert(data):
    conn = sqlite3.connect(Database_PATH, timeout=30, isolation_level="EXCLUSIVE")
    conn.execute("BEGIN EXCLUSIVE")
    conn.execute("""
    INSERT INTO upstream_true_positives (
        localId, reason, log
    ) VALUES (?, ?, ?)
    """, data)
    conn.commit()
    conn.close()
    return True

        
def getFalsePositives():
    conn = sqlite3.connect(Database_PATH, timeout=30, isolation_level="EXCLUSIVE")
    cursor = conn.cursor()
    try:
        cursor.execute("""
        SELECT * FROM upstream_false_positives
        """)
        rows = cursor.fetchall()
        res = []
        for x in rows:
            res.append(x[0])
        return res
    except:
        FAIL("[-] FAILED to get data from Database")
        return False
    finally:
        conn.close()
def getNotFalsePositives():
    conn = sqlite3.connect(Database_PATH, timeout=30, isolation_level="EXCLUSIVE")
    cursor = conn.cursor()
    try:
        cursor.execute("""
        SELECT * FROM upstream_true_positives
        """)
        rows = cursor.fetchall()
        res = []
        for x in rows:
            res.append(x[0])
        return res
    except:
        FAIL("[-] FAILED to get data from Database")
        return False
    finally:
        conn.close()
def false_positive(localId,focec_retest = False):
    # Check OSS-Fuzz's Compiled Binary to see if the poc can crash the target or not.
    # return true  when it's likely a false positive
    # return false when it's not a false positive
    # return none  when we can't tell
    store = OSS_Fuzz_Arch / str(localId)
    def _leaveRet(res,msg=None):
        if msg: WARN(msg)
        shutil.rmtree(store)
        return res
    if not focec_retest and localId in getFalsePositives():
        return True
    if localId in getNotFalsePositives():
        return False
    if store.exists():
        shutil.rmtree(store)

    # Do download 
    store.mkdir(parents=True, exist_ok=True)
    if not getOSSFuzzer(localId, store,limit=(1<<30)):
        return _leaveRet(None,"[FAILED] too much to download, do it later")
    for target in store.iterdir():
        with zipfile.ZipFile(target, "r") as zf:
            file_list = zf.namelist()
        subprocess.run(["unar",str(target)],cwd=store)
        if len(file_list)==1:
            new_dir = store / target.name.split(".")[0]
            new_dir.mkdir()
            shutil.move(store/file_list[0], store/new_dir,)
    # Find the target dirs
    todo = []
    for target in store.iterdir():
        if "zip" not in target.name:
            todo.append(target)
    if(len(todo) !=2): 
        return _leaveRet(None,"[FAILED] to get the fuzz target")
    todo.sort(key=lambda x: x.name)
    LogDir = ARVO/"Log"/"upstream_false_positives"
    if not LogDir.exists(): 
        LogDir.mkdir()
    poc = getPoc(localId)
    if not poc:  
        return _leaveRet(None,"[FAILED] to download the poc")
    res = []
    tag = "vul"
    for x in todo:
        fuzz_target = getFuzzer(localId,x)
        if fuzz_target == None: return _leaveRet(None,"[FAILED] {localId=} {x} can't find the fuzz target")
        cmd = ['docker','run','--rm','--privileged']
        args = ['-e', ASAN_OPTIONS, '-e',UBSAN_OPTIONS, '-e', MSAN_OPTIONS,
                "-v",f"{poc}:/tmp/poc", '-v',f"{str(fuzz_target.parent)}:/out",
            f"gcr.io/oss-fuzz-base/base-runner", "timeout", "180",
            f'/out/{fuzz_target.name}','/tmp/poc']
        cmd.extend(args)
        INFO(" ".join(cmd))
        with open(LogDir/f"{localId}_{tag}.log",'wb') as f:
            returnCode = execute_ret(cmd,stdout=f,stderr=f)
            f.write(f"\nReturn Code: {returnCode}\n".encode())
        if returnCode == 255: # deprecated style    
            with open(LogDir/f"{localId}_{tag}.log",'rb') as f:
                if_warn = b"WARNING: using the deprecated call style " in f.read()
            if if_warn:
                    cmd = ['docker','run','--rm','--privileged']
                    args = ['-e', ASAN_OPTIONS, '-e',UBSAN_OPTIONS, '-e', MSAN_OPTIONS,
                            "-v",f"{poc}:/tmp/poc", '-v',f"{str(fuzz_target.parent)}:/out",
                        f"gcr.io/oss-fuzz-base/base-runner", "timeout", "180",
                        f'/tmp/{fuzz_target.name}','/tmp/poc']
                    cmd.extend(args)
                    INFO(" ".join(cmd))
                    with open(LogDir/f"{localId}_{tag}.log",'wb') as f:
                        returnCode = execute_ret(cmd,stdout=f,stderr=f)
                        f.write(f"\nReturn Code: {returnCode}\n".encode())
            res.append(pocResultChecker(returnCode,LogDir/f"{localId}_{tag}.log",args,True))
        else:
            res.append(pocResultChecker(returnCode,LogDir/f"{localId}_{tag}.log",args,False))
        tag = 'fix'
    # clean poc and downloaded binary
    shutil.rmtree(poc.parent)
    shutil.rmtree(store)
    if res != [False,True]:
        return True # False positive
    else:
        return False
def false_positives(localIds,failed_on_verify=True):
    # The passed localIds must return 
    confirmed = []
    for localId in localIds:
        if failed_on_verify != True and verify(localId):
            continue
        if false_positive(localId)==True:
            confirmed.append(localId)
    return confirmed
fp_init()

