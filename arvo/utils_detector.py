import sqlite3
import time
from .utils import *
from .dev import *
import zipfile
from datetime import datetime
import random
Database_PATH = ARVO / "upstream_false_positives.db"
OSS_Fuzz_Arch = OSS_TMP / "OSS_Fuzz_Arch"

def fp_init():
    with sqlite3.connect(Database_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
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
def fp_insert(data, max_retries=3, retry_delay=0.1):
    for attempt in range(max_retries):
        conn = None
        try:
            conn = sqlite3.connect(Database_PATH, timeout=30)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("""
            INSERT INTO upstream_false_positives (
                localId, reason, log
            ) VALUES (?, ?, ?)
            """, data)
            conn.commit()
            return True
        except sqlite3.OperationalError as e:
            if conn:
                conn.rollback()
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))
                continue
            raise
        except Exception:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

def tp_insert(data, max_retries=3, retry_delay=0.1):
    for attempt in range(max_retries):
        conn = None
        try:
            conn = sqlite3.connect(Database_PATH, timeout=30)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("""
            INSERT INTO upstream_true_positives (
                localId, reason, log
            ) VALUES (?, ?, ?)
            """, data)
            conn.commit()
            return True
        except sqlite3.OperationalError as e:
            if conn:
                conn.rollback()
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))
                continue
            raise
        except Exception:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

        
def getFalsePositives(max_retries=3, retry_delay=0.1):
    for attempt in range(max_retries):
        conn = None
        try:
            conn = sqlite3.connect(Database_PATH, timeout=30)
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM upstream_false_positives
            """)
            rows = cursor.fetchall()
            res = []
            for x in rows:
                res.append(x[0])
            return res
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))
                continue
            FAIL("[-] FAILED to get data from Database")
            return False
        except Exception:
            FAIL("[-] FAILED to get data from Database")
            return False
        finally:
            if conn:
                conn.close()
def getNotFalsePositives(max_retries=3, retry_delay=0.1):
    for attempt in range(max_retries):
        conn = None
        try:
            conn = sqlite3.connect(Database_PATH, timeout=30)
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM upstream_true_positives
            """)
            rows = cursor.fetchall()
            res = []
            for x in rows:
                res.append(x[0])
            return res
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))
                continue
            FAIL("[-] FAILED to get data from Database")
            return False
        except Exception:
            FAIL("[-] FAILED to get data from Database")
            return False
        finally:
            if conn:
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
    while True:
        res = getOSSFuzzer(localId, store,limit=(1<<30))
        if res == False:
            return _leaveRet(None,"[FAILED] Failed to get necessary metadate to locate the resource")
        elif res == None:
            WARN("[FAILED] too much to download, do it later")
            sleep(30)
        else:
            break

    for target in store.iterdir():
        with zipfile.ZipFile(target, "r") as zf:
            file_list = zf.namelist()
        subprocess.run(["unar",str(target)],stdout=open('/dev/null','w'),cwd=store)
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
        if fuzz_target == None: 
            return _leaveRet(None,f"[FAILED] {localId=} {x} can't find the fuzz target")
        cmd = ['docker','run','--rm','--privileged']
        args = ['-e', ASAN_OPTIONS, '-e',UBSAN_OPTIONS, '-e', MSAN_OPTIONS,
                "-v",f"{poc}:/tmp/poc", '-v',f"{str(fuzz_target.parent)}:/out",
            f"gcr.io/oss-fuzz-base/base-runner", "timeout", "180",
            f'/out/{fuzz_target.name}','/tmp/poc']
        cmd.extend(args)
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
    if res == [False,True]:
        return False # Not False Positives
    else:
        return True  # False Positives

# False positives
def check_false_positive(localId):
    LogDir = ARVO / "Log" / "upstream_false_positives"
    INFO(f"[ARVO] [{datetime.now()}]working on {localId=}")
    res = false_positive(localId)
    vul_result = LogDir/f"{localId}_vul.log"
    fix_result = LogDir/f"{localId}_fix.log"

    if res != True:
        log = "=== vulnerable version ===:\n\n"
        if vul_result.exists():
            with open(vul_result,'rb') as f:
                log += f.read().decode("utf-8", errors="replace").replace("�", "\x00")
        else:
            log += "None\n"
        log+= "\n=== fixed version ===:\n\n"
        if fix_result.exists():
            with open(fix_result,'rb') as f:
                log += f.read().decode("utf-8", errors="replace").replace("�", "\x00")
        else:
            log += "None\n"
        if res == False:
            tp_insert((localId,f"The check result seems good",log))
        else: # Infra issue so we can't decide
            tp_insert((localId,f"The check result can't tell if it's a false positive",log))
        SUCCESS(f"Add new upstream true positive: {localId=}")
        return "Not False Posiitve"
    else:
        if not vul_result.exists() or not fix_result.exists():
            PANIC("Internal Error in false_positive")
        log = "=== vulnerable version ===:\n\n"
        with open(vul_result,'rb') as f:
            log += f.read().decode("utf-8", errors="replace").replace("�", "\x00")
        log+= "\n=== fixed version ===:\n\n"
        with open(fix_result,'rb') as f:
            log += f.read().decode("utf-8", errors="replace").replace("�", "\x00")
        fp_insert((localId,"The OSS-Fuzz compiled binary doesn't pass the crash/fix test",log))
        WARN(f"Add new upstream false positive: {localId=}")
        return "False Posiitve"
fp_init()

