"""
ARVO False Positive Detection Module

This module provides functionality for detecting and managing false positives in OSS-Fuzz
vulnerability reports. It maintains a database of known false positives and true positives,
and provides testing capabilities to verify if a vulnerability report is legitimate.

Key Features:
- Database management for false/true positive tracking
- Automated testing against OSS-Fuzz compiled binaries
- POC (Proof of Concept) validation against vulnerable and fixed versions
- Retry logic for database operations to handle concurrency
- Comprehensive logging of test results

The module downloads OSS-Fuzz artifacts, runs proof-of-concept exploits against both
vulnerable and patched versions, and determines if the vulnerability report is accurate
based on the execution results.
"""

import sqlite3
import time
from .utils import *
from .dev import *
import zipfile
from datetime import datetime
Database_PATH = ARVO / "upstream_false_positives.db"
OSS_Fuzz_Data = OSS_TMP / "OSS_Fuzz_Data"

def fp_init():
    """
    Initialize the database for false positives detection.
    Creates tables for upstream_false_positives and upstream_true_positives if they don't exist.
    """
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
    """
    Insert data into the upstream_false_positives table with retry logic.
    
    Args:
        data: Tuple containing (localId, reason, log) to insert
        max_retries: Maximum number of retry attempts
        retry_delay: Base delay between retries
    
    Returns:
        bool: True if successful, raises exception otherwise
    """
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
    """
    Insert data into the upstream_true_positives table with retry logic.
    
    Args:
        data: Tuple containing (localId, reason, log) to insert
        max_retries: Maximum number of retry attempts
        retry_delay: Base delay between retries
    
    Returns:
        bool: True if successful, raises exception otherwise
    """
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
    """
    Retrieve all false positive localIds from the database.
    
    Args:
        max_retries: Maximum number of retry attempts
        retry_delay: Base delay between retries
    
    Returns:
        list: List of localIds marked as false positives, False on error
    """
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
    """
    Retrieve all true positive localIds from the database.
    
    Args:
        max_retries: Maximum number of retry attempts
        retry_delay: Base delay between retries
    
    Returns:
        list: List of localIds marked as true positives, False on error
    """
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
def upstream_state_reason(localId):
    """
    Get the reason for a localId being classified as false positive or true positive.
    
    Args:
        localId: The ID to get the reason for
        
    Returns:
        str: The reason string from the database, or error message if not found
    """
    dataset1 = getFalsePositives()
    dataset2 = getNotFalsePositives()
    if localId not in dataset1 and localId not in dataset2:
        # not in the dataset
        return False
    
    max_retries = 3
    retry_delay = 0.1
    
    if localId in dataset1:
        # Get reason from false positives table
        for attempt in range(max_retries):
            conn = None
            try:
                conn = sqlite3.connect(Database_PATH, timeout=30)
                cursor = conn.cursor()
                cursor.execute("SELECT reason FROM upstream_false_positives WHERE localId = ?", (localId,))
                row = cursor.fetchone()
                if row:
                    return f"{row[0]}"
                else:
                    return "No reason found"
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                return None
            except Exception:
                return None
            finally:
                if conn:
                    conn.close()
    else:
        # Get reason from true positives table
        for attempt in range(max_retries):
            conn = None
            try:
                conn = sqlite3.connect(Database_PATH, timeout=30)
                cursor = conn.cursor()
                cursor.execute("SELECT reason FROM upstream_true_positives WHERE localId = ?", (localId,))
                row = cursor.fetchone()
                if row:
                    return f"{row[0]}"
                else:
                    return "No reason found"
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                return None
            except Exception:
                return None
            finally:
                if conn:
                    conn.close()

def upstream_state_log(localId):
    """
    Get the log for a localId being classified as false positive or true positive.
    
    Args:
        localId: The ID to get the log for
        
    Returns:
        str: The log string from the database, or error message if not found
    """
    dataset1 = getFalsePositives()
    dataset2 = getNotFalsePositives()
    if localId not in dataset1 and localId not in dataset2:
        # not in the dataset
        return False
    
    max_retries = 3
    retry_delay = 0.1
    
    if localId in dataset1:
        # Get log from false positives table
        for attempt in range(max_retries):
            conn = None
            try:
                conn = sqlite3.connect(Database_PATH, timeout=30)
                cursor = conn.cursor()
                cursor.execute("SELECT log FROM upstream_false_positives WHERE localId = ?", (localId,))
                row = cursor.fetchone()
                if row:
                    return f"{row[0]}"
                else:
                    return "No log found"
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                return None
            except Exception:
                return None
            finally:
                if conn:
                    conn.close()
    else:
        # Get log from true positives table
        for attempt in range(max_retries):
            conn = None
            try:
                conn = sqlite3.connect(Database_PATH, timeout=30)
                cursor = conn.cursor()
                cursor.execute("SELECT log FROM upstream_true_positives WHERE localId = ?", (localId,))
                row = cursor.fetchone()
                if row:
                    return f"{row[0]}"
                else:
                    return "No log found"
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                return None
            except Exception:
                return None
            finally:
                if conn:
                    conn.close()

def upstream_state_delete(localId):
    """
    Delete a localId from either false positives or true positives table.
    Automatically detects which table contains the localId and removes it.
    
    Args:
        localId: The ID to delete from the database
        
    Returns:
        str: Success message or error message
    """
    dataset1 = getFalsePositives()
    dataset2 = getNotFalsePositives()
    
    if localId not in dataset1 and localId not in dataset2:
        return False
    
    max_retries = 3
    retry_delay = 0.1
    
    if localId in dataset1:
        # Delete from false positives table
        for attempt in range(max_retries):
            conn = None
            try:
                conn = sqlite3.connect(Database_PATH, timeout=30)
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute("DELETE FROM upstream_false_positives WHERE localId = ?", (localId,))
                if cursor.rowcount > 0:
                    conn.commit()
                    return True
                else:
                    conn.rollback()
                    return False
            except sqlite3.OperationalError as e:
                if conn:
                    conn.rollback()
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                return False
            except Exception as e:
                if conn:
                    conn.rollback()
                return False
            finally:
                if conn:
                    conn.close()
    
    if localId in dataset2:
        # Delete from true positives table
        for attempt in range(max_retries):
            conn = None
            try:
                conn = sqlite3.connect(Database_PATH, timeout=30)
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute("DELETE FROM upstream_true_positives WHERE localId = ?", (localId,))
                if cursor.rowcount > 0:
                    conn.commit()
                    return True
                else:
                    conn.rollback()
                    return False
            except sqlite3.OperationalError as e:
                if conn:
                    conn.rollback()
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                return False
            except Exception as e:
                if conn:
                    conn.rollback()
                return False
            finally:
                if conn:
                    conn.close()
    
    return False
            
# False positives
def check_false_positive(localId):
    """
    Check if a given localId is a false positive by running the false_positive test.
    Logs results and stores them in appropriate database tables.
    
    Args:
        localId: The ID to check for false positive status
    
    Returns:
        str: "False Positive" if it's a false positive, "Not False Positive" otherwise
    """
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

def false_positive(localId,force_reset = False):
    """
    Test if a vulnerability report is a false positive by running POC against compiled binaries.
    Downloads OSS-Fuzz binaries, runs proof-of-concept against vulnerable and fixed versions.
    
    Args:
        localId: The vulnerability ID to test
        force_reset: Force retest even if already cached
    
    Returns:
        bool or None: True if false positive, False if true positive, None if indeterminate
    """
    store = OSS_Fuzz_Data / str(localId)
    def _leaveRet(res,msg=None):
        if msg: WARN(msg)
        shutil.rmtree(store)
        return res
    if not force_reset and localId in getFalsePositives():
        return True
    if localId in getNotFalsePositives():
        return False
    if store.exists():
        shutil.rmtree(store)

    # Do download 
    store.mkdir(parents=True, exist_ok=True)
    while True:
        res = getOSSFuzzer(localId, store,limit=(1<<30)*4) # Limit 10 GB
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
        if None in res:
            return _leaveRet(None,f"[FAILED] {localId=} {x} running enviroment is needed")
        tag = 'fix'
    # clean poc and downloaded binary
    shutil.rmtree(poc.parent)
    shutil.rmtree(store)
        
    if res == [False,True]:
        return False # Not False Positives
    else:
        return True  # False Positives


fp_init()

