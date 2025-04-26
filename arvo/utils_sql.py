########################################################
# Sqlite support for ARVO
########################################################
import sqlite3
from .utils_init    import *
from .utils_log     import *
from .utils         import *
DB_PATH = ARVO / "arvo.db"
FalsePositiveDB_PATH = ARVO / "false_positive.db"

def db_init():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS arvo (
            localId INTEGER PRIMARY KEY,
            project TEXT NOT NULL,
            reproduced BOOLEAN NOT NULL,
            reproducer_vul TEXT,
            reproducer_fix TEXT,
            patch_located BOOLEAN,
            patch_url TEXT,
            verified BOOLEAN,
            fuzz_target TEXT,
            fuzz_engine TEXT,
            sanitizer TEXT,
            crash_type TEXT,
            crash_output TEXT,
            severity TEXT,
            report TEXT,
            fix_commit TEXT,
            language TEXT
        )
        """)
        conn.commit()
def insert_entry(data):
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level="EXCLUSIVE")
    try:
        conn.execute("BEGIN EXCLUSIVE")
        conn.execute("""
        INSERT INTO arvo (
            localId, project, reproduced, reproducer_vul, reproducer_fix, patch_located,
            patch_url, verified, fuzz_target, fuzz_engine,
            sanitizer, crash_type, crash_output, severity, report, fix_commit, language
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, data)
        conn.commit()
        return True
    except:
        FAIL("[-] FAILED to INSERT to DB")
        return False
    finally:
        conn.close()
def delete_entry(localId):
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level="EXCLUSIVE")
    try:
        conn.execute("BEGIN EXCLUSIVE")
        conn.execute("DELETE FROM arvo WHERE localId = ?", (localId,))
        conn.commit()
        return True
    except:
        FAIL("[-] FAILED to DELETE from DB")
        return False
    finally:
        conn.close()
def arvoRecorded(local_id):
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute("""
            SELECT reproduced, patch_located 
            FROM arvo WHERE localId = ?
        """, (local_id,))
        return cursor.fetchone()
    except:
        FAIL("[-] Failed to access DB")
        return False
    finally:
        conn.close()
def fp_init():
    with sqlite3.connect(FalsePositiveDB_PATH) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS false_positive (
            localId INTEGER PRIMARY KEY,
            reason TEXT
        )
        """)
        conn.commit()
def fp_insert(data):
    conn = sqlite3.connect(FalsePositiveDB_PATH, timeout=30, isolation_level="EXCLUSIVE")
    try:
        conn.execute("BEGIN EXCLUSIVE")
        conn.execute("""
        INSERT INTO false_positive (
            localId, reason
        ) VALUES (?, ?)
        """, data)
        conn.commit()
        return True
    except:
        FAIL("[-] FAILED to INSERT to FalsePositiveDB")
        return False
    finally:
        conn.close()
def getFalsePositives():
    conn = sqlite3.connect(FalsePositiveDB_PATH, timeout=30, isolation_level="EXCLUSIVE")
    cursor = conn.cursor()
    try:
        cursor.execute("""
        SELECT * FROM false_positive
        """)
        rows = cursor.fetchall()
        res = []
        for x in rows:
            res.append(x[0])
        return res
    except:
        FAIL("[-] FAILED to get data from FalsePositiveDB")
        return False
    finally:
        conn.close()