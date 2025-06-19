########################################################
# Sqlite support for ARVO
########################################################
import sqlite3
from .utils_init    import *
from .utils_log     import *
from .utils         import *
DB_PATH = ARVO / "arvo.db"
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
    for _ in range(10):
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
            conn.close()
            return True
        except:
            WARN(f"Failed to update the dataset, retry ({_}/10)")            
    FAIL("[-] FAILED to INSERT to DB")
    conn.close()
    return False
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
