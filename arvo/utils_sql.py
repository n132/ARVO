########################################################
# Sqlite support for ARVO
########################################################
import sqlite3
from .utils_init    import *
from .utils_log     import *
from .utils         import *
import fcntl  # Only works on Unix
import time

DB_PATH = ARVO / "arvo.db"

LOCK_PATH = ARVO / "arvo.db.lock"

def db_init():
    with open(LOCK_PATH, 'w') as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)  # block until lock acquired
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("PRAGMA journal_mode=WAL")  # better for concurrency
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

def insert_entry(data, max_retries=5, retry_delay=0.1):
    for attempt in range(max_retries):
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH, timeout=30)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("""
            INSERT INTO arvo (
                localId, project, reproduced, reproducer_vul, reproducer_fix, patch_located,
                patch_url, verified, fuzz_target, fuzz_engine,
                sanitizer, crash_type, crash_output, severity, report, fix_commit, language
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, data)
            conn.commit()
            return True
        except sqlite3.OperationalError as e:
            if conn:
                conn.rollback()
            if "database is locked" in str(e) and attempt < max_retries - 1:
                WARN(f"Database locked, retrying ({attempt + 1}/{max_retries})")
                time.sleep(retry_delay * (2 ** attempt))
                continue
            FAIL(f"[-] FAILED to INSERT to DB: {e}")
            return False
        except Exception as e:
            if conn:
                conn.rollback()
            FAIL(f"[-] FAILED to INSERT to DB: {e}")
            return False
        finally:
            if conn:
                conn.close()
def delete_entry(localId, max_retries=3, retry_delay=0.1):
    for attempt in range(max_retries):
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH, timeout=30)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM arvo WHERE localId = ?", (localId,))
            conn.commit()
            return True
        except sqlite3.OperationalError as e:
            if conn:
                conn.rollback()
            if "database is locked" in str(e) and attempt < max_retries - 1:
                WARN(f"Database locked, retrying delete ({attempt + 1}/{max_retries})")
                time.sleep(retry_delay * (2 ** attempt))
                continue
            FAIL(f"[-] FAILED to DELETE from DB: {e}")
            return False
        except Exception as e:
            if conn:
                conn.rollback()
            FAIL(f"[-] FAILED to DELETE from DB: {e}")
            return False
        finally:
            if conn:
                conn.close()
def arvoRecorded(local_id, max_retries=3, retry_delay=0.1):
    for attempt in range(max_retries):
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH, timeout=30)
            cursor = conn.execute("""
                SELECT reproduced, patch_located 
                FROM arvo WHERE localId = ?
            """, (local_id,))
            return cursor.fetchone()
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                WARN(f"Database locked, retrying read ({attempt + 1}/{max_retries})")
                time.sleep(retry_delay * (2 ** attempt))
                continue
            FAIL(f"[-] Failed to access DB: {e}")
            return False
        except Exception as e:
            FAIL(f"[-] Failed to access DB: {e}")
            return False
        finally:
            if conn:
                conn.close()
