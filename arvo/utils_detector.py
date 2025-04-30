import sqlite3
from .utils import *
FalsePositiveDB_PATH = ARVO / "false_positive.db"
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
fp_init()
