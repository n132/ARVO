########################################################
# Sqlite support for ARVO
########################################################
import sqlite3
from tqdm           import tqdm
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
            docker_env TEXT,
            patch_located BOOLEAN,
            patch_url TEXT,
            verified BOOLEAN,
            fuzz_target TEXT,
            fuzz_engine TEXT,
            sanitizer TEXT,
            crash_type TEXT,
            crash_output TEXT,
            severity TEXT,
            report TEXT
        )
        """)
        conn.commit()
def db_getDone():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("SELECT localId FROM arvo")
        return [row[0] for row in cursor.fetchall()]
def insert_entry(data):
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level="EXCLUSIVE")
    try:
        conn.execute("BEGIN EXCLUSIVE")
        conn.execute("""
        INSERT INTO arvo (
            localId, project, reproduced, docker_env, patch_located,
            patch_url, verified, fuzz_target, fuzz_engine,
            sanitizer, crash_type, crash_output, severity, report
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, data)
        conn.commit()
    finally:
        FAIL("[-] FAILED to INSERT to DB")
        conn.close()

# def sync_db():
#     done = getDone()
#     db_done = db_getDone()
#     todo = [x for x in done if x not in db_done]
#     weird_cases = []
#     for x in tqdm(todo):
#         localId = x 
#         project = getPname(localId)
#         reproduced = True
#         report = getReport(localId)
#         docker_env = "TODO"
#         if report:
#             patch_located = True
#             patch_url     = report['fix']
#             verified      = True if report['verify'] == '1' else False
#             assert(localId == report['localId'])
#             if(project != report['project']):
#                 weird_cases.append(localId)
#                 continue
#             fuzz_target    = "TODO"
#             fuzz_engine    = report['fuzzer']
#             sanitizer      = report['sanitizer']
#             crash_type     = report['crash_type']
#             crash_output   = "TODO"
#             severity       = report['severity'] if 'severity' in report else "UNK"
#             report         = json.dumps(report,indent=4)
#             insert_entry((localId, project, reproduced, docker_env, patch_located,
#             patch_url, verified, fuzz_target, fuzz_engine,
#             sanitizer, crash_type, crash_output, severity, report))
#         else:
#             pass
#     print(weird_cases)