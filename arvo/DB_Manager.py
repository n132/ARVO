from pathlib import Path
from ._profile import *
import json
import shutil
from time import sleep
from base58 import b58encode
from typing import Dict, Union, Optional
from .utils_log import FAIL, WARN, INFO, PANIC
OSS_DB      = Path(OSS_DB_DIR)
OSS_DB_MAP  = OSS_DB/"map"
OSS_DB_LOCK = OSS_DB/"map.lock"
RETRY       = 4
from filelock import FileLock
LOG = Path(ARVO_DIR) / "Log"

if not LOG.exists():
    LOG.mkdir(exist_ok=True)

def updateCrashLog(result: str, log_file: str, perm: str = 'a') -> bool:
    """Update crash log file with result message using file locking."""
    if not result or not log_file:
        return False
    try:
        logFilelock = LOG / f"{log_file}.lock"
        logFile = LOG / f"{log_file}"
        lock = FileLock(logFilelock)
        with lock:
            with open(logFile, perm, encoding='utf-8') as f:
                f.write(result + "\n")
        return True
    except Exception as e:
        FAIL(f"Failed to update crash log {log_file}: {e}")
        return False
def DB_DUMP(rec: Dict[str, str]) -> bool:
    """Dump database record to JSON file with retry mechanism."""
    if not isinstance(rec, dict):
        FAIL("DB_DUMP: Invalid record type, expected dict")
        return False
    
    ct = 0 
    while ct < RETRY:
        try:
            lock = FileLock(OSS_DB_LOCK)
            with lock:
                with open(OSS_DB_MAP, 'w', encoding='utf-8') as f:
                    json.dump(rec, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            WARN(f"DB_DUMP attempt {ct + 1} failed: {e}")
            sleep(0.3)
            ct += 1
    
    FAIL("DB_DUMP: All retry attempts failed")
    return False
def DB_INSERT(url: str, orig: Path) -> bool:
    """Insert a directory into the database with URL as key."""
    if not url or not isinstance(orig, Path):
        FAIL("DB_INSERT: Invalid parameters")
        return False
    
    if not orig.exists():
        WARN(f"DB_INSERT: Source path does not exist: {orig}")
        return False
    
    try:
        rec = DB_MAP()
        if url in rec:
            del rec[url]
        
        dest = OSS_DB / b58encode(url.encode()).decode()
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, exist_ok=True)
        
        shutil.copytree(orig, dest / orig.name, symlinks=True)
        rec[url] = str(dest / orig.name)
        
        if not DB_DUMP(rec):
            PANIC("DB_INSERT: Failed to update database")
        
        INFO(f"DB_INSERT: Successfully inserted {url}")
        return True
    except Exception as e:
        FAIL(f"DB_INSERT: Failed to insert {url}: {e}")
        return False


def DB_CHECK(url: str) -> Union[Path, bool]:
    """Check if URL exists in database and return path if valid."""
    if not url:
        return False
    
    try:
        db_map = DB_MAP()
        if url in db_map:
            res = Path(db_map[url])
            if res.exists():
                return res
            else:
                WARN(f"DB_CHECK: Path no longer exists for {url}, removing from database")
                DB_remove(url, res)
                return False
        else:
            return False
    except Exception as e:
        FAIL(f"DB_CHECK: Error checking {url}: {e}")
        return False
def DB_MAP() -> Dict[str, str]:
    """Load database mapping from JSON file with retry mechanism."""
    ct = 0 
    while ct < RETRY * 2:
        try:
            with open(OSS_DB_MAP, 'r', encoding='utf-8') as f:
                res = json.load(f)
            return res if isinstance(res, dict) else {}
        except FileNotFoundError:
            WARN("DB_MAP: Database map file not found, creating empty map")
            empty_map = {}
            if DB_DUMP(empty_map):
                return empty_map
            else:
                FAIL("DB_MAP: Failed to create empty map")
                break
        except Exception as e:
            WARN(f"DB_MAP attempt {ct + 1} failed: {e}")
            sleep(0.3)
            ct += 1
    
    PANIC("DB_MAP: All retry attempts failed")
def DB_remove(url: str, path: Path) -> bool:
    """Remove entry from database and delete associated files."""
    if not url:
        WARN("DB_remove: Empty URL provided")
        return False
    
    try:
        if isinstance(path, Path) and path.exists():
            shutil.rmtree(path)
            INFO(f"DB_remove: Deleted directory {path}")
        
        data = DB_MAP()
        if url in data:
            del data[url]
            INFO(f"DB_remove: Removed {url} from database")
        
        return DB_DUMP(data)
    except Exception as e:
        FAIL(f"DB_remove: Failed to remove {url}: {e}")
        return False
    