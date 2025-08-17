from .utils         import *
from .utils_rep     import *

def get_failed_to_get_fuzz_targets():
    DB_PATH = ARVO / "arvo.db"
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute('SELECT localId FROM arvo WHERE fuzz_target = ?', ('FAILED_TO_GET',))
        rows = cursor.fetchall()
        
        if not rows:
            print('No rows found with fuzz_target == "FAILED_TO_GET"')
            return []
        
        # Extract localId values from the tuples
        localIds = [row[0] for row in rows]
        print(f'Found {len(localIds)} rows with fuzz_target == "FAILED_TO_GET"')
        
        return localIds
    finally:
        conn.close()
def dataset_fix_crash_output():
    """
    Update database records that have crash_ouput: 'Unable to find Image...'
    with correct crash_output
    """
    import sqlite3
    
    # Get all localIds with crash_output containing 'Unable to find Image'
    DB_PATH = ARVO / "arvo.db"
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute("""
            SELECT localId FROM arvo 
            WHERE crash_output LIKE '%Unable to find Image%'
        """)
        failed_localIds = [row[0] for row in cursor.fetchall()]
    finally:
        conn.close()
    
    if not failed_localIds:
        WARN("No records with 'Unable to find Image' crash_output found")
        return
    
    todo = failed_localIds
    
    def _CHECKOUT(localId):
        DB_PATH = ARVO / "arvo.db"
        try:

            # Get crash output
            crash_output = getCrashOutput(localId)
            INFO(f"  Retrieved crash output ({len(crash_output)} chars)")
            
            # Update the database
            conn = sqlite3.connect(DB_PATH)
            try:
                conn.execute("""
                    UPDATE arvo 
                    SET crash_output = ? 
                    WHERE localId = ?
                """, (crash_output, localId))
                conn.commit()
                INFO(f"  Updated database for localId {localId}")
            finally:
                conn.close()
                
        except Exception as e:
            INFO(f"  Error processing localId {localId}: {e}")
            return False
        return True
    xExplore(todo, "dataset_fix.log", _CHECKOUT)
def prune_crash_output():
    """
    sql search the DB_PATH = ARVO / "arvo.db" and find the rows that there are docker pull information in crash_output: Status: "Downloaded newer image for ". Print the localIds and update crash_output to keep only the part after "Downloaded newer image for"
    """
    import sqlite3
    
    DB_PATH = ARVO / "arvo.db"
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute("""
            SELECT localId, crash_output FROM arvo 
            WHERE crash_output LIKE '%Downloaded newer image for%'
        """)
        records = cursor.fetchall()
    finally:
        conn.close()
    if records:
        print(f"Found {len(records)} records with docker pull information:")
        updated_count = 0
        
        for localId, crash_output in records:
            print(f"  Processing localId: {localId}")
            
            # Find the position after "Downloaded newer image for"
            marker = "Downloaded newer image for"
            pos = crash_output.find(marker)
            if pos != -1:
                # Find the end of the line containing the marker
                line_end = crash_output.find('\n', pos)
                if line_end != -1:
                    # Keep everything after this line
                    pruned_output = crash_output[line_end + 1:]
                    
                    # Update the database
                    conn = sqlite3.connect(DB_PATH)
                    try:
                        conn.execute("""
                            UPDATE arvo 
                            SET crash_output = ? 
                            WHERE localId = ?
                        """, (pruned_output, localId))
                        conn.commit()
                        updated_count += 1
                        print(f"    Updated crash_output (removed {len(crash_output) - len(pruned_output)} chars)")
                    finally:
                        conn.close()
        
        print(f"Updated {updated_count} records")
    else:
        print("No records with docker pull information found")

def getFuzzTarget_DBFix(localId):
    cmd = ['docker','run','--rm','-it',f'n132/arvo:{localId}-vul','grep','/tmp/poc','/bin/arvo']
    try:
        output = execute(cmd)
        if not output:
            PANIC("FAILED_TO_GET Fuzz Target")
        output = output.decode()
        # Parse output like: "/out/android_codec /tmp/poc"
        lines = output.strip().split('\n')

        for line in lines:
            line = line.strip()
            if '/out/' in line and '/tmp/poc' in line:
                # Extract the part between /out/ and /tmp/poc
                parts = line.split()
                for part in parts:
                    if part.startswith('/out/') and not part.endswith('/tmp/poc'):
                        fuzz_target = part.replace('/out/', '')
                        return fuzz_target
        
        PANIC("FAILED_TO_GET Fuzz Target")
    except:
        PANIC("FAILED_TO_GET Fuzz Target")
def getCrashOutput(localId):
    cmd = f"docker run --rm -it n132/arvo:{localId}-vul arvo".split(" ")
    tmpfile = tmpFile()
    with open(tmpfile, "w") as f:
        subprocess.run(cmd, stdout=f,stderr=f)
    with open(tmpfile,'rb') as f:
        crash_output = f.read().decode("utf-8", errors="replace").replace("�", "\x00")
    os.remove(tmpfile)
    return crash_output

def dataset_fix_fuzz_target():
    """
    Update database records that have fuzz_target = 'FAILED_TO_GET'
    with correct fuzz_target and crash_output
    """
    import sqlite3
    
    # Get all localIds with FAILED_TO_GET fuzz_target
    failed_localIds = get_failed_to_get_fuzz_targets()
    
    if not failed_localIds:
        WARN("No records with FAILED_TO_GET fuzz_target found")
        return
    
    todo = failed_localIds
    
    def _CHECKOUT(localId):
        DB_PATH = ARVO / "arvo.db"
        try:
            # Get the correct fuzz target
            fuzz_target = getFuzzTarget_DBFix(localId)
            INFO(f"  Found fuzz_target: {fuzz_target}")
            
            # Get crash output
            crash_output = getCrashOutput(localId)
            INFO(f"  Retrieved crash output ({len(crash_output)} chars)")
            
            # Update the database
            conn = sqlite3.connect(DB_PATH)
            try:
                conn.execute("""
                    UPDATE arvo 
                    SET fuzz_target = ?, crash_output = ? 
                    WHERE localId = ?
                """, (fuzz_target, crash_output, localId))
                conn.commit()
                INFO(f"  Updated database for localId {localId}")
            finally:
                conn.close()
                
        except Exception as e:
            INFO(f"  Error processing localId {localId}: {e}")
            return False
        return True
    xExplore(todo, "dataset_fix.log", _CHECKOUT)
def dataset_info_correct():
    dataset_fix_crash_output()
    prune_crash_output()