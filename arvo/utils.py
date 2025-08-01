import re, shutil, requests, sys, math, tiktoken
from datetime       import datetime
from base58         import b58encode
from .utils_exec    import *
from .utils_docker  import *
from .DB_Manager    import *
from .utils_log     import *
from .transform     import pname_table, trans_table
from .utils_init    import *
from .utils_sql     import *
from rich.progress import Progress
from collections.abc import Sized
from .avoid         import avoid_issues

def getAvoid():
    return avoid_issues

def initARVODir(dirs):
    for i in dirs:
        if not i.exists():
            i.mkdir()
initARVODir([DOCKER_PUSH_QUEUE,OSS_LOCK,OSS_IMG,OSS_TMP,OSS_OUT,OSS_WORK,OSS_DB,OSS_ERR,ExeLog,ARVO_ZDC])
if not OSS_DB_MAP.exists():
    OSS_DB_MAP.touch()
    with open(OSS_DB_MAP,'w') as f:
        f.write(json.dumps(dict(),indent=4))
session = requests.Session()

# Init Done
def eventLog(s,ext=False):
    FAIL(s)
    with open(ARVO/"Log"/"_Event.log",'a') as f:
        f.write(s+"\n")
    if ext:
        exit(1)
    else:
        return False
def tmpDir(path=OSS_TMP,pre="ARVO_",dont_mk=False):
    name = pre+b58encode(os.urandom(16)).decode()
    res = Path(path)
    res = res/name
    if(not dont_mk):
        res.mkdir()
    return res
def tmpFileName(n=0x10):
    return b58encode(os.urandom(n)).decode()
def tmpFile():
    tmpfile = tmpDir() / tmpFileName()
    tmpfile.touch()
    return tmpfile
def clean_dir(victim):
    if not victim.exists():
        return True
    try:
        shutil.rmtree(victim)
        return True
    except:
        WARN(f"[FAILED] to remove tmp file {victim}")
        return False
def leaveRet(return_val,tmp_dir):
    if not CLEAN_TMP: return return_val
    if type(tmp_dir) != list:
        clean_dir(tmp_dir)
    else:
        for _ in tmp_dir: clean_dir(_)
    return return_val
def remove_oss_fuzz_img(localId):
    imgName = f"gcr.io/oss-fuzz/{localId}"
    INFO(f"[+] Delete images, {imgName}")
    docker_rmi(imgName)

#==================================================================
#
#                  OSS-fuzz meta retrive
#
#==================================================================
def get_projectInfo(localId,pname=None):
    srcmap = getSrcmaps(localId)
    if(len(srcmap)!=2):
        eventLog(f"[-] get_projectInfo: Can't find enough srcmaps: {localId}",True)
    if not pname: pname = getPname(localId)
    with open(srcmap[0]) as f:
        info1 = json.load(f)["/src/"+pname]
    with open(srcmap[1]) as f:
        info2 = json.load(f)["/src/"+pname]
    _,info1['url'],info1['type'] = trans_table("/src/"+pname,info1['url'],info1['type'])
    _,info2['url'],info2['type'] = trans_table("/src/"+pname,info2['url'],info2['type'])
    if info1['url'] == None or info2['url'] == None:
        return False
    return info1, info2
def prepareLatestOssfuzz(pname):
    '''
    This function prepare a current version oss-fuzz
    '''
    tmp_dir          = clone("https://github.com/google/oss-fuzz.git",name="oss-fuzz")
    tmp_oss_fuzz_dir = tmp_dir / "oss-fuzz"
    tmp_list = [x for x in tmp_oss_fuzz_dir.iterdir() if x.is_dir()]
    if tmp_oss_fuzz_dir/ "projects" in tmp_list:
        proj_dir = tmp_oss_fuzz_dir/ "projects" / pname
    elif tmp_oss_fuzz_dir/ "targets" in tmp_list:
        # support aceint oss-fuzz
        proj_dir = tmp_oss_fuzz_dir/ "targets" / pname
    else:
        return leaveRet(False,tmp_dir)
    return proj_dir,tmp_dir
def prepareOssfuzz(localId,tag='vul'):
    '''
    This function prepare a old version oss-fuzz for a specific case
    '''
    commit_date = getDate(localId,tag)
    project_name = getPname(localId,False)
    if not project_name or not commit_date:
        return False
    # 1. Clone OSS Fuzz
    tmp_dir          = clone("https://github.com/google/oss-fuzz.git",name="oss-fuzz")
    # 2. Get the Commit Close to Commit_Date
    tmp_oss_fuzz_dir = tmp_dir / "oss-fuzz"
    cmd = ['git','log','--before='+ commit_date.isoformat(), '-n1', '--format=%H']
    oss_fuzz_commit = execute(cmd,tmp_oss_fuzz_dir).strip()
    if not oss_fuzz_commit:
        cmd = ['git','log','--reverse', '--format=%H']
        oss_fuzz_commit = execute(cmd,tmp_oss_fuzz_dir).splitlines()[0].strip()
        if not oss_fuzz_commit:
            return leaveRet(False,tmp_dir)
    # 3. Reset OSS Fuzz
    try:
        cmd = ['git','reset','--hard',oss_fuzz_commit]
        execute(cmd,tmp_oss_fuzz_dir)
    except:
        return leaveRet(False,tmp_dir)
    # 4. Locate Project Dir
    tmp_list = [x for x in tmp_oss_fuzz_dir.iterdir() if x.is_dir()]
    if tmp_oss_fuzz_dir/ "projects" in tmp_list:
        proj_dir = tmp_oss_fuzz_dir/ "projects" / project_name
    elif tmp_oss_fuzz_dir/ "targets" in tmp_list:
        proj_dir = tmp_oss_fuzz_dir/ "targets" / project_name
    else:
        return leaveRet(False,tmp_dir)
    return proj_dir,tmp_dir
def getBuildScript(localId,tag='vul'):
    pof = prepareOssfuzz(localId,tag)
    if pof == False:
        return False
    proj_dir, tmp_dir = pof
    # Get the Buildscript
    buildscript = proj_dir/"build.sh"
    if not buildscript.exists():
        return leaveRet(False,tmp_dir)
    with open(buildscript) as f:
        buildscript = f.read()
    return leaveRet(buildscript,tmp_dir)
def getDockerfile(localId,tag='vul'):
    pof = prepareOssfuzz(localId,tag)
    if pof == False:
        return False
    proj_dir, tmp_dir = pof
    # Get the Dockerfile
    dockerfile = proj_dir/"Dockerfile"
    if not dockerfile.exists():
        return leaveRet(False,tmp_dir)
    with open(dockerfile) as f:
        dockerfile = f.read()
    return leaveRet(dockerfile,tmp_dir)
def getProjectYaml(localId,tag='vul'):
    pof = prepareOssfuzz(localId,tag)
    if pof == False:
        return False
    proj_dir, tmp_dir = pof
    # Get the Dockerfile
    porjymal = proj_dir/"project.yaml"
    if not porjymal.exists():
        return leaveRet(False,tmp_dir)
    with open(porjymal) as f:
        porjymal = f.read()
    return leaveRet(porjymal,tmp_dir)
def getLanguage(localId):
    # Fast Path
    project_name = getPname(localId,False)
    if project_name in PLanguage.keys(): return PLanguage[project_name]
    # Slow Path
    porjymal = getProjectYaml(localId)
    if porjymal== False:
        eventLog(f"[!] getLanguage: Failed to get project.yaml file, {localId}")
        return False
    res = re.findall(r'language\s*:\s*([^\s]+)',porjymal)
    if len(res) != 1:
        eventLog(f"[!] getLanguage: Get more than one languages, {localId}")
        return False
    language = str(res[0])
    PLanguage[project_name] = language
    return language     
def getDate(localId,tag="vul"):
    srcmaps = getSrcmaps(localId)
    if len(srcmaps)!=2:
        return False
    if tag != "fix":
        srcmap_name = srcmaps[0].name
    else:
        srcmap_name = srcmaps[1].name
    commit_date = srcmap_name.split(".")[0].split("-")[-1]
    return str2date(commit_date,STAMP_DELAY)
def getDone(avoid=False, avoid_list=['binutils', 'libreoffice']):
    conn = sqlite3.connect(DB_PATH)
    try:
        if avoid:
            placeholders = ','.join('?' for _ in avoid_list)
            query = f"SELECT localId FROM arvo WHERE reproduced = 1 AND project NOT IN ({placeholders})"
            cursor = conn.execute(query, avoid_list)
        else:
            cursor = conn.execute("SELECT localId FROM arvo WHERE reproduced = 1")
        return [row[0] for row in cursor.fetchall()]
    except:
        return False
    finally:
        conn.close()
def getEngine(localId):
    # ['afl', 'libfuzzer', 'honggfuzz']
    issue = getIssue(localId)
    if not issue:
        return False
    engine = issue['job_type'].split("_")[0]
    if engine not in ['libfuzzer','afl','honggfuzz','centipede']:
        return False
    return engine
def getSan(localId):
    # ['memory', 'address', 'undefined']
    issue = getIssue(localId)
    if not issue:
        return False
    return getSanitizer(issue['job_type'].split("_")[1])
def getArch(localId):
    issue = getIssue(localId)
    if not issue:
        return False
    if issue['job_type'].split("_")[2]=="i386":
        return 'i386'
    else:
        return 'x86_64'
def getPname(localId,srcmapCheck=True):
    srcmap,issue = getIssueTuple(localId)
    if not srcmap or not issue:
        FAIL("[FAILED] to get srcmap/issue")
        return False
    if 'project' not in issue:
        FAIL("[FAILED] to get project feild in issue")
        return False
    else:
        pname = issue['project']
    if srcmapCheck == False: 
        return pname # return when no check
    if pname in pname_table: 
        return pname_table[pname] # handling special cases
    with open(srcmap[0]) as f: 
        info1 = json.load(f)
    with open(srcmap[1]) as f: 
        info2 = json.load(f)
    except_name = "/src/" + pname
    if (except_name in info1) and (except_name in info2) and (info1[except_name]!=info2[except_name]):
        return pname
    else:
        # Chose the first common one, it may be wrong
        candidates = []
        for x in info2.keys():
            if x in list(info1.keys()):
                candidates.append(x)
        if len(candidates)==0:
            eventLog(f"[Pname]: {localId} could be a false positive since vulsrcmap~=fixedsrcmap")
            return False

        first_item = "/"
        for x in candidates:
            if x!="/src" and x!='/src/aflplusplus' and x!='/src/libfuzzer' and x!='/src/afl' and info2[x]['rev']!=info1[x]['rev']:
                first_item = x
                break
        if first_item=="/":
            return False
        pname = first_item.split("/")[-1]
        if pname == 'qtqa' and '/src/qt/qtqa' in candidates:
            pname = 'qt/qtqa'
        return pname
def getLocalIdsBetween(start,end):
    res = []
    with open(MetaDataFile) as f:
        while(1):
            line = f.readline()
            if(not line):
                break
            line = json.loads(line)
            localId = int(line['localId'])
            if localId>= start and localId <= end:
                res.append(localId)
    return res
def getAllLocalIds():
    return getLocalIdsBetween(0,math.inf)
def getIssueTuple(localId):
    srcmap = getSrcmaps(localId)
    issue  = getIssue(localId)
    return srcmap,issue
def getPoc(localId,issue=None, outPath = None):
    case_dir = outPath.parent if outPath else tmpDir()
    name = outPath.name if outPath else "poc"
    issue = issue if issue else getIssue(localId)
    try:
        pocPath = downloadPoc(issue,case_dir,name)
    except:
        pocPath = False
    if not pocPath or not pocPath.exists():
        eventLog(f"[-] getPoc {localId}: Failed to download PoC")
        return leaveRet(None,case_dir)
    return pocPath
def mapMapping():
    global MAPPING
    if MAPPING:
        return MAPPING
    with open(ARVO/"oss_fuzz_mappings.csv","r") as f:
            lines = f.readlines()
    MAPPING = {}
    for line in lines:
        tmp  = line.split(",")
        MAPPING[int(tmp[0])] = int(tmp[1])
    return MAPPING
def mapMappingRev():
    with open(ARVO/"oss_fuzz_mappings.csv","r") as f:
            lines = f.readlines()
    res = {}
    for line in lines:
        tmp  = line.split(",")
        res[int(tmp[1])] = int(tmp[0])
    return res
def getSrcmaps(localId):
    def _cmp(a):
        return str(a)
    issue_dir = DATADIR / "Issues" / (str(localId) + "_files")
    if not issue_dir.exists():
        eventLog(f"[-] no such issue_dir for {localId}")
        return False
    srcmap = list(issue_dir.glob('*.srcmap.json'))
    srcmap.sort(key=_cmp)
    return srcmap
def bar(iterable, description="[ARVO]"):
    total = len(iterable) if isinstance(iterable, Sized) else None
    with Progress() as progress:
        task = progress.add_task(description, total=total)
        for item in iterable:
            yield item
            progress.update(task, advance=1)
def listProject(pro_names):
    if type(pro_names) == type(""):
        pro_names = [pro_names]
    res = []
    with open(MetaDataFile) as f:
        while(1):
            line = f.readline()
            if(not line):
                break
            line = json.loads(line)
            try:
                pro = line["project"]
                if pro in pro_names:
                    res.append(line['localId'])
            except:
                pass
    return res
def getMainComponent(localId):
    pname   = getPname(localId)
    if pname == False:
        return False
    srcmap  = getSrcmaps(localId)
    with open(srcmap[0]) as f:
        info1 = json.load(f)
    except_name = "/src/"+pname
    if except_name in info1:
        return except_name
    else:
        with open(srcmap[1]) as f:
            info2 = json.load(f)
        first_common_key = None
        for _ in info1.keys():
            if _ in info2.keys():
                first_common_key = _
                break
        # chose the first one if it doesn't work just give up it
        if first_common_key == None:
            return False
        return first_common_key
def getCrashType(localId):
    return getIssue(localId)['crash_type']
def getAllIssues():
    data = getMetadata()
    res = []
    for line in data:
        issue = json.loads(line)
        res.append(issue)
    return res
def getIssue(localId):
    data = getMetadata()
    if isinstance(localId,str):
        localId = int(localId)
    for _ in data:
        issue = json.loads(_)
        if(issue['localId']==localId):
            return issue
    eventLog(f"[-] no such issue, {localId}")
    return False
def getDepNum(localId):
    srcmaps = getSrcmaps(localId)
    if not srcmaps:
        return None
    res = 0
    for srcmap in srcmaps:
        with open(srcmap) as f:
            keys = list(json.loads(f.read()).keys())
        if '/src/afl' in keys:
            keys.remove('/src/afl')
        if '/src/aflplusplus' in keys:
            keys.remove('/src/aflplusplus')
        if '/src/libfuzzer' in keys:
            keys.remove('/src/libfuzzer')
        res += len(keys)
    return (res-2)//2
def getFuzzer(localId,wkdir):
    """
    search the fuzzer at wkdir
    """
    issue = getIssue(localId)
    def _checkexist(name):
        return True if (wkdir / name).exists() else False
    def _findFuzzer(key,off):
        name = "_".join(issue[key].split("_")[off:])
        if _checkexist(name):
            return wkdir / name
        else:
            if name.startswith("afl") or name.startswith("libfuzzer") or name.startswith("honggfuzz"):
                name = "_".join(name.split("_")[off+1:])
                if _checkexist(name):
                    return wkdir / name
                else:
                    return issue_record(issue['project'],localId,f"Failed to get the fuzzer",retv=None)
    if "fuzz_target" in issue:
        return _findFuzzer("fuzz_target",0)
    elif "fuzzer" in issue:
        return _findFuzzer("fuzzer",1)
    elif 'issue' in issue and 'summary' in issue['issue']:
        name = issue['issue']['summary'].split(":")[1]
        if _checkexist(name):
            return wkdir / name
        else:
            return issue_record(issue['project'],localId,f"Failed to get the fuzzer in summary",retv=None)
    else:
        return issue_record(issue['project'],localId,f"Doesn't specify a fuzzer",retv=None)
def downloadPoc(issue,path,name):
    global session
    session = requests.Session()
    url = issue['reproducer']
    response = session.head(url, allow_redirects=True)

    if response.status_code != 200:
        return False
    reproducer_path = path / name
    response = session.get(url)

    if response.status_code != 200:
        return False
    reproducer_path.write_bytes(response.content)
    return reproducer_path
def getSanitizer(fuzzer_sanitizer):
    if(fuzzer_sanitizer=='asan'):
        fuzzer_sanitizer    ="address"
    elif(fuzzer_sanitizer=='msan'):
        fuzzer_sanitizer    ='memory'
    elif(fuzzer_sanitizer=='ubsan'):
        fuzzer_sanitizer    ='undefined'
    else:
        fuzzer_sanitizer = False
    return fuzzer_sanitizer
def getMetadata():
    with open(MetaDataFile) as f:
        data = f.readlines()
    return data
def str2date(issue_date,offset="+0000"):
    return datetime.strptime(issue_date+" "+offset, '%Y%m%d%H%M %z')
def issue_record(name,localId,des,log_addr = "_CrashLOGs",retv=False):
    filename = ARVO / log_addr
    FAIL(f"| {name} | {localId} | {des} |")
    with open(filename,'a+') as f:
        f.write(f"| {name} | {localId} | {des} |\n")
    return retv
def getReports():
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute("SELECT localId FROM arvo WHERE patch_located = 1")
        return [row[0] for row in cursor.fetchall()]
    except:
        return False
    finally:
        conn.close()
def getReport(localId):
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute(f"SELECT * FROM arvo WHERE localId = {localId}")
        meta_data = cursor.fetchall()[0]
        res = {}
        res['localId'] = meta_data[0]
        res['project'] = meta_data[1]
        res['reproduced'] = True if meta_data[2] else False
        res['reproducer_vul'] = meta_data[3]
        res['reproducer_fix'] = meta_data[4]
        res['patch_located'] = True if meta_data[5] else False
        res['patch_url'] = meta_data[6]
        res['verified'] = True if meta_data[7] else False
        res['fuzz_target'] = meta_data[8]
        res['fuzz_engine'] = meta_data[9]
        res['sanitizer'] = meta_data[10]
        res['crash_type'] = meta_data[11]
        res['crash_output'] = meta_data[12]
        res['severity'] = meta_data[13]
        res['report']  = meta_data[14]
        res['fix_commit']  = meta_data[15]
        res['language']  = meta_data[16]
        return res
    except:
        FAIL(f"[FAILED] to find the reported case: {localId}")
        return False
    finally:
        conn.close()
    # if fname.exists():
    #     return json.loads(open(fname).read())
    # return False

#==================================================================
#
#                  Version Control Part Starts
#
#==================================================================
def git_pull(cwd):
    with open("/dev/null",'w') as f:
        return check_call(['git','pull'],cwd=cwd,stderr=f,stdout=f)
def hg_pull(cwd):
    with open("/dev/null",'w') as f:
        return check_call(['hg','pull'],cwd=cwd,stderr=f,stdout=f)
def svn_pull(cwd):
    with open("/dev/null",'w') as f:
        return check_call(['svn','update'],cwd=cwd,stderr=f,stdout=f)
def clone(url,commit=None,dest=None,name=None,main_repo=False,commit_date=None):
    def _git_clone(url,dest,name):
        if dbCOPY(url,dest,name):
            return True
        cmd = ['git','clone',url]
        if name != None:
            cmd.append(name)
        if not check_call(cmd,dest):
            return False
        if name == None:
            name = list(dest.iterdir())[0]
        return DB_INSERT(url,dest/name)
    def _check_out(commit,path):
        with open('/dev/null','w') as f:
            return check_call(['git',"reset",'--hard', commit], cwd=path, stdout=f)
    if(dest):
        dest = Path(dest)
    else:
        dest = tmpDir()

    if not _git_clone(url,dest,name):
        eventLog(f"[!] - clone: Failed to clone {url}")
        return False
    if commit:
        if name==None:
            name = list(dest.iterdir())[0]
        if _check_out(commit,dest / name):
            return dest
        else:
            if main_repo == True:
                eventLog(f"[!] - clone: Failed to checkout {name}")
                return False
            else:
                if commit_date==None:
                    eventLog(f"[!] - clone: Failed to checkout {name} but it's not the main component, using the latest version")
                    return dest
                WARN("[!] Failed to checkout, try a version before required commit")
                cmd = ["git", "log", f"--before='{commit_date.isoformat()}'", "--format='%H'", "-n1"]
                commit = execute(cmd , dest/ name).decode().strip("'")
                INFO(f"[+] Checkout to {commit}")
                if _check_out(commit, dest / name):
                    return dest
                else:
                    eventLog(f"[!] - clone: Failed to checkout {name}")
                    return False
    return dest
def svn_clone(url,commit=None,dest=None,rename=None):
    def _svn_clone(url,dest,name=None):
        if dbCOPY(url,dest,name):
            return True
        cmd = "svn co".split(" ")
        cmd +=[url]
        if name:
            cmd.append(name)
        if not check_call(cmd,dest):
            return False
        if name == None:
            name = list(dest.iterdir())[0]
        return DB_INSERT(url,dest/name)
    if(dest):
        tmp = Path(dest)
    else:
        tmp = tmpDir()
    if not _svn_clone(url,tmp,rename):
        eventLog(f"[!] - svn_clone: Failed to clone {url}")
        return False
    if commit:
        name = rename if rename else list(tmp.iterdir)[0]
        if execute(['svn',"up",'--force','-r', commit], cwd=tmp / name)==False:
            return False
    return tmp
def hg_clone(url,commit=None,dest=None,rename=None):
    def _hg_clone(url,dest,name=None):
        if dbCOPY(url,dest,name):
            return True
        cmd = "hg clone".split(" ")
        cmd +=[url]
        if name:
            cmd.append(name)
        if not check_call(cmd,dest):
            return False
        if name == None:
            name = list(dest.iterdir())[0]
        return DB_INSERT(url,dest/name)
    if(dest):
        tmp = Path(dest)
    else:
        tmp = tmpDir()
    if not _hg_clone(url,tmp,rename):
        eventLog(f"[!] - hg_clone: Failed to clone {url}")
        return False
    if commit:
        if rename:
            name = rename
        else:
            name = list(tmp.iterdir())[0]
        tmp = tmp / name
        if check_call(['hg',"update", '--clean', '-r', commit], cwd=tmp) and \
        check_call(['hg',"purge", '--config', 'extensions.purge='], cwd=tmp):
            pass
        else:
            return False
    return tmp
def dbCOPY(url,dest,name):
    records = DB_MAP()
    if url in records.keys():
        original_dir = records[url]
        db_repo = Path(original_dir)
        if db_repo.exists():
            if name == None:
                name = db_repo.name
            try:
                shutil.copytree(original_dir,dest/name,symlinks=True)
                return True
            except:
                return False
        else:
            DB_remove(url,db_repo)
            return False
    else:
        return False

#==================================================================
#
#                  Crash Check Part
#
#==================================================================
def pocResultChecker(returnCode,logfile, args, recursive_call=False):
    with open(logfile,'rb') as f:
        log_ctx = f.read()
    if b"error while loading shared libraries" in log_ctx:
        PANIC("[PANIC] RUNNING ENV WAS BROKEN")
    if returnCode == 0: # not crash
        return True
    elif ("timeout" in args) and returnCode == 124: # timeout
        return True
    # Handle of old fuzzing targets that only supports `fuzz < poc`
    elif returnCode == 255 and not recursive_call:
        # It could be some old version of fuzzing engine
        # `WARNING: using the deprecated call style `/out/pdf_fuzzer 1000`
        # If it still dies with /out/fuzzer < /tmp/poc we keep the first log file
        # check if Running: "WARNING: iterations invalid /tmp/poc" in the str
        if b"WARNING: iterations invalid" not in log_ctx:
            return False # crashes
        else:
            INFO("Found a Fuzzing Target Doesn't Support `Fuzzer POC`")
            fuzz_target = args[-2]
            poc_path = args[-1]
            new_args = args[:-2] + ["bash", "-c" , f'cat {poc_path} | {fuzz_target}'] # remove original command
            return fuzzerExecution(new_args, logfile, True)
    else:
        if b'out-of-memory' in log_ctx:
            return True # Out of mem
        return False # Crashes

def fuzzerExecution(args, log_tag, recursive_call = False):
    cmd = ['docker','run','--rm','--privileged']
    cmd.extend(args)
    if DEBUG:
        if not recursive_call:
            INFO("="*0x20)
            INFO(" ".join(cmd[:-1] + [f'"{cmd[-1]}"']))
        else:
            INFO(" ".join(cmd))
    with open(log_tag,'w') as f:
        returnCode = execute_ret(cmd,stdout=f,stderr=f)
        f.write(f"\nReturn Code: {returnCode}\n")
    INFO(f"[+] The execution return value is {returnCode}")
    INFO("="*0x20)

    return pocResultChecker(returnCode,log_tag, args, recursive_call)

def ifCrash(fuzz_target,case,issue,log_tag,timeout, detect_uninitialized = True):
    out  = OSS_OUT / str(issue['localId'])
    local_ubsan_op = UBSAN_OPTIONS+":detect_uninitialized=0" if not detect_uninitialized else UBSAN_OPTIONS
    return fuzzerExecution(['-e', ASAN_OPTIONS, '-e',local_ubsan_op, '-e', MSAN_OPTIONS,
            "-v",f"{case}:/tmp/poc",
            '-v',f"{out}:/out",f"gcr.io/oss-fuzz/{issue['localId']}"]+timeout+['/out/'+fuzz_target,'/tmp/poc'],log_tag)

def crashVerify(issue,reproduce_case,tag,timeout=180,detect_uninitialized=True):
    # Return True if NOT crash
    # Return False if crash
    INFO(" "*0x20)
    INFO("$"*0x20)
    INFO(" "*0x20)

    if not check_call(['sudo','chown','-R',f'{UserName}:{UserName}',str(issue['localId'])],OSS_OUT):
        return None
    fuzz_target = getFuzzer(issue['localId'],OSS_OUT / str(issue['localId']))
    if fuzz_target == None:
        return None

    if tag == None:
        log_tag = tmpFile()
    else:
        # tag could be a path or a str
        log_tag = ARVO / "Log" / "FuzzerExecution" / f"{issue['localId']}_{tag}.log" if type(tag) == str else tag
    timeout = ['timeout',str(timeout)] if timeout else []
    res = ifCrash(fuzz_target.name,str(reproduce_case),issue,log_tag,timeout,detect_uninitialized)

    if tag == None:
        shutil.rmtree(log_tag.parent)
    INFO(" "*0x20)
    INFO("$"*0x20)
    INFO(" "*0x20)
    return res

#==================================================================
#
#                  CrashInfo Parsing
#
#==================================================================
def parseCrash(path):
    with open(path,'rb') as f:
        lines = f.readlines()
    token = []
    for line in lines:
        if line.startswith(b"SUMMARY: "):
            if len(line.split(b":")) >3:
                line = line.split(b":")[2].strip()
            else:
                line = line
            return token, line
        elif line.startswith(b'DEDUP_TOKEN: '):
            tmp =  line[13:].strip(b"\n").split(b'--')
            token += [x.decode() for x in tmp]
    if b"Return Code: 0" in lines[-1]:
        return None
    return token, "No SUMMARY"
def getCrashSummary(originalLog):
    if not originalLog.exists():
        WARN("CrashSummary Doesn't Exist")
        return False
    targetCrash = parseCrash(originalLog)
    if not targetCrash:
        WARN(f"Failed to parse CrashSummary {originalLog}")
        return False
    targetCrash = targetCrash[1] # Only compare the summary
    return targetCrash
#==================================================================
#
#                  Meta Filter
#
#==================================================================
def remove_issue_meta(localIds):
    data = getMetadata()
    data  = [json.loads(x) for x in data]
    new_data = []
    for x in data:
        if x['localId'] not in localIds:
            new_data.append(x)
    with open(MetaDataFile,'w') as f:
        for x in new_data:
            f.write(json.dumps(x)+'\n')
def remove_issue_data(localIds):
    target = DATADIR/"Issues"
    for x in localIds:
        fname = str(x)+"_files"
        try:
            shutil.rmtree(target/fname)
        except:
            pass

def tokenLen(message: str,model='gpt-4'):
    encoding = tiktoken.encoding_for_model(model)
    return len(encoding.encode(message))
def silentRun(func, *args, **kwargs):
    original_stdout = sys.stdout
    sys.stdout = open(os.devnull, 'w')
    result = func(*args, **kwargs)
    sys.stdout = original_stdout
    return result
def localIdMapping(localId):
    if NEW_ISSUE_TRACKER and localId < 40000000:
        mapping = mapMapping()
        if localId not in mapping:
            WARN("[x] LocalId not in mapping, using obsolete localId")
        else:
            localId = mapping[localId]
    return localId

# Init sql db
db_init() 

if __name__ == "__main__":
    pass
