# Issue Tracer,
# Locate the patch, based on poc and diff file
# import subprocess
from .utils import *
from .utils_tracer import *
from .reproducer import *
import json
import sys
from .results import addNewcase
# fmt: off
import configparser


#==================================================================
#
#                  Global Variables
#
#==================================================================
CHANCE_VAL = 32
CHANCE = "TO_BE_SET_IN_vulCommit"
'''
If TURBO is true, the first bisect search commit 
is not in the mid of the commit list but a commit 
2 days before the last commit.

We do this to speed the bisect search faster 
based on the fact (highly likely) that oss-fuzz 
verified the fix in the last two days before filing 
the report. Technically, 
it's one day but we make the range wider 
to make sure we hit it (if it exists).
'''
TURBO = False

#==================================================================
#
#                  Utils for Locator
#
#===================================================================
def turboSearch(l,t):
    ct = 0 
    for x in l:
        if isinstance(x,str) and x==t:
            return ct
        elif isinstance(x,list) and (t in x):
            return ct
        else:
            ct+=1
    return False    
def dichotomy_log(localId,s,tag):
    log = ARVO /"Log"/tag/f"{localId}"/f"{localId}.log"
    with open(log,'a') as f:
        f.write(f'{s}\n')
def _check_buid_prompt(s):
    print("\n\n")
    print("*"*0x20)
    print(f"commit: {s}")
    print("*"*0x20)
    print("\n\n")
def checkBuild(commit,localId,pname,poc,tag=None,oss_fuzz_commit=False,submodule_tracker=[]):
    if type(commit) != str:
        commit = commit[-1]
    _check_buid_prompt(commit)
    # Step1: Get the basic information
    srcmap, issue = getIssueTuple(localId)
    # Step2: Prepare(Fake) a srcmap with the new commit

    cts = customSrcmap(srcmap,pname,commit)
    if not cts:
        eventLog(f"[-] checkBuild {localId}: Failed to create customSrcmap, where commit=={commit}&&pname=={pname}")
        return None
    # Step3: Try to build/compile the fuzz target
    # We dont need verifyFix=True since we are sure we can checkout the mainComponent
    build_res = build_from_srcmap(cts,issue,ForceNoErrDump='/dev/null',oss_fuzz_commit=oss_fuzz_commit,custom_script=submodule_tracker)
    if not poc: # Build only mode
        return build_res
    if build_res == True:
        # Step4: Verify and return
        log = ARVO /"Log" / tag / f"{localId}" / f"{commit}.exec.log"
        lock = FileLock( ARVO / "Log" / tag / f"{localId}" / f"{commit}.exec.log.lock")
        if lock.acquire(timeout=.3):
            res = crashVerify(issue, poc,log)
            lock.release()
        else:
            PANIC("[!] Log file is locked")

        remove_oss_fuzz_img(localId)
        print(f"Result: {commit}:{res}")
        return leaveRet(res,cts.parent)
    elif build_res == False:
        eventLog(f"[-] checkBuild {localId}: Failed to build fuzztarget, where commit=={commit}&&pname=={pname}")
        remove_oss_fuzz_img(localId)
        return leaveRet(None,cts.parent)
    else:
        eventLog(f"[-] Weird return value from build_from_srcmap: {build_res}",True)
#==================================================================
#
#                  Report Generator
#
#==================================================================
def dichotomy_search(commits_list,localId,pname,poc,tag):
    global CHANCE, TURBO
    # The first commit is not tested
    # the last commit is fixed!
    print(commits_list)
    print(f"[+] {len(commits_list)} commits Left")
    log = ARVO /"Log"/tag/f"{localId}"/f"{localId}.log"
    if not log.exists():
        with open(log,'w') as f:
            f.write("[+] LogFrom: dichotomy_search\n")
            f.write(f"[+] LocalId: {localId}\n")
            f.write(f"[+] Bisect Search on {len(commits_list)} commits\n")
            f.write("=="*0x20+"\n")
    list_len = len(commits_list)
    if(list_len == 1):
        dichotomy_log(localId,f"[+] Final Result:\n\tCommit: {commits_list[-1]}\n"+"=="*0x20, tag)
        return commits_list[-1]
    
    if not TURBO:
        mid = int(list_len//2)-1
    else:
        turbo_idx = turboSearch(commits_list,TURBO) 
        mid = turbo_idx if (turbo_idx and turbo_idx != len(commits_list)-1) else (int(list_len//2)-1)
        
    
    res = checkBuild(commits_list[mid],localId,pname,poc,tag)
    if res == None:
        # Failed to Compile/Build: combine it and its next commit
        dichotomy_log(localId,f"[!] [{commits_list[mid]}]: Failed to build the fuzz targets, left chance {CHANCE}", tag) 
        if isinstance(commits_list[mid],str):
            tmp  = [commits_list[mid]]
            if isinstance(commits_list[mid+1],str):
                tmp += [commits_list[mid+1]] 
            else:
                tmp += commits_list[mid+1]
        else:
            tmp  = commits_list[mid]
            if isinstance(commits_list[mid+1],str):
                tmp += [commits_list[mid+1]] 
            else:
                tmp += commits_list[mid+1]
        TURBO = tmp[-1]
        commits_list = commits_list[:mid] + [tmp] + commits_list[mid+2:]
        CHANCE-=1
        if CHANCE==0:
            return False
        return dichotomy_search(commits_list,localId,pname,poc,tag)
    elif res == True: # Not Crash
        TURBO = False
        dichotomy_log(localId,f"[+] [{commits_list[mid]}]: Not Crash", tag)
        return dichotomy_search(commits_list[:mid+1],localId,pname,poc,tag)
    elif res == False:# Crash
        TURBO = False
        dichotomy_log(localId,f"[+] [{commits_list[mid]}]: Crash", tag)
        # Since we only care about the last commit stopped the crash so we just check if it crashs
        # More detailed methods are used in tracer
        return dichotomy_search(commits_list[mid+1:],localId,pname,poc,tag)
    else:
        PANIC(f"Impossible to reach here")
def list_commits(localId,pname):
    # Step1: Get Basic Information
    inclusive = True
    info1, info2 = get_projectInfo(localId,pname)
    protocol = info2['type']
    if info1['type']!=info2['type'] or info1['url']!=info2['url']:
        inclusive = False
        srcmap = getSrcmaps(localId)
        gt = GitTool(info2['url'],protocol)
        bk_t1 = int(str2date(srcmap[0].name.split(".")[0].split("-")[-1],STAMP_DELAY).timestamp())
        bk_t2 = int(str2date(srcmap[1].name.split(".")[0].split("-")[-1],STAMP_DELAY).timestamp())
        res = gt.listCommits(bk_t1,bk_t2)
        inclusive = False
        if not res:
            return leaveRet(False,gt.repo.parent)
    else:
        url      = info1['url']
        # Step2: List the commits
        gt = GitTool(url,protocol)
        res = gt.listCommits(info1['rev'],info2['rev'])
        if not res:
            srcmap = getSrcmaps(localId)
            bk_t1 = int(str2date(srcmap[0].name.split(".")[0].split("-")[-1],STAMP_DELAY).timestamp())
            bk_t2 = int(str2date(srcmap[1].name.split(".")[0].split("-")[-1],STAMP_DELAY).timestamp())
            res = gt.listCommits(bk_t1,bk_t2)
            inclusive = False
            if not res:
                return leaveRet(False,gt.repo.parent)
    recentCommit = gt.getRecentCommit(res)
    return leaveRet((res,recentCommit,inclusive),gt.repo.parent)
def vulCommit(localId,retryChance=None):
    global CHANCE, TURBO, CHANCE_VAL
    CHANCE = CHANCE_VAL if not retryChance else retryChance
    # 0 - Sanity Check, don't remove it even it's not used in this function
    # the tuple will be used in other functions that this function will call
    srcmap,issue = getIssueTuple(localId)
    if not srcmap or not issue:
        eventLog(f"\t[-] vulCommit {localId}: Failed to get srcmap/issue")
        return False
    elif len(srcmap)!=2:
        eventLog(f"\t[-] vulCommit {localId}: Len(srcmap)!=2")
        return False
    # 1 - Do the work
    pname   = getPname(localId)
    if pname == False:
        return False
    commits = list_commits(localId,pname)
    
    if commits == False:
        eventLog(f"\t[-] vulCommit {localId}: Failed to list commits")
        return False
    commits, TURBO, inclusive = commits
    
    if len(commits)<=1:
        eventLog(f"\t[-] vulCommit {localId}: Found {len(commits)} commit, which is abnormal")
        return False
    
    commits = commits[1:] if inclusive else commits
    poc = getPoc(localId,issue)
    if not poc:
        eventLog(f"\t[-] vulCommit {localId}: Failed to download the PoC")
        return False
    # 2 - Prepare for log
    log = ARVO /"Log"/"bisect"/f"{localId}"
    if log.exists():
        shutil.rmtree(log)
    log.mkdir(parents=True,exist_ok=True)
    target_commit = dichotomy_search(commits,localId,pname,poc,'bisect')
    # Get the gt
    
    if isinstance(target_commit,list):
        ifsub = False
    else:
        _,info2 = get_projectInfo(localId,pname)
        gt = GitTool(info2['url'],info2['type'])
        if not gt:
            return False
        diff_file = gt.showCommit(target_commit)
        if not diff_file:
            return False
        ifsub = checkIfSubmodule(diff_file)
    
    if ifsub == None:
        return False
    elif ifsub == False:
        pass
    else:
        submodules = parseSubmoduleUpdate(ifsub)
        def get_submodule_url(path, gitmodules_path=".gitmodules"):
            parser = configparser.ConfigParser()
            parser.read(gitmodules_path)
            
            for section in parser.sections():
                if section.startswith('submodule "') and parser[section].get("path") == path:
                    return parser[section].get("url")
            return None
        for x in submodules:
            # docker run .... ""
            # TODO bisect
            
            execute(['git','submodule','init'],gt.repo)
            # sub_path = execute(['git','config','--file','.gitmodules',f'submodule.{x[0]}.path'],gt.repo)
            # if not sub_path:
            #     PANIC("Failed to get the submodule path")
            sub_path = str(Path(pname)/x[0])
            sub_url = get_submodule_url(sub_path)

            appendix = ["bash",'-c',f'rm -rf {sub_path} && git clone {sub_url} {sub_path} && pushd {sub_path} && git checkout {x[1]} && popd && compile']
            INFO(f"Trying {sub_path}...")
            res = checkBuild(target_commit,localId,pname,poc,'sub-tracker',submodule_tracker=appendix)
            if res == None:
                # Failed to Compile/Build: combine it and its next commit
                WARN(f"Not the submodule: {x[0]}")
                continue
            elif res == True:
                # Not Crash
                WARN(f"Not the submodule: {x[0]}")
                continue
            elif res == False:
                # Crash
                INFO(f"Found the submodule matters: {x[0]}")
                found = checkSubmodulePatch(localId,pname,target_commit,x,poc,sub_path,gt)
                if not found:
                    return leaveRet(target_commit,poc.parent)
                else:
                    return leaveRet(found,poc.parent)
            else:
                PANIC(f"Impossible to reach here")
        # Can't work it out, still return the submodule update commit 
        WARN("Failed to locate the specific submodule matters")
    return leaveRet(target_commit,poc.parent)
def checkSubmodulePatch(localId,pname,commit,submodule_info,poc,sub_path,gt_main):
    # git config --file .git/config submodule.qtbase.url
    cmd = ['git','config','--file','.git/config',f'submodule.{submodule_info[0]}.url']
    sub_url = execute(cmd,gt_main.repo)
    if not sub_url:
        return leaveRet(False,[gt_main.repo])
    sub_url = sub_url.decode()
    gt_subm = GitTool(sub_url)
    sub_commits = gt_subm.listCommits(submodule_info[1],submodule_info[2])
    if not sub_commits:
        return leaveRet(False,[gt_main.repo,gt_subm.repo])
    # TODO bisect
    found = False
    for sub_commit in sub_commits[1:]:
        appendix = ["bash",'-c',f'pushd {sub_path} && git checkout {sub_commit} && popd && compile']
        res = checkBuild(commit,localId,pname,poc,'sub-tracker',submodule_tracker=appendix)
        if res == None:
            # Failed to Compile/Build: combine it and its next commit
            WARN(f"INFO Failed to build: submodule -> {submodule_info[0]} {sub_commit}")
            continue
        elif res == True:
            SUCCESS(f"Bug Fixed:{submodule_info[0]} {sub_commit}")
            found = sub_commit
            break
        elif res == False:
            # Crash
            INFO(f"Still Buggy:{submodule_info[0]} {sub_commit}")
            continue
        else:
            PANIC(f"Impossible to reach here")
    if not found:
        # Failed to locate
        return leaveRet(False,[gt_main.repo,gt_subm.repo])
    else:
        return leaveRet(f"submodule {sub_url} {found}",[gt_main.repo,gt_subm.repo])
def parseSubmoduleUpdate(diff_ctx):
    # Regex to match submodule changes
    pattern = re.compile(
        r"diff --git a/(\S+) b/\1\n"
        r"index \S+\.\.(\S+) 160000\n"
        r"--- a/\1\n"
        r"\+\+\+ b/\1\n"
        r"@@ -1 \+1 @@\n"
        r"-Subproject commit (\S+)\n"
        r"\+Subproject commit (\S+)"
    )
    matches = pattern.findall(diff_ctx.decode())

    # Convert matches into desired list format
    result = [[match[0], match[2], match[3]] for match in matches]
    return result
    # TODO
def checkIfSubmodule(diff_file):
    with open(diff_file,'rb') as f:
        diff_ctx = f.read()
    if b"@@\n-Subproject commit" in diff_ctx:
        return diff_ctx
    else:
        return False
def reportFix(repo,commit):
    if repo.startswith("https://github.com") or repo.startswith("http://github.com"):
        repo = repo[:-4] if repo.endswith(".git") else repo
        repo = repo[:-1] if repo.endswith("/") else repo
        repo += "/commit/"
    elif ".googlesource.com" in repo:
        repo += "/+/"
    elif repo.startswith("https://gitlab.com/") or repo.startswith("http://gitlab.com/"):
        repo = repo[:-4] if repo.endswith(".git") else repo
        repo += "/-/commit/"
    elif "git://code.qt.io/qt/qtbase.git" in repo:
        repo = "https://code.qt.io/cgit/qt/qtbase.git/commit/?id="
    elif "git.ffmpeg.org/ffmpeg.git" in repo:
        repo = "https://git.ffmpeg.org/gitweb/ffmpeg.git/commitdiff/"
    elif "git://code.qt.io/qt/qt5.git" == repo:
        repo = 'https://code.qt.io/cgit/qt/qt5.git/commit/?id='
    elif "git://git.code.sf.net/p/matio/matio" == repo:
        repo = "https://github.com/tbeu/matio/commit/"
    elif repo == "git://git.ghostscript.com/ghostpdl.git":
        repo = 'https://github.com/ArtifexSoftware/ghostpdl/commit/'
    elif repo == "git://git.ghostscript.com/mupdf.git":
        repo = 'https://github.com/ArtifexSoftware/mupdf/commit/'
    elif repo == 'git://thekelleys.org.uk/dnsmasq.git':
        repo = repo+" -> "
    elif repo == "git://sourceware.org/git/binutils-gdb.git":
        repo = 'https://github.com/bminor/binutils-gdb/commit/'
    elif repo == "git://w1.fi/srv/git/hostap.git":
        repo = 'https://w1.fi/cgit/hostap/commit/?id='
    elif repo == "https://gitlab.gnome.org/GNOME/libxml2.git":
        repo = 'https://gitlab.gnome.org/GNOME/libxml2/-/commit/'
    elif repo == "git://git.code.sf.net/p/net-snmp/code":
        repo = 'https://github.com/net-snmp/net-snmp/commit/'
    elif repo == "git://git.sv.nongnu.org/freetype/freetype2.git":
        repo = 'https://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id='
    elif repo == "git://sourceware.org/git/elfutils.git":
        repo = 'https://sourceware.org/git/?p=elfutils.git;a=commitdiff;h='
    elif repo == "https://git.osgeo.org/gitea/geos/geos.git":
        repo = 'https://git.osgeo.org/gitea/geos/geos/commit/'
    elif repo == "https://git.gnu.org.ua/gdbm.git":  
        repo = 'https://git.gnu.org.ua/gdbm.git/commit/?id='
    res = repo + commit
    if ".googlesource.com" in res:
        res+="%5E%21/"
    return res
def fileReport(localId,fix_commit):
    srcmap, issue = getIssueTuple(localId)
    pname = getPname(localId)
    with open(srcmap[0]) as f:
        info = json.load(f)
    vulComponentName    = "/src/"+pname
    vulComponentUrl     = info[vulComponentName]['url']
    vulComponentType    = info[vulComponentName]['type']
    _,vulComponentUrl,_   = trans_table(vulComponentName,vulComponentUrl,vulComponentType)
    #######################################################
    #               Dump the report
    #######################################################
    fix_commits = fix_commit
    fix_commit = fix_commit[-1] if type(fix_commit) != str else fix_commit

    if "submodule" in fix_commit:
        vulComponentUrl,fix_commit = fix_commit.split(" ")[1:]
        fix_commits  = fix_commit
    fix = reportFix(vulComponentUrl,fix_commit)
    res = dict()
    res['fix']      = fix
    res['verify']   = False
    res['localId']  = localId
    res['project']  = pname
    # data from original issues
    tmp                 = issue['job_type'].split("_")
    res['fuzzer']       = tmp[0]
    res['sanitizer']    = tmp[1]
    res['crash_type']   = issue['crash_type']
    try:
        res['severity'] = issue['severity']
    except:
        pass
    res['report']       = f"https://issues.oss-fuzz.com/issues/{localId}"
    res['fix_commit']   = fix_commits
    res['repo_addr']    = vulComponentUrl
    return res
def report(localId,verified=False):
    # Step1: Verfy if the case is reproduciable currently
    localId = localIdMapping(localId)
    
    if not verified:
        print(f"[+] Verifying {localId}")
        if (not verify(localId)):
            eventLog(f"[-] Failed to reproduce {localId}: Unable to Reproduce")
            return False
        done = getDone()
        if localId not in done:
            lock = FileLock(ARVO/"Results.json.lock")
            while(1):
                print(f"[+] Add {localId} to results")
                with lock.acquire(timeout=1):
                    addNewcase([localId])
                    break
            
    # Step2: Find the commit that fixed the bug+
    fix_commit= vulCommit(localId,0x40)
    if fix_commit == False or fix_commit=="":
        eventLog(f"[-] Failed to locate the patches for issue {localId}")
        return False
    # return fix_commit
    # Step3: File the report 
    return fileReport(localId,fix_commit)
#============================
#
#
#
#    Life Span, get the commit when the bug is introduced
#
#
#
#============================
def dichotomy_search_TC(commits_list,localId,pname,poc,tag,targetCrash,oss_fuzz_commit):
    global CHANCE, TURBO
    # only use this function when commits_list is reversed
    # The first commit is not tested
    # the last commit is fixed!
    # print(commits_list)
    print(f"[+] {len(commits_list)} commits Left")
    print(tag,localId)
    log = ARVO /"Log" /tag/f"{localId}"/f"{localId}.log"
    if not log.exists():
        with open(log,'w') as f:
            f.write("[+] LogFrom: dichotomy_search_TC\n")
            f.write(f"[+] LocalId: {localId}\n")
            f.write(f"[+] Bisect Search on {len(commits_list)} commits\n")
            f.write("=="*0x20+"\n")
    list_len = len(commits_list)
    if(list_len == 1):
        dichotomy_log(localId,f"[+] Final Result:\n\tCommit: {commits_list[-1]}\n"+"=="*0x20, tag)
        return commits_list[-1]
    
    if not TURBO:
        mid = int(list_len//2)-1
    else:
        turbo_idx = turboSearch(commits_list,TURBO) 
        mid = turbo_idx if turbo_idx else (int(list_len//2)-1)
    tmp_mid = commits_list[mid] if isinstance(commits_list[mid],str) else commits_list[mid][::-1] 
    res = checkBuild(tmp_mid,localId,pname,poc,tag,oss_fuzz_commit)
    if res == None:
        # Failed to Compile/Build: combine it and its next commit
        dichotomy_log(localId,f"[!] [{commits_list[mid]}]: Failed to build the fuzz targets, left chance {CHANCE}", tag) 
        if isinstance(commits_list[mid],str):
            tmp  = [commits_list[mid]]
            if isinstance(commits_list[mid-1],str):
                tmp = [commits_list[mid-1]] + tmp 
            else:
                tmp = commits_list[mid-1] + tmp
        else:
            tmp = commits_list[mid]
            if isinstance(commits_list[mid-1],str):
                tmp = [commits_list[mid-1]] + tmp  
            else:
                tmp = commits_list[mid-1] + tmp 
        TURBO = tmp[0]
        commits_list = commits_list[:mid] + [tmp] + commits_list[mid+2:]
        CHANCE-=1
        if CHANCE==0:
            return False
        return dichotomy_search_TC(commits_list,localId,pname,poc,tag,targetCrash,oss_fuzz_commit)
    elif res == True: # Not Crash
        TURBO = False
        dichotomy_log(localId,f"[+] [{commits_list[mid]}]: Not Crash", tag)
        return dichotomy_search_TC(commits_list[:mid+1],localId,pname,poc,tag,targetCrash,oss_fuzz_commit)
    elif res == False:# Crash
        TURBO = False
        curCrash = getCrashSummary(log.parent / f"{commits_list[mid]}.exec.log")
        if curCrash == False:
            PANIC(f"[+] Broken crash info for {localId}")
        if targetCrash == curCrash:
            # Only compare the summary, since the DEDUPTOKEN could be so different for UAF
            dichotomy_log(localId,f"[+] [{commits_list[mid]}]: Crash", tag)
            return dichotomy_search_TC(commits_list[mid+1:],localId,pname,poc,tag,targetCrash,oss_fuzz_commit)
        else:
            dichotomy_log(localId,f"[!] [{commits_list[mid]}]: Crash because of different crashInfo, assuming it's a different bug", tag)
            # return dichotomy_search_TC(commits_list[mid+1:],localId,pname,poc,tag,targetCrash,oss_fuzz_commit)

            return dichotomy_search_TC(commits_list[:mid+1],localId,pname,poc,tag,targetCrash,oss_fuzz_commit)
    else:
        PANIC(f"Impossible to reach here")
def lifeSpan_getInitTimeStamp(localId,oss_commit=False):
    project = getPname(localId, False)
    if project == False:
        return False
    gta = GitTool("https://github.com/google/oss-fuzz.git", "git")
    commit1 = gta.createdCommit("./projects/%s/Dockerfile" % project)
    commit2 = gta.createdCommit("./projects/%s/build.sh" % project)
    if commit1== False or commit2 == False:
        return False
    if commit1 != commit2:
        init_timestamp1 = gta.timestamp(commit1)
        init_timestamp2 = gta.timestamp(commit2)
        init_timestamp  = init_timestamp1 if init_timestamp1 > init_timestamp2 else init_timestamp2
    else:
        init_timestamp = gta.timestamp(commit1)
    if oss_commit != False:
        init_timestamp = gta.getCommitbyTimestamp(init_timestamp)
    shutil.rmtree(gta.repo)
    return init_timestamp
def lifeSpan_prepareProject(localId,pname):
    srcmap = getSrcmaps(localId)
    init_timestamp = lifeSpan_getInitTimeStamp(localId)
    if not init_timestamp:
        eventLog(f"[lifeSpan]: Failed to get the init_timestamp for {localId}")
        return False
    ti = json.loads(open(srcmap[0]).read())[f"/src/{pname}"]
    _, ti["url"], ti["type"] = trans_table(f"/src/{pname}", ti["url"], ti["type"])
    gt = GitTool(ti["url"], ti["type"])
    beg_commit = gt.getCommitbyTimestamp(init_timestamp)
    if beg_commit == False:
        return False
    vulnerable_commit = ti["rev"]
    return gt, beg_commit, vulnerable_commit
def lifeSpan(localId):
    global CHANCE, OSS_FUZZ_DIR, TURBO
    # 1. Get Pname
    print(f"[+] Working on {localId}")
    CHANCE  = 0x10
    pname = getPname(localId)
    if not pname:
        eventLog(f"[lifeSpan]: Failed to get basices for {localId}")
        return False

    # 2. Prepare Commits
    tmp_res = lifeSpan_prepareProject(localId,pname)
    if not tmp_res:
        eventLog(f"[lifeSpan]: Failed to get the commit information for {localId}")
        return False
    gt, beg_commit, vulnerable_commit  = tmp_res
    beg_ts = gt.timestamp(beg_commit) 
    vul_ts = gt.timestamp(vulnerable_commit)
    if beg_ts > vul_ts:
        oss_fuzz_commit = lifeSpan_getInitTimeStamp(localId,True)
    else:
        oss_fuzz_commit = False
    if not oss_fuzz_commit:
        commits = gt.listCommits(beg_commit, vulnerable_commit)
    else:
        commits = gt.listCommits(vul_ts-3600*24*7,vul_ts)
        beg_commit = commits[0]
    if not isinstance(commits,list):
        eventLog(f"[lifeSpan]: Failed to list commits listCommits for {localId}")
        return leaveRet(False, gt.repo)
    elif len(commits) < 2:
        eventLog(f"[lifeSpan]: Less than two commits to check for {localId}")
        return False
    TURBO = gt.getRecentCommit(commits)
    commits = (commits[:-1])[::-1] # Remove info[0][/src/pname][rev] and rev the list
    shutil.rmtree(gt.repo)
    # 3. Prepare logFile
    log = ARVO /"Log"/"lifeSpan"/f"{localId}"
    if log.exists():
        shutil.rmtree(log)
    log.mkdir(parents=True,exist_ok=True)

    # 4. Get the target Crash
    targetCrash = getCrashSummary(ARVO / "Log" / "Round1" / f"{localId}_vul.log")
    if not targetCrash:
        eventLog(f"Failed to get crashSummary for {localId}")
        return False
    
    # 5. Get PoC
    poc = getPoc(localId, getIssue(localId))
    if not poc:
        eventLog(f"Failed to get the poc getPoc({localId})")
        return False
    
    # 6. Do search
    found   = dichotomy_search_TC(commits, localId, pname, poc, 'lifeSpan',targetCrash, oss_fuzz_commit)
    if (found is False):
        eventLog(f"Dichotomy_search failed for {localId}")
        return leaveRet((False, vulnerable_commit, beg_commit), poc.parent)

    # 7. Process the result
    if isinstance(found, list):
        return leaveRet((found, vulnerable_commit, beg_commit), poc.parent)

    if found == commits[-1]:
        '''
        If the result is oldest_commit, that's a false positive
        '''
        return leaveRet((None, vulnerable_commit, beg_commit), poc.parent)
    else:
        '''
        the found's index could be 0
        which means the latest_commit introduced the bug so we return vulnerable_commit
        '''
        vulncommit = commits[commits.index(found)-1] if commits.index(found)!=0 else vulnerable_commit
        print("lifeSpan: ", (vulncommit, vulnerable_commit, beg_commit))
        return leaveRet((vulncommit, vulnerable_commit, beg_commit), poc.parent)

#============================
#
#
#
#    vZero
#
#
#
#============================
import time

def vzListCommits(localId,pname):
    # Step1: Get Basic Information
    inclusive = True
    _, info2 = get_projectInfo(localId,pname)
    protocol = info2['type']
    url      = info2['url']
    # Step2: List the commits
    gt = GitTool(url,protocol,latest=True)
    cur_commit = gt.curCommit()
    res = gt.listCommits(info2['rev'],cur_commit)
    if not res:
        srcmap      = getSrcmaps(localId)
        bk_t2       = int(str2date(srcmap[1].name.split(".")[0].split("-")[-1],STAMP_DELAY).timestamp())
        cur_time    = int(time.time())
        res = gt.listCommits(bk_t2,cur_time)
        inclusive = False
        if not res:
            return leaveRet(False,gt.repo.parent)
    return leaveRet((res,False,inclusive),gt.repo.parent)

def vZero(localId,retryChance=None):
    global CHANCE, TURBO, CHANCE_VAL
    CHANCE = CHANCE_VAL if not retryChance else retryChance
    # 0 - Sanity Check, don't remove it even it's not used in this function
    # the tuple will be used in other functions that this function will call
    srcmap,issue = getIssueTuple(localId)
    if not srcmap or not issue:
        eventLog(f"\t[-] vulCommit {localId}: Failed to get srcmap/issue")
        return False
    elif len(srcmap)!=2:
        eventLog(f"\t[-] vulCommit {localId}: Len(srcmap)!=2")
        return False
    # 1 - Do the work
    pname   = getPname(localId)
    if pname == False:
        return False
    commits = vzListCommits(localId,pname)
    
    if commits == False:
        eventLog(f"\t[-] vulCommit {localId}: Failed to list commits")
        return False
    commits, TURBO, inclusive = commits
    
    if len(commits)<=1:
        eventLog(f"\t[-] vulCommit {localId}: Found {len(commits)} commit, which is abnormal")
        return False
    
    commits = commits[1:] if inclusive else commits
    poc = getPoc(localId,issue)
    if not poc:
        eventLog(f"\t[-] vulCommit {localId}: Failed to download the PoC")
        return False
    # 2 - Prepare for log
    log = ARVO /"Log"/"vZero"/f"{localId}"
    if log.exists():
        shutil.rmtree(log)
    log.mkdir(parents=True,exist_ok=True)
    target_commit = dichotomy_search(commits+["ZDV"],localId,pname,poc,'vZero')
    return leaveRet(target_commit,poc.parent)
def reproduce(localId, dockerize = True, update = True):
    localId = localIdMapping(localId)
    exist_record  = arvoRecorded(localId)
    if exist_record and not update:
        INFO("[+] Record Exists")
        return True
    if (not verify(localId,dockerize)):
        eventLog(f"[-] Failed to reproduce {localId}: Unable to Reproduce")
        return False
    
    reproduced      = True

    reproducer_vul = f"docker run --rm -it n132/arvo:{localId}-vul arvo"
    reproducer_fix = f"docker run --rm -it n132/arvo:{localId}-fix arvo"

    res = report(localId,True)
    if not res: return False
    patch_located  = True
    patch_located  = True
    patch_url      = res['fix']
    verified       = res['verify']
    reproduced     = True
    project        = getPname(localId)
    fuzz_engine    = res['fuzzer']
    sanitizer      = res['sanitizer']
    crash_type     = res['crash_type']
    severity       = res['severity'] if 'severity' in res else "UNK"
    fix_commit     = res['fix_commit']
    language       = getLanguage(localId)
    # We still have the layers cached so it's not hard to re-run and get some info

    # Get fuzz_target
    cmd = f"docker run --rm -it n132/arvo:{localId}-vul grep -oP -m1 '/out/\\K\\S+' /bin/arvo"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        fuzz_target = result.stdout.strip()
    else:
        FAIL(f"Command failed: {result.stderr.strip()}")
        fuzz_target = "FAILED_TO_GET"

    # Get Stdout/Stderr
    tmpfile = tmpFile()
    cmd = f"docker run --rm -it n132/arvo:{localId}-vul arvo".split(" ")
    with open(tmpfile, "w") as f:
        subprocess.run(cmd, stdout=f,stderr=f)
    with open(tmpfile,'rb') as f:
        crash_output = f.read().decode("utf-8", errors="replace").replace("�", "\x00")
    os.remove(tmpfile)
    

    if exist_record:
        if not delete_entry(localId):
            return False
    
    return insert_entry((localId, project, reproduced, reproducer_vul, reproducer_fix, patch_located,
        patch_url, verified, fuzz_target, fuzz_engine,
        sanitizer, crash_type, crash_output, severity, res['report'],fix_commit, language))

if __name__ == '__main__':
    if len(sys.argv) == 2:
        report(int(sys.argv[1]),debug=True)
    else:
        pass
