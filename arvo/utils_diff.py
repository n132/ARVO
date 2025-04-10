from .utils import *
from .utils_git import *
from unidiff import PatchSet
from .utils_tracer import customSrcmap_PM
from .reproducer import build_from_srcmap
class DiffTool():
    def __init__(self,id) -> None:
        if isinstance(id,int):
            diff = getDiff(id) 
            if not diff:
                PANIC(f"[+] Failed to get the Diff file for {id}")
            with open(diff) as f:
                self.diff = f.read()
        elif type(id) == type(Path("/tmp")):
            if not id.exists():
                PANIC(f"[+] Failed to get the Diff file for {id}")
            with open(id) as f:
                self.diff = f.read()
        elif isinstance(id,str):
            id = Path(id)
            if not id.exists():
                PANIC(f"[+] Failed to get the Diff file for {id}")
            with open(id) as f:
                self.diff = f.read()
        else:
            PANIC(f"[+] InValid input for diff")
    def splitHunks(self):
        res = []
        # function_pattern = r'^\s*[a-zA-Z_][a-zA-Z0-9_]*\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(.*\)\s*{'
        patch_set = PatchSet(self.diff)
        
        # Iterate over patches in the set
        index = 0 
        for patch in patch_set:
            if not patch.is_modified_file:
                continue
            target_line = None
            
            for hunk in patch:
                # print(str(hunk.source))
                # exit(1)
                # if "(" not in list(hunk.source_lines())[0].value:
                #     # TODO: a better way to judge if it's a c/c++ function
                #     break
                ct = 0 
                for line in str(hunk).split("\n"):
                    if "{" in line:
                        # TODO: a better way to locate the start of function body
                        break
                    ct+=1
                target_line = hunk.source_start+ct
                break
            if target_line:
                index+=1
                res.append((patch.path,target_line,index))
        return res


def _getGtforReport(localId):
    pname   = getPname(localId)
    if not pname:
        return False
    _,info2 = get_projectInfo(localId,pname)
    protocol = info2['type']
    gt = GitTool(info2['url'],protocol)
    return gt
def getFixCommit(localId):
    report = getReport(localId)
    return False if report == False else report['fix_commit']

def getVulCommit(localId):
    # Get the commit just before the fix commit
    commit    = getReport(localId)['fix_commit']
    gt = _getGtforReport(localId)
    if not gt:
        return False
    res = gt.prevCommit(commit) if not isinstance(commit,list) else gt.prevCommit(commit[-1])
    return leaveRet(res,gt.repo.parent)
def getFixTs(localId):
    commit    = getReport(localId)['fix_commit']
    gt = _getGtforReport(localId)
    if not gt:
        return False
    
    if not isinstance(commit,list):
        res = gt.timestamp(commit)
    else:
        res = gt.timestamp(commit[-1])
    return leaveRet(res,gt.repo.parent)

def getRevDiff(localId,multi_commits=False):
    localDp = ARVO/"PatchesRev"/f"{localId}.diff"
    commit    = getReport(localId)['fix_commit']

    if localDp.exists():
        if not isinstance(commit,list) or multi_commits==False:
            return localDp

    gt = _getGtforReport(localId)
    if not gt:
        return False
    
    if not isinstance(commit,list):
        res = gt.showCommit(commit,rev=True)
    else:
        if multi_commits:
            res = tmpFile()
            for one in commit:
                gt.showCommit(one,res,rev=True)
        else:
            res = gt.showCommit(commit[-1],rev=True)
    return leaveRet(res,gt.repo.parent)
def getDiff(localId,multi_commits=False):
    localDp = ARVO/"Patches"/f"{localId}.diff"

    commit    = getReport(localId)['fix_commit']

    if localDp.exists():
        if not isinstance(commit,list) or multi_commits==False:
            return localDp

    gt = _getGtforReport(localId)
    if not gt:
        return False
    if not isinstance(commit,list):
        res = gt.showCommit(commit)
    else:
        if multi_commits:
            res = tmpFile()
            for one in commit:
                gt.showCommit(one,res)
        else:
            res = gt.showCommit(commit[-1])
    return leaveRet(res,gt.repo.parent)
def getVulComponentProtocol(localId):
    # Filter not supported protocol
    pname   = getPname(localId)
    srcmap = getSrcmaps(localId)
    with open(srcmap[0]) as f:
        return json.loads(f.read())[f'/src/{pname}']['type']
def ccBuild(localId,poc,tag,patches):
    # Step1: Get the basic information
    srcmap, issue = getIssueTuple(localId)
    # Step2: Prepare(Fake) a srcmap with the new commit
    cts = customSrcmap_PM(srcmap)
    if not cts:
        return "Failed to Create customSrcmap"
    # Step3: Try to build/compile the fuzz target
    # We dont need verifyFix=True since we are sure we can checkout the mainComponent

    build_res = build_from_srcmap(cts,issue,ForceNoErrDump=True,patches=patches)
    
    if build_res == True:
        # Step4: Verify and return
        log = ARVO /"Log"/tag/f"{localId}" / f"{localId}.exec.log"
        res = crashVerify(issue, poc,log)
        remove_oss_fuzz_img(localId)
        return leaveRet(res,cts.parent)
    elif build_res == False:
        remove_oss_fuzz_img(localId)
        return leaveRet("Failed to Compile",cts.parent)
    else:
        eventLog(f"[-] Weird return value from build_from_srcmap: {build_res}",True)

def patchVerification(localId):
    if getVulComponentProtocol(localId) != 'git':
        return False
    wkdir = ARVO/"Log"/"diff"/f"{localId}"
    assert(localId in getReports())
    dt      = DiffTool(localId)
    hks     = dt.splitHunks()
    print(hks)
    
    poc     = getPoc(localId,getIssue(localId))
    wkdir.mkdir(parents=True,exist_ok=True)
    res = ccBuild(localId,poc,"diff",hks)
    
    if res  not in [True,False]:
        return res
    if res == False:
        return "The Fix Version Still Crashes"
    if not (OSS_OUT/f"{localId}"/"arvo_pv").exists():
        return "Miss"
    if check_call(['sudo','cp',str(OSS_OUT/f"{localId}"/"arvo_pv"), str(wkdir)]) and check_call(['sudo','chmod',"777", str(wkdir/"arvo_pv")]):
        return True
    else:
        return "ARVO Failed to COPY RESULT OUT"
def getAllPatches(targetdir):
    if not targetdir.exists():
        return False
    issues = getReports()
    for localId in issues:
        print(f"{issues.index(localId)}/{len(issues)}")
        tmp = targetdir/f"{localId}.diff"
        if tmp.exists():
            continue
        res = getDiff(localId)
        if res == False:
            print(f"[-] Failed to get the patch for {localId}")
            continue
        shutil.copy(res,tmp)
        print(f"[+] {localId}")
if __name__ == "__main__":
    targetdir = Path(ARVO/"Patches")
    getAllPatches(targetdir)
