# Use to deal with the data of fix
from .Locator        import *
from .utils_GPT      import *
from .utils          import *
from .utils_LLMFix   import *
from .reproducer           import build_from_srcmap
from .utils_diff           import getVulCommit, getDiff
from .utils_runfix         import runFixLogInit, runFixLogImp, runFixCheckModule, runFixGetVulCode, get_vul_code
from unidiff        import PatchSet
# from FuzzVerification import fuzzVerify

STORE_FOR_FUZZ = True
def perform_fix(fix,ori_code,target_file):
    with open(target_file,'rb') as f:
        raw_code = f.read()
    raw_code  = raw_code.replace(ori_code,fix)
    with open(target_file,'wb') as f:
        f.write(raw_code)
def getGetVulCode(localId):
    # 1. Get meta data
    pname       = getPname(localId)
    if pname        == False:
        return False
    vul_commit  = getVulCommit(localId)
    if vul_commit   == False:
        return False
    diff_file   = getDiff(localId)
    if diff_file    == False:
        return False
    pInfo         = get_projectInfo(localId,pname)[1]
    gt = GitTool(pInfo['url'],pInfo['type'],vul_commit)
    repo_dir = gt.repo
    vul_code = runFixGetVulCode(diff_file,repo_dir)
    vul_code = get_vul_code(diff_file,repo_dir)
    return [ x[0] for x in vul_code]
def verify_FIX(localId,repo_dir,pname):
    # TODO: Functional checking
    print(localId)
    # localId, int
    # return value: -1 error, 0 False, 1 True
    def leave(result):
        if CLEAN_TMP and case_dir:
            clean_dir(case_dir)
        if(RM_IMAGES):
            remove_oss_fuzz_img(localId)
        return result
    
    srcmap,issue = getIssueTuple(localId)
    case_dir = tmpDir()
    try:
        case_path = downloadPoc(issue,case_dir,"crash_case")
    except:
        return leave(False)
    if not case_path or not case_path.exists():
        return leave(False)
    
    srcmap =  srcmap[0]
    # We don't need verifyFix=True since we'll provide the main Components 
    build_res = \
        build_from_srcmap(srcmap,issue,replace_dep=[pname,repo_dir])
    
    if not build_res:
        return leave("Failed to Compile")
    not_crash = crashVerify(issue,case_path)
    if not_crash == True:
        return leave(True)
    else:
        return leave(False)
def BenchMarkAPI(localId,fix):
    """
    Provide the fix code in bytes and return if the fix can fix the bug
    """
    # 1. Get Meta-data
    pname       = getPname(localId)
    if pname == False:
        return False
    vul_commit  = getVulCommit(localId)
    if vul_commit==False:
        return False
    diff_file   = getDiff(localId)
    if diff_file==False:
        return False

    # 2. Setup Repo
    pInfo         = get_projectInfo(localId,pname)[1]

    gt = GitTool(pInfo['url'],pInfo['type'],vul_commit)
    repo_dir = gt.repo
    vul_code = runFixGetVulCode(diff_file,repo_dir)
    if not vul_code:
        panic("[X] Has more than one hunks. Not support now.")
    
    target_file = vul_code[3]  

    # Try to build and verify all possibe fixes  
    perform_fix(fix,vul_code[0],repo_dir/target_file[2:])
    res = verify_FIX(localId,repo_dir,pname)
    if res:
        print("[+] Successful fix: ")
        print(fix.decode())
        print("[+] SUCCESS!")
        return leaveRet(True,[repo_dir.parent,diff_file.parent])
    else:
        print("[-] FAIL to FIX.")
        return leaveRet(False,[repo_dir.parent,diff_file.parent])
def runFix(localId,module,lite=False,logDiff=False,tag=""):
    # 0. Preprocess Vars
    logDiff = runFixLogInit(logDiff, module,tag)
    module  = runFixCheckModule(module)
    # 1. Get Meta-data
    pname       = getPname(localId)
    if pname == False:
        return "ARVO Bug"
    vul_commit  = getVulCommit(localId)
    if vul_commit==False:
        return "ARVO Bug"
    diff_file   = getDiff(localId)
    if diff_file==False:
        return "ARVO Bug"

    # 2. Setup Repo
    pInfo         = get_projectInfo(localId,pname)[1]
    gt = GitTool(pInfo['url'],pInfo['type'],vul_commit)
    repo_dir = gt.repo
    vul_code = runFixGetVulCode(diff_file,repo_dir)
    if not vul_code:
        panic("[X] Has more than one hunks. Not support now.")
    
    # 3. Perform Fixing
    if(module in ["Codex","gpt-3.5-turbo-instrct","code-davinci-edit-001"]):
        res = get_Codex_fix(localId,vul_code,repo_dir,model=module,lite=lite,logDiff=logDiff)
        if not res:
            return leaveRet("Failed to get the patch",[repo_dir.parent,diff_file.parent])
        else:
            fixes, ori_code, target_file = res
    elif("Wizard" in module):
        res = get_Wizard_fix(localId,vul_code,repo_dir,model=module,lite=lite)
        if not res:
            return leaveRet("Failed to get the patch",[repo_dir.parent,diff_file.parent])
        else:
            fixes, ori_code, target_file = res
    elif module in ['gpt-4-turbo',"gpt-3.5-turbo","gpt-4","gpt-4-1106-preview","gpt-3.5-turbo-16k"]:
        res = get_GPT_fix(localId,vul_code,repo_dir,model=module,lite=lite,logDiff=logDiff)
        if not res:
            return leaveRet("Failed to get the patch",[repo_dir.parent,diff_file.parent])
        else:
            fixes, ori_code, target_file = res
    elif module == "Starcoder":
        res = get_star_fix(localId,vul_code,repo_dir,model=module,lite=lite,)
        if not res:
            return leaveRet("Failed to get the patch",[repo_dir.parent,diff_file.parent])
        else:
            fixes, ori_code, target_file = res
    else:
        panic("UNK Module")
    
    # 4. Verification: Try to build and verify all possibe fixes
    # Only choce the first one since we don't have resource to test all
    fix = fixes[0]
    if fix == b"":
        return leaveRet("Failed to get the patch",[repo_dir.parent,diff_file.parent])
    perform_fix(fix,ori_code,target_file)

    res = verify_FIX(localId,repo_dir,pname)
    if res==True:
        print("[+] Successful fix: ")
        print(fix.decode())

        """
        Doing fuzzing verification. The result will be loaded after 24 hours
        """
        # fuzzVerify(localId,module+"_"+tag)


    if logDiff:
        runFixLogImp(logDiff, localId, vul_code, fixes, diff_file,res)
    else:
        pass
    if res==True:
        print("[+] SUCCESS!")
        return leaveRet(True,[repo_dir.parent,diff_file.parent])
    else:
        print("[-] FAIL to FIX.")
        return leaveRet(res,[repo_dir.parent,diff_file.parent])

def ifSimpleFix(localId):
    # 1. Get Meta-data
    diff_file =  getDiff(localId)
    try:
        ct = 0 
        patch = PatchSet.from_filename(diff_file, encoding='utf-8')
        for _ in range(len(patch)):
            target_set = patch[_]
            if target_set.is_modified_file:
                for _ in target_set:
                    ct+=1
        return ct==1
    except:
        return False
def getSimpleCases():
    reports = getReports()
    res = []
    for x in reports:
        print(x)
        fixes = getReport(x)['fix_commit']
        if isinstance(fixes,list) and len(fixes)>1:
            continue
        if ifSimpleFix(x):
            res.append(x)
    return res
if __name__ =="__main__":
    # res = getSimpleCases()
    # print(len(res))
    # with open("_simple.log",'w') as f:
    #     for x in res:
    #         f.write(f"{x}\n")
    res=[]
    with open("_simple.log",'r') as f:
        for l in f:
            lid=int(l.strip())
            # if getPname(lid)=="libreoffice":
            #     print(getPname(lid),lid)
            if lid==2287 or lid==888:
                continue
            res.append(lid)
    print(len(res))
    # input()
    GenerateWizardInput("./wizard_input.jsonl", localIds=res)
    # runFix(22080,"gpt-3.5-turbo")