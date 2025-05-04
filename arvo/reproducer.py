from .utils import *
from .utils_core import *
from .utils_git import *
from .dev import *
import collections
BuildData = collections.namedtuple(
    'BuildData', ['project_name', 'engine', 'sanitizer', 'architecture'])
from .transform import trans_table
from . import utils_ctx 

# Global
CONTAINER_ENV = []
def permissionResolve(target_path):
    res = execute_ret(["sudo","chown","-R",f"{UserName}:{UserName}",target_path])
    if res!=0: FAIL(f"[-] Chown result = {res}")
def doPatchMain(localId,dockerfile,patches):
    pname = getPname(localId)
    dft = DfTool(dockerfile)
    def _cmp(a):
        return a[2]
    patches.sort(key=_cmp)
    counter = {}
    dkdir = dockerfile.parent
    with open(dkdir/"ARVO.sh",'a') as f:
        f.write("set +x\n")
    for patch in patches:
        fname, line_num, mark = patch
        # create + rw
        strlen = len(f"Hit Function {mark}: ")
        newline = f'int ARVO_FD=open(\\"/out/arvo_pv\\",66); write(ARVO_FD,\\"Hit Function {mark}: \\",{strlen}); write(ARVO_FD,__FUNCTION__,strlen(__FUNCTION__));  write(ARVO_FD,\\"\\\\n\\",1); close(ARVO_FD);'
        line_num  = line_num+counter[line] if fname in counter else line_num
        line = f'''sed -i '{line_num}i {newline}' $SRC/{pname}/{fname}'''
        with open(dkdir/"ARVO.sh",'a') as f:
            f.write(line+"\n")
        
        if fname not in counter:
            counter[fname] = 1
        else:
            counter[fname] +=1
    dft.appendLine("COPY ARVO.sh /")
    dft.appendLine("RUN bash /ARVO.sh")
    dft.flush()
def doCommitClean(localId,tag):
    if not docker_commit(f"reproducer_{localId}",f"n132/arvo:{localId}-{tag}"):
        return False
    if not docker_rm(f"reproducer_{localId}"):
        return False
    return True
def reproducerPrepareOssFuzz(project_name,commit_date):
    # 1. Clone OSS Fuzz
    tmp_dir          = clone("https://github.com/google/oss-fuzz.git",name="oss-fuzz")
    # 2. Get the Commit Close to Commit_Date
    tmp_oss_fuzz_dir = tmp_dir / "oss-fuzz"
    if isinstance(commit_date,str):
        oss_fuzz_commit = commit_date
    else:
        cmd = ['git','log','--before='+ commit_date.isoformat(), '-n1', '--format=%H']
        oss_fuzz_commit = execute(cmd,tmp_oss_fuzz_dir).strip()

        if not oss_fuzz_commit:
            cmd = ['git','log','--reverse', '--format=%H']
            oss_fuzz_commit = execute(cmd,tmp_oss_fuzz_dir).splitlines()[0].strip()
            if not oss_fuzz_commit:
                eventLog('[-] reproducerPrepareOssFuzz: Failed to get oldest oss-fuzz commit')
                return leaveRet(False,tmp_dir)
    # 3. Reset OSS Fuzz
    gt = GitTool(tmp_oss_fuzz_dir)
    if not gt.reset(oss_fuzz_commit):
        eventLog("[-] reproducerPrepareOssFuzz: Fail to Reset OSS-Fuzz")
        return leaveRet(False,tmp_dir)
    # 4. Locate Project Dir
    tmp_list = [x for x in tmp_oss_fuzz_dir.iterdir() if x.is_dir()]
    if tmp_oss_fuzz_dir/ "projects" in tmp_list:
        proj_dir = tmp_oss_fuzz_dir/ "projects" / project_name
    elif tmp_oss_fuzz_dir/ "targets" in tmp_list:
        proj_dir = tmp_oss_fuzz_dir/ "targets" / project_name
    else:
        eventLog(f"[-] reproducerPrepareOssFuzz {project_name}: Fail to locate the project")
        return leaveRet(False,tmp_dir)
    return (tmp_dir, proj_dir)
def build_from_srcmap(srcmap,issue,replace_dep=None,save_img=False,verifyFix=False,ForceNoErrDump=False,patches=None,oss_fuzz_commit=False,custom_script=[]):
    # Get Basic Information
    fuzzer_info = issue['job_type'].split("_")
    engine      = fuzzer_info[0]
    sanitizer   = getSanitizer(fuzzer_info[1])
    arch ='i386' if fuzzer_info[2] == 'i386' else 'x86_64'
    # Get Issue Date
    issue_date  = srcmap.name.split(".")[0].split("-")[-1]
    commit_date = str2date(issue_date,STAMP_DELAY)
    # Depends on case 344, 367, 36021, the date provided by srcmap should be in UTC-9 to UTC-12
    if 'issue' not in issue: issue['issue'] = {'localId':issue['localId']}
    if engine not in ['libfuzzer','afl','honggfuzz','centipede']:
        return issue_record(issue['project'],issue['issue']['localId'],"Failed to get engine",retv=False)
    if sanitizer == False:
        return issue_record(issue['project'],issue['issue']['localId'],"Failed to get Sanitizer",retv=False)
    return build_fuzzer_with_source(issue['issue']['localId'],issue['project'],
            srcmap,sanitizer,engine,arch,commit_date,replace_dep=replace_dep,
            save_img=save_img,verifyFix=verifyFix, 
            ForceNoErrDump = ForceNoErrDump,patches=patches,oss_fuzz_commit=oss_fuzz_commit,custom_script=custom_script)
def build_fuzzer_with_source(localId,project_name,srcmap,sanitizer,engine,arch,commit_date,replace_dep=None,\
    save_img=False,verifyFix=False,ForceNoErrDump = False,patches=None,oss_fuzz_commit=False,custom_script=[]):
    global REBUTTAL_EXP
    # Build source_dir
        
    srcmap_items = json.loads(open(srcmap).read())
    if not oss_fuzz_commit:
        if "/src" in srcmap_items and srcmap_items['/src']['url']=='https://github.com/google/oss-fuzz.git':
            res = reproducerPrepareOssFuzz(project_name,srcmap_items['/src']['rev'])
        else:
            res = reproducerPrepareOssFuzz(project_name,commit_date)
    else:
        res = reproducerPrepareOssFuzz(project_name,oss_fuzz_commit)
    if not res: return False
    else: tmp_dir , project_dir = res
    
    dockerfile = project_dir / 'Dockerfile'
    INFO(f"[+] dockerfile: {dockerfile}")
    build_data = BuildData(
        sanitizer=sanitizer,
        architecture=arch,
        engine=engine,
        project_name=project_name)
    
    # Step ZERO: Rebase Dockerfiles
    if not rebaseDockerfile(dockerfile,str(commit_date).replace(" ","-")):
        eventLog(f"[-] build_fuzzer_with_source: Fail to Rebase Dockerfile, {localId}")
        return leaveRet(False,tmp_dir)
    # Step ONE: Fix Dockerfiles 
    dockerfileCleaner(dockerfile)
    if not fixDockerfile(dockerfile,project_name):
        eventLog(f"[-] build_fuzzer_with_source: Fail to Fix Dockerfile, {localId}")
        return leaveRet(False,tmp_dir)
    
    # Step TWO: Prepare Dependencies
    with open(srcmap) as f:
        data = json.loads(f.read())
    source_dir = tmpDir()
    src = source_dir / "src"
    src.mkdir(parents=True, exist_ok=True)
    docker_volume = []
    unsorted = list(data.keys())
    sortedKey = sorted(unsorted, key=len)
    mainCompoinent = getPname(localId)
    if mainCompoinent == False: return leaveRet(False,tmp_dir)

    if "/src/xz" in sortedKey: # Edge case
        ForceNoErrDump = True
    
    # Handle Srcmap Info
    for x in sortedKey:
        # INFO(f"[+] Prepare Dependency: {x}")
        if skipComponent(project_name,x):
            continue
        
        if REBUTTAL_EXP and "/src/"+mainCompoinent!=x:
            INFO(f"[+] Not main components, Skip {x}")
            continue
        if verifyFix and mainCompoinent==x:
            approximate = '+'
        else:
            approximate = '-'
        
        newD = {}
        newD['rev'] = data[x]['rev']
        newKey, newD['url'], newD['type'] = trans_table(x,data[x]['url'],data[x]['type'])
        
        del(data[x])
        data[newKey]    = newD
        
        item_name   = newKey
        item_url    = data[newKey]['url']
        item_type   = data[newKey]['type']
        item_rev    = data[newKey]['rev']
        item_name = "/".join(item_name.split("/")[2:])

        if specialComponent(project_name,newKey,data[newKey],dockerfile,commit_date):
            continue
        if item_name == 'aflplusplus' and item_url =='https://github.com/AFLplusplus/AFLplusplus.git':
            continue
        if item_name == 'libfuzzer' and 'llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer' in item_url:
            continue
        
        # Broken Revision
        if item_rev=="" or item_rev == "UNKNOWN":
            issue_record(project_name,localId,f"Broken Meta: No Revision Provided")
            return leaveRet(False,[tmp_dir,source_dir])
        # Ignore not named dependencies if it's not main
        if item_name.strip(" ") == "" and len(data.keys())==1:
            issue_record(project_name,localId,f"Broken Meta: Found Not Named Dep")
            return leaveRet(False,[tmp_dir,source_dir])
        # Borken type
        if item_type not in ['git','svn','hg']:
            issue_record(project_name,localId,f"Broken Meta: No support for {item_type}")
            return leaveRet(False,[tmp_dir,source_dir])
        
        # Try to perform checkout in dockerfile, 
        # which could make reproducing more reliable
        if replace_dep and newKey == "/src/"+replace_dep[0]:
            # modify the dockerfile
            rep_path = replace_dep[1]
            # Tell updateRevisionInfo the path
            rep_dest = dockerfile.parent / rep_path.name
            shutil.copytree(rep_path,rep_dest,symlinks=True,dirs_exist_ok=True)
            if updateRevisionInfo(dockerfile,localId,newKey,data[newKey],rep_dest,approximate):
                continue
            else:
                return leaveRet(False,tmp_dir)
        else:
            if updateRevisionInfo(dockerfile,localId,newKey,data[newKey],commit_date,approximate):
                continue
            
        if item_rev == 'xXxXx': # Branch For patch locating
            with open(getSrcmaps(localId)[0]) as f:
                meta= json.loads(f.read())
            if x in meta:
                item_rev = meta[x]['rev']
            else:
                with open(getSrcmaps()[1]) as f:
                    meta= json.loads(f.read())
                if x in meta: item_rev = meta[x]['rev']
                else: PANIC(f"[x] Weird Key Found {localId}: {x}")
        # Prepare the dependencies and record them. We'll use -v to mount them to the docker container
        if(item_type=='git'):
            clone_res = clone(item_url,item_rev,src,item_name,commit_date=commit_date)
            if clone_res == False:
                eventLog(f"[!] build_from_srcmap: Failed to clone & checkout [{localId}]: {item_name}")
                issue_record(project_name,localId,f"[!] build_from_srcmap: Failed to clone & checkout [{localId}]: {item_name}")
                return leaveRet(False,[tmp_dir,source_dir])
            elif clone_res == None:
                command = f'git log --before="{commit_date.isoformat()}" -n 1 --format="%H"'
                res = subprocess.run(command, stdout=subprocess.PIPE, text=True, shell=True,cwd=src/item_name)
                res = res.stdout.strip()
                if check_call(['git',"reset",'--hard', res], cwd=src/item_name) == False:
                    eventLog(f"[!] build_from_srcmap: Failed to clone & checkout [{localId}]: {item_name}")
                    issue_record(project_name,localId,f"[!] build_from_srcmap: Failed to clone & checkout [{localId}]: {item_name}")
                    return leaveRet(False,[tmp_dir,source_dir])
            docker_volume.append(newKey)
        elif(item_type=='svn'):
            if not svn_clone(item_url,item_rev,src,item_name):
                eventLog(f"[!] build_from_srcmap/svn: Failed clone & checkout: {item_name}")
                return leaveRet(False,[tmp_dir,source_dir])
            docker_volume.append(newKey)
        elif(item_type=='hg'):
            if not hg_clone(item_url,item_rev,src,item_name):
                eventLog(f"[!] build_from_srcmap/hg: Failed clone & checkout: {item_name}")
                return leaveRet(False,[tmp_dir,source_dir])
            docker_volume.append(newKey)
        else:
            PANIC("[Failed] Impossible")
    # Step Three: Extra Scripts
    if not extraScritps(project_name,project_dir,source_dir):
        eventLog(f"[-] build_fuzzer_with_source: Fail to Run ExtraScripts, {localId}")
        return leaveRet(False,[tmp_dir,source_dir])    
    if not fixBuildScript(project_dir/"build.sh",project_name):
        eventLog(f"[-] build_fuzzer_with_source: Fail to Fix Build.sh, {localId}")
        return leaveRet(False,[tmp_dir,source_dir])
    if patches: doPatchMain(localId,dockerfile,patches) # Only used in special mode
    # Used for AIxCC Target Gen
    utils_ctx.BUIL_DIR = project_dir if utils_ctx.BUIL_DIR == None else utils_ctx.BUIL_DIR
    # Let's Build It
    result = build_fuzzers_impl(localId,project=project_name,
                                project_dir= project_dir,
                                engine=build_data.engine,
                                sanitizer=build_data.sanitizer,
                                architecture=build_data.architecture,
                                source_path= source_dir/"src",
                                mount_path=Path("/src"),
                                save_img=save_img,noDump=ForceNoErrDump,
                                custom_script=custom_script)
    # we need sudo since the docker container root touched the folder
    if not CLEAN_TMP: check_call(["sudo","rm","-rf",source_dir])
    return leaveRet(result,tmp_dir)
def build_fuzzers_impl( localId,project,project_dir,engine,
    sanitizer,architecture,source_path,
    mount_path=None,save_img=False,noDump=False,custom_script=[]):
    global CONTAINER_ENV
    # Set the LogFile
    logFile = OSS_ERR / f"{localId}_Image.log"
    INFO(f"[+] Check the output in file: {logFile}")

    # Clean The WORK/OUT DIR
    project_out  = OSS_OUT  / str(localId) 
    project_work = OSS_WORK / str(localId)
    if project_out.exists():  check_call(["sudo","rm","-rf",project_out])
    if project_work.exists(): check_call(["sudo","rm","-rf",project_work])
    project_out.mkdir()
    project_work.mkdir()
    
    args = ['-t',f'gcr.io/oss-fuzz/{localId}','--file', str(project_dir/"Dockerfile"), str(project_dir)]
    if not docker_build(args,logFile=logFile):
        return issue_record(project,localId,f"Failed to build DockerImage",retv=False)
    
    # Build Succeed, Try Compiling
    if logFile and logFile.exists(): os.remove(str(logFile))
    env = [
        'FUZZING_ENGINE=' + engine,
        'SANITIZER=' + sanitizer,
        'ARCHITECTURE=' + architecture,
        'FUZZING_LANGUAGE=' + getLanguage(localId),
    ]
    command = sum([['-e', x] for x in env], [])


    # Mount the Source/Dependencies (we try to replace this with modifying dockerfile)
    if source_path and mount_path:
        for item in source_path.iterdir():  
            command += [ '-v', '%s:%s' % (item, mount_path / item.name)]
    # Mount out/work dir
    command += ['-v', '%s:/out' % project_out, '-v','%s:/work' % project_work, '-t', f'gcr.io/oss-fuzz/{localId}']
    # supports for submodule tracker
    command += custom_script

    # if save_img:
    #     result = docker_run(["--name",f"arvo_body_{localId}_{save_img}"]+command,rm=False)
    # else:
    if(1):
        if noDump == '/dev/null':
            logFile = Path('/dev/null')
        elif noDump == False:
            logFile = OSS_ERR / f"{localId}_Compile.log"
            INFO(f"[+] Check the output in file: {str(logFile)}")
        else:
            logFile = None
        result = docker_run(command,logFile=logFile)
    if not result:
        FAIL('[-] Failed to Build Targets')
        return False
    else:
        if logFile and logFile.exists() and str(logFile) != "/dev/null":
            os.remove(str(logFile))

    if save_img:
        CONTAINER_ENV = [] # This is used to store the env
        cur_idx = 0 
        budy_container_arg = ["-d","--name",f"reproducer_{localId}"]
        mounting_folders = []
        while(cur_idx < len(command)):
            if command[cur_idx] == "-v":
                tmp = command[cur_idx+1].split(":")
                mounting_folders.append((tmp[0],tmp[1]))
                cur_idx +=2
            elif command[cur_idx] == "-t":
                budy_container_arg.append("-t")
                budy_container_arg.append(command[cur_idx+1])
                budy_container_arg.append("sleep")
                budy_container_arg.append("infinity")
                cur_idx +=2
            elif command[cur_idx] == "-e":
                CONTAINER_ENV.append("-e")
                CONTAINER_ENV.append(command[cur_idx+1])
                cur_idx +=2
            else:
                budy_container_arg.append(command[cur_idx])
                cur_idx +=1
        
        # Spawn a budy_container, we copy things out from it to the reproducer
        docker_run(budy_container_arg,rm=False)
        # Copy the mounted file to the budy-container
        for src, dst in mounting_folders:
            if(dst=='/work'): # Skip the work dir
                docker_exec(f"reproducer_{localId}",["mkdir","-p",'/work'])
                continue
            permissionResolve(src)
            # ensure there is  no existing folder
            if Path(src).is_dir(): docker_exec(f"reproducer_{localId}",["rm","-rf",dst])
            if(docker_cp(src,f"reproducer_{localId}:"+dst)==False): return False
        
    return True
def saveCommand(fpath,image,issue):
    global CONTAINER_ENV
    envs = ['-e',ASAN_OPTIONS,'-e',MSAN_OPTIONS,'-e',UBSAN_OPTIONS,'-e',FUZZER_ARGS,'-e',AFL_FUZZER_ARGS]
    envs += CONTAINER_ENV
    localId = issue['localId']
    fuzz_target = getFuzzer(localId, OSS_OUT / str(localId)).name
    
    # For local
    tmp = ["docker","run","--rm","--privileged"] + envs + ["-t",image] +[f"/out/{fuzz_target}","/tmp/poc"]
    with open(fpath,'w') as f:
        f.write(" ".join(tmp)+"\n")
    
    if (fpath.parent/"arvo").exists(): return True
    
    # For in-Image script
    enable_env = ''
    for i in range(1,len(envs),2):
        enable_env+= f"export {envs[i]}\n"
    do_check = f"/out/{fuzz_target} /tmp/poc\n"
    
    arvo = f"""#!/bin/bash
{enable_env}
if [ "$#" -ge 1 ]; then
# Get the first parameter
first_param="$1"

if [ "$first_param" = "compile" ]; then
    compile
elif [ "$first_param" = "run" ]; then
    {do_check}
else
    echo "Unknown command: $first_param"
fi
    else
        {do_check}
fi
"""
    with open(fpath.parent/"arvo",'w') as f:
        f.write(arvo)
    return True if execute_ret(['chmod','+x',str(fpath.parent/"arvo")])==0 else False
def pushImgRemote(localId,issue):
    imgSavePath = OSS_IMG / str(localId)
    if imgSavePath.exists(): shutil.rmtree(imgSavePath)
    imgSavePath.mkdir()
    vul = Path(OSS_IMG / f"{localId}/arvo_vul.sh")
    fix = Path(OSS_IMG / f"{localId}/arvo_fix.sh")

    cnv = f"arvo_rf_{localId}_vul"
    cnf = f"arvo_rf_{localId}_fix"
    if  saveCommand(vul,f"n132/arvo:{localId}-vul",issue) and \
        saveCommand(fix,f"n132/arvo:{localId}-fix",issue) and \
        docker_create(cnv,f"n132/arvo:{localId}-vul") and \
        docker_create(cnf,f"n132/arvo:{localId}-fix") and \
        docker_cp(OSS_IMG/f"{localId}"/'arvo',f"{cnv}:/bin/arvo") and \
        docker_cp(OSS_IMG/f"{localId}"/'arvo',f"{cnf}:/bin/arvo") and \
        docker_commit(cnv,f"n132/arvo:{localId}-vul") and \
        docker_commit(cnf,f"n132/arvo:{localId}-fix") and \
        docker_push(f"n132/arvo:{localId}-vul") and \
        docker_push(f"n132/arvo:{localId}-fix"):

        docker_rm(cnv)
        docker_rm(cnf)
        docker_rmi(f"n132/arvo:{localId}-vul")
        docker_rmi(f"n132/arvo:{localId}-fix")
        return True
    else:
        FAIL(f"[-] Failed to dockerize {localId}")
        docker_rm(cnv)
        docker_rm(cnf)
        return leaveRet(False,imgSavePath)
def verify(localId,save_img=False):
    # if Save_img == True, we should make sure there is no two workers working
    # on the same localId or confliction may happen
    def leave(result):
        if save_img:
            docker_rm(f"reproducer_{localId}")
            docker_rmi(f"n132/arvo:{localId}-vul")
            docker_rmi(f"n132/arvo:{localId}-fix")
        if CLEAN_TMP and case_dir: clean_dir(case_dir)
        if RM_IMAGES: remove_oss_fuzz_img(localId)
        return result
    def saveImg_LoadCommit(tag):
        if not save_img:
            return True
        if not docker_cp(case_path.absolute(),f"reproducer_{localId}:"+"/tmp/poc"):
            return False
        return False if not doCommitClean(localId,tag) else True
    
    def pushImg(): return pushImgRemote(localId,issue) if save_img else True
    localId = localIdMapping(localId)
    INFO(f"[+] Working on {localId}")
    if save_img:
        docker_rmi(f"n132/arvo:{localId}-vul")
        docker_rmi(f"n132/arvo:{localId}-fix")

    # 1. Fetch the basic info for the vul
    srcmap,issue = getIssueTuple(localId)
    if not srcmap or not issue:
        eventLog(f"Failed to get the srcmap or issue for {localId}")
        return False
    # Set project for early issues
    if 'project' not in issue.keys(): issue['project'] = issue['fuzzer'].split("_")[1]
    if(len(srcmap)!=2):
        issue_record(issue['project'],localId,f"Have more/less than 2 Scrmap")
        return leave(False)
    old_srcmap =  srcmap[0]
    new_srcmap =  srcmap[1]

    # 2. Download the PoC
    INFO("[+] Downloading PoC")
    case_dir = tmpDir()
    try:
        case_path = downloadPoc(issue,case_dir,"crash_case")
    except:
        issue_record(issue['project'],localId,f"Fail to Download the Reproducer")
        return leave(False)
    if not case_path or not case_path.exists():
        issue_record(issue['project'],localId,f"Fail to Download the Reproducer")
        return leave(False)
    
    
    # 3. Build the Vulnerabel Software
    INFO("[+] Build the Vulnerable Version")

    save_img_tag = "Vul" if save_img else False
    old_res = build_from_srcmap(old_srcmap,issue,save_img=save_img_tag)
    if not old_res:
        issue_record(issue['project'],localId,f"Fail to build old fuzzers from srcmap")
        return leave(False)
    ret_code = crashVerify(issue,case_path,'vul')
    if ret_code == None: 
        issue_record(issue['project'],localId,f"Fail to get the fuzzer")
        return leave(False)
    if ret_code == True:
        issue_record(issue['project'],localId,f"Fail to reproduce the crash")
        return leave(False)
    if not saveImg_LoadCommit('vul'): return leave(False)
    remove_oss_fuzz_img(localId) # Remove docker image

    # 4. Build the Fixed Software
    INFO("[+] Build the Fixed Version")
    save_img_tag = "Fix" if save_img else False
    new_res = build_from_srcmap(new_srcmap,issue,save_img=save_img_tag,verifyFix=True)
    if not new_res:
        issue_record(issue['project'],localId,f"Fail to build new fuzzers from srcmap")
        return leave(False)
    ret_code = crashVerify(issue,case_path,'fix')
    if not ret_code:
        issue_record(issue['project'],localId,f"Fail to reproduce the fix")
        return leave(False)
    if not saveImg_LoadCommit('fix'): return leave(False)
    remove_oss_fuzz_img(localId) # Remove docker image

    # 5. Push the local DockerImg to dockerhub
    return leave(False) if not pushImg() else leave(True)

if __name__ == "__main__":
    pass
