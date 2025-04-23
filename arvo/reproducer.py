from .utils import *
from .utils_core import *
from .utils_git import *
from .dev import *
import collections
BuildData = collections.namedtuple(
    'BuildData', ['project_name', 'engine', 'sanitizer', 'architecture'])
from .transform import trans_table
# Global
import copy
DEAMON_CMD = []
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
def doCommitNclean(localId,tag):
    if not docker_commit(f"reproducer_{localId}",f"n132/arvo:{localId}-{tag}"):
        return False
    if not docker_rm(f"reproducer_{localId}"):
        return False
    if not docker_rm(f"arvo_deamon_{localId}"):
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
    if 'issue' not in issue:
        issue['issue'] = {'localId':issue['localId']}
    if engine not in ['libfuzzer','afl','honggfuzz','centipede']:
        issue_record(issue['project'],issue['issue']['localId'],"Failed to get engine")
        return False
    if sanitizer == False:
        issue_record(issue['project'],issue['issue']['localId'],"Failed to get Sanitizer")
        return False
    return build_fuzzer_with_source(issue['issue']['localId'],issue['project'],
            srcmap,sanitizer,engine,arch,commit_date,replace_dep=replace_dep,
            save_img=save_img,verifyFix=verifyFix, 
            ForceNoErrDump = ForceNoErrDump,patches=patches,oss_fuzz_commit=oss_fuzz_commit,custom_script=custom_script)

def build_fuzzer_with_source(localId,project_name,srcmap,sanitizer,engine,arch,commit_date,replace_dep=None,\
    save_img=False,verifyFix=False,ForceNoErrDump = False,patches=None,oss_fuzz_commit=False,custom_script=[]):
    global REBUTTAL_EXP
    '''
    Most projects are git repos, but we still have:
    hg: njs, graphicsmagick...

    '''
    # Build source_dir
    def rootRM(dir_path):
        if CLEAN_TMP:
            dir_name = str(dir_path).split("/")[-1]
            docker_run(["-v", f"{OSS_TMP}:/mnt" , "ubuntu", "/bin/bash", "-c",
                        f"rm -rf /mnt/{dir_name}"]) 

    srcmap_items = json.loads(open(srcmap).read())
    if not oss_fuzz_commit:
        if "/src" in srcmap_items and srcmap_items['/src']['url']=='https://github.com/google/oss-fuzz.git':
            res = reproducerPrepareOssFuzz(project_name,srcmap_items['/src']['rev'])
        else:
            # Reset OSS-Fuzz to get Dependencies 
            res = reproducerPrepareOssFuzz(project_name,commit_date)
    else:
        res = reproducerPrepareOssFuzz(project_name,oss_fuzz_commit)
    if not res:
        return False
    else:
        tmp_dir , project_dir = res
    
    dockerfile = project_dir / 'Dockerfile'
    if DEBUG:
        print(f"[+] dockerfile: {dockerfile}")
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
    if DEBUG:
        print(f"[+] Main Component: {mainCompoinent}")
    if mainCompoinent == False:
        return leaveRet(False,tmp_dir)
    if "/src/xz" in sortedKey:
        ForceNoErrDump = True
    

    for x in sortedKey:
        if DEBUG:
            print(f"[+] Prepare Dependency: {x}")
        if skipComponent(project_name,x):
            continue
        
        if REBUTTAL_EXP and "/src/"+mainCompoinent!=x:
            print(f"[+] Not main components, Skip {x}")
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
        # if ( item_name == 'aflplusplus' and item_url =='https://github.com/AFLplusplus/AFLplusplus.git') or \
        #     (item_name=='afl' and item_url=='https://github.com/google/AFL.git'):
        if ( item_name == 'aflplusplus' and item_url =='https://github.com/AFLplusplus/AFLplusplus.git'):
                # print("[+] AFL++: Use the one on BaseIMG")
                continue
        if( item_name == 'libfuzzer' and
            'llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer' in item_url):
                # print("[+] libfuzzer: Use the one on BaseIMG")
                continue
        
        # Broken Revision
        if item_rev=="" or item_rev == "UNKNOWN":
            issue_record(project_name,localId,f"Broken Meta: No Revision Provided")
            shutil.rmtree(source_dir)
            return leaveRet(False,tmp_dir)
        # Ignore not named dependencies if it's not main
        if item_name.strip(" ") == "" and len(data.keys())==1:
            issue_record(project_name,localId,f"Broken Meta: Found Not Named Dep")
            shutil.rmtree(source_dir)
            return leaveRet(False,tmp_dir)
        # Borken type
        if item_type not in ['git','svn','hg']:
            issue_record(project_name,localId,f"Broken Meta: No support for {item_type}")
            shutil.rmtree(source_dir)
            return leaveRet(False,tmp_dir)
        
        
        # Try to perform checkout in dockerfile, 
        # which could make reproducing more reliable
        if replace_dep and newKey == "/src/"+replace_dep[0]:
            # modify the dockerfile
            rep_path = replace_dep[1]
            # Tell updateRevisionInfo the path
            rep_dest = dockerfile.parent/rep_path.name
            shutil.copytree(rep_path,rep_dest,symlinks=True,dirs_exist_ok=True)
            if updateRevisionInfo(dockerfile,localId,newKey,data[newKey],rep_dest,approximate):
                continue
            else:
                return leaveRet(False,tmp_dir)
        else:
            if updateRevisionInfo(dockerfile,localId,newKey,data[newKey],commit_date,approximate):
                continue
            
        if item_rev == 'xXxXx':
            with open(getSrcmaps(localId)[0]) as f:
                meta= json.loads(f.read())
            if x in meta:
                item_rev = meta[x]['rev']
            else:
                with open(getSrcmaps()[1]) as f:
                    meta= json.loads(f.read())
                if x in meta:
                    item_rev = meta[x]['rev']
                else:
                    PANIC(f"[x] Weird Key Found {localId}: {x}")
        # Prepare the dependencies and record them. We'll use -v to mount them to the docker container
        if(item_type=='git'):
            clone_res = clone(item_url,item_rev,src,item_name,commit_date=commit_date)
            if clone_res == False:
                eventLog(f"[!] build_from_srcmap: Failed to clone & checkout [{localId}]: {item_name}")
                shutil.rmtree(source_dir)
                issue_record(project_name,localId,f"[!] build_from_srcmap: Failed to clone & checkout [{localId}]: {item_name}")
                return leaveRet(False,tmp_dir)
            elif clone_res == None:
                command = f'git log --before="{commit_date.isoformat()}" -n 1 --format="%H"'
                res = subprocess.run(command, stdout=subprocess.PIPE, text=True, shell=True,cwd=src/item_name)
                res = res.stdout.strip()
                if check_call(['git',"reset",'--hard', res], cwd=src/item_name) == False:
                    eventLog(f"[!] build_from_srcmap: Failed to clone & checkout [{localId}]: {item_name}")
                    shutil.rmtree(source_dir)
                    issue_record(project_name,localId,f"[!] build_from_srcmap: Failed to clone & checkout [{localId}]: {item_name}")
                    return leaveRet(False,tmp_dir)
            docker_volume.append(newKey)
        elif(item_type=='svn'):
            if not svn_clone(item_url,item_rev,src,item_name):
                eventLog(f"[!] build_from_srcmap/svn: Failed clone & checkout: {item_name}")
                shutil.rmtree(source_dir)
                return leaveRet(False,tmp_dir)
            docker_volume.append(newKey)
        elif(item_type=='hg'):
            if not hg_clone(item_url,item_rev,src,item_name):
                eventLog(f"[!] build_from_srcmap/hg: Failed clone & checkout: {item_name}")
                shutil.rmtree(source_dir)
                return leaveRet(False,tmp_dir)
            docker_volume.append(newKey)
        else:
            pass # Impossible to hit this line
    # Step Three: Extra Scripts
    if not extraScritps(project_name,project_dir,source_dir):
        eventLog(f"[-] build_fuzzer_with_source: Fail to Run ExtraScripts, {localId}")
        shutil.rmtree(source_dir)
        return leaveRet(False,tmp_dir)    
    if not fixBuildScript(project_dir/"build.sh",project_name):
        eventLog(f"[-] build_fuzzer_with_source: Fail to Fix Build.sh, {localId}")
        shutil.rmtree(source_dir)
        return leaveRet(False,tmp_dir)
    if patches:
        doPatchMain(localId,dockerfile,patches)
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
    rootRM(source_dir)
    return leaveRet(result,tmp_dir)

def build_fuzzers_impl( localId,project,project_dir,engine,
    sanitizer,architecture,source_path,
    mount_path=None,save_img=False,noDump=False,custom_script=[]):
    global DEAMON_CMD
    project_out  = OSS_OUT  / str(localId) 
    project_work = OSS_WORK / str(localId)

    if not project_out.exists():
        project_out.mkdir()        
    if not project_work.exists():
        project_work.mkdir()
    
    args = ['-t',f'gcr.io/oss-fuzz/{localId}','--file', str(project_dir/"Dockerfile"), str(project_dir)]
    
    
    if DUMPERR!=False:
        dumpErr = OSS_ERR / f"{localId}_Image.log"
        print(f"[+] Check the output in file: {str(dumpErr)}")
    else:
        dumpErr = None


    if not docker_build(args,dumpErr=dumpErr):
        issue_record(project,localId,f"Failed to build DockerImage")
        return False
    

    if DUMPERR and dumpErr!=None and dumpErr.exists():
        os.remove(str(dumpErr))
    if DEBUG:
        print('[+] Cleaning existing out dir')
    if DEBUG:
        rm_output = None
    else:
        rm_output = "/dev/null"
    docker_run([
        '-v',
        '%s:/out' % project_out , '-t',
        f'gcr.io/oss-fuzz/{localId}', '/bin/bash', '-c', 'rm -rf /out/*'
    ],dumpErr=rm_output)
    docker_run([
        '-v',
        '%s:/work' % project_work , '-t',
        f'gcr.io/oss-fuzz/{localId}', '/bin/bash', '-c', 'rm -rf /work/*'
    ],dumpErr=rm_output)
    env = [
        'FUZZING_ENGINE=' + engine,
        'SANITIZER=' + sanitizer,
        'ARCHITECTURE=' + architecture,
        'FUZZING_LANGUAGE=' + getLanguage(localId),
    ]
    command = sum([['-e', x] for x in env], [])

    additional_script(project,source_path)
    if source_path and mount_path:
        for item in source_path.iterdir():  
            command += [
                '-v',
                '%s:%s' % (item, mount_path / item.name),
            ]

    command += [
                '-v',
                '%s:/out' % project_out, '-v',
                '%s:/work' % project_work, '-t',
                f'gcr.io/oss-fuzz/{localId}'
    ]
    
    # support submodule tracker
    command+= custom_script
    if save_img != False:
        result = docker_run(["--name",f"arvo_deamon_{localId}_{save_img}"]+command,rm=False)
    else:
        if DUMPERR!=False and noDump==False:
            dumpErr = OSS_ERR / f"{localId}_Compile.log"
            print(f"[+] Check the output in file: {str(dumpErr)}")
        elif noDump == '/dev/null':
            dumpErr = Path('/dev/null')
            # [+] Hide the output
        else:
            dumpErr = None
        
        result = docker_run(command,dumpErr=dumpErr)
    if not result:
        print('[-] Failed to Build Targets')
        return False
    else:
        if DUMPERR!=False and dumpErr!= None and dumpErr.exists():
            if str(dumpErr) != "/dev/null":
                os.remove(str(dumpErr))

    if save_img:
        DEAMON_CMD = []
        cur_idx = 0 
        deamon = ["-d","--name",f"reproducer_{localId}"]
        cps = []
        while(cur_idx < len(command)):
            if command[cur_idx] == "-v":
                dirs = command[cur_idx+1].split(":")
                cps.append((dirs[0],dirs[1]))
                cur_idx +=2
            elif command[cur_idx] == "-t":
                deamon.append("-t")
                deamon.append(command[cur_idx+1])
                deamon.append("sleep")
                deamon.append("infinity")
                cur_idx +=2
            elif command[cur_idx] == "-e":
                DEAMON_CMD.append("-e")
                DEAMON_CMD.append(command[cur_idx+1])
                cur_idx +=2
            else:
                deamon.append(command[cur_idx])
                cur_idx +=1
        # Spawn a deamon container
        
        docker_run(deamon,rm=False)
        # Copy the mounted file to the deamon container
        for pr in cps:
            # find /opt/lampp/htdocs -type d -exec chmod 755 {} \;
            permissionResolve(pr[0])
            if Path(pr[0]).is_dir():
                docker_exec(f"reproducer_{localId}",["rm","-rf",pr[1]])
            if(docker_cp(pr[0],f"reproducer_{localId}:"+pr[1])==False):
                return False
        # Save the command which includes ENV
    
    return True
def permissionResolve(target_path):
    # Test Code to make testing faster
    res = execute_ret(["sudo","chown","-R",f"{UserName}:{UserName}",target_path])
    print(f"[+] Chown result = {res}")

def saveCommand(fpath,image,issue):
    global DEAMON_CMD
    envs = ['-e',ASAN_OPTIONS,'-e',MSAN_OPTIONS,'-e',UBSAN_OPTIONS,'-e',FUZZER_ARGS,'-e',AFL_FUZZER_ARGS]
    envs += DEAMON_CMD
    localId = issue['localId']
    fuzz_target = getFuzzer(localId, OSS_OUT / str(localId)).name
    
    # For local
    tmp = ["docker","run","--rm","--privileged"] 
    tmp += envs
    tmp += ["-t",image]
    tmp += [f"/out/{fuzz_target}","/tmp/poc"]
    with open(fpath,'w') as f:
        f.write(" ".join(tmp)+"\n")
    
    if (fpath.parent/"arvo").exists():
        return True
    
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
    if execute_ret(['chmod','+x',str(fpath.parent/"arvo")])==0:
        return True
    return False
def saveImg(localId,issue):
    imgSavePath = OSS_IMG / str(localId)
    if not imgSavePath.exists():
        imgSavePath.mkdir()
    else:
        shutil.rmtree(imgSavePath)
        imgSavePath.mkdir()
    vul = Path(OSS_IMG / f"{localId}/arvo_vul.sh")
    fix = Path(OSS_IMG / f"{localId}/arvo_fix.sh")
    # rf -> refactor
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
        print(f"[-] Failed to dockerize {localId}")
        docker_rm(cnv)
        docker_rm(cnf)
        shutil.rmtree(imgSavePath)
        return False
OSS_Fuzz_Arch = OSS_TMP / "OSS_Fuzz_Arch"

def false_positive(localId):
    # Check OSS-Fuzz's Compiled Binary to see if the poc can crash the target or not.
    # return true  when it's likely a false positive
    # return false when it's not a false positive
    # return none  when we can't decide
    store = OSS_Fuzz_Arch / str(localId)
    if not store.exists():
        store.mkdir(parents=True, exist_ok=True)
        if not getOSSFuzzer(localId, store):
            shutil.rmtree(store)
            return False
        for target in store.iterdir():
            with zipfile.ZipFile(target, "r") as zf:
                file_list = zf.namelist()
            single_file = True if len(file_list)==1 else False
            subprocess.run(["unar",str(target)],cwd=store)
            if single_file:
                new_dir = store / target.name.split(".")[0]
                new_dir.mkdir()
                subprocess.run(["mv",file_list[0],str(new_dir)],cwd=store)
    todo = []
    for target in store.iterdir():
        if "zip" not in target.name:
            todo.append(target)
    if(len(todo) !=2):
        WARN("FAILED to get the fuzz target")
        return None
    todo.sort(key=lambda x: x.name)

    LogDir = ARVO/"Log"/"false_positive"
    if not LogDir.exists():
        LogDir.mkdir()
    poc = getPoc(localId)
    if not poc:
        return None
    res = []
    for x in todo:
        fuzz_target = getFuzzer(localId,x)
        if fuzz_target == None:
            WARN(f"{localId=} {x=} can't find the fuzz target")
            continue
        cmd = ['docker','run','--rm','--privileged']
        cmd.extend(["-v",f"{poc}:/tmp/poc", '-v',f"{str(fuzz_target.parent)}:/out",
            f"gcr.io/oss-fuzz-base/base-runner", "timeout", "180",
            f'/out/{fuzz_target.name}','/tmp/poc'])
    
        with open(LogDir/x.name,'wb') as f:
            print(" ".join(cmd))
            returnCode = execute_ret(cmd,stdout=f,stderr=f)
            f.write(f"\nReturn Code: {returnCode}\n".encode())
        if returnCode == 255: # deprecated style
            with open(LogDir/x.name,'rb') as f:
                if_warn = b"WARNING: using the deprecated call style " in f.read()
            if if_warn:
                    cmd = ['docker','run','--rm','--privileged']
                    cmd.extend(["-v",f"{poc}:/tmp/poc", '-v',f"{str(fuzz_target.parent)}:/out",
                        f"gcr.io/oss-fuzz-base/base-runner", "timeout", "180",
                        f'/tmp/{fuzz_target.name}','/tmp/poc'])
                    with open(LogDir/x.name,'wb') as f:
                        print(" ".join(cmd))
                        returnCode = execute_ret(cmd,stdout=f,stderr=f)
                        f.write(f"\nReturn Code: {returnCode}\n".encode())
        res.append(pocResultChecker(returnCode,LogDir/x.name,[],True))
    # clean poc and downloaded binary
    if CLEAN_TMP:
        shutil.rmtree(poc.parent)
        shutil.rmtree(store)
    if res != [False,True]:
        return True # False positive
    else:
        return False
def false_positives(localIds,failed_on_verify=True):
    # The passed localIds must return 
    confirmed = []
    for localId in localIds:
        if failed_on_verify != True and verify(localId):
            continue
        if false_positive(localId)==True:
            confirmed.append(localId)
    return confirmed
def verify(localId,save_img=False):
    localId = localIdMapping(localId)
    # if localId in avoid.avoid:
    #     print(f"[+] Please avoid waste time on issue {localId}")
    #     return False
    # if Save_img == True, we should make sure there is no two workers working
    # on the same localId or confliction may happen
    print(localId)

    built_img = False
    if save_img:
        docker_rmi(f"n132/arvo:{localId}-vul")
        docker_rmi(f"n132/arvo:{localId}-fix")
    def leave(result):
        if save_img:
            docker_rm(f"reproducer_{localId}")
            if result == False:
                docker_rmi(f"n132/arvo:{localId}-vul")
                docker_rmi(f"n132/arvo:{localId}-fix")
        if CLEAN_TMP and case_dir:
            clean_dir(case_dir)
        if RM_IMAGES and built_img:
            try:
                remove_oss_fuzz_img(localId)
            except:
                pass
        return result
    
    srcmap,issue = getIssueTuple(localId)

    if not srcmap or not issue:
        eventLog(f"Failed to get the srcmap or issue for case {localId}")
        return False
    if 'project' not in issue.keys():
        issue['project'] = issue['fuzzer'].split("_")[1]
    case_dir = tmpDir()
    print("[+] Downloading PoC")
    try:
        case_path = downloadPoc(issue,case_dir,"crash_case")
    except:
        issue_record(issue['project'],localId,f"Fail to Download the Reproducer")
        return leave(False)
    if not case_path or not case_path.exists():
        issue_record(issue['project'],localId,f"Fail to Download the Reproducer")
        return leave(False)
    if(len(srcmap)!=2):
        issue_record(issue['project'],localId,f"Have more/less than 2 Scrmap")
        return leave(False)
    old_srcmap =  srcmap[0]
    new_srcmap =  srcmap[1]
    print("[+] Build the Vulnerable Version")
    if save_img:
        old_res = build_from_srcmap(old_srcmap,issue,save_img="Vul")
    else:
        old_res = build_from_srcmap(old_srcmap,issue)
    if not old_res:
        issue_record(issue['project'],localId,f"Fail to build old fuzzers from srcmap")
        return leave(False)

    built_img = True
    ret_code = crashVerify(issue,case_path,'vul')
    if ret_code==None:
        issue_record(issue['project'],localId,f"Fail to get the fuzzer")
        return leave(False)
    if ret_code:
        issue_record(issue['project'],localId,f"Fail to reproduce the crash")
        return leave(False)
    if save_img:
        if not docker_cp(case_path.absolute(),f"reproducer_{localId}:"+"/tmp/poc"):
            return leave(False)
        if not doCommitNclean(localId,'vul'):
            return leave(False)
     
    print("[+] Build the Fixed Version")
    if save_img:
        remove_oss_fuzz_img(localId) # Remove docker image
    built_img = False
    if save_img:
        new_res = build_from_srcmap(new_srcmap,issue,save_img="Fix",verifyFix=True)
    else:
        new_res = build_from_srcmap(new_srcmap,issue,verifyFix=True)
    if not new_res:
        issue_record(issue['project'],localId,f"Fail to build new fuzzers from srcmap")
        return leave(False)
    built_img = True
    ret_code = crashVerify(issue,case_path,'fix')
    if not ret_code:
        issue_record(issue['project'],localId,f"Fail to reproduce the fix")
        return leave(False)
    if save_img:
        if not docker_cp(case_path.absolute(),f"reproducer_{localId}:"+"/tmp/poc"):
            return leave(False)
        if not doCommitNclean(localId,'fix'):
            return leave(False)
    if save_img:
        if saveImg(localId,issue)==False:
            return leave(False)
    return leave(True)

        
if __name__ == "__main__":
    pass
