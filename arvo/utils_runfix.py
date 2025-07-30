from .utils import *
from unidiff        import PatchSet

def oracleDiff(src,dst,name):
    with open(src) as f:
        diff_content = f.read()
    with open(Path(dst)/name,'w') as f:
        f.write(diff_content)
def genDiff(ori,update):
    filea = tmpFile()
    fileb = tmpFile()
    with open(filea,'wb') as f:
        f.write(ori)
    with open(fileb,'wb') as f:
        f.write(update)
    res = execute(["git",'diff',"-W",filea.absolute(),fileb.absolute()],return_code=[0,1])
    print(res)
    shutil.rmtree(filea.parent.absolute())
    shutil.rmtree(fileb.parent.absolute())
    return res
def fixDiff(fix,dst,name):
    with open(Path(dst)/name,'wb') as f:
        f.write(fix)

"""
"""
def get_vul_code(diff_file,repo_dir):
    # Get the vul code
    patch = PatchSet.from_filename(diff_file, encoding='utf-8')
    mods = []
    # parse the file
    for _ in range(len(patch)):
        target_set = patch[_]
        if target_set.is_modified_file:
            file_name = target_set.source_file[1:]
            for mod in target_set:
                tmp = (file_name,mod.source_start,mod.source_length)
                mods.append([tmp,target_set])
    
    vul_code = []
    count = 0  # Counter for mod
    for x,y in mods:
        if not (repo_dir/x[0][1:]).is_file():
            continue
        with open(repo_dir/x[0][1:],'rb') as f:
            code = f.readlines()[x[1]-1:x[1]+x[2]-1]
        # line info 
        diff_content = str(y).split("\n")
        added_lines   = []
        removed_lines = []
        # pase the diff
        tmp = count
        for z in range(len(diff_content)):
            if(diff_content[z].startswith("@@ ")):
                if tmp !=0:
                    tmp-=1
                else:
                    diff_content = diff_content[z+1:]
                    break
        ct = 0
        while(ct<len(diff_content)):
            if diff_content[ct].startswith("-"):
                removed_lines.append(ct)
            elif diff_content[ct].startswith("+"):
                added_lines.append(ct)
            elif diff_content[ct].startswith("@@ "):
                break
            ct+=1
        # store them
        ori_code = b"".join(code)
        item = [ori_code,removed_lines,added_lines,y.target_file]
        vul_code.append(item)
        count+=1
    return vul_code
def runFixLogInit(logDiff, module,tag):
    logDiff = (logDiff / f"{module}_{tag}") if logDiff else False
    if logDiff != False:
        logDiff.mkdir(exist_ok=True)
    return logDiff
def runFixLogImp(logDiff, localId, vul_code, fixes, diff_file,res):
    dst= logDiff / str(localId)
    dst.mkdir(exist_ok=True)
    diff_content = genDiff(vul_code[0],fixes[0])
    fixDiff(diff_content,dst,f"fix_{localId}.diff")
    oracleDiff(diff_file,dst,f"ora_{localId}.diff")
    dst= logDiff / str(localId)
    with open(dst/"res",'w') as f:
        if res:
            f.write(f"[+] SUCCESS!\n")
        else:
            f.write(f"[-] FAIL.\n")
def runFixCheckModule(module):
    if module == "Codex":
        return "code-davinci-edit-001"
    if module not in ['gpt-4-turbo',"gpt-3.5-turbo-16k","Starcoder","gpt-3.5-turbo-instruct","code-davinci-edit-001","gpt-3.5-turbo","gpt-4","gpt-4-1106-preview"] and \
        'Wizard' not in module:
        PANIC(f"[X] Invalid Model {module}")
    return module
def runFixGetVulCode(diff_file,repo):
    # Get code info, maker sure there should be only one case
    vul_code = get_vul_code(diff_file,repo)
    return vul_code[0] if len(vul_code)==1 else False