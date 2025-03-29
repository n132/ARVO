from .utils import *
from .utils_GPT import GPTLabeler
from .OpenAI import performCompletionFix, performChatFix
import jsonlines
import re
from .starcoder              import start_coder_fix
from .utils_diff             import getVulCommit, getDiff
from .utils_runfix           import get_vul_code
from .utils_git              import GitTool
TEMP = 0.75

def parseDescription(patch_desc):
    # parsing
    x,y,z = 0,0,0
    for _ in range(len(patch_desc)):
        if x==0 and patch_desc[_].endswith("ity:\n"):
            x=_+1
        elif y==0 and patch_desc[_].endswith("ix:\n"):
            y=_+1
        elif z==0 and patch_desc[_].endswith("ix:\n"):
            z=_+1
    d = dict()
    d['vul'] =  ("\n".join(patch_desc[x:y-1])).strip(" \n")
    d['summary'] = ("\n".join(patch_desc[y:z-1])).strip(" \n")
    d['details'] = ("\n".join(patch_desc[z:])).strip(" \n")
    if d['vul']=="":
        return False
    return d
def getDescription(fname):
    if fname.exists():
        with open(fname,'r') as f:
            patch_desc = f.readlines()
        return parseDescription(patch_desc)
    else:
        return False
def getDesc(localId):
    localDesc = Path(f"./PatchDesc/{localId}.log")
    if localDesc.exists():
        patch_desc = getDescription(localDesc)
    else:
        patch_desc = GPTLabeler(localId)
        assert(patch_desc != False)
        with open(localDesc,'w') as f:
            f.write(patch_desc)
    return patch_desc
def extractDesc(localId):
    crash_logs = ARVO / "Log" / "Round1" / f"{localId}_vul.log"
    if not crash_logs.exists():
        panic("[-] Unable to extract the crash info from the log file. We may need to generate it first...")
    with open(crash_logs,'rb') as f:
        crashInfo = f.read()
    return crashInfo
"""
"""
def get_GPT_fix(localId,vul_code,work_dir,model,lite=False,logDiff=False):
    print("[*] Getting Fix Description")
    code = vul_code [0]
    if lite == True:
        desciption = getCrashType(localId)
    else:
        patch_desc = extractDesc(localId)
        # desciption = patch_desc['vul']
        desciption = patch_desc
    
    prompt = f"""
Can you fix the vulnerability in the following code? Please only return the code in the response. Do not include explanations in your reply.
If you can't fix it, return the original code.
The vulnerable code:
```
{code.decode()}
```
    
There is a sanitizer crash report for the possible bug:
```
{desciption.decode('latin-1')}
```
"""
    # print(prompt)
    if model == "gpt-4":
        if tokenLen(prompt,model) >= 4096:
            print(f"[+] Tokenlength Overflow, skip..")
            return None
    if logDiff != False:
        dst= logDiff / str(localId)
        dst.mkdir(exist_ok=True)
        with open(dst/"prompt","w") as f:
            f.write(prompt)
    
    print("[+] Performing GPT Fixing..")
    fixed_code = performChatFix(prompt,model)
    print("[+] Recieved the result from ChatGPT")
    # extract the code out 
    if "maximum context length" in fixed_code:
        eventLog(f"[-] GPT failed to fix the bug: Inout OOB, {localId}")
        return None
    fixed_code = re.sub(r'```.*\n', "\n_XxXSPLITTAGXxX_\n", fixed_code)
    fixed_code = re.sub(r'```', "\n_XxXSPLITTAGXxX_\n", fixed_code)
    if "_XxXSPLITTAGXxX_" in fixed_code:
        tmp = fixed_code.split("_XxXSPLITTAGXxX_")
        if(len(tmp)!=3):
            eventLog(f"[X] get_GPT_fix: Odd return Value from GPT:\n\n {fixed_code} \n\n")
            return None
        fixed_code = tmp[1]

    return [fixed_code.encode()], code, work_dir/vul_code[3][2:]
def get_Codex_fix(localId,vul_code,work_dir,model,lite=False,logDiff=False):
    print("[*] Getting Fix Description")
    code = vul_code [0]
    if lite == True:
        desciption = getCrashType(localId)
    else:
        # patch_desc = getDesc(localId)
        # desciption = patch_desc['vul']
        patch_desc = extractDesc(localId)
        desciption = patch_desc
    prompt = f"""
Can you fix the vulnerability in the given code.
    
There is a sanitizer crash report for the possible bug:

{desciption}

"""
    if logDiff != False:
        dst= logDiff / str(localId)
        dst.mkdir(exist_ok=True)
        with open(dst/"prompt","w") as f:
            f.write(prompt)
    print("[+] Performing Codex Fixing..")

    # "gpt-3.5-turbo-instruct",
    # "code-davinci-edit-001"
    if model not in ["gpt-3.5-turbo-instruct","code-davinci-edit-001"]:
        panic(f"[X] Invalid Model {model}")
    res = performCompletionFix(code.decode(),prompt,model=model,n=1,temperature=TEMP)
    print(res)
    fixed_code = list(set([ x['text'].encode()  for x in res['choices'] if "error" not in x.keys() ]))
    return fixed_code, code, work_dir/vul_code[3][2:]
def get_Wizard_fix(localId,vul_code,work_dir,model="Wizard-15B",lite=False,logDiff=False):
    print("[*] Getting Wizard Fix Description")
    code = vul_code [0]
    target_file = vul_code[3] 
    print("[+] Getting Wizard Fix Code..")
    fixed_code=""
    if lite == True:
        output_data = jsonlines.open(f"./_wizard_data/{model}_lite.jsonl", mode='r')
        if logDiff != False:
            pass
    else:
        output_data = jsonlines.open(f"./_wizard_data/{model}.jsonl", mode='r')
    for line in output_data:
        one_data = line
        id = one_data["id"]
        if id==localId:
            fixed_code=one_data["wizardcoder"]
            break
    return [fixed_code.encode()], code, work_dir/target_file[2:]
def get_star_fix(localID,vul_code,work_dir,model="startcoder",lite=False):
    print("[*] Getting Starcoder Fix Description")
    code = vul_code [0]
    target_file = vul_code[3] 
    print("[+] Getting Starcoder Fix Code..")
    fixed_code=""
    fixed_code = start_coder_fix(localID)
    return [fixed_code.encode()], code, work_dir/target_file[2:]

### returns prompt
def getWizardPrompt(localId, code,lite=False):
    if lite == True:
        desciption = getCrashType(localId)
    else:
        patch_desc = extractDesc(localId)
        # desciption = patch_desc['vul']
        desciption = patch_desc
    prompt = f"""
Can you fix the vulnerability in the following code:
```
{code}
```
    
There is a vulnerability description for the possible bug:

{desciption}

Please only return the code in the response. Do not include explanations in your reply.
"""
    print(prompt)
    return prompt
### Generate input.jsonl for WizardCoder Inference
def GenerateWizardInput(input_file_path, localIds=[58086], limit=1,lite=False,logDiff=False):
    # Do test
    input_file = jsonlines.open(input_file_path, mode='w')
    cnt=0
    valid_localIds = []
    for localId in localIds:
        print(localId)
        vul_code = [b'']
        # Get meta data
        pname       = getPname(localId)
        if not pname:
            raise ValueError("No pname")
        vul_commit  = getVulCommit(localId)
        if not vul_commit:
            raise ValueError('Incorrect vul commit.')
        diff_file   = getDiff(localId)
        if not diff_file:
            raise ValueError('Incorrect diff file.')
        
        # Setup Repo
        pInfo           = get_projectInfo(localId,pname)[1]
        gt = GitTool(pInfo['url'],pInfo['type'],vul_commit)
        repo_dir = gt.repo
        # Get code info, maker sure there should be only one case
        vul_code = get_vul_code(diff_file,repo_dir)
        if(len(vul_code)!=1):
            print("[X] Has more than one hunks. Not support now.")
            continue
        else:
            vul_code = vul_code[0]

        if vul_code is not [b'']:
            prompt = getWizardPrompt(localId,vul_code[0].decode(),lite)
            input_data = {"idx":localId, "Instruction":prompt}
            input_file.write(input_data)
            cnt+=1
            if logDiff != False:
                dst= logDiff / str(localId)
                dst.mkdir(exist_ok=True)
                with open(dst/"prompt","w") as f:
                    f.write(prompt)
            valid_localIds.append(localId)
        if cnt==100:
            break
    print(valid_localIds)
    print(len(valid_localIds))
    print(f"[+] Finished writing {str(cnt)} prompts to {input_file_path}")
def BenchMarkFuncExamp(localId,vul_code,work_dir,model="code-davinci-edit-001"):
    print("[*] Getting Fix Description")
    code = vul_code [0]
    patch_desc = getDesc(localId)
    desciption = patch_desc['vul']
    prompt = f"""
Can you fix the vulnerability in the given code.
    
There is a vulnerability description for the possible bug:

{desciption}

"""
    print("[+] Performing Codex Fixing..")
    res = performCompletionFix(code.decode(),prompt,model=model,n=1,temperature=TEMP)
    print(res)
    fixed_code = list(set([ x['text'].encode()  for x in res['choices'] if "error" not in x.keys() ]))
    return fixed_code, code, work_dir/vul_code[3][2:]