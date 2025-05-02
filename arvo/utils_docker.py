import re
import subprocess
from .utils_exec import *
from ._profile import CPU_LIMIT, DEBUG
from .utils_log import *
class DfTool():
    def __init__(self,path) -> None:
        self.path = path
        with open(path) as f:
            self.content = f.read()
        comments = re.compile(r'^\s*#.*\n',re.MULTILINE)
        self.content = comments.sub("",self.content)
        self.content = self.content.replace("\\\n","")
        blankLine = re.compile(r'\n(\s)*\n',re.MULTILINE)
        self.content = blankLine.sub("\n",self.content)
    def PANIC(self,s):
        FAIL(f"[FAILED] {s}")
        exit(1)
    def flush(self):
        return self.writeDf()
    def writeDf(self):
        try:
            with open(self.path,'w') as f:
                f.write(self.content)
        except:
           return False
        return True
    def strReplaceAll(self,paires):
        for key in paires:
            self.content = self.content.replace(key,paires[key])
    def strReplace(self,old,new):
        self.content = self.content.replace(old,new)
    def replaceLineat(self,pos,line):
        lines = self.content.split("\n")
        lines[pos] = line
        self.content = "\n".join(lines)
    def replace(self,old,new):
        self.content = re.sub(old,new,self.content)
    def replaceOnce(self,old,new):
        self.content = re.sub(old,new,self.content,count=1)
    def insertLineBefore(self,target,newline):
        lineNum = self.locateStr(target)
        if lineNum == False:
            return False
        self.insertLineat(lineNum,newline)
    def insertLineAfter(self,target,newline):
        lineNum = self.locateStr(target)
        if lineNum == False:
            return False
        self.insertLineat(lineNum+1,newline)
    def insertLineat(self,pos,line):
        lines = self.content.split("\n")
        lines.insert(pos,line)
        self.content = "\n".join(lines)
    def appendLine(self,line):
        lines = self.content.split("\n")
        lines.append(line)
        self.content = "\n".join(lines)
    def dump(self):
        INFO("[+] Dumping the Content")
        INFO("=="*0x10)
        INFO(self.content)
        INFO("=="*0x10)
    def removeRange(self,starts,ends):
        lines = self.content.split("\n")
        new_lines = []
        for num in range(len(lines)):
            if num >= starts and num < ends:
                continue
            new_lines.append(lines[num])
        self.content = '\n'.join(new_lines)
    # New Feature: Dockerfile Parser
    def cleanComments(self):
        # Code comes from GPT.
        # Pattern to match comments: starts with # and goes till the end of the line
        # Also handles cases where spaces precede the #
        pattern = re.compile(r'^#.*',re.MULTILINE)
        # Remove comments from each line
        self.content = pattern.sub('', self.content)
        newline_pattern = re.compile(r'^\n',re.MULTILINE)
        # Remove any empty lines left after removing comments
        self.content = newline_pattern.sub('', self.content)
        # return self.writeDf()
    def getDockerCMD(self,line):
        CMD = line.split(" ")[0]
        if CMD != "":
            return CMD
        else:
            return None
    def locateStr(self,keyword):
        ct =  0 
        linenum = False
        lines = self.content.split("\n")
        res = []
        for line in lines:
            if keyword in line:
                res.append(line)
                linenum = ct
            ct +=1
        return linenum
    def getLine(self,keyword):
        res = []
        lines = self.content.split("\n")
        ct =  0 
        linenum = 0
        
        for line in lines:
            ct +=1
            if keyword in line:
                res.append(line)
                linenum = ct
        if len(res)<2:
            return res, linenum
        pat = re.compile(rf"{keyword}(\s.*$|$)")
        res = []
        ct =  0 
        linenum = 0
        for line in lines:
            ct +=1
            if pat.findall(line):
                res.append(line)
                linenum = ct
        return res, linenum
            
# Docker Options
def docker_create(name,img):
    cmd = ['docker','create','--name',name,img]
    INFO(f"[+] Docker Create: {name} <- {img}")
    return check_call(cmd)

def docker_tag(src,dst):
    cmd = ['docker','tag',src,dst]
    INFO(f"[+] Docker Tag {src} -> {dst}")
    return check_call(cmd)
def docker_push(name):
    cmd = ['docker','push',name]
    INFO(f"[+] Docker Push {name}")
    with open('/dev/null','w') as f:
        return check_call(cmd,stdout=f,stderr=f)
def docker_login():
    res = subprocess.run(["docker","login"])
    return res.returncode
def docker_run(args,rm=True,dumpErr=None):
    if rm:
        cmd = ['docker','run','--rm','--privileged']
    else:
        cmd = ['docker','run','--privileged']
    if type(CPU_LIMIT)==type(1):
        cmd += [f'--cpus={CPU_LIMIT}']

    cmd.extend(args)
    INFO("[+] Docker Run: \n"+" ".join(cmd))
    if dumpErr!=None:
        with open(dumpErr,'w') as f:
            res = check_call(cmd,stdout=f,stderr=f)
            f.write("\n"+" ".join(cmd)+"\n")
            return res
    else:
        return check_call(cmd)
def docker_cp(arg1,arg2):
    cmd = ['docker','cp',arg1,arg2]
    return check_call(cmd)
def docker_images(name):
    cmd = ["docker","images","-aq",name]
    return execute(cmd).decode()
def docker_rmi(img_name):
    target_hash = docker_images(img_name)
    if target_hash== "":
        return True
    cmd = ['docker','rmi',target_hash]
    return check_call(cmd)
def docker_ps(container_name):
    cmd = ["docker", "ps", "-aq", "-f", f"name={container_name}"]
    return execute(cmd).decode()
def docker_commit(container_name,image_name):
    cmd = ['docker','commit',container_name,image_name]
    return check_call(cmd)
def docker_rm(container_name):
    target_hash = docker_ps(container_name)
    if target_hash == "":
        return True
    cmd = ['docker','kill',target_hash]
    cmd2= ['docker','rm',target_hash]
    with open('/dev/null','w') as f:
        if check_call(cmd,stdout=f,stderr=f,verbose=False):
            target_hash = docker_ps(container_name)
            if "\n" in target_hash:
                target_hash = target_hash.split("\n")
                cmd = ['docker','rm']+target_hash
            else:
                if target_hash == "":
                    return True
                cmd = ['docker','rm',target_hash]
            return check_call(cmd,stdout=f,stderr=f,verbose=False)
        else:
            if check_call(cmd2,stdout=f,stderr=f,verbose=False):
                return True
            return False
def docker_save(img_name,output_name):
    output_name = str(output_name)
    with open('/dev/null','w') as f:
        cmd = ['docker','save',"-o", output_name , img_name]
        return check_call(cmd,stdout=f,stderr=f)
def docker_build(args,logFile=None):
    cmd = ['docker','build']
    cmd.extend(args)
    INFO("[+] Docker Build: \n"+" ".join(cmd))
    if logFile:
        with open(logFile,'w') as f:
            res = check_call(cmd,stderr=f,stdout=f)
            f.write("\n"+" ".join(cmd)+"\n")
            return res
    else:
        return check_call(cmd)
def docker_load(instream):
    cmd = ['docker','load']
    INFO("[+] Docker Load: \n"+" ".join(cmd))
    return check_call(cmd,stdin=instream)
def docker_exec(container: str,command: list):
    cmd = ['docker','exec',container]+command
    INFO("[+] Docker Exec: \n"+" ".join(cmd))
    with open('/dev/null','w') as f:
        return check_call(cmd,stdout=f,stderr=f)

if __name__ == "__main__":
    pass