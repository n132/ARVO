from utils import *
from utils_git import *
from utils_exec import *
from utils_rep import *
def checkReachability(localId):
    pname = getPname(localId)
    if not pname:
        print(f"[-] {localId}: Failed to get Pname")
        return "Failed to get Pname"
    if1, if2 = get_projectInfo(localId,pname)
    if if1['url']!= if2['url'] or if1['type']!=if2['type'] or if1['type']!='git':
        print(f"[-] {localId}: Different urls/type found")
        return "Different urls/type found"
    gt = GitTool(if1['url'],if1['type'])
    cmd = ['git','merge-base','--is-ancestor',if1['rev'],if2['rev']]
    res,output = run_stderr(cmd,cwd = gt.repo)
    if res == 0:
        return True
    else:
        stderr = output.strip("\n")
        print(f"{localId}: {stderr}")
        return stderr
def dumpAll():
    done = getDone()
    xExplore(done,"checkOsv.log",checkReachability)

target = ARVO / "Explorer" / "checkOsv.log"

with open(target) as f:
    lines = f.readlines()
for x in lines:
    d = json.loads(x)
    k = list(d.keys())[0]
    if d[k]==True:
        continue
    print(k,d[k],getPname(int(k)))
