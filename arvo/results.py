# Options related to data
import json
from .fx import *
from .utils_diff import getDiff, getVulCommit
from .resultData import *
from .utils import *
from .utils_runfix import get_vul_code
'''
This script summarizes the result in the log file and show us the statistics of our dataset 
'''
LOG_FILE = ARVO / "Data/FixMeta.json"
RESULTS = ARVO / "Results.json"
'''
        Statistics
        These functions are used to dump the statistics of the result/dataset
'''
def _statistics(id):
    localIds = getReports()
    assert(id in localIds)
    work_dir = tmpDir()
    pname = getPname(id)
    diff_file   = getDiff(id)
    vul_commit  = getVulCommit(id)
    if vul_commit== False or diff_file== False:
        return False
    repo_dir = work_dir/pname
    shutil.copytree( OSS_DB/pname, repo_dir,symlinks=True)
    check_call(['git','reset','--hard',vul_commit],repo_dir)
    vul_code = get_vul_code(diff_file,repo_dir)
    shutil.rmtree(repo_dir)
    modified_files  = set([x[3] for x in vul_code])
    modification = [x[3] for x in vul_code]
    removed_lines = sum([len(x[1]) for x in vul_code])
    added_lines = sum([len(x[2]) for x in vul_code])
    modified_files = len(modified_files)
    modification = len(modification)
    return modified_files,modification, removed_lines, added_lines
def dump_data(off=0):
    localIds = getReports()
    for i in localIds[off:]:
        try:
            nf, md, rl, al = _statistics(i) 
        except:
            continue
        # nf-> n files are modified
        # rl-> removed lines
        # al-> added lines
        with open(LOG_FILE,'a+') as f:
            f.write(json.dumps({
                i:{
                    "Modified_files":nf,
                    "Modification": md,
                    "Removed_lines":rl,
                    "Added_lines":al,
                    },

                }))
            f.write("\n")
def sort_data():
    with open(LOG_FILE,'r') as f:
        data = f.readlines()
    res = [json.loads(x) for x in data]
    def cmp_f(a):
        for x in a.keys():
            return int(x)
    res.sort(key=cmp_f)
    with open(LOG_FILE,'w') as f:
        for x in res:
            f.write(json.dumps(x)+"\n")
def addNewcase(issues):
    res = len(issues)*[ True ]
    matric_ins(issues,res)
    matric_sort()

if __name__ == '__main__':
    cmd = 0
    if cmd==0:
        matric_del([])
        matric_sort()
    elif cmd==1:
        issues = []
        res = len(issues)*[ True ]
        matric_ins(issues,res)
        matric_sort()
    elif cmd==3:
        matric_sort()