from pathlib import Path
from report_gen import getReports
import json
from utils import getPname,get_projectInfo, DATADIR, getReport,getSrcmaps
from utils_exec import execute
from utils_git import GitTool
from datetime import datetime
def timeStamp(date_string):
    date_object = datetime.strptime(date_string, '%a %b %d %H:%M:%S %Y %z')
    timestamp = date_object.timestamp()
    return timestamp
def prepare_repo(localId):
    meta    = getReport(localId)
    if not meta:
        return False
    url     = meta['repo_addr']
    srcmaps = getSrcmaps(localId)
    pname   = getPname(localId)
    if not pname or not srcmaps:
        return False
    with open(srcmaps[0]) as f:
        protocol = json.loads(f.read())[f"/src/{pname}"]['type']
    gt = GitTool(url,protocol)
    return gt.repo
def getFixTime(localId):
    report = Path(".")/"Reports"/f"{localId}.json"
    with open(report) as f:
        meta = json.loads(f.read())
    fix     = meta['fix_commit']
    pname   = getPname(localId)
    info1,info2 = get_projectInfo(localId,pname)
    rev1 = info1['rev']
    rev2 = info2['rev']
    # git show -s --format='%cd' commit
    repo_dir = prepare_repo(localId)
    cmd = ['git','show','-s',"--format='%cd'",rev1]
    res = execute(cmd,cwd = repo_dir)[1:-1].decode()
    ts1 = timeStamp(res)
    cmd = ['git','show','-s',"--format='%cd'",rev2]
    res = execute(cmd,cwd = repo_dir)[1:-1].decode()
    ts3 = timeStamp(res)
    cmd = ['git','show','-s',"--format='%cd'",fix]
    res = execute(cmd,cwd = repo_dir)[1:-1].decode()
    ts2 = timeStamp(res)

    gto = GitTool(repo_dir)
    n1 = len(gto.listCommits(rev1,fix))-2
    n2 = len(gto.listCommits(fix,rev2))-2
    n3 = len(gto.listCommits(rev1,rev2))-2
    # print(n1,n2,n3)
    return ((ts1,ts2,ts3),(n1,n2,n3))
def averaging_fixTime():
    reports = getReports()
    tCostFix = []
    tCostVerify = []
    cCostFix = []
    cCostVerify = []
    meta = {}
    for report in reports:
        res = getFixTime(report)
        print(res)
        if res != False:
            ts1,ts2,ts3 = res[0]
            tCostFix = (ts2 - ts1) / (3600*24)
            tCostVerify = (ts3 - ts2) / (3600*24)
            cCostFix = res[1][0]+1
            cCostVerify = res[1][1]+1
        print(f"{tCostFix=},{tCostVerify=},{cCostFix=},{cCostVerify=}")
        meta[str(report)] = {
            "TimeCostforFixing": tCostFix,
            "TimeCostforVerifying": tCostVerify,
            "CommitGapforFixing": int(cCostFix),
            "CommitGapforVerifying": int(cCostVerify)
        }
    with open("/tmp/FixingMeta.json",'w') as f:
        f.write(json.dumps(meta,indent=4))
    # return sum(res)/len(res)
def projectDistribution():
    localIds = getReports()
    names = {}
    for localId in localIds:
        name  = getPname(localId,False)
        if name not in names.keys():
            names[name]=1
        else:
            names[name]+=1
    print(names)
def _cmp(a):
    return str(a)
def yearDistribution():
    localIds = getReports()
    years = {}
    for localId in localIds:
        issue_dir = DATADIR / "Issues" / (str(localId) + "_files")
        srcmap = list(issue_dir.glob('*.srcmap.json'))
        srcmap.sort(key=_cmp)
        year = int(srcmap[1].name.split(".srcmap.")[0].split("-")[-1][:4])
        print(year)
        if year not in years.keys():
            years[year]=1
        else:
            years[year]+=1

    print(years)
def fixDataLoader(location = Path("./Data/Data/Round2"),filter="L"):
    loadedData = {}
    for fn in location.iterdir():
        if "n132FxLog_" not in fn.name or \
        fn.name.split("_")[-1] != filter:
            continue
        with open(fn) as f:
            lines = f.readlines()
        lines = lines[4:]
        d = {}
        for i in lines:
            tmp = json.loads(i)
            key = list(tmp.keys())[0]
            d[int(key)] = tmp[key]
        res = {k: d[k] for k in sorted(d)}
        rrr = []
        for k in res.keys():
            rrr.append(res[k])
        loadedData[fn.name.split("_")[1]] = rrr
    print(json.dumps(loadedData,indent=4))
            


if __name__ == "__main__":
    # print(averaging_fixTime())
    # yearDistribution()
    fixDataLoader()
    # projectDistribution()
