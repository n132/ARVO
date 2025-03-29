import json 
import pandas as pd
import collections
from utils          import *
from glob           import glob
from pathlib        import Path
from unidiff        import PatchSet
from glob           import glob
from .utils_diff import getDiff
START_DATE = '2016-08' 
END_DATE = '2024-04'

def _get_year(d):
    return int(d[:4])
def _get_month_diff(start, end):
    sy = _get_year(start)
    ey = _get_year(end)
    sm = int(start[5:])
    em = int(end[5:])
    dif = 0
    if ey>sy:
        dif += (ey-sy)*12
        if sm>em:
            dif -= 12
            dif += 12-abs(em-sm)
        else:
            dif += 12-abs(em-sm)
    else:
        dif += abs(em-sm)
    return dif
# Get verified cases from Results.json's git commits (# of added cases)
def _get_reproducible_cases():
    cases = []
    locator = []
    with open('./Results.json') as f:
        for line in f:
            data = json.loads(line)
            if data['pass']==True:
                cases.append(data['localId'])
                if Path(f"./Reports/{data['localId']}.json").exists():
                    locator.append(data['localId'])
    return cases,locator
def group_by_month(d, unit_month):
    trend = list(d.items()) # convert dictionary to tuple
    pivot = START_DATE      # this one moves
    organized = [0]         # will be separated by unit months
    for c in trend:
        diff = _get_month_diff(pivot, c[0])
        # print(c[0])
        # print(diff)
        if diff < unit_month:
            organized[-1] += c[1]
        else:
            for i in range(0, diff-1):
                organized.append(organized[-1])
            organized.append(organized[-1] + c[1])
            pivot = c[0]
    for i in range(_get_month_diff(trend[-1][0], END_DATE)):
        organized.append(organized[-1])
    return organized
def organize_data():
    bug_trend = {} # All bugs besides below two
    rep_trend = {} # Reproducible
    fix_trend = {} # Easy fixes
    loc_trend = {}
    # print("[*] Getting single mods (easy fixes)")
    # sm = [38843, 6214, 45884, 12684, 37334, 20491, 28953, 340, 39070, 8511, 6066, 7361, 8317, 14912, 3658, 6626, 24854, 5832, 9180, 3522, 11074, 22244, 3956, 28654, 31038, 31556, 10953, 31124, 25545, 4822, 33663, 5568, 40589, 5710, 8529, 21356, 40617, 26442, 10724, 33576, 35342, 5296, 6899, 4099, 10356, 30113, 20800, 5935, 30831, 37759, 10762, 14423, 44089, 21309, 27279, 31425, 1304, 11290, 3559, 26171, 5362, 23396, 28392, 3645, 7171, 8316, 37222, 25226, 39103, 4296, 19386, 37158, 4819, 38924, 3257, 6243, 40429, 5381, 29821, 22169, 6829, 21070, 28682, 4637, 6906, 8241, 30748, 46309, 19324, 11429, 39664, 38898, 26755, 13016, 33841, 338, 13467, 32275, 20363, 39036, 12642, 11245, 5577, 391, 21349, 22864, 33843, 23826, 13531, 35300, 37575, 3265, 43370, 3474, 4345, 3621, 33071, 31065, 4561, 3862, 7538, 12871, 5534, 35297, 27812, 12818, 11011, 3322, 17147, 37866, 5729, 5429, 35288, 3938, 420, 4300, 14393, 38146, 30974, 10990, 27816, 12241, 32177, 14854, 5499, 42741, 7262, 6975, 5372, 16445, 11060, 4670, 12549, 10081, 10881, 5652, 5373, 910, 5547, 40269, 27368, 39053, 919, 5482, 25973, 4440, 14018, 3376, 7206, 5504, 346, 21348, 8505, 36611, 39102, 5576, 31586, 3447, 14035, 12312, 10082, 4764, 14331, 21296, 38900, 12552, 15603, 5761, 31552, 10097, 22912, 30293, 3530, 11351, 3497, 4569, 12787, 28315, 5326, 5481, 4346, 22498, 24293, 18877, 31585, 14481, 7884, 5443, 31454, 11305, 10955, 5498, 37564, 12532, 18756, 39056, 38237, 8616, 5256, 4396, 19332, 5480, 1856, 6831, 3680, 12631, 4289, 37647, 5740, 3371, 3498, 4812, 39028, 11376, 39094, 3285, 10084, 5843, 42729, 5873, 26406, 38121, 12679, 19100, 22167, 6790, 33264, 34259, 3558, 29816, 40431, 6007, 39083, 3560, 37878, 5450, 31551, 19338, 25118, 37211, 31535, 33863, 21346, 38341, 12536, 31705]
    reproducibles,locatordata = _get_reproducible_cases()
    # print(len(reproducibles))
    # single_mods = [f for f in sm if f not in reproducibles]
    # print(reproducibles)
    # print(len(single_mods))   # 266
    with open('./Type.Bug-Security_label.Reproducible_status.Verified/metadata.jsonl') as f:
        for line in f:
            data = json.loads(line)
            timestamp = datetime.fromtimestamp(data['issue']['statusModifiedTimestamp']).strftime("%Y-%m")
            localId = data['localId']
            if localId in locatordata:
                if timestamp not in loc_trend.keys():
                    loc_trend[timestamp] = 1
                else:
                    loc_trend[timestamp] += 1
            if localId in reproducibles:
                try:
                    rep_trend[timestamp] += 1
                except KeyError as e:
                    rep_trend[timestamp] = 1

            # elif localId in single_mods:
            #     try:
            #         fix_trend[timestamp] += 1
            #     except KeyError as e:
            #         fix_trend[timestamp] = 1
            try:
                bug_trend[timestamp] += 1
            except KeyError as e:
                bug_trend[timestamp] = 1
    # fix_sorted = collections.OrderedDict(sorted(fix_trend.items()))
    loc_sorted = collections.OrderedDict(sorted(loc_trend.items()))
    rep_sorted = collections.OrderedDict(sorted(rep_trend.items()))
    bug_sorted = collections.OrderedDict(sorted(bug_trend.items()))
    # print(rep_sorted)
    # print(sum(rep_sorted.values()))
    return loc_sorted,rep_sorted, bug_sorted
# save db size growth data to csv
def export_reproduce_data(unit_month = 1):
    locatable, reproducible, all_bugs = organize_data()
    dates = pd.date_range(START_DATE, END_DATE, freq=str(unit_month)+'MS').strftime("%Y-%m").tolist()
    # print(reproducible)
    # print(all_bugs)
    loc_organized = group_by_month(locatable, unit_month)
    rep_organized = group_by_month(reproducible, unit_month)
    # fix_organized = group_by_month(easy_fixes, unit_month)
    bug_organized = group_by_month(all_bugs, unit_month)
    # print(rep_organized)
    # print(bug_organized)
    # print(len(loc_organized))
    # print(len(rep_organized))
    # print(len(bug_organized))
    assert(len(rep_organized) == len(bug_organized) == len(loc_organized))
    print("Reported cases by month: ",end='')
    print(loc_organized)
    print("Reproducible cases by month: ",end='')
    print(rep_organized)
    # print("Single fix cases by month: ",end='')
    # print(fix_organized)
    print("All bug-related cases by month: ",end='')
    print(bug_organized)
    
    
    df = pd.DataFrame({'Date':dates, 'Fix Located':loc_organized})
    df = df.join(pd.DataFrame({'Reproducible':rep_organized}))
    df = df.join(pd.DataFrame({'All Bugs':bug_organized}))
    print(df)
    
    ### export to csv
    df.to_csv(r'./Data/dbsize.csv', index=False)
    print("[+] Exported to dbsize.csv")
def _get_proj_lang(proj_name):
    dirnames = glob("../oss-fuzz/projects/*")
    lang=''
    # print(dirnames)
    for p in dirnames:
        if p.split("/")[-1] == proj_name:
            info = Path(p)/"project.yaml"
            if info.exists():
                with open(info) as f:
                    lines = f.readlines()
                    for line in lines:
                        if "language" in line:
                            # print("lang exists")
                            dt = line.strip().split(": ")
                            if dt[0] == "language":
                                # print(dt)
                                # if dt[1].startswith('"'):
                                #     dt[1] = dt[1][1:-1] 
                                lang = dt[1]
    if lang!='c++'and lang!='c'and lang!='python' and lang!='rust' and lang!='swift':
        print(lang)
        print(proj_name)
    return lang
def get_lang_dist():
    dirnames = glob("../oss-fuzz/projects/*")
    # print(dirnames)
    bug_dist = dict()
    for _ in dirnames:
        info = Path(_)/"project.yaml"
        if info.exists():
            with open(info) as f:
                lines = f.readlines()
            for line in lines:
                dt = line.strip().split(": ")
                if dt[0] == "language":
                    if dt[1].startswith('"'):
                        dt[1] = dt[1][1:-1] 
                    if dt[1] not in bug_dist:
                        bug_dist[dt[1]] = 1
                    else:
                        bug_dist[dt[1]] +=1 
        else:
            print(f"{info} doesn't exist, skiping...")
    print(bug_dist)  # all bugs lang distribution
    
    langs = dict()
    proj_map = dict()
    with open('./Results.json') as f:
        for line in f:
            data = json.loads(line)
            if data['pass']=='false':
                continue
            proj_name = data['project']
            if proj_name in proj_map:
                continue
            proj_map[proj_name] = 1
            proj_lang = _get_proj_lang(proj_name)
            if proj_lang not in langs:
                langs[proj_lang] = 1
            else:
                langs[proj_lang] += 1
    print(langs)
    
    res = dict()
    for l in langs:
        if l in bug_dist:
            res[l] = langs[l]/bug_dist[l]
    print(res)
    return res
def export_lang_dist():
    dist = get_lang_dist()
    df = pd.DataFrame({'Language':list(dist.keys()), 'Reproducible':list(dist.values())})
    print()
    print(df)
    df.to_csv(r'./Data/langdist.csv', index=False)
    print("[+] Exported to langdist.csv\n")
def get_proj_dist():
    proj_names = dict()
    with open('./Results.json') as f:
        for line in f:
            data = json.loads(line)
            if data['pass']=='false':
                continue
            proj_name = data['project']
            if proj_name not in proj_names:
                proj_names[proj_name] = 1
            else:
                proj_names[proj_name] += 1
    print(proj_names)
    print("Total Projects: ",end="")
    print(len(proj_names))
def report_combined_results(localIds):
    models = ['Codex','gpt-4','GPT','Wizard-34B','Wizard-15B']
    combined_results = {}
    for localId in localIds:
        combined_results[localId]=False
    for model in models:
        with open(f"/tmp/OSSlog/ARVO_FxLog_{model}_{model}") as f:
            header_cnt=0
            for line in f:
                if header_cnt<4:
                    header_cnt+=1
                    continue
                data = json.loads(line)
                localId, result = next(iter(data.items()))
                if result:
                    combined_results[localId]=True
    
    true_cnt=0
    for key,val in combined_results.items():
        if val==True:
            true_cnt+=1
    print(combined_results)
    print("True: "+str(true_cnt))
    return combined_results
def lines_report():
    filename="./_Dumped_Statistics.log"
    localId_cnt=0
    patched_files=0
    added_lines=0
    removed_lines=0
    related_functions=0
    with open(filename) as f:
        for line in f:
            if "Testing localID" in line:
                localId_cnt+=1
            elif "Patched Files" in line:
                patched_files+=int(line.split()[-1])
            elif "Added Lines" in line:
                added_lines+=int(line.split()[-1])
            elif "Removed Lines" in line:
                removed_lines+=int(line.split()[-1])
            elif "Related Functions" in line:
                related_functions+=int(line.split()[-1])
    print(localId_cnt,patched_files,added_lines,removed_lines,related_functions)
    print("Patched Files: "+str(patched_files/localId_cnt))
    print("Added Lines: "+str(added_lines/localId_cnt))
    print("Removed Lines: "+str(removed_lines/localId_cnt))
    print("Related Functions: "+str(related_functions/localId_cnt))
def reproduce_vs_google():
    local = [False, False, False, False, False, False, True, False, False, True, False, False, True, False, False, False, True, True, False, False, False, False, True, False, False, True, False, False, False, False, False, False, False, False, False, False, False, True, False, False, False, False, False, False, False, False, False, False, False, False, False, True, True, False, False, False, False, False, True, True, False, False, False, False, False, True, True, False, True, False, True, False, False, False, False, False, False, True, True, False, False, False, False, False, False, False, False, True, True, False, False, True, False, False, False, False, False, False, False, False]
    # print(len(local))
    google = [False]*40+ [True]*2+[False]*40+[True]*3+[False]*15
    # print(len(google))
    assert len(local) == len(google)
    n = len(local)
    res_local = [1 if local[0]==True else 0]
    res_google = [1 if google[0]==True else 0]
    for i in range(1,n):
        if local[i]==True:
            res_local.append(res_local[-1]+1)
        else:
            res_local.append(res_local[-1])
        if google[i]==True:
            res_google.append(res_google[-1]+1)
        else:
            res_google.append(res_google[-1])
    print(res_local)
    print(res_google)
    col = [i for i in range(1,n+1)]
    df = pd.DataFrame({'Case':col, 'OSS Reproducer':res_local})
    df = df.join(pd.DataFrame({'Google':res_google}))
    df.to_csv(r'./Data/vsgoogle.csv', index=False)
    print("[+] Exported to vsgoogle.csv\n")
## Usage: _get_issue_from_date("2021-11")
def _get_issue_from_date(d):
    issues = []
    with open('./Type.Bug-Security_label.Reproducible_status.Verified/metadata.jsonl') as f:
        for line in f:
            data = json.loads(line)
            exact_time = datetime.fromtimestamp(data['issue']['statusModifiedTimestamp'])
            timestamp = exact_time.strftime("%Y-%m")
            localId = data['localId']
            if timestamp==d:
                issues.append((exact_time,localId))
    issues.sort(key=lambda t:t[0])
    return issues
RESULTS = ARVO / "Reports"
def vulnerabilityType():
    VulType = dict()
    VulType["Heap-overflow"] = 0
    VulType["Heap-UAF"] = 0
    VulType["Unknown"] =0
    VulType["Stack-overflow"] = 0
    VulType['Uninitialized-Variable'] = 0
    VulType['Index-out-of-bounds'] = 0
    VulType["Global-buffer-overflow"] =0 
    VulType['TypeError'] = 0
    VulType['Invalid-free'] = 0
    VulType['Stack-use-after-return'] = 0 
    VulType['Negative-size'] = 0 
    VulType['Use-after-poison'] = 0 
    VulType["Memory-overlap"] = 0
    for x in Path(RESULTS).iterdir():
        with open(x) as f:
            res = json.loads(f.read())
        vt = res['crash_type']
        if "Heap-buffer-overflow" in vt:
            VulType["Heap-overflow"]+=1
        elif "Heap-use-after-free" in vt or "Heap-double-free" in vt:
            VulType["Heap-UAF"]+=1
        elif "UNKNOWN" in vt or "Check failed" in vt or "Unknown-crash" in vt or "Segv on unknown address" in vt:
            VulType["Unknown"]+=1
        elif "Dynamic-stack-buffer-overflow" in vt or "Stack-buffer-overflow" in vt or "Stack-buffer-underflow" in vt:
            VulType["Stack-overflow"]+=1
        elif "Use-of-uninitialized-value" in vt:
            VulType['Uninitialized-Variable']+=1
        elif "Index-out-of-bounds" in vt:
            VulType['Index-out-of-bounds']+=1
        elif "Global-buffer-overflow" in vt:
            VulType["Global-buffer-overflow"]+=1
        elif "Bad-cast" in vt or "Incorrect-function-pointer-type" in vt:
            VulType['TypeError']+=1
        elif "Invalid-free" in vt or "Bad-free" in vt:
            VulType['Invalid-free']+=1
        elif "Stack-use-after-return" in vt or "Stack-use-after-scope" in vt:
            VulType['Stack-use-after-return']+=1
        elif "Negative-size-param" in vt or "Object-size" in vt or "Non-positive-vla-bound-value" in vt:
            VulType['Negative-size']+=1
        elif "Use-after-poison" in vt:
            VulType['Use-after-poison'] = 0 
        elif "Null-dereference" in vt:
            VulType["Unknown"]+=1
        elif "Memcpy-param-overlap" in vt or "Container-overflow" in vt:
            VulType["Memory-overlap"]+=1
        else:
            print(vt)
    print(VulType)

def patches():
    res = glob("./Reports/*")
    reports = [int(x.split("/")[-1][:-5]) for x in res]
    res = dict()
    dumpDir = Path("./Data") / "Stat" 
    diffDir = dumpDir / "Diff"

    reports = [40851]
    for r in reports:
        print("[*] Testing localID: " + str(r))
        diff_file = getDiff(r)

        print(diff_file)
        with open(diff_file,'rb') as f:
            lines = f.readlines()
        lineNum = len(lines)
        for x in range(lineNum):
            if lines[x].startswith(b"diff "):
                break
        diffSize = lineNum - x
        if diff_file == False:
            print(f"[-] Failed to get the diff of case {r}")
            continue
        try:
            patch = PatchSet.from_filename(diff_file, encoding='utf-8')
            
        except:
            continue
        patched_files = [x.path for x in patch]

        added = 0 
        removed = 0 
        ct= 0 
        for x in patch:
            added+= x.added
            removed+= x.removed
            lines = str(x).split("\n")
            for x in lines:
                if x.startswith("@@"):
                    ct+=1
        if len(patched_files) == 0:
            continue
        d  = dict()
        d["localId"] = r
        d["patchedFiles"] = len(patched_files)
        d['addedLines'] = added 
        d['removedLines'] = removed
        d['relatedFunctions'] = ct
        d['diffSize'] = diffSize
        res[str(r)] = d
        tmpDir = diffDir / str(r)
        if not tmpDir.exists():
            tmpDir.mkdir()
        shutil.copyfile(diff_file,tmpDir/f"{r}.diff")
        with open(tmpDir/f"{r}_stat.json",'w') as f:
            f.write(json.dumps(d,indent=4))
        print(f"\t[+] Patched Files: {len(patched_files)}")
        print(f"\t[+] Added Lines: {added}")
        print(f"\t[+] Removed Lines: {removed}")
        print(f"\t[+] Related Functions: {ct}")
    
    reportStat  = dumpDir / "stat.json"
    with open(reportStat,'w') as f:
        f.write(json.dumps(res,indent=4))
    
def dump_statistics(filename="./_Dumped_Statistics.log"):
    with open(filename,"r") as f:
        lines=f.readlines()
    lenL = len(lines)
    line = 0 
    jsonList = []
    while line < lenL:
        ctx = lines[line]
        print(ctx)
        if "Testing" in ctx:
            localId = int(ctx.split(": ")[1])
            line+=3
            ctx = lines[line]
            if("[+] Patched Files: " not in ctx):
                continue
            patched_files = int(ctx.split(": ")[1])
            line+=1
            ctx = lines[line]
            if("[+] Added Lines: " not in ctx):
                continue
            added_lines = int(ctx.split(": ")[1])
            line+=1
            ctx = lines[line]
            if("[+] Removed Lines: " not in ctx):
                continue
            removed_lines = int(ctx.split(": ")[1])
            line+=1
            ctx = lines[line]
            if("[+] Related Functions: " not in ctx):
                continue
            related_funcs = int(ctx.split(": ")[1])
            line+=1
            d  = dict()
            d["localId"] = localId
            d["patchedFiles"] = patched_files
            d['addedLines'] = added_lines 
            d['removedLines'] = removed_lines
            d['relatedFunctions'] = related_funcs
            jsonList.append(d)
        else:
            print(f"Skippin Line: {ctx}")
            line+=1
    print(len(jsonList))
    print(jsonList[:3])

if __name__ =="__main__":
    cmd = 4
    if cmd==1:
        vulnerabilityType()
    elif cmd==2:
        patches()
    elif cmd==3:
        export_lang_dist()
    elif cmd==4:
        # Change end-date everytime before running it
        export_reproduce_data()
    elif cmd==5:
        localIds = [53623, 55499, 46194, 52049, 55026, 45846, 45439, 52410, 55778, 54593, 40406, 47802, 51006, 49386, 59650, 47724, 38237, 58190, 52694, 34960, 59817, 54312, 38733, 33852, 40623, 42907, 43629, 53036, 38121, 51090, 57369, 45849, 57354, 33340, 51011, 34863, 47507, 45206, 49698, 42821, 40540, 33315, 56160, 56308, 37581, 43904, 49407, 37413, 34480, 37222, 51187, 49901, 53536, 35672, 48749, 43544, 39053, 45974, 42324, 39211, 45969, 44221, 57320, 47516, 33056, 42736, 46081, 38355, 58786, 42327, 53405, 51837, 42741, 38900, 48161, 55218, 55964, 53512, 44851, 54972, 60655, 33556, 55365, 60557, 57429, 38749, 54594, 33041, 46128, 43688, 44695, 56465, 59673, 60238, 42111, 52258, 57342, 37570, 51745, 47730]
        report_combined_results(localIds)
    elif cmd==6:
        get_proj_dist()
    elif cmd==7:
        reproduce_vs_google()
    elif cmd==8:
        dump_statistics()
    elif cmd==9:
        lines_report()