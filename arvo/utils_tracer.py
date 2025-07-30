from .utils import *
from .utils_git import * 
def commitBeforeDate(url,target_ts,protocol,c1,c2):
    date_obj = datetime.strptime(target_ts, "%Y%m%d%H%M")
    timestamp = datetime.timestamp(date_obj)
    res = False
    gt = GitTool(url,protocol)
    commits = gt.listCommits(c1,c2)
    if not commits:
        shutil.rmtree(gt.repo)
        return False
    
    tsL = []
    for x in commits:
        ts = gt.timestamp(x)
        if ts != False:
            if ts > timestamp:
                assert(len(tsL)>0)
                res = tsL[-1]
                break
            tsL.append(ts)
        else:
            return False
    shutil.rmtree(gt.repo)
    return res
def commitDate(url,commit,protocol):
    gt = GitTool(url,protocol)
    res= gt.commitDate(commit)
    shutil.rmtree(gt.repo)
    return res
def customSrcmap_PM(srcmap):
    # For patch minimization
    """
    Take original srcmaps and create a customSrcmap based on the given commit
    Mark other component.rev as xXxXx
    """
    wd = tmpDir()
    idx = 1
    chosen_srcmap = srcmap[idx].name
    Asrcmap = wd / chosen_srcmap
    if not check_call(['cp',srcmap[idx],Asrcmap]):
        return False
    with open(Asrcmap) as f:
        data = json.load(f)

    ## Update srcmap
    for key in data:
        nk, data[key]['url'], data[key]['type'] = trans_table(key,data[key]['url'],data[key]['type'])
        if data[key]['url'] == None:
            del(data[key]) 
        if nk != key:
            data[nk] = data[key]
            del(data[key])
    
    # vk = "/src/"+pname
    # if vk in data:
    #     data[vk]['rev']=commit
    # else:
    #     leaveRet(0xdeadbeef,wd)
    #     PANIC(f"[!] Can't find the key({vk}) in json data")
    
    # readstat-address-201901210219.srcmap.json
    Bsrcmap = wd / srcmap[idx].name
    
    # for key in data:
    #     if (key != vk) and key not in ["/src",'/src/aflplusplus','/src/libfuzzer','/src/afl']:
    #         # Mess the revision so we'll use the a commit that is close to the datetime.
    #         # since we implemented that in util_core
    #         if data[key]['type'] == 'git':
    #             data[key]['rev'] = "xXxXx"
    with open(Bsrcmap,'w') as f:
        f.write(json.dumps(data))
    if DEBUG:
        print(json.dumps(data,indent=4))
    return Bsrcmap

def customSrcmap(srcmap,pname,commit):
    """
    Take original srcmaps and create a customSrcmap based on the given commit
    Mark other component.rev as xXxXx
    """
    wd = tmpDir()
    with open(srcmap[0]) as f:
        sm0 = json.load(f)
    with open(srcmap[1]) as f:
        sm1 = json.load(f)
    
    idx = 1 if len(list(sm1.keys())) >= len(list(sm0.keys())) else 0 
    chosen_srcmap = srcmap[idx].name
    Asrcmap = wd / chosen_srcmap
    if not check_call(['cp',srcmap[idx],Asrcmap]):
        return False
    with open(Asrcmap) as f:
        data = json.load(f)

    ## Update srcmap
    for key in list(data.keys()):
        nk, data[key]['url'], data[key]['type'] = trans_table(key,data[key]['url'],data[key]['type'])
        if data[key]['url'] == None:
            del(data[key]) 
        if nk != key:
            data[nk] = data.pop(key)
    vk = "/src/"+pname
    if vk in data:
        data[vk]['rev']=commit
    else:
        leaveRet(0xdeadbeef,wd)
        PANIC(f"[!] Can't find the key({vk}) in json data")
    
    # readstat-address-201901210219.srcmap.json
    ts = commitDate(data[vk]['url'],commit,data[vk]['type'])
    if not ts:
        return False

    for key in data:
        if (key != vk) and key not in ["/src",'/src/aflplusplus','/src/libfuzzer','/src/afl']:
            # Mess the revision so we'll use the a commit that is close to the datetime.
            # since we implemented that in util_core
            if data[key]['type'] == 'git':
                data[key]['rev'] = "xXxXx"
    ori = srcmap[0].name.split("-")
    ori[-1] = ts
    Bsrcmap = wd / ("-".join(ori)+".scrmap.json")

    with open(Bsrcmap,'w') as f:
        f.write(json.dumps(data))
    if DEBUG:
        print(json.dumps(data,indent=4))
    return Bsrcmap
