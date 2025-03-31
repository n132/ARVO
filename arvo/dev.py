from .utils import *
from .utils_exec import *

# x86_64 libfuzzer: clusterfuzz-builds
# i386 libfuzzer: clusterfuzz-builds-i386
# x86_64 afl: clusterfuzz-builds-afl
# x86_64 honggfuzz: clusterfuzz-builds-honggfuzz
# ENGINE_INFO = {
#     'libfuzzer':
#         EngineInfo(upload_bucket='clusterfuzz-builds',
#                    supported_sanitizers=['address', 'memory', 'undefined'],
#                    supported_architectures=['x86_64', 'i386']),
#     'afl':
#         EngineInfo(upload_bucket='clusterfuzz-builds-afl',
#                    supported_sanitizers=['address'],
#                    supported_architectures=['x86_64']),
#     'honggfuzz':
#         EngineInfo(upload_bucket='clusterfuzz-builds-honggfuzz',
#                    supported_sanitizers=['address'],
#                    supported_architectures=['x86_64']),
#     'dataflow':
#         EngineInfo(upload_bucket='clusterfuzz-builds-dataflow',
#                    supported_sanitizers=['dataflow'],
#                    supported_architectures=['x86_64']),
#     'none':
#         EngineInfo(upload_bucket='clusterfuzz-builds-no-engine',
#                    supported_sanitizers=['address'],
#                    supported_architectures=['x86_64']),
# }
def donwloadFuzzer(pname,srcmap_name,engine='libfuzzer',arch="x86_64",storage=None):
    if arch=='i386':
        if engine == 'libfuzzer':
            bucket =  'clusterfuzz-builds-i386'
        else:
            eventLog(f'dev:downloadFuzzer: {engine}:{arch}')
            return False
    elif arch=='x86_64':
        if engine=='libfuzzer':
            bucket = 'clusterfuzz-builds'
        elif engine=='afl':
            bucket = 'clusterfuzz-builds-afl'
        elif engine=='honggfuzz':
            bucket = 'clusterfuzz-builds-honggfuzz'
        elif engine=='dataflow':
            bucket = 'clusterfuzz-builds-dataflow'
        elif engine=='none':
            bucket = 'clusterfuzz-builds-no-engine'
        else:
            eventLog(f'dev:downloadFuzzer: Unknown Engine {engine}')
    else:
        return False
    url = f'gs://{bucket}/{pname}/{srcmap_name}.zip'
    if storage== None:
        target_dir = tmpDir()
    else:
        target_dir = storage
    if check_call(['gcloud','storage','cp', url, str(target_dir)]):
        return target_dir
    else:
        cmd = ['gcloud','storage','cp', url, str(target_dir)]
        cmd = ' '.join(cmd)
        eventLog(f'dev:downloadFuzzer: {cmd}')
        return False

def getFuzzerbyName(localId,srcmap_name,storage):
    issue = getIssue(localId)
    fuzzer_info = issue['job_type'].split("_")
    engine = fuzzer_info[0]
    if engine not in ['libfuzzer','afl','honggfuzz','centipede','dataflow','none']:
        eventLog(f'[-] dev:getFuzzer: weird engine found {engine}')
        return False
    if fuzzer_info[2] == 'i386':
        arch='i386'
    else:
        arch='x86_64'
    pname = getPname(localId,False)
    donwloadFuzzer(pname, srcmap_name, engine, arch, storage)
    return list(storage.iterdir())[0]

def getFuzzer(localId,storage=None):
    issue = getIssue(localId)
    fuzzer_info = issue['job_type'].split("_")
    engine = fuzzer_info[0]
    if engine not in ['libfuzzer','afl','honggfuzz','centipede','dataflow','none']:
        eventLog(f'[-] dev:getFuzzer: weird engine found {engine}')
        return False
    if fuzzer_info[2] == 'i386':
        arch='i386'
    else:
        arch='x86_64'
    pname = getPname(localId,False)
    
    
    srcmap_name = getSrcmaps(localId)[0].name.split(".")[0]
    donwloadFuzzer(pname, srcmap_name, engine, arch, storage)

    srcmap_name = getSrcmaps(localId)[1].name.split(".")[0]
    donwloadFuzzer(pname, srcmap_name, engine, arch, storage)
    return 
    

def getFuzzers():
    issues = getAllLocalIds()
    storage = Path("/data/n132/oss-fuzz")
    ct =  0
    for x in issues:
        if ct % 30 == 29:
            sleep(30)
        try:
            tmp = storage / str(x)
            tmp.mkdir(exist_ok=True)
            res = getFuzzer(x,tmp)
        except:
            pass

if __name__ == "__main__":
    pass