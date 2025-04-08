import requests
# obsolete url format: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=30419
import re
from datetime import datetime
from .utils_log import *
from .utils import *
import json
from tqdm import tqdm
from google.cloud import storage
from urllib.parse import urlparse
from urllib.parse import parse_qs

if NEW_ISSUE_TRACKER:
    META = ARVO / NEW_ISSUE_TRACKER

def getIssueIds():
    localIds = []
    session = requests.Session()
    # Step 1: Get the token from the cookie
    session.get("https://issues.oss-fuzz.com/")
    xsrf_token = session.cookies.get("XSRF_TOKEN")
    # Step 2: Use it in the header
    headers = {
        'Content-Type': 'application/json',
        'Origin': 'https://issues.oss-fuzz.com',
        'Referer': 'https://issues.oss-fuzz.com/',
        'X-XSRF-Token': xsrf_token
    }
    url = 'https://issues.oss-fuzz.com/action/issues/list'
    start_index = 0
    start_year  = 2016
    next_year   = datetime.now().year + 1
    while start_year != next_year:
        init_num = len(localIds)
        start_index = 0
        while True:
            end_year = start_year +1
            data = [None, None, None, None, None, ["391"], [f"type:vulnerability status:verified created<{end_year}-01-01 created>{start_year}-01-01", None, 500, f"start_index:{start_index}"]]
            response = session.post(url, headers=headers, json=data)
            data = response.text
            # Fix malformed JSON-like string
            clean_data = re.sub(r'\bnull\b', 'null', data)
            clean_data = clean_data.replace("'", '"')
            clean_data = re.sub(r',\s*]', ']', clean_data)
            # Parse with regex (quick and dirty)
            issues = re.findall(r'\[\s*null\s*,\s*(\d+),\s*\[\d+,\d+,\d+,\d+,\d+,"(.*?)"', clean_data)
            
            for issue_id, title in issues:
                localIds.append(issue_id)
            if len(issues)!=500:
                break
            start_index+=500
            if (len(localIds) - init_num == 2500):
                WARN("Out of Limit. Not Supported yet. (You may split it by month instead of year)")
                exit(1)
        added_num = len(localIds) - init_num
        INFO(f"Add {added_num} issues in year {start_year}")
        start_year+=1
    
    return [int(x) for x in localIds]

def parse_oss_fuzz_report(report_text: bytes,localId: int) -> dict:
    text = report_text.decode('unicode_escape', errors='ignore')  # decode escaped unicode like \u003d
    def extract(pattern,default=''):
        m = re.search(pattern, text)
        if not m:
            if default=='':
                WARN(f"FAILED to PARSE {pattern} {localId=}")
                exit(1)
            else:
                return default
        return m.group(1).strip()
    res = {
        "project": extract(r'(?:Target|Project):\s*(\S+)','NOTFOUND'),
        "job_type": extract(r'Job Type:\s*(\S+)'),
        "platform": extract(r'Platform Id:\s*(\S+)','linux'),
        "crash_type": extract(r'Crash Type:\s*(.+)'),
        "crash_address": extract(r'Crash Address:\s*(\S+)'),
        "severity": extract(r'Security Severity:\s*(\w+)', 'Medium'),
        "regressed": extract(r'(?:Regressed|Crash Revision):\s*(https?://\S+)',"NO_REGRESS"),
        "reproducer": extract(r'(?:Minimized Testcase|Reproducer Testcase|Download).*:\s*(https?://\S+)'),
        "verified_fixed": extract(r'(?:fixed in|Fixed:)\s*(https?://\S+)','NO_FIX'),
        "localId": localId
    }
    sanitizer_map = {
        "address (ASAN)": "address",
        "memory (MSAN)": "memory",
        "undefined (UBSAN)": "undefined",
        "asan": "address",
        "msan": "memory",
        "ubsan": "undefined",
    }
    fuzz_target = extract(r'(?:Fuzz Target|Fuzz target binary):\s*(\S+)','NOTFOUND')
    if len(res['job_type'].split("_"))==2:
        WARN(f"FAILED to GET sanitizer {localId=} {res['job_type']}")
        return False
    else:
        res['sanitizer'] = sanitizer_map[res['job_type'].split("_")[1]]

    if fuzz_target != 'NOTFOUND':
        res['fuzz_target'] = fuzz_target
    if res['project'] == "NOTFOUND":
        res['project'] = res['job_type'].split("_")[-1]
    return res
def getIssue(issue_id):
    url = f'https://issues.oss-fuzz.com/action/issues/{issue_id}/events?currentTrackerId=391'
    session = requests.Session()
    # Step 1: Get the token from the cookie
    session.get("https://issues.oss-fuzz.com/")
    xsrf_token = session.cookies.get("XSRF_TOKEN")
    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en,zh-CN;q=0.9,zh;q=0.8,ar;q=0.7',
        'priority': 'u=1, i',
        'referer': 'https://issues.oss-fuzz.com/',
        'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Linux"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
        'X-XSRF-Token': xsrf_token
    }
    response = session.get(url, headers=headers)
    raw_text = response.content
    try:
        res = parse_oss_fuzz_report(raw_text,issue_id)
    except:
        WARN(f"FAIL on {issue_id}, skip")
        return False
    return res
    
def getIssues(issue_ids):
    issues = []
    fp = META / "metadata.json"
    if not fp.exists():
        fp.touch()
    done = []
    with open(fp,'r') as f:
        lines = f.readlines()
    for line in lines:
        done.append(json.loads(line)['localId'])
    # print(done)
    for x in tqdm(issue_ids):
        if x in done:
            continue
        res = getIssue(x)
        if res:
            issues.append(res)
            with open(fp,'a') as f:
                f.write(json.dumps(res) + '\n') 
        else:
            WARN(f"Failed to fetch the issue for {x}")
    return issues
# Parse the job type into parts
def parse_job_type(job_type):
    parts = job_type.split('_')
    remainder = []
    parsed = {}
    while len(parts) > 0:
        part = parts.pop(0)
        if part in ['afl', 'honggfuzz', 'libfuzzer']:
            parsed['engine'] = part
        elif part in ['asan', 'ubsan', 'msan']:
            parsed['sanitizer'] = part
        elif part == 'i386':
            parsed['arch'] = part
        elif part == 'untrusted':
            parsed['untrusted'] = True
        else:
            remainder.append(part)
    if len(remainder) > 0:
        parsed['project'] = '_'.join(remainder)
    if 'arch' not in parsed:
        parsed['arch'] = 'x86_64'
    if 'engine' not in parsed:
        parsed['engine'] = 'none'
    if 'untrusted' not in parsed:
        parsed['untrusted'] = False
    return parsed
storage_client = None
def download_build_artifacts(metadata, url, outdir):
    global storage_client
    if storage_client is None:
        storage_client = storage.Client()
    bucket_map = {
        "libfuzzer_address_i386": "clusterfuzz-builds-i386",
        "libfuzzer_memory_i386": "clusterfuzz-builds-i386",
        "libfuzzer_undefined_i386": "clusterfuzz-builds-i386",
        "libfuzzer_address": "clusterfuzz-builds",
        "libfuzzer_memory": "clusterfuzz-builds",
        "libfuzzer_undefined": "clusterfuzz-builds",
        "afl_address": "clusterfuzz-builds-afl",
        "honggfuzz_address": "clusterfuzz-builds-honggfuzz",
    }
    sanitizer_map = {
        "address (ASAN)": "address",
        "memory (MSAN)": "memory",
        "undefined (UBSAN)": "undefined",
        "asan": "address",
        "msan": "memory",
        "ubsan": "undefined",
        "address": "address",
        "memory": "memory",
        "undefined": "undefined",
        None: "",
    }
    job_name = metadata["job_type"]
    job = parse_job_type(job_name)
    
    # These don't have any build artifacts
    if job['untrusted']: return False
    if job['engine'] == 'none': return False

    # Prefer the info from the job name, since the metadata
    # format has changed several times.
    if 'project' in metadata:
        project = metadata["project"]
    else:
        project = job['project']
    if 'sanitizer' in metadata:
        sanitizer = sanitizer_map[metadata["sanitizer"]]
        assert sanitizer == sanitizer_map[job['sanitizer']]
    else:
        sanitizer = sanitizer_map[job['sanitizer']]
    fuzzer = job['engine']
    bucket_string = f"{fuzzer}_{sanitizer}"
    if job['arch'] == 'i386':
        bucket_string += '_i386'
    assert bucket_string in bucket_map
    bucket_name = bucket_map[bucket_string]

    # Grab the revision from the URL
    urlparams = parse_qs(urlparse(url).query)
    
    if 'revision' in urlparams:
        revision = urlparams['revision'][0]
    elif 'range' in urlparams:
        revision = urlparams['range'][0].split(':')[1]
    else:
        return False
    
    zip_name = f'{project}-{sanitizer}-{revision}.zip'
    srcmap_name = f'{project}-{sanitizer}-{revision}.srcmap.json'
    zip_path = f'{project}/{zip_name}'
    srcmap_path = f'{project}/{srcmap_name}'
    downloaded_files = []
    bucket = storage_client.bucket(bucket_name)
    for path, name in [(srcmap_path, srcmap_name)]:
#    for path, name in [(zip_path, zip_name), (srcmap_path, srcmap_name)]:

        download_path = outdir / name

        if download_path.exists():
            print(f'Skipping {name} (already exists)')
            downloaded_files.append(download_path)
            continue
        blob = bucket.blob(path)
        if not blob.exists():
            print(f'Skipping {name} (not found)')
            continue
        print(download_path)
        ret = blob.download_to_filename(str(download_path))
        
        print(f'Downloaded {name}')
        downloaded_files.append(download_path)
    return [str(f) for f in downloaded_files]

def data_download():
    metadata_file =  META / "metadata.json"
    metadata = {}
    for line in open(metadata_file):
        mdline = json.loads(line)
        metadata[mdline['localId']] = mdline
    #for localId in metadata:
    for localId in tqdm(metadata):
        # Get reproducer(s) and save them.
        issue_dir = META / "Issues" / f"{localId}_files"
        if issue_dir.exists():
            done = []
            for x in issue_dir.iterdir():
                done.append(x)
            if len(done) == 2:
                INFO(f"Already downloaded {localId}")
                continue
            elif len(done) != 0:
                shutil.rmtree(issue_dir)
        issue_dir.mkdir(parents=True, exist_ok=True)
        if 'regressed' not in metadata[localId] or 'verified_fixed' not in metadata[localId] or \
            metadata[localId]['verified_fixed'] == 'NO_FIX':
            continue

        silentRun(download_build_artifacts,metadata[localId], metadata[localId]['regressed'], issue_dir)
        silentRun(download_build_artifacts,metadata[localId], metadata[localId]['verified_fixed'], issue_dir)
    # issueFilter()
    return True
def syncMeta(localIds):
    # load the meta to metadata.jsonl
    getIssues(localIds)
    
def getMeta():
    if not NEW_ISSUE_TRACKER:
        WARN("THIS SCRIPT ONLY WORKS FOR NEW_ISSUE_TRACKER")
        exit(1)
    if not META.exists():
        META.mkdir()
    localIds = getIssueIds()
    syncMeta(localIds)
    

if __name__ == "__main__":
    pass
