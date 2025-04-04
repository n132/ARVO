import requests
# obsolete url format: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=30419
import re
from datetime import datetime
from .utils_log import *
from .utils import ARVO
from ._profile import DATA_FOLD2
import json
from tqdm import tqdm

META = ARVO / DATA_FOLD2

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
        "project": extract(r'(?:Target|Project):\s*(\S+)'),
        "job_type": extract(r'Job Type:\s*(\S+)'),
        "platform": extract(r'Platform Id:\s*(\S+)','linux'),
        "crash_type": extract(r'Crash Type:\s*(.+)'),
        "crash_address": extract(r'Crash Address:\s*(\S+)'),
        "severity": extract(r'Security Severity:\s*(\w+)', 'Medium'),
        "regressed": extract(r'(?:Regressed|Fixed):\s*(https?://\S+)'),
        "reproducer": extract(r'(?:Minimized Testcase|Reproducer Testcase|Download).*:\s*(https?://\S+)'),
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
    res['sanitizer'] = sanitizer_map[res['job_type'].split("_")[1]]
    if fuzz_target != 'NOTFOUND':
        res['fuzz_target'] = fuzz_target
    return res
def getIssue(issue_id,debug = False):
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
    if debug:
        print(raw_text)
    res = parse_oss_fuzz_report(raw_text,issue_id)
    if debug:
        print(res)
    return res
    
def getIssues(issue_ids):
    issues = []
    for x in issue_ids:
        res = getIssue(x)
        if res:
            issues.append(res)
        else:
            WARN(f"Failed to fetch the issue for {x}")
    return issues
def syncMeta(localIds):
    # load the meta to metadata.jsonl
    fp = META / "metadata.jsonl"
    res = getIssues(localIds)
    done = []
    if fp.exist():
        with open(fp,'r') as f:
            lines = f.readlines()
        for line in lines:
            done.append(json.loads(line)['localId'])
    with open(fp,'w') as f:
        for x in tqdm(res):
            if x['localId'] not in done:
                f.write(json.dumps(x))
def getSrcmap():
    pass
def getMeta():
    if not META.exists():
        META.mkdir()
    localIds = getIssueIds()
    syncMeta(localIds)

if __name__ == "__main__":
    pass
