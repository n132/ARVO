#!/usr/bin/env python
import _profile
import os
import requests
import json
import json5 # For initial token context which is in JS
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.parse import parse_qs
from utils import issueFilter
DEBUG = 1
DEBUG_SIZE = 0x100

# Replace this with your own API key
# Instructions: https://cloud.google.com/storage/docs/reference/libraries
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = _profile.gcloud_key

from google.cloud import storage

# Not sure how many of these are necessary!
headers = {
    'authority': 'bugs.chromium.org',
    'sec-ch-ua': '"Google Chrome";v="95", "Chromium";v="95", ";Not A Brand";v="99"',
    'dnt': '1',
    'sec-ch-ua-mobile': '?0',
    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36',
    'content-type': 'application/json',
    'accept': 'application/json',
    'sec-ch-ua-platform': '"macOS"',
    'origin': 'https://bugs.chromium.org',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-mode': 'cors',
    'sec-fetch-dest': 'empty',
    'accept-language': 'en-US,en;q=0.9',
    'cookie': 'GOOGAPPUID=x',
}

def get_context():
    request_url = "https://bugs.chromium.org/p/oss-fuzz/issues/list"
    page = session.get(request_url).text
    page_context_start = page.find("window.CS_env =")
    page_context_end = page.find("</script>", page_context_start)
    page_context = page[page_context_start:page_context_end]
    page_context = page_context.replace("window.CS_env = ", "")
    page_context = page_context.replace(";", "")
    context_json = json5.loads(page_context)

    return context_json

def token_expired(context):
    return time.time() > context["tokenExpiresSec"]

# Decorator to automatically refresh token if expired
def check_token(func):
    def wrapper(context, *args, **kwargs):
        if token_expired(context):
            print("Token expired, refreshing...")
            context = get_context()
        return func(context, *args, **kwargs)
    return wrapper

@check_token
def make_prpc_request(context, request_url, data):
    token = {'x-xsrf-token': context["token"]}
    response = session.post(request_url, headers={**headers,**token}, data=data)
    #print(f"Debug: got response {response.status_code}, size {len(response.text)}")
    response_json = json.loads(response.text[5:])
    return response_json

# Sample query to search for issues:
"""
curl 'https://bugs.chromium.org/prpc/monorail.Issues/ListIssues' \
  --data-raw '{"projectNames":["oss-fuzz"],"query":"Type=Bug-Security label:Reproducible status:Verified","cannedQuery":1,"sortSpec":"-id","pagination":{"maxItems":100}}'
"""
def search_issues(context, query,maxLen=None,updateFrom=0):
    request_url = "https://bugs.chromium.org/prpc/monorail.Issues/ListIssues"
    def query_data(query, start=0):
        data = {
            "projectNames": ["oss-fuzz"],
            "query": query,
            "cannedQuery": 1,
            "sortSpec": "-id",
            "pagination": {"maxItems": 100}
        }
        if start > 0:
            data["pagination"]["start"] = start
        return json.dumps(data)
    issues = []
    print("Searching for issues...")
    response_json = make_prpc_request(context, request_url, query_data(query,updateFrom))
    issues += response_json["issues"]
    total_results = response_json["totalResults"]
    if(not maxLen):
        maxLen = total_results

    print(f"Got {len(issues)}/{total_results} results")
    while len(issues) < maxLen:
        response_json = make_prpc_request(context, request_url, query_data(query, len(issues)))
        issues += response_json["issues"]
        print(f"Got {len(issues)}/{total_results} results")
    return issues

# Sample query that lists a single issue:
"""
curl 'https://bugs.chromium.org/prpc/monorail.Issues/ListComments' \
  --data-raw '{"issueRef":{"localId":40064,"projectName":"oss-fuzz"}}'
  """
def get_issue_comments(context, issue_id):
    request_url = "https://bugs.chromium.org/prpc/monorail.Issues/ListComments"
    data = {
        "issueRef": {
            "localId": issue_id,
            "projectName": "oss-fuzz"
        }
    }
    response_json = make_prpc_request(context, request_url, json.dumps(data))
    return response_json

# Try to get reproducer from issue comments. This updates the metadata dict
# with a list of reproducer filenames downloaded.
def download_reproducer(issue_json, dest_dir, metadata):
    i = 0
    metadata['reproducer_filenames'] = []
    for comment in issue_json['comments']:
        if 'content' not in comment: continue
        for line in comment['content'].splitlines():
            if line.startswith("Reproducer Testcase:"):
                reproducer_url = line.split(":", 1)[1].strip()
                print(f"Downloading reproducer {reproducer_url} to {dest_dir}: ", end="", flush=True)
                response = session.head(reproducer_url, allow_redirects=True)
                if response.status_code != 200:
                    print(f"Error: failed to download reproducer: {response.status_code}")
                    continue
                if 'Content-Disposition' in response.headers:
                    filename = response.headers['Content-Disposition'].split("filename=")[1].strip('"')
                else:
                    filename = f"{comment['localId']}.{i}.bin"
                    i += 1
                print(f"{filename}")
                reproducer_path = Path(dest_dir) / filename
                if reproducer_path.exists():
                    print(f"Reproducer already exists, skipping")
                    continue
                response = session.get(reproducer_url)
                if response.status_code != 200:
                    print(f"Error: failed to download reproducer: {response.status_code}")
                    continue
                reproducer_path.write_bytes(response.content)
                metadata['reproducer_filenames'].append(filename)
                
    return bool(metadata['reproducer_filenames'])

# Sample metadata we want to extract:
# Project: imagemagick
# Fuzzer: libFuzzer_imagemagick_ping_dng_fuzzer
# Fuzz target binary: ping_dng_fuzzer
# Job Type: libfuzzer_msan_imagemagick
# Platform Id: linux
# Crash Type: Use-of-uninitialized-value
# Crash Address: 
# Sanitizer: memory (MSAN)
# Recommended Security Severity: Medium
# Regressed: https://oss-fuzz.com/revisions?job=libfuzzer_msan_imagemagick&range=201804220437:201804240143
# Crash Revision: https://oss-fuzz.com/revisions?job=libfuzzer_asan_fastjson2&revision=202110220601
# Reproducer Testcase: https://oss-fuzz.com/download?testcase_id=5662852382195712
# ClusterFuzz testcase 5662852382195712 is verified as fixed in https://oss-fuzz.com/revisions?job=libfuzzer_msan_imagemagick&range=202005130137:202005140539
def get_metadata(issue_json):
    metadata = {}
    for comment in issue_json['comments']:
        if 'content' not in comment: continue
        for line in comment['content'].splitlines():
            if line.startswith("Project:"):
                metadata["project"] = line.split(":", 1)[1].strip()
            elif line.startswith("Target:"):
                metadata["project"] = line.split(":", 1)[1].strip()
            elif line.startswith("Fuzzer:"):
                metadata["fuzzer"] = line.split(":", 1)[1].strip()
            elif line.startswith("Fuzz target binary:"):
                metadata["fuzz_target"] = line.split(":", 1)[1].strip()
            elif line.startswith("Fuzzer binary:"):
                metadata["fuzz_target"] = line.split(":", 1)[1].strip()
            elif line.startswith("Job Type:"):
                metadata["job_type"] = line.split(":", 1)[1].strip()
            elif line.startswith("Platform Id:"):
                metadata["platform"] = line.split(":", 1)[1].strip()
            elif line.startswith("Crash Type:"):
                metadata["crash_type"] = line.split(":", 1)[1].strip()
            elif line.startswith("Crash Address:"):
                metadata["crash_address"] = line.split(":", 1)[1].strip()
            elif line.startswith("Sanitizer:"):
                metadata["sanitizer"] = line.split(":", 1)[1].strip()
            elif line.startswith("Recommended Security Severity:"):
                metadata["severity"] = line.split(":", 1)[1].strip()
            elif line.startswith("Regressed:"):
                metadata["regressed"] = line.split(":", 1)[1].strip()
            elif line.startswith("Crash Revision:"):
                metadata["regressed"] = line.split(":", 1)[1].strip()
            elif line.startswith("Reproducer Testcase:"):
                metadata["reproducer"] = line.split(":", 1)[1].strip()
            elif line.startswith("Minimized Testcase"):
                metadata["reproducer"] = line.split(":", 1)[1].strip()
            elif line.startswith("Fixed:"):
                metadata["verified_fixed"] = line.split(":", 1)[1].strip()
            elif "is verified as fixed in" in line:
                metadata["verified_fixed"] = line.split()[-1].strip()
    return metadata

# metzman — 11/15/2021
# In the crash revision link is the revision: e.g. https://oss-fuzz.com/revisions?job=libfuzzer_asan_i386_qt&range=202108160601:202108170610
# or https://oss-fuzz.com/revisions?job=libfuzzer_ubsan_assimp&revision=202107080606
# Some times there are two numbers in the range sometimes there are one
# Sorry, i'm trying to verify the workflow I'm about to post
# metzman — 11/15/2021
# If there is one number, then the bug predates OSS-Fuzz. The number is the first build the bug appears in.
# If there are two numbers, I think you want the second revision number (seperated by a colon) because that is the first build the bug appears in.
# Then you can download the build from the build bucket:
# gs://$BUCKET_NAME/$PROJECT/$PROJECT-$SANITIZER-$REVISION.zip
# You should be able to figure out $PROJECT, $SANITIZER and $REVISION from the issue.
# $BUCKET_NAME varies depending on the build type:
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
        assert project == job['project']
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

def query_to_pathname(query):
    return query.replace(" ", "_").replace("/", "_").replace(":", ".").replace("=", ".")
def data_download(Dodownload=False,Update=False):
    global session
    session = requests.Session()
    ctx = get_context()
    print(f"Got XSRF token: {ctx['token']}, expires at {time.ctime(ctx['tokenExpiresSec'])} expired: {token_expired(ctx)}")
    query = "Type=Bug-Security label:Reproducible status:Verified"
    print("Using cache dir:", query_to_pathname(query))
    # Create a new directory for the query and save the results

    outdir = Path(query_to_pathname(query))
    outdir.mkdir(parents=True, exist_ok=True)

    metadata_file = outdir / "metadata.jsonl"
    metadata = {}
    if metadata_file.exists() and Update==False:
        for line in open(metadata_file):
            mdline = json.loads(line)
            metadata[mdline['localId']] = mdline
    else:
        # Save metadata found in jsonl format
        md_file = open(metadata_file, "w")
        # Search for issues
        issue_file = outdir / "issues.json"
        if issue_file.exists():
            if not Update:
                with open(issue_file) as f:
                    issues = json.load(f)
            else:
                issues = search_issues(ctx, query)
                with open(issue_file, "w") as f:
                    json.dump(issues, f)
        else:
            issues = search_issues(ctx, query)
            with open(issue_file, "w") as f:
                json.dump(issues, f)
        print(f"Found {len(issues)} issues")
        Issues_dir = outdir / "Issues"
        Issues_dir.mkdir(exist_ok=True)
        for issue in issues[::-1]:
            print(f"Issue {issue['localId']} {issue.get('summary','[missing summary]')}")
            tmp = Issues_dir /f"{issue['localId']}_files"
            tmp.mkdir(exist_ok=True)
            issue_file = tmp / f"{issue['localId']}.json"
            if issue_file.exists():
                comments = json.load(open(issue_file))
            else:
                comments = get_issue_comments(ctx, issue['localId'])
                with open(issue_file, "w") as f:
                    json.dump(comments, f)
            # Get metadata
            metadata_single = get_metadata(comments)#parse comment's content
            metadata_single['issue'] = issue
            metadata_single['localId'] = issue['localId']
            #print(f"Found metadata for {issue['localId']}: {','.join(metadata)}")
            # Get reproducer(s) and save them. 

            # got_reproducer = download_reproducer(comments, tmp, metadata)
            got_reproducer = False
            metadata_single['reproducer_downloaded'] = got_reproducer
            json.dump(metadata_single, md_file)
            md_file.write("\n")
            metadata[issue['localId']] = metadata_single
        md_file.close()
    

    if(Dodownload):
        updated_metadata_file = outdir / "metadata.jsonl"
        updated_md_file = open(updated_metadata_file, "w")
        #for localId in metadata:
        print(len(metadata))
        for localId in metadata:
            # Get reproducer(s) and save them.
            issue_dir = outdir / "Issues" / f"{localId}_files"
            issue_dir.mkdir(parents=True, exist_ok=True)
            if 'regressed' in metadata[localId]:
                downloaded_filenames = download_build_artifacts(metadata[localId], metadata[localId]['regressed'], issue_dir)
                metadata[localId]['regressed_files'] = downloaded_filenames
            else:
                print('No regressed build:', localId)
            if 'verified_fixed' in metadata[localId]:
                downloaded_filenames = download_build_artifacts(metadata[localId], metadata[localId]['verified_fixed'], issue_dir)
                metadata[localId]['verified_fixed_files'] = downloaded_filenames
            else:
                print('No fixed:', localId)

            json.dump(metadata[localId], updated_md_file)
            updated_md_file.write("\n")
        updated_md_file.close()
    issueFilter()
    return str(outdir)

if __name__ =="__main__":
    print(data_download(True,True))


