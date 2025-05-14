# ARVO reproducer
# Paper: https://arxiv.org/abs/2408.02153
# ARVO Implementation: https://github.com/n132/ARVO
# Neil — May 5, 2025 — Seattle, USA
"""
Module reproduces a vulnerability and its fix on OSS-Fuzz.
Login gcloud:
    $ gcloud auth application-default login 
"""

storage_client = None

from arvo_utils import *
from arvo_data import *

import os
import json
import time
import argparse
import requests
import collections
from bisect import bisect_right
from google.cloud import storage
from dateutil.parser import parse
from urllib.parse import urlparse
from urllib.parse import parse_qs

BuildData = collections.namedtuple(
    'BuildData', ['project_name', 'engine', 'sanitizer', 'architecture'])


# Functiosn to fetch the information from OSS-Fuzz
def parse_oss_fuzz_report(report_text: bytes, localId: int) -> dict:
  text = report_text.decode(
      'unicode_escape', errors='ignore')  # decode escaped unicode like \u003d

  def extract(pattern, default=''):
    m = re.search(pattern, text)
    if not m:
      if default == '':
        logging.error("FAILED to PARSE {pattern} {localId=}")
        exit(1)
      else:
        return default
    return m.group(1).strip()

  res = {
      "project":
          extract(r'(?:Target|Project):\s*(\S+)', 'NOTFOUND'),
      "job_type":
          extract(r'Job Type:\s*(\S+)'),
      "platform":
          extract(r'Platform Id:\s*(\S+)', 'linux'),
      "crash_type":
          extract(r'Crash Type:\s*(.+)'),
      "crash_address":
          extract(r'Crash Address:\s*(\S+)'),
      "severity":
          extract(r'Security Severity:\s*(\w+)', 'Medium'),
      "regressed":
          extract(r'(?:Regressed|Crash Revision):\s*(https?://\S+)',
                  "NO_REGRESS"),
      "reproducer":
          extract(
              r'(?:Minimized Testcase|Reproducer Testcase|Download).*:\s*(https?://\S+)'
          ),
      "verified_fixed":
          extract(r'(?:fixed in|Fixed:)\s*(https?://\S+revisions\S+)',
                  'NO_FIX'),
      "localId":
          localId
  }
  sanitizer_map = {
      "address (ASAN)": "address",
      "memory (MSAN)": "memory",
      "undefined (UBSAN)": "undefined",
      "asan": "address",
      "msan": "memory",
      "ubsan": "undefined",
  }
  fuzz_target = extract(r'(?:Fuzz Target|Fuzz target binary):\s*(\S+)',
                        'NOTFOUND')
  if len(res['job_type'].split("_")) == 2:
    return False
  else:
    res['sanitizer'] = sanitizer_map[res['job_type'].split("_")[1]]

  if fuzz_target != 'NOTFOUND':
    res['fuzz_target'] = fuzz_target
  if res['project'] == "NOTFOUND":
    res['project'] = res['job_type'].split("_")[-1]
  return res


def fetch_issue(localId):
  # TODO: Replace this with proper issue tracker API calls
  url = f'https://issues.oss-fuzz.com/action/issues/{localId}/events?currentTrackerId=391'
  session = requests.Session()
  # Step 1: Get the token from the cookie
  session.get("https://issues.oss-fuzz.com/")
  xsrf_token = session.cookies.get("XSRF_TOKEN")
  headers = {
      'accept':
          'application/json, text/plain, */*',
      'accept-language':
          'en,zh-CN;q=0.9,zh;q=0.8,ar;q=0.7',
      'priority':
          'u=1, i',
      'referer':
          'https://issues.oss-fuzz.com/',
      'sec-ch-ua':
          '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
      'sec-ch-ua-mobile':
          '?0',
      'sec-ch-ua-platform':
          '"Linux"',
      'sec-fetch-dest':
          'empty',
      'sec-fetch-mode':
          'cors',
      'sec-fetch-site':
          'same-origin',
      'user-agent':
          'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
      'X-XSRF-Token':
          xsrf_token
  }
  response = session.get(url, headers=headers)
  raw_text = response.content
  try:
    res = parse_oss_fuzz_report(raw_text, localId)
  except:
    logging.error(f"FAIL on {localId}, skip")
    return False
  return res


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
  if job['untrusted']:
    return False
  if job['engine'] == 'none':
    return False
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
    download_path = outdir / name

    if download_path.exists():
      logging.info(f'Skipping {name} (already exists)')
      downloaded_files.append(download_path)
      continue
    blob = bucket.blob(path)
    if not blob.exists():
      logging.info(f'Skipping {name} (not found)')
      continue
    ret = blob.download_to_filename(str(download_path))

    logging.info(f'Downloaded {name}')
    downloaded_files.append(download_path)
  return [str(f) for f in downloaded_files]


# Functions to get meta info
def get_pname(issue, srcmap):
  if 'project' not in issue:
    FAIL("[FAILED] to get project feild in issue")
    return False
  else:
    pname = issue['project']
  if pname in pname_table:
    return pname_table[pname]  # handling special cases
  with open(srcmap) as f:
    info1 = json.load(f)
  except_name = "/src/" + pname
  if (except_name in info1):
    return pname
  else:
    return FAIL(
        f"Failed to locate the main component, plz add that to pname_table")


def get_language(project_dir):
  porjymal = project_dir / "project.yaml"
  if not porjymal.exists():
    return False
  with open(porjymal) as f:
    porjymal = f.read()
  res = re.findall(r'language\s*:\s*([^\s]+)', porjymal)
  if len(res) != 1:
    FAIL(f"[!] Get more than one languages")
    return False
  return str(res[0])


def get_sanitizer(fuzzer_sanitizer):
  if (fuzzer_sanitizer == 'asan'):
    fuzzer_sanitizer = "address"
  elif (fuzzer_sanitizer == 'msan'):
    fuzzer_sanitizer = 'memory'
  elif (fuzzer_sanitizer == 'ubsan'):
    fuzzer_sanitizer = 'undefined'
  else:
    fuzzer_sanitizer = False
  return fuzzer_sanitizer


def download_poc(issue, path, name):
  global session
  session = requests.Session()
  url = issue['reproducer']
  response = session.head(url, allow_redirects=True)

  if response.status_code != 200:
    return False
  reproducer_path = path / name
  response = session.get(url)

  if response.status_code != 200:
    return False
  reproducer_path.write_bytes(response.content)
  return reproducer_path


# Functions required during reproducing
def prepare_ossfuzz(project_name, commit_date):
  # 1. Clone OSS Fuzz
  tmp_dir = clone("https://github.com/google/oss-fuzz.git", name="oss-fuzz")
  # 2. Get the Commit Close to Commit_Date
  tmp_oss_fuzz_dir = tmp_dir / "oss-fuzz"
  if isinstance(commit_date, str):
    oss_fuzz_commit = commit_date
  else:
    cmd = [
        'git', 'log', '--before=' + commit_date.isoformat(), '-n1',
        '--format=%H'
    ]
    oss_fuzz_commit = execute(cmd, tmp_oss_fuzz_dir).strip()

    if oss_fuzz_commit == False:
      cmd = ['git', 'log', '--reverse', '--format=%H']
      oss_fuzz_commit = execute(cmd, tmp_oss_fuzz_dir).splitlines()[0].strip()
      if oss_fuzz_commit == False:
        FAIL('Failed to get oldest oss-fuzz commit')
        return leave_ret(False, tmp_dir)
  # 3. Reset OSS Fuzz
  gt = VersionControlTool(tmp_oss_fuzz_dir)
  if gt.reset(oss_fuzz_commit) == False:
    FAIL("Failed to Reset OSS-Fuzz")
    return leave_ret(False, tmp_dir)
  # 4. Locate Project Dir
  tmp_list = [x for x in tmp_oss_fuzz_dir.iterdir() if x.is_dir()]
  if tmp_oss_fuzz_dir / "projects" in tmp_list:
    proj_dir = tmp_oss_fuzz_dir / "projects" / project_name
  elif tmp_oss_fuzz_dir / "targets" in tmp_list:
    proj_dir = tmp_oss_fuzz_dir / "targets" / project_name
  else:
    FAIL(f"Failed to locate the project({project_name}) in oss-fuzz")
    return leave_ret(False, tmp_dir)
  return (tmp_dir, proj_dir)


def rebase_dockerfile(dockerfile_path, commit_date):

  def _get_base(date, repo="gcr.io/oss-fuzz-base/base-builder"):
    cache_name = repo.split("/")[-1]
    CACHE_FILE = f"/tmp/{cache_name}_cache.json"
    CACHE_TTL = 86400  # 24 hours
    if os.path.exists(CACHE_FILE) and (
        time.time() - os.path.getmtime(CACHE_FILE)) < CACHE_TTL:
      with open(CACHE_FILE, 'r') as f:
        res = json.load(f)
    else:
      cmd = [
          "gcloud", "container", "images", "list-tags", repo, "--format=json",
          "--sort-by=timestamp"
      ]
      res = execute(cmd)
      res = json.loads(res)
      with open(CACHE_FILE, 'w') as f:
        f.write(json.dumps(res, indent=4))
    ts = []
    for x in res:
      ts.append(int(parse(x['timestamp']['datetime']).timestamp()))
    target_ts = int(parse(date).timestamp())
    return res[bisect_right(ts, target_ts - 1) - 1]['digest'].split(":")[1]

  # Load the Dockerfile
  try:
    with open(dockerfile_path) as f:
      data = f.read()
  except:
    return FAIL(f"No such a dockerfile: {dockerfile_path}")
  # Locate the Repo
  res = re.search(r'FROM .*', data)
  if res == None:
    return FAIL("Failed to get the base-image: {dockerfile_path}")
  else:
    repo = res[0][5:]
  if "@sha256" in repo:
    repo = repo.split("@sha256")[0]
  if repo == 'ossfuzz/base-builder' or repo == 'ossfuzz/base-libfuzzer':
    repo = "gcr.io/oss-fuzz-base/base-builder"
  if ":" in repo:
    repo = repo.split(":")[0]
  image_hash = _get_base(commit_date, repo)
  # We insert update insce some old dockerfile doesn't have that line
  data = re.sub(
      r"FROM .*",
      f"FROM {repo}@sha256:" + image_hash + "\nRUN apt-get update -y\n", data)
  with open(dockerfile_path, 'w') as f:
    f.write(data)
  return True


def update_revision_info(dockerfile, src_path, item, commit_date, approximate):
  item_url = item['url']
  item_rev = item['rev']
  item_type = item['type']
  dft = DockerfileModifier(dockerfile)

  if item_url.startswith("http:"):
    keyword = item_url[4:]
  elif item_url.startswith("https:"):
    keyword = item_url[5:]
  else:
    keyword = item_url

  hits, ct = dft.get_line(keyword)
  # mismatch
  if len(hits) != 1:
    return False
  line = hits[0]
  if item_type == 'git':
    pat = re.compile(rf"{item_type}\s+clone")
  elif item_type == 'hg':
    pat = re.compile(rf"{item_type}\s+clone")
  elif item_type == 'svn':
    pat = re.compile(rf"RUN\s+svn\s+(co|checkout)+")
  else:
    return FAIL("NOT supported protocol")

  if len(pat.findall(line)) != 1:  # mismatch
    return False

  if isinstance(commit_date, Path):
    rep_path = commit_date
    # Replace mode: for bisection
    """
            Replace the original line with ADD/COPY command
            Then RUN init/update the submodule
            """
    dft.replace_line_at(ct - 1, f"ADD {rep_path.name} {src_path}")
    dft.insert_line_at(
        ct,
        f"RUN bash -cx 'pushd {src_path} ;(git submodule init && git submodule update --force) ;popd'"
    )
    dft.flush()
    return True
  else:
    # Insertion Mode
    if item_type == "git":
      if approximate == '-':
        dft.insert_line_at(
            ct,
            f"RUN bash -cx 'pushd {src_path} ; (git reset --hard {item_rev}) || (commit=$(git log --before='{commit_date.isoformat()}' --format='%H' -n1) && git reset --hard $commit || exit 99) ;  (git submodule init && git submodule update --force) ;popd'"
        )
      else:
        dft.insert_line_at(
            ct,
            f"RUN bash -cx 'pushd {src_path} ; (git reset --hard {item_rev}) || (commit=$(git log --since='{commit_date.isoformat()}' --format='%H' --reverse | head -n1) && git reset --hard $commit || exit 99) ;  (git submodule init && git submodule update --force) ;popd'"
        )
    elif item_type == 'hg':
      # TODO: support approximate
      dft.insert_line_at(
          ct,
          f'''RUN bash -cx "pushd {src_path} ; (hg update --clean -r {item_rev} && hg purge --config extensions.purge=)|| exit 99 ; popd"'''
      )
    elif item_type == "svn":
      # TODO: support approximate
      dft.replace(pat, f"RUN svn checkout -r {item_rev}")
    else:
      return False
    dft.flush()
    return True


# Main reproducing entries
def build_fuzzers_impl(localId,
                       project_dir,
                       engine,
                       sanitizer,
                       architecture,
                       source_path,
                       mount_path=None,
                       noDump=False,
                       custom_script=[]):
  # Set the LogFile
  logFile = OSS_ERR / f"{localId}_Image.log"
  INFO(f"Check the output in file: {logFile}")

  # Clean The WORK/OUT DIR
  project_out = OSS_OUT / f"{localId}_OUT"
  project_work = OSS_WORK / f"{localId}_WORK"
  if project_out.exists():
    check_call(["sudo", "rm", "-rf", project_out])
  if project_work.exists():
    check_call(["sudo", "rm", "-rf", project_work])
  project_out.mkdir()
  project_work.mkdir()

  args = [
      '-t', f'gcr.io/oss-fuzz/{localId}', '--file',
      str(project_dir / "Dockerfile"),
      str(project_dir)
  ]
  if docker_build(args, logFile=logFile) == False:
    return FAIL(f"Failed to build DockerImage")

  # Build Succeed, Try Compiling
  if logFile and logFile.exists():
    os.remove(str(logFile))
  env = [
      'FUZZING_ENGINE=' + engine,
      'SANITIZER=' + sanitizer,
      'ARCHITECTURE=' + architecture,
      'FUZZING_LANGUAGE=' + get_language(project_dir),
  ]
  command = sum([['-e', x] for x in env], [])

  # Mount the Source/Dependencies (we try to replace this with modifying dockerfile)
  if source_path and mount_path:
    for item in source_path.iterdir():
      command += ['-v', '%s:%s' % (item, mount_path / item.name)]
  # Mount out/work dir
  command += [
      '-v',
      '%s:/out' % project_out, '-v',
      '%s:/work' % project_work, '-t', f'gcr.io/oss-fuzz/{localId}'
  ]
  # supports for submodule tracker
  command += custom_script

  if noDump == False:
    logFile = OSS_ERR / f"{localId}_Compile.log"
    INFO(f"Check the output in file: {str(logFile)}")
  else:
    logFile = None

  result = docker_run(command, logFile=logFile)
  if result == False:
    FAIL('Failed to Build Targets')
    return False
  else:
    if logFile and logFile.exists() and str(logFile) != "/dev/null":
      os.remove(str(logFile))
  INFO(f"OUT: {project_out}")
  return True


def build_fuzzer_with_source(localId, project_name, srcmap, sanitizer, engine,
                             arch, commit_date, issue, tag):
  # Build source_dir
  srcmap_items = json.loads(open(srcmap).read())
  if "/src" in srcmap_items and srcmap_items['/src'][
      'url'] == 'https://github.com/google/oss-fuzz.git':
    res = prepare_ossfuzz(project_name, srcmap_items['/src']['rev'])
  else:
    res = prepare_ossfuzz(project_name, commit_date)
  if not res:
    return False
  else:
    tmp_dir, project_dir = res
  dockerfile = project_dir / 'Dockerfile'
  INFO(f"dockerfile: {dockerfile}")
  build_data = BuildData(sanitizer=sanitizer,
                         architecture=arch,
                         engine=engine,
                         project_name=project_name)

  # Step ZERO: Rebase Dockerfiles
  if not rebase_dockerfile(dockerfile, str(commit_date).replace(" ", "-")):
    FAIL(f"build_fuzzer_with_source: Failed to Rebase Dockerfile, {localId}")
    return leave_ret(False, tmp_dir)
  # Step ONE: Fix Dockerfiles
  if not fix_dockerfile(dockerfile, project_name):
    FAIL(f"build_fuzzer_with_source: Failed to Fix Dockerfile, {localId}")
    return leave_ret(False, tmp_dir)

  # Step TWO: Prepare Dependencies
  with open(srcmap) as f:
    data = json.loads(f.read())
  source_dir = Path(tempfile.mkdtemp())
  src = source_dir / "src"
  src.mkdir(parents=True, exist_ok=True)
  docker_volume = []
  unsorted = list(data.keys())
  sortedKey = sorted(unsorted, key=len)
  mainCompoinent = get_pname(issue, srcmap)
  if mainCompoinent == False:
    return leave_ret(False, tmp_dir)
  ForceNoErrDump = True if "/src/xz" in sortedKey else False

  # Handle Srcmap Info
  for x in sortedKey:
    # INFO(f"Prepare Dependency: {x}")
    if skip_component(project_name, x):
      continue

    if tag == 'fix' and mainCompoinent == x:
      approximate = '+'
    else:
      approximate = '-'

    newD = {}
    newD['rev'] = data[x]['rev']
    newKey, newD['url'], newD['type'] = update_resource_info(
        x, data[x]['url'], data[x]['type'])

    del (data[x])
    data[newKey] = newD

    item_name = newKey
    item_url = data[newKey]['url']
    item_type = data[newKey]['type']
    item_rev = data[newKey]['rev']
    item_name = "/".join(item_name.split("/")[2:])

    if special_component(project_name, newKey, data[newKey], dockerfile):
      continue
    if item_name == 'aflplusplus' and item_url == 'https://github.com/AFLplusplus/AFLplusplus.git':
      continue
    if item_name == 'libfuzzer' and 'llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer' in item_url:
      continue

    # Broken Revision
    if item_rev == "" or item_rev == "UNKNOWN":
      FAIL(f"Broken Meta: No Revision Provided")
      return leave_ret(False, [tmp_dir, source_dir])
    # Ignore not named dependencies if it's not main
    if item_name.strip(" ") == "" and len(data.keys()) == 1:
      FAIL(f"Broken Meta: Found Not Named Dep")
      return leave_ret(False, [tmp_dir, source_dir])
    # Borken type
    if item_type not in ['git', 'svn', 'hg']:
      FAIL(f"Broken Meta: No support for {item_type}")
      return leave_ret(False, [tmp_dir, source_dir])

    # Try to perform checkout in dockerfile,
    # which could make reproducing more reliable
    if update_revision_info(dockerfile, newKey, data[newKey], commit_date,
                            approximate):
      continue

    # Prepare the dependencies and record them. We'll use -v to mount them to the docker container
    if (item_type == 'git'):
      clone_res = clone(item_url,
                        item_rev,
                        src,
                        item_name,
                        commit_date=commit_date)
      if clone_res == False:
        FAIL(
            f"[!] build_from_srcmap: Failed to clone & checkout [{localId}]: {item_name}"
        )
        return leave_ret(False, [tmp_dir, source_dir])
      elif clone_res == None:
        command = f'git log --before="{commit_date.isoformat()}" -n 1 --format="%H"'
        res = subprocess.run(command,
                             stdout=subprocess.PIPE,
                             text=True,
                             shell=True,
                             cwd=src / item_name)
        res = res.stdout.strip()
        if check_call(['git', "reset", '--hard', res],
                      cwd=src / item_name) == False:
          FAIL(
              f"[!] build_from_srcmap: Failed to clone & checkout [{localId}]: {item_name}"
          )
          return leave_ret(False, [tmp_dir, source_dir])
      docker_volume.append(newKey)
    elif (item_type == 'svn'):
      if not svn_clone(item_url, item_rev, src, item_name):
        FAIL(f"[!] build_from_srcmap/svn: Failed clone & checkout: {item_name}")
        return leave_ret(False, [tmp_dir, source_dir])
      docker_volume.append(newKey)
    elif (item_type == 'hg'):
      if not hg_clone(item_url, item_rev, src, item_name):
        FAIL(f"[!] build_from_srcmap/hg: Failed clone & checkout: {item_name}")
        return leave_ret(False, [tmp_dir, source_dir])
      docker_volume.append(newKey)
    else:
      FAIL(f"Failed to support {item_type}")
      exit(1)
  # Step Three: Extra Scripts
  if not extra_scritps(project_name, source_dir):
    FAIL(f"Failed to Run ExtraScripts, {localId}")
    return leave_ret(False, [tmp_dir, source_dir])
  if not fix_build_script(project_dir / "build.sh", project_name):
    FAIL(f"Failed to Fix Build.sh, {localId}")
    return leave_ret(False, [tmp_dir, source_dir])
  # Let's Build It
  result = build_fuzzers_impl(localId,
                              project_dir=project_dir,
                              engine=build_data.engine,
                              sanitizer=build_data.sanitizer,
                              architecture=build_data.architecture,
                              source_path=source_dir / "src",
                              mount_path=Path("/src"),
                              noDump=ForceNoErrDump)
  # we need sudo since the docker container root touched the folder
  check_call(["sudo", "rm", "-rf", source_dir])
  return leave_ret(result, tmp_dir)


def build_from_srcmap(srcmap, issue, tag):
  # Get Basic Information
  fuzzer_info = issue['job_type'].split("_")
  engine = fuzzer_info[0]
  sanitizer = get_sanitizer(fuzzer_info[1])
  arch = 'i386' if fuzzer_info[2] == 'i386' else 'x86_64'
  # Get Issue Date
  issue_date = srcmap.name.split(".")[0].split("-")[-1]
  commit_date = datetime.strptime(issue_date + " +0000", '%Y%m%d%H%M %z')
  if 'issue' not in issue:
    issue['issue'] = {'localId': issue['localId']}
  if engine not in ['libfuzzer', 'afl', 'honggfuzz', 'centipede']:
    return FAIL("Failed to get engine")
  if sanitizer == False:
    return FAIL("Failed to get Sanitizer")
  return build_fuzzer_with_source(issue['issue']['localId'], issue['project'],
                                  srcmap, sanitizer, engine, arch, commit_date,
                                  issue, tag)


def arvo_reproducer(localId, tag):
  INFO(f"Working on {localId}")
  # 1. Fetch the basic info for the vul
  issue = fetch_issue(localId)  # TODO, ask for a fast way
  if not issue:
    return FAIL(f"Failed to get the srcmap or issue for {localId}")
  tmpdir = Path(tempfile.mkdtemp())
  srcmap_url = srcmap_url = issue['regressed'] if tag == 'vul' else issue[
      'verified_fixed']
  srcmap = download_build_artifacts(issue, srcmap_url, tmpdir)[0]
  if not srcmap:
    return FAIL(f"Failed to get the srcmap for {localId}")
  srcmap = Path(srcmap)
  # Early issues don't have 'project' feild. Set project for issues that didn't have it.
  if 'project' not in issue.keys():
    issue['project'] = issue['fuzzer'].split("_")[1]

  # 2. Download the PoC
  INFO("Downloading PoC")
  case_dir = Path(tempfile.mkdtemp())
  try:
    case_path = download_poc(issue, case_dir, "crash_case")
  except:
    return FAIL(f"Failed to Download the Reproducer")
  INFO(f"POC: {case_path}")
  if not case_path or not case_path.exists():
    return FAIL(f"Failed to Download the Reproducer")

  # 3. Build the Vulnerabel Software
  INFO("Building the Binary")

  res = build_from_srcmap(srcmap, issue, tag)

  if not res:
    return FAIL(f"Failed to build old fuzzers from srcmap")
  return True


def main():
  """Main function."""
  parser = argparse.ArgumentParser(description='Reproduce ')
  parser.add_argument(
      '--issueId',
      help='The issueId of the found vulnerability https://issues.oss-fuzz.com/',
      required=True)
  parser.add_argument('--version',
                      default='fix',
                      help="The fixed version or vulnerable version")
  args = parser.parse_args()
  # In this script, localId == issueId
  arvo_reproducer(args.issueId, args.version)


if __name__ == "__main__":
  main()
