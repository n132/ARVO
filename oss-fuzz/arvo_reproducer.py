# ARVO reproducer
# Paper: https://arxiv.org/abs/2408.02153
# ARVO Implementation: https://github.com/n132/ARVO
# Neil — May 5, 2025 — Seattle, USA
"""
Module reproduces a vulnerability and its fix on OSS-Fuzz.
Login gcloud:
    $ gcloud auth application-default login 
"""
from pathlib import Path

OSS_OUT = OSS_WORK = OSS_ERR = Path("/tmp")

storage_client = None
from arvo_data import *
import argparse
import requests
import pytz
from datetime import datetime

import re
import os
import tempfile
from google.cloud import storage
from urllib.parse import urlparse
from urllib.parse import parse_qs
import logging
import warnings
import shutil
import subprocess
import json
import collections
from dateutil.parser import parse
import time
from bisect import bisect_right

BuildData = collections.namedtuple(
    'BuildData', ['project_name', 'engine', 'sanitizer', 'architecture'])
warnings.filterwarnings("ignore",
                        category=UserWarning,
                        module="google.auth._default")
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def INFO(s):
  logging.info(s)


def WARN(s):
  logging.warning(s)


def FAIL(s, res=False):
  logging.error(s)
  return res


class DockerfileModifier():

  def __init__(self, path) -> None:
    self.path = path
    with open(path) as f:
      self.content = f.read()
    comments = re.compile(r'^\s*#.*\n', re.MULTILINE)
    self.content = comments.sub("", self.content)
    self.content = self.content.replace("\\\n", "")
    blankLine = re.compile(r'\n(\s)*\n', re.MULTILINE)
    self.content = blankLine.sub("\n", self.content)

  def flush(self):
    try:
      with open(self.path, 'w') as f: f.write(self.content)
      return True
    except:
      return False
    
  def str_replace(self, old, new):
    self.content = self.content.replace(old, new)

  def str_replace_all(self, paires):
    for key in paires: self.str_replace(key,paires[key])

  def replace_line_at(self, pos, line):
    lines = self.content.split("\n")
    lines[pos] = line
    self.content = "\n".join(lines)

  def replace(self, old, new, flags=0):
    self.content = re.sub(old, new, self.content, flags=flags)

  def replace_once(self, old, new):
    self.content = re.sub(old, new, self.content, count=1)

  def insert_line_before(self, target, newline):
    lineNum = self.locate_str(target)
    if lineNum == False:
      return False
    self.insert_line_at(lineNum, newline)

  def insert_line_after(self, target, newline):
    lineNum = self.locate_str(target)
    if lineNum == False:
      return False
    self.insert_line_at(lineNum + 1, newline)

  def insert_line_at(self, pos, line):
    lines = self.content.split("\n")
    lines.insert(pos, line)
    self.content = "\n".join(lines)

  def remove_range(self, starts, ends):
    lines = self.content.split("\n")
    new_lines = []
    for num in range(len(lines)):
      if num >= starts and num < ends:
        continue
      new_lines.append(lines[num])
    self.content = '\n'.join(new_lines)

  def clean_comments(self):
    pattern = re.compile(r'^#.*', re.MULTILINE)
    # Remove comments from each line
    self.content = pattern.sub('', self.content)
    newline_pattern = re.compile(r'^\n', re.MULTILINE)
    # Remove any empty lines left after removing comments
    self.content = newline_pattern.sub('', self.content)

  def locate_str(self, keyword):
    ct = 0
    linenum = False
    lines = self.content.split("\n")
    res = []
    for line in lines:
      if keyword in line:
        res.append(line)
        linenum = ct
      ct += 1
    return linenum

  def get_line(self, keyword):
    res = []
    lines = self.content.split("\n")
    ct = 0
    linenum = 0

    for line in lines:
      ct += 1
      if keyword in line:
        res.append(line)
        linenum = ct
    if len(res) < 2:
      return res, linenum
    pat = re.compile(rf"{keyword}(\s.*$|$)")
    res = []
    ct = 0
    linenum = 0
    for line in lines:
      ct += 1
      if pat.findall(line):
        res.append(line)
        linenum = ct
    return res, linenum

class GitTool():

  def __init__(self,
               oriRepo,
               vctype='git',
               revision=None,
               latest=False) -> None:
    if vctype not in ['git', 'hg', 'svn']:
      FAIL(f'[-] GitTool: Does not support {vctype}', ext=True)
    self.type = vctype
    if type(oriRepo) == str:
      repoPath = Path(oriRepo)
    else:
      repoPath = oriRepo
    if not repoPath.exists():
      repoPath = self.clone(oriRepo, revision)
    if not repoPath:
      FAIL(f'[-] GitTool: Failed to init {oriRepo}', ext=True)
    self.repo = repoPath
    self.name = self.repo.name
    if latest and not self.pull():
      FAIL(f'[-] GitTool: Failed to Update {oriRepo}', ext=True)

  def pull(self):
    if self.type == 'git':
      return git_pull(self.repo)
    elif self.type == 'hg':
      return hg_pull(self.repo)
    else:
      return svn_pull(self.repo)

  def clone(self, url, revision=None):
    if self.type == 'git':
      repo = clone(url, revision)
      if repo != False:
        self.repo = list(repo.iterdir())[0]
      else:
        return False
    elif self.type == 'hg':
      repo = hg_clone(url, revision)
      if repo != False:
        self.repo = list(repo.iterdir())[0]
      else:
        return False
    else:
      repo = svn_clone(url, revision)
      if repo != False:
        self.repo = list(repo.iterdir())[0]
      else:
        return False
    return self.repo

  def commit_date(self, commit):
    if self.type == 'git':
      res = execute(['git', 'show', '-s', '--format=%ci', commit], self.repo)
      if res != False:
        return time_reformat(res.decode())
    elif self.type == 'hg':
      res = execute(['hg', 'log', '-r', commit, '--template', '{date}'],
                    self.repo)
      if res != False:
        return datetime.utcfromtimestamp(int(res.decode().split(".")[0])).strftime('%Y%m%d%H%M')
    else:
      res = execute(['svn', 'log', '-r', commit, '-q'], self.repo)
      if res != False:
        res = res.decode()
        res = res.split('\n')
        if len(res) == 1:
          return False
        res = res[1].split(' | ')[2].split(' (')[0]
        return time_reformat(res)

    return False

  def reset(self, commit):
    if self.type == 'git':
      cmd = ['git', 'reset', '--hard', commit]
      with open('/dev/null', 'w') as f:
        return check_call(cmd, self.repo, stdout=f)
    elif self.type == 'hg':
      cmd1 = ['hg', 'update', '--clean', '-r', commit]
      cmd2 = ['hg', "purge", '--config', 'extensions.purge=']
      if check_call(cmd1, self.repo) and check_call(cmd2, self.repo):
        return True
      else:
        return False
    elif self.type == "svn":
      return check_call(['svn', "up", '--force', '-r', commit], cwd=self.repo)
    else:
      return False

def git_pull(cwd):
  with open("/dev/null", 'w') as f:
    return check_call(['git', 'pull'], cwd=cwd, stderr=f, stdout=f)


def hg_pull(cwd):
  with open("/dev/null", 'w') as f:
    return check_call(['hg', 'pull'], cwd=cwd, stderr=f, stdout=f)


def svn_pull(cwd):
  with open("/dev/null", 'w') as f:
    return check_call(['svn', 'update'], cwd=cwd, stderr=f, stdout=f)


def clone(url,
          commit=None,
          dest=None,
          name=None,
          main_repo=False,
          commit_date=None):

  def _git_clone(url, dest, name):
    cmd = ['git', 'clone', url]
    if name != None:
      cmd.append(name)
    if check_call(cmd, dest) == False:
      return False
    if name == None:
      name = list(dest.iterdir())[0]
    return True

  def _check_out(commit, path):
    with open('/dev/null', 'w') as f:
      return check_call(['git', "reset", '--hard', commit], cwd=path, stdout=f)

  dest = Path(dest) if dest else Path(tempfile.mkdtemp())
  if not _git_clone(url, dest, name):
    return FAIL(f"[!] - clone: Failed to clone {url}")
  if commit:
    INFO(f"[+] Checkout to commit {commit}")
    name = list(dest.iterdir())[0] if name == None else name
    if _check_out(commit, dest / name):
      return dest
    else:
      if main_repo == True:
        return FAIL(f"[!] - clone: Failed to checkout {name}")
      else:
        if commit_date == None:
          WARN(
              f"[!] - clone: Failed to checkout {name} but it's not the main component, using the latest version"
          )
          return dest
        WARN("[!] Failed to checkout, try a version before required commit")
        cmd = [
            "git", "log", f"--before='{commit_date.isoformat()}'",
            "--format='%H'", "-n1"
        ]
        commit = execute(cmd, dest / name).decode().strip("'")
        INFO(f"[+] Checkout to {commit}")
        if _check_out(commit, dest / name):
          return dest
        else:
          return FAIL(f"[!] - clone: Failed to checkout {name}")
  return dest


def time_reformat(original_str):
  # Parse the datetime string to a datetime object, specifying the original format
  original_dt = datetime.strptime(original_str, "%Y-%m-%d %H:%M:%S %z")
  # Convert the datetime object to UTC
  utc_dt = original_dt.astimezone(pytz.utc)
  # Format the UTC datetime object to the new string format without timezone information
  formatted_str = utc_dt.strftime("%Y%m%d%H%M")
  return formatted_str

def svn_clone(url, commit=None, dest=None, rename=None):

  def _svn_clone(url, dest, name=None):
    cmd = "svn co".split(" ")
    cmd += [url]
    if name:
      cmd.append(name)
    if check_call(cmd, dest) == False:
      return False
    name = list(dest.iterdir())[0] if not name else name
    return True

  tmp = Path(dest) if dest else Path(tempfile.mkdtemp())
  if not _svn_clone(url, tmp, rename):
    return FAIL(f"[!] - svn_clone: Failed to clone {url}")
  if commit:
    name = rename if rename else list(tmp.iterdir)[0]
    tmp = tmp / name
    if check_call(['svn', "up", '--force', '-r', commit], cwd=tmp) == False:
      return False
  return tmp


def hg_clone(url, commit=None, dest=None, rename=None):

  def _hg_clone(url, dest, name=None):
    cmd = "hg clone".split(" ")
    cmd += [url]
    if name:
      cmd.append(name)
    if check_call(cmd, dest) == False:
      return False
    if name == None:
      name = list(dest.iterdir())[0]
    return True

  tmp = Path(dest) if dest else Path(tempfile.mkdtemp())
  if not _hg_clone(url, tmp, rename):
    FAIL(f"[!] - hg_clone: Failed to clone {url}")
    return False
  if commit:
    name = rename if rename else list(tmp.iterdir)[0]
    tmp = tmp / name
    if check_call(['hg',"update", '--clean', '-r', commit], cwd=tmp) and \
    check_call(['hg',"purge", '--config', 'extensions.purge='], cwd=tmp):
      pass
    else:
      return False
  return tmp




def execute(cmd, cwd=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
  try:
    res = subprocess.run(cmd,
                         cwd=cwd,
                         stderr=stdout,
                         stdout=stderr,
                         check=False)
    if res.returncode == 0:
      return res.stdout.strip() if res.stdout.strip() != b'' else True
    else:
      return False
  except Exception as e:
    return False


def check_call(cmd, cwd=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
  try:
    res = subprocess.run(cmd,
                         cwd=cwd,
                         stderr=stdout,
                         stdout=stderr,
                         check=False)
    if res.returncode == 0:
      return True
    else:
      return False
  except Exception as e:
    return False

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


# Parse the job type into parts
def fix_build_script(file, pname):
  if not file.exists():
    return True
  dft = DockerfileModifier(file)
  if pname == "uwebsockets":
    '''
        https://github.com/alexhultman/zlib
        ->
        https://github.com/madler/zlib.git
        '''
    script = "sed -i 's/alexhultman/madler/g' fuzzing/Makefile"
    dft.insert_line_at(0, script)
  elif pname == 'libreoffice':
    '''
        If you don't want to destroy your life. 
        Please leave this project alone. too hard to fix and the compiling takes several hours
        '''
    line = '$SRC/libreoffice/bin/oss-fuzz-build.sh'
    dft.insert_line_before(
        line,
        "sed -i 's/make fuzzers/make fuzzers -i/g' $SRC/libreoffice/bin/oss-fuzz-build.sh"
    )
    dft.insert_line_before(
        line,
        "sed -n -i '/#starting corpuses/q;p' $SRC/libreoffice/bin/oss-fuzz-build.sh"
    )
    dft.insert_line_before(
        line,
        r"sed -n -i '/pushd instdir\/program/q;p' $SRC/libreoffice/bin/oss-fuzz-build.sh"
    )
    dft.insert_line_before(
        line,
        'echo "pushd instdir/program && mv *fuzzer $OUT" >> $SRC/libreoffice/bin/oss-fuzz-build.sh'
    )
  elif pname == 'jbig2dec':
    dft.replace('unzip.*', 'exit 0')
  elif pname == "ghostscript":
    old = r"mv \$SRC\/freetype freetype"
    new = "cp -r $SRC/freetype freetype"
    dft.replace(old, new)
  elif pname == 'openh264':
    lines = dft.content.split("\n")
    starts = -1
    ends = -1
    for num in range(len(lines)):
      if "# prepare corpus" in lines[num]:
        starts = num
      elif "# build" in lines[num]:
        ends = num
        break
    if starts != -1 and ends != -1:
      dft.remove_range(starts, ends)
  elif pname in ['libredwg', 'duckdb']:
    dft.replace(r'^make$', 'make -j`nproc`\n')
  assert (dft.flush() == True)
  return True


def get_pname(issue, srcmap):
  if 'project' not in issue:
    FAIL("[FAILED] to get project feild in issue")
    return False
  else:
    pname = issue['project']
  if pname in PnameTable:
    return PnameTable[pname]  # handling special cases
  with open(srcmap) as f:
    info1 = json.load(f)
  except_name = "/src/" + pname
  if (except_name in info1):
    return pname
  else:
    return FAIL(
        f"Failed to locate the main component, plz add that to PnameTable")


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


def skip_component(pname, itemName):
  NoOperation = [
      "/src",
      "/src/LPM/external.protobuf/src/external.protobuf",
      "/src/libprotobuf-mutator/build/external.protobuf/src/external.protobuf",
  ]
  itemName = itemName.strip(" ")
  # Special for skia, Skip since they are done by submodule init
  if pname in ['skia', 'skia-ftz']:
    if itemName.startswith("/src/skia/"):
      return True
  if itemName in NoOperation:
    return True
  return False


def dockerfile_cleaner(dockerfile):
  dft = DockerfileModifier(dockerfile)
  dft.replace(r'(--single-branch\s+)', "")  # --single-branch
  dft.replace(r'(--branch\s+\S+\s+|-b\s\S+\s+|--branch=\S+\s+)',
              "")  # remove --branch or -b
  dft.flush()


def fix_dockerfile(dockerfile_path, project=None):
  # todo: complex manual work to make it faster
  def _x265Fix(dft):
    # The order of following two lines matters
    dft.replace(
        r'RUN\shg\sclone\s.*bitbucket.org/multicoreware/x265\s*(x265)*',
        "RUN git clone https://bitbucket.org/multicoreware/x265_git.git x265\n")
    dft.replace(
        r'RUN\shg\sclone\s.*hg.videolan.org/x265\s*(x265)*',
        "RUN git clone https://bitbucket.org/multicoreware/x265_git.git x265\n")

  dft = DockerfileModifier(dockerfile_path)
  dft.replace_once(
      r'RUN apt',
      "RUN apt update -y && apt install git ca-certificates -y && git config --global http.sslVerify false && git config --global --add safe.directory '*'\nRUN apt"
  )
  dft.str_replace_all(global_str_replace)

  if project == "lcms":
    dft.replace(r'#add more seeds from the testbed dir.*\n', "")
  elif project == 'wolfssl':
    dft.str_replace(
        'RUN gsutil cp gs://wolfssl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/wolfssl_cryptofuzz-disable-fastmath/public.zip $SRC/corpus_wolfssl_disable-fastmath.zip',
        "RUN touch 0xdeadbeef && zip $SRC/corpus_wolfssl_disable-fastmath.zip 0xdeadbeef"
    )
  elif project == 'skia':
    dft.str_replace('RUN wget', "# RUN wget")
    line = 'COPY build.sh $SRC/'
    dft.insert_line_after(line, "RUN sed -i 's/cp.*zip.*//g' $SRC/build.sh")
  elif project == 'libreoffice':
    dft.str_replace('RUN ./bin/oss-fuzz-setup.sh',\
    "RUN sed -i 's|svn export --force -q https://github.com|#svn export --force -q https://github.com|g' ./bin/oss-fuzz-setup.sh")
    dft.str_replace('RUN svn export', '# RUN svn export')
    dft.str_replace('ADD ', '# ADD ')
    dft.str_replace('RUN zip', '# RUN zip')
    dft.str_replace('RUN mkdir afl-testcases', "# RUN mkdir afl-testcases")
    dft.str_replace(
        'RUN ./bin/oss-fuzz-setup.sh',
        "# RUN ./bin/oss-fuzz-setup.sh")  # Avoid downloading not related stuff
  elif project == 'graphicsmagick':  # Done
    line = r'RUN hg clone .* graphicsmagick'
    dft.replace(
        line,
        'RUN (CMD="hg clone --insecure https://foss.heptapod.net/graphicsmagick/graphicsmagick graphicsmagick" && for x in `seq 1 100`; do $($CMD); if [ $? -eq 0 ]; then break; fi; done)'
    )
    _x265Fix(dft)
  elif project == 'libheif':
    _x265Fix(dft)
  elif project == 'ffmpeg':
    _x265Fix(dft)
  elif project == 'imagemagick':
    dft.replace(r'RUN svn .*heic_corpus.*',
                "RUN mkdir /src/heic_corpus && touch /src/heic_corpus/XxX")
  elif project == "jbig2dec":
    dft.replace(r'RUN cd tests .*', "")
  elif project == 'dlplibs':
    dft.replace(r"ADD", '# ADD')
    dft.replace(r"RUN wget", '#RUN wget')
  elif project == 'quickjs':
    dft.str_replace('https://github.com/horhof/quickjs',
                   'https://github.com/bellard/quickjs')
  elif project == 'cryptofuzz':
    line = "RUN cd $SRC/libressl && ./update.sh"
    dft.insert_line_before(
        line,
        "RUN sed -n -i '/^# setup source paths$/,$p' $SRC/libressl/update.sh")
  elif project == 'libyang':
    dft.str_replace(
        'RUN git clone https://github.com/PCRE2Project/pcre2 pcre2 &&',
        "RUN git clone https://github.com/PCRE2Project/pcre2 pcre2\nRUN ")
  elif project == "yara":
    if 'bison' not in dft.content:
      line = "RUN git clone https://github.com/VirusTotal/yara.git"
      dft.insert_line_before(line, "RUN apt install -y bison")
  elif project == "lwan":
    dft.str_replace('git://github.com/lpereira/lwan',
                   'https://github.com/lpereira/lwan.git')
  elif project == "radare2":
    dft.str_replace("https://github.com/radare/radare2-regressions",
                   'https://github.com/rlaemmert/radare2-regressions.git')
  elif project == "wireshark":
    dft.replace(r"RUN git clone .*wireshark.*", "")
  dft.clean_comments()
  assert (dft.flush() == True)
  return True


def docker_build(args, logFile=None):
  cmd = ['docker', 'build']
  cmd.extend(args)
  INFO("[+] Docker Build: \n" + " ".join(cmd))
  if logFile:
    with open(logFile, 'w') as f:
      res = check_call(cmd, stderr=f, stdout=f)
      f.write("\n" + " ".join(cmd) + "\n")
      return res
  else:
    return check_call(cmd)


def docker_run(args, rm=True, logFile=None):
  if rm:
    cmd = ['docker', 'run', '--rm', '--privileged']
  else:
    cmd = ['docker', 'run', '--privileged']

  cmd.extend(args)
  INFO("[+] Docker Run: \n" + " ".join(cmd))
  if logFile:
    with open(logFile, 'w') as f:
      res = check_call(cmd, stdout=f, stderr=f)
      f.write("\n" + " ".join(cmd) + "\n")
      return res
  else:
    return check_call(cmd)


def extra_scritps(pname, oss_dir, source_dir):
  """
    This function allows us to modify build.sh scripts and other stuff to modify the compiling setting
    """
  if pname == 'imagemagick':
    target = source_dir / "src" / pname / "Magick++" / "fuzz" / "build.sh"
    if target.exists():
      with open(target) as f:
        lines = f.readlines()
      for x in range(3):
        if "zip" in lines[-x]:
          del (lines[-x])
      with open(target, 'w') as f:
        f.write("\n".join(lines))
  return True


def special_component(pname, itemKey, item, dockerfile, commit_date):
  if pname == 'libressl' and itemKey == '/src/libressl/openbsd':
    return False
  if pname == 'gnutls' and itemKey == '/src/gnutls/nettle':
    # Just Ignore since we have submodule update --init
    with open(dockerfile) as f:
      dt = f.read()
    if item['rev'] not in dt:
      return True
    else:
      return False
  return False


def update_revision_info(dockerfile, localId, src_path, item, commit_date,
                       approximate):
  item_url = item['url']
  item_rev = item['rev']
  item_type = item['type']
  dft = DockerfileModifier(dockerfile)
  keyword = item_url
  if keyword.startswith("http:"):
    keyword = keyword[4:]
  elif keyword.startswith("https:"):
    keyword = keyword[5:]
  hits, ct = dft.get_line(keyword)
  d = dict()
  d['localId'] = localId
  d['url'] = item_url
  d['type'] = item_type
  # Case Miss
  if len(hits) == 0:
    d['reason'] = "Not Found"
    return False
  # Case MisMatch
  elif len(hits) != 1:
    d['reason'] = "More then one results"
    return False
  # Case Hit
  else:
    line = hits[0]
    if item_type == 'git':
      pat = re.compile(rf"{item_type}\s+clone")
    # Could not be a clone command
    elif item_type == 'hg':
      pat = re.compile(rf"{item_type}\s+clone")
    elif item_type == 'svn':
      pat = re.compile(rf"RUN\s+svn\s+(co|checkout)+")
    else:
      return False
    if len(pat.findall(line)) != 1:
      d['reason'] = f"Missing type: {item_type}, {line}"
      return False
    else:
      if type(commit_date) == type(Path("/tmp")):
        rep_path = commit_date
        # Replace mode
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
        # Insert Mode
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
          dft.flush()
          return True
        elif item_type == 'hg':
          dft.insert_line_at(
              ct,
              f'''RUN bash -cx "pushd {src_path} ; (hg update --clean -r {item_rev} && hg purge --config extensions.purge=)|| exit 99 ; popd"'''
          )
          dft.flush()
          return True
        elif item_type == "svn":
          dft.replace(pat, f"RUN svn checkout -r {item_rev}")
          dft.flush()
          return True
        else:
          return False


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
    return FAIL(
        f"[-]No such a dockerfile: {dockerfile_path}")
  # Locate the Repo
  res = re.search(r'FROM .*', data)
  if (res == None):
    return FAIL(
        f"[-] Failed to get the base-image: {dockerfile_path}"
    )
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


def clean_dir(victim):
  if not victim.exists():
    return True
  try:
    shutil.rmtree(victim)
    return True
  except:
    WARN(f"[FAILED] to remove tmp file {victim}")
    return False


def leave_ret(return_val, tmp_dir):
  if type(tmp_dir) != list:
    clean_dir(tmp_dir)
  else:
    for _ in tmp_dir:
      clean_dir(_)
  return return_val


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
        FAIL(
            '[-] Failed to get oldest oss-fuzz commit'
        )
        return leave_ret(False, tmp_dir)
  # 3. Reset OSS Fuzz
  gt = GitTool(tmp_oss_fuzz_dir)
  if gt.reset(oss_fuzz_commit) == False:
    FAIL("[-] Fail to Reset OSS-Fuzz")
    return leave_ret(False, tmp_dir)
  # 4. Locate Project Dir
  tmp_list = [x for x in tmp_oss_fuzz_dir.iterdir() if x.is_dir()]
  if tmp_oss_fuzz_dir / "projects" in tmp_list:
    proj_dir = tmp_oss_fuzz_dir / "projects" / project_name
  elif tmp_oss_fuzz_dir / "targets" in tmp_list:
    proj_dir = tmp_oss_fuzz_dir / "targets" / project_name
  else:
    FAIL(
        f"[-] Fail to locate the project({project_name}) in oss-fuzz"
    )
    return leave_ret(False, tmp_dir)
  return (tmp_dir, proj_dir)


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
  INFO(f"[+] dockerfile: {dockerfile}")
  build_data = BuildData(sanitizer=sanitizer,
                         architecture=arch,
                         engine=engine,
                         project_name=project_name)

  # Step ZERO: Rebase Dockerfiles
  if not rebase_dockerfile(dockerfile, str(commit_date).replace(" ", "-")):
    FAIL(f"[-] build_fuzzer_with_source: Fail to Rebase Dockerfile, {localId}")
    return leave_ret(False, tmp_dir)
  # Step ONE: Fix Dockerfiles
  dockerfile_cleaner(dockerfile)
  if not fix_dockerfile(dockerfile, project_name):
    FAIL(f"[-] build_fuzzer_with_source: Fail to Fix Dockerfile, {localId}")
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
    # INFO(f"[+] Prepare Dependency: {x}")
    if skip_component(project_name, x):
      continue

    if tag == 'fix' and mainCompoinent == x:
      approximate = '+'
    else:
      approximate = '-'

    newD = {}
    newD['rev'] = data[x]['rev']
    newKey, newD['url'], newD['type'] = update_resource_info(x, data[x]['url'],
                                                    data[x]['type'])

    del (data[x])
    data[newKey] = newD

    item_name = newKey
    item_url = data[newKey]['url']
    item_type = data[newKey]['type']
    item_rev = data[newKey]['rev']
    item_name = "/".join(item_name.split("/")[2:])

    if special_component(project_name, newKey, data[newKey], dockerfile,
                        commit_date):
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
    if update_revision_info(dockerfile, localId, newKey, data[newKey],
                          commit_date, approximate):
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
      FAIL(f"[Failed] to support {item_type}")
      exit(1)
  # Step Three: Extra Scripts
  if not extra_scritps(project_name, project_dir, source_dir):
    FAIL(f"[-] build_fuzzer_with_source: Fail to Run ExtraScripts, {localId}")
    return leave_ret(False, [tmp_dir, source_dir])
  if not fix_build_script(project_dir / "build.sh", project_name):
    FAIL(f"[-] build_fuzzer_with_source: Fail to Fix Build.sh, {localId}")
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
  INFO(f"[+] Check the output in file: {logFile}")

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
    INFO(f"[+] Check the output in file: {str(logFile)}")
  else:
    logFile = None

  result = docker_run(command, logFile=logFile)
  if result == False:
    FAIL('[-] Failed to Build Targets')
    return False
  else:
    if logFile and logFile.exists() and str(logFile) != "/dev/null":
      os.remove(str(logFile))
  INFO(f"OUT: {project_out}")
  return True


def arvo_reproducer(localId, tag):
  INFO(f"[+] Working on {localId}")
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
  INFO("[+] Downloading PoC")
  case_dir = Path(tempfile.mkdtemp())
  try:
    case_path = download_poc(issue, case_dir, "crash_case")
  except:
    return FAIL(f"Fail to Download the Reproducer")
  INFO(f"POC: {case_path}")
  if not case_path or not case_path.exists():
    return FAIL(f"Fail to Download the Reproducer")

  # 3. Build the Vulnerabel Software
  INFO("[+] Building the Binary")

  res = build_from_srcmap(srcmap, issue, tag)

  if not res:
    return FAIL(f"Fail to build old fuzzers from srcmap")
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
