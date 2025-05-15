import re
import pytz
import shutil
import logging
import tempfile
import warnings
import subprocess

from pathlib import Path
from datetime import datetime

OSS_OUT = OSS_WORK = OSS_ERR = Path("/tmp")
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
warnings.filterwarnings("ignore",
                        category=UserWarning,
                        module="google.auth._default")


def INFO(s):
  logging.info(s)


def WARN(s):
  logging.warning(s)


def FAIL(s, res=False):
  logging.error(s)
  return res


def execute(cmd,
            cwd=Path("/tmp"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE):
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


def check_call(cmd,
               cwd=Path("/tmp"),
               stdout=subprocess.PIPE,
               stderr=subprocess.PIPE):
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
    INFO(f"Checkout to commit {commit}")
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
        INFO(f"Checkout to {commit}")
        if _check_out(commit, dest / name):
          return dest
        else:
          return FAIL(f"[!] - clone: Failed to checkout {name}")
  return dest


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
      with open(self.path, 'w') as f:
        f.write(self.content)
      return True
    except:
      return False

  def str_replace(self, old, new):
    self.content = self.content.replace(old, new)

  def str_replace_all(self, paires):
    for key in paires:
      self.str_replace(key, paires[key])

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


class VersionControlTool():

  def __init__(self,
               oriRepo,
               vctype='git',
               revision=None,
               latest=False) -> None:
    if vctype not in ['git', 'hg', 'svn']:
      FAIL(f'VersionControlTool: Does not support {vctype}', ext=True)
    self.type = vctype
    if type(oriRepo) == str:
      repoPath = Path(oriRepo)
    else:
      repoPath = oriRepo
    if not repoPath.exists():
      repoPath = self.clone(oriRepo, revision)
    if not repoPath:
      FAIL(f'VersionControlTool: Failed to init {oriRepo}', ext=True)
    self.repo = repoPath
    self.name = self.repo.name
    if latest and not self.pull():
      FAIL(f'VersionControlTool: Failed to Update {oriRepo}', ext=True)

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

    def time_reformat(original_str):
      # Parse the datetime string to a datetime object, specifying the original format
      original_dt = datetime.strptime(original_str, "%Y-%m-%d %H:%M:%S %z")
      # Convert the datetime object to UTC
      utc_dt = original_dt.astimezone(pytz.utc)
      # Format the UTC datetime object to the new string format without timezone information
      formatted_str = utc_dt.strftime("%Y%m%d%H%M")
      return formatted_str

    if self.type == 'git':
      res = execute(['git', 'show', '-s', '--format=%ci', commit], self.repo)
      if res != False:
        return time_reformat(res.decode())
    elif self.type == 'hg':
      res = execute(['hg', 'log', '-r', commit, '--template', '{date}'],
                    self.repo)
      if res != False:
        return datetime.utcfromtimestamp(int(
            res.decode().split(".")[0])).strftime('%Y%m%d%H%M')
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


def docker_build(args, logFile=None):
  cmd = ['docker', 'build']
  cmd.extend(args)
  INFO("Docker Build: \n" + " ".join(cmd))
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
  INFO("Docker Run: \n" + " ".join(cmd))
  if logFile:
    with open(logFile, 'w') as f:
      res = check_call(cmd, stdout=f, stderr=f)
      f.write("\n" + " ".join(cmd) + "\n")
      return res
  else:
    return check_call(cmd)


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


if __name__ == "__main__":
  pass
