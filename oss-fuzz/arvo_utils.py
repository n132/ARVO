"""ARVO utilities module.

This module provides utility functions for ARVO reproducer including:
- Command execution functions
- Version control operations
- Docker operations
- File system utilities
- Dockerfile modification tools
"""

import logging
import re
import shutil
import subprocess
import tempfile
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import pytz

# Global constants
OSS_OUT = OSS_WORK = OSS_ERR = Path("/tmp")

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Suppress Google auth warnings
warnings.filterwarnings("ignore",
                        category=UserWarning,
                        module="google.auth._default")


def info(message: str) -> None:
  """Log an info message.
    
    Args:
        message: The message to log.
    """
  logging.info(message)


def warn(message: str) -> None:
  """Log a warning message.
    
    Args:
        message: The message to log.
    """
  logging.warning(message)


def fail(message: str, result: Any = False) -> Any:
  """Log an error message and return a result.
    
    Args:
        message: The error message to log.
        result: The result to return (default: False).
        
    Returns:
        The specified result value.
    """
  logging.error(message)
  return result


def execute(cmd: List[str],
            cwd: Path = Path("/tmp"),
            stdout: int = subprocess.PIPE,
            stderr: int = subprocess.PIPE) -> Union[bytes, bool]:
  """Execute a command and return its output or status.
    
    Args:
        cmd: Command to execute as a list of strings.
        cwd: Working directory for the command.
        stdout: Stdout redirection target.
        stderr: Stderr redirection target.
        
    Returns:
        Command output as bytes if successful and non-empty, True if successful
        but empty output, False if failed.
    """
  try:
    result = subprocess.run(cmd,
                            cwd=cwd,
                            stderr=stderr,
                            stdout=stdout,
                            check=False)
    if result.returncode == 0:
      if result.stdout and result.stdout.strip() != b'':
        return result.stdout.strip()
      return True
    return False
  except (subprocess.SubprocessError, OSError):
    return False


def check_call(cmd: List[str],
               cwd: Path = Path("/tmp"),
               stdout: int = subprocess.PIPE,
               stderr: int = subprocess.PIPE) -> bool:
  """Execute a command and return success status.
    
    Args:
        cmd: Command to execute as a list of strings.
        cwd: Working directory for the command.
        stdout: Stdout redirection target.
        stderr: Stderr redirection target.
        
    Returns:
        True if command succeeded, False otherwise.
    """
  try:
    result = subprocess.run(cmd,
                            cwd=cwd,
                            stderr=stderr,
                            stdout=stdout,
                            check=False)
    return result.returncode == 0
  except (subprocess.SubprocessError, OSError):
    return False


def git_pull(cwd: Path) -> bool:
  """Pull latest changes from git repository.
    
    Args:
        cwd: Path to the git repository.
        
    Returns:
        True if pull succeeded, False otherwise.
    """
  with open("/dev/null", 'w', encoding='utf-8') as f:
    return check_call(['git', 'pull'], cwd=cwd, stderr=f, stdout=f)


def hg_pull(cwd: Path) -> bool:
  """Pull latest changes from mercurial repository.
    
    Args:
        cwd: Path to the mercurial repository.
        
    Returns:
        True if pull succeeded, False otherwise.
    """
  with open("/dev/null", 'w', encoding='utf-8') as f:
    return check_call(['hg', 'pull'], cwd=cwd, stderr=f, stdout=f)


def svn_pull(cwd: Path) -> bool:
  """Update SVN repository to latest revision.
    
    Args:
        cwd: Path to the SVN repository.
        
    Returns:
        True if update succeeded, False otherwise.
    """
  with open("/dev/null", 'w', encoding='utf-8') as f:
    return check_call(['svn', 'update'], cwd=cwd, stderr=f, stdout=f)


def clone(url: str,
          commit: Optional[str] = None,
          dest: Optional[Union[str, Path]] = None,
          name: Optional[str] = None,
          main_repo: bool = False,
          commit_date: Optional[datetime] = None) -> Union[Path, bool]:
  """Clone a git repository and optionally checkout a specific commit.
    
    Args:
        url: Repository URL to clone.
        commit: Specific commit to checkout.
        dest: Destination directory for cloning.
        name: Name for the cloned repository directory.
        main_repo: Whether this is the main repository.
        commit_date: Date of the commit for fallback checkout.
        
    Returns:
        Path to cloned repository on success, False on failure.
    """

  def _git_clone(url: str, dest: Path, name: Optional[str]) -> bool:
    """Helper function to perform git clone operation."""
    cmd = ['git', 'clone', url]
    if name is not None:
      cmd.append(name)
    if not check_call(cmd, dest):
      return False
    return True

  def _check_out(commit: str, path: Path) -> bool:
    """Helper function to checkout a specific commit."""
    with open('/dev/null', 'w', encoding='utf-8') as f:
      return check_call(['git', "reset", '--hard', commit], cwd=path, stdout=f)

  dest_path = Path(dest) if dest else Path(tempfile.mkdtemp())

  if not _git_clone(url, dest_path, name):
    return fail(f"[!] - clone: Failed to clone {url}")

  if commit:
    info(f"Checkout to commit {commit}")
    repo_name = list(dest_path.iterdir())[0] if name is None else name
    repo_path = dest_path / repo_name

    if _check_out(commit, repo_path):
      return dest_path
    else:
      if main_repo:
        return fail(f"[!] - clone: Failed to checkout {repo_name}")
      else:
        if commit_date is None:
          warn(f"[!] - clone: Failed to checkout {repo_name} but it's not "
               "the main component, using the latest version")
          return dest_path

        warn("[!] Failed to checkout, try a version before required commit")
        cmd = [
            "git", "log", f"--before='{commit_date.isoformat()}'",
            "--format='%H'", "-n1"
        ]
        fallback_commit = execute(cmd, repo_path)
        if isinstance(fallback_commit, bytes):
          fallback_commit = fallback_commit.decode().strip("'")
          info(f"Checkout to {fallback_commit}")
          if _check_out(fallback_commit, repo_path):
            return dest_path

        return fail(f"[!] - clone: Failed to checkout {repo_name}")

  return dest_path


def svn_clone(url: str,
              commit: Optional[str] = None,
              dest: Optional[Union[str, Path]] = None,
              rename: Optional[str] = None) -> Union[Path, bool]:
  """Clone an SVN repository and optionally checkout a specific revision.
    
    Args:
        url: SVN repository URL.
        commit: Specific revision to checkout.
        dest: Destination directory.
        rename: Name for the cloned directory.
        
    Returns:
        Path to cloned repository on success, False on failure.
    """

  def _svn_clone(url: str, dest: Path, name: Optional[str] = None) -> bool:
    """Helper function to perform SVN checkout operation."""
    cmd = ["svn", "co", url]
    if name:
      cmd.append(name)
    if not check_call(cmd, dest):
      return False
    return True

  tmp_path = Path(dest) if dest else Path(tempfile.mkdtemp())

  if not _svn_clone(url, tmp_path, rename):
    return fail(f"[!] - svn_clone: Failed to clone {url}")

  if commit:
    repo_name = rename if rename else list(tmp_path.iterdir())[0]
    repo_path = tmp_path / repo_name
    if not check_call(['svn', "up", '--force', '-r', commit], cwd=repo_path):
      return False

  return tmp_path


def hg_clone(url: str,
             commit: Optional[str] = None,
             dest: Optional[Union[str, Path]] = None,
             rename: Optional[str] = None) -> Union[Path, bool]:
  """Clone a Mercurial repository and optionally checkout a specific commit.
    
    Args:
        url: Mercurial repository URL.
        commit: Specific commit to checkout.
        dest: Destination directory.
        rename: Name for the cloned directory.
        
    Returns:
        Path to cloned repository on success, False on failure.
    """

  def _hg_clone(url: str, dest: Path, name: Optional[str] = None) -> bool:
    """Helper function to perform hg clone operation."""
    cmd = ["hg", "clone", url]
    if name:
      cmd.append(name)
    if not check_call(cmd, dest):
      return False
    return True

  tmp_path = Path(dest) if dest else Path(tempfile.mkdtemp())

  if not _hg_clone(url, tmp_path, rename):
    fail(f"[!] - hg_clone: Failed to clone {url}")
    return False

  if commit:
    repo_name = rename if rename else list(tmp_path.iterdir())[0]
    repo_path = tmp_path / repo_name
    if not (check_call(['hg', "update", '--clean', '-r', commit], cwd=repo_path)
            and check_call(['hg', "purge", '--config', 'extensions.purge='],
                           cwd=repo_path)):
      return False

  return tmp_path


class DockerfileModifier:
  """A class for modifying Dockerfile content with various text operations."""

  def __init__(self, path: Union[str, Path]) -> None:
    """Initialize the DockerfileModifier.
        
        Args:
            path: Path to the Dockerfile to modify.
        """
    self.path = Path(path)
    with open(self.path, encoding='utf-8') as f:
      self.content = f.read()

    # Clean up the content
    comments = re.compile(r'^\s*#.*\n', re.MULTILINE)
    self.content = comments.sub("", self.content)
    self.content = self.content.replace("\\\n", "")
    blank_line = re.compile(r'\n(\s)*\n', re.MULTILINE)
    self.content = blank_line.sub("\n", self.content)

  def flush(self) -> bool:
    """Write the modified content back to the file.
        
        Returns:
            True if write succeeded, False otherwise.
        """
    try:
      with open(self.path, 'w', encoding='utf-8') as f:
        f.write(self.content)
      return True
    except IOError:
      return False

  def str_replace(self, old: str, new: str) -> None:
    """Replace all occurrences of old string with new string.
        
        Args:
            old: String to replace.
            new: Replacement string.
        """
    self.content = self.content.replace(old, new)

  def str_replace_all(self, pairs: Dict[str, str]) -> None:
    """Replace multiple string pairs.
        
        Args:
            pairs: Dictionary of old -> new string mappings.
        """
    for key, value in pairs.items():
      self.str_replace(key, value)

  def replace_line_at(self, pos: int, line: str) -> None:
    """Replace the line at specified position.
        
        Args:
            pos: Line position (0-indexed).
            line: New line content.
        """
    lines = self.content.split("\n")
    if 0 <= pos < len(lines):
      lines[pos] = line
      self.content = "\n".join(lines)

  def replace(self, old: str, new: str, flags: int = 0) -> None:
    """Replace using regular expressions.
        
        Args:
            old: Regular expression pattern.
            new: Replacement string.
            flags: Regular expression flags.
        """
    self.content = re.sub(old, new, self.content, flags=flags)

  def replace_once(self, old: str, new: str) -> None:
    """Replace first occurrence using regular expressions.
        
        Args:
            old: Regular expression pattern.
            new: Replacement string.
        """
    self.content = re.sub(old, new, self.content, count=1)

  def insert_line_before(self, target: str, newline: str) -> Optional[bool]:
    """Insert a new line before the target line.
        
        Args:
            target: Target line to find.
            newline: New line to insert.
            
        Returns:
            None if target not found, otherwise inserts the line.
        """
    line_num = self.locate_str(target)
    if line_num is False:
      return False
    self.insert_line_at(line_num, newline)
    return None

  def insert_line_after(self, target: str, newline: str) -> Optional[bool]:
    """Insert a new line after the target line.
        
        Args:
            target: Target line to find.
            newline: New line to insert.
            
        Returns:
            None if target not found, otherwise inserts the line.
        """
    line_num = self.locate_str(target)
    if line_num is False:
      return False
    self.insert_line_at(line_num + 1, newline)
    return None

  def insert_line_at(self, pos: int, line: str) -> None:
    """Insert a line at specified position.
        
        Args:
            pos: Position to insert at.
            line: Line content to insert.
        """
    lines = self.content.split("\n")
    lines.insert(pos, line)
    self.content = "\n".join(lines)

  def remove_range(self, starts: int, ends: int) -> None:
    """Remove lines in the specified range.
        
        Args:
            starts: Start line number (inclusive).
            ends: End line number (exclusive).
        """
    lines = self.content.split("\n")
    new_lines = []
    for num, line in enumerate(lines):
      if not (starts <= num < ends):
        new_lines.append(line)
    self.content = '\n'.join(new_lines)

  def clean_comments(self) -> None:
    """Remove comment lines from the content."""
    pattern = re.compile(r'^#.*', re.MULTILINE)
    self.content = pattern.sub('', self.content)
    newline_pattern = re.compile(r'^\n', re.MULTILINE)
    self.content = newline_pattern.sub('', self.content)

  def locate_str(self, keyword: str) -> Union[int, bool]:
    """Find the line number containing the keyword.
        
        Args:
            keyword: Keyword to search for.
            
        Returns:
            Line number if found, False otherwise.
        """
    lines = self.content.split("\n")
    for line_num, line in enumerate(lines):
      if keyword in line:
        return line_num
    return False

  def get_line(self, keyword: str) -> Tuple[List[str], int]:
    """Get lines containing the keyword and the last line number.
        
        Args:
            keyword: Keyword to search for.
            
        Returns:
            Tuple of (matching_lines, last_line_number).
        """
    lines = self.content.split("\n")
    matching_lines = []
    last_line_num = 0

    for line_num, line in enumerate(lines, 1):
      if keyword in line:
        matching_lines.append(line)
        last_line_num = line_num

    if len(matching_lines) < 2:
      return matching_lines, last_line_num

    # Use regex for more precise matching
    pattern = re.compile(rf"{keyword}(\s.*$|$)")
    matching_lines = []
    last_line_num = 0

    for line_num, line in enumerate(lines, 1):
      if pattern.search(line):
        matching_lines.append(line)
        last_line_num = line_num

    return matching_lines, last_line_num


class VersionControlTool:
  """A unified interface for version control operations (git, hg, svn)."""

  def __init__(self,
               repo_path: Union[str, Path],
               vc_type: str = 'git',
               revision: Optional[str] = None,
               latest: bool = False) -> None:
    """Initialize the VersionControlTool.
        
        Args:
            repo_path: Path to the repository or URL to clone.
            vc_type: Version control type ('git', 'hg', 'svn').
            revision: Specific revision to checkout.
            latest: Whether to pull latest changes.
            
        Raises:
            ValueError: If vc_type is not supported.
        """
    if vc_type not in ['git', 'hg', 'svn']:
      raise ValueError(f'VersionControlTool: Does not support {vc_type}')

    self.type = vc_type
    repo_path_obj = Path(repo_path) if isinstance(repo_path, str) else repo_path

    if not repo_path_obj.exists():
      repo_path_obj = self.clone(str(repo_path), revision)
      if not repo_path_obj:
        raise RuntimeError(f'VersionControlTool: Failed to init {repo_path}')

    self.repo = repo_path_obj
    self.name = self.repo.name

    if latest and not self.pull():
      raise RuntimeError(f'VersionControlTool: Failed to Update {repo_path}')

  def pull(self) -> bool:
    """Pull latest changes from the repository.
        
        Returns:
            True if pull succeeded, False otherwise.
        """
    if self.type == 'git':
      return git_pull(self.repo)
    elif self.type == 'hg':
      return hg_pull(self.repo)
    else:
      return svn_pull(self.repo)

  def clone(self,
            url: str,
            revision: Optional[str] = None) -> Union[Path, bool]:
    """Clone the repository.
        
        Args:
            url: Repository URL to clone.
            revision: Specific revision to checkout.
            
        Returns:
            Path to cloned repository on success, False on failure.
        """
    if self.type == 'git':
      repo = clone(url, revision)
      if repo is not False:
        self.repo = list(repo.iterdir())[0]
        return self.repo
    elif self.type == 'hg':
      repo = hg_clone(url, revision)
      if repo is not False:
        self.repo = list(repo.iterdir())[0]
        return self.repo
    else:
      repo = svn_clone(url, revision)
      if repo is not False:
        self.repo = list(repo.iterdir())[0]
        return self.repo

    return False

  def commit_date(self, commit: str) -> Union[str, bool]:
    """Get the date of a specific commit.
        
        Args:
            commit: Commit hash or revision.
            
        Returns:
            Formatted date string on success, False on failure.
        """

    def time_reformat(original_str: str) -> str:
      """Reformat time string to standard format."""
      original_dt = datetime.strptime(original_str, "%Y-%m-%d %H:%M:%S %z")
      utc_dt = original_dt.astimezone(pytz.utc)
      return utc_dt.strftime("%Y%m%d%H%M")

    if self.type == 'git':
      result = execute(['git', 'show', '-s', '--format=%ci', commit], self.repo)
      if result is not False and isinstance(result, bytes):
        return time_reformat(result.decode())
    elif self.type == 'hg':
      result = execute(['hg', 'log', '-r', commit, '--template', '{date}'],
                       self.repo)
      if result is not False and isinstance(result, bytes):
        timestamp = int(result.decode().split(".")[0])
        return datetime.utcfromtimestamp(timestamp).strftime('%Y%m%d%H%M')
    else:
      result = execute(['svn', 'log', '-r', commit, '-q'], self.repo)
      if result is not False and isinstance(result, bytes):
        lines = result.decode().split('\n')
        if len(lines) > 1:
          date_part = lines[1].split(' | ')[2].split(' (')[0]
          return time_reformat(date_part)

    return False

  def reset(self, commit: str) -> bool:
    """Reset the repository to a specific commit.
        
        Args:
            commit: Commit hash or revision to reset to.
            
        Returns:
            True if reset succeeded, False otherwise.
        """
    if self.type == 'git':
      cmd = ['git', 'reset', '--hard', commit]
      with open('/dev/null', 'w', encoding='utf-8') as f:
        return check_call(cmd, self.repo, stdout=f)
    elif self.type == 'hg':
      cmd1 = ['hg', 'update', '--clean', '-r', commit]
      cmd2 = ['hg', "purge", '--config', 'extensions.purge=']
      return (check_call(cmd1, self.repo) and check_call(cmd2, self.repo))
    elif self.type == "svn":
      return check_call(['svn', "up", '--force', '-r', commit], cwd=self.repo)

    return False


def docker_build(args: List[str], log_file: Optional[Path] = None) -> bool:
  """Build a Docker image.
    
    Args:
        args: Arguments for docker build command.
        log_file: Optional log file to write output.
        
    Returns:
        True if build succeeded, False otherwise.
    """
  cmd = ['docker', 'build']
  cmd.extend(args)
  info("Docker Build: \n" + " ".join(cmd))

  if log_file:
    with open(log_file, 'w', encoding='utf-8') as f:
      result = check_call(cmd, stderr=f, stdout=f)
      f.write("\n" + " ".join(cmd) + "\n")
      return result
  else:
    return check_call(cmd)


def docker_run(args: List[str],
               rm: bool = True,
               log_file: Optional[Path] = None) -> bool:
  """Run a Docker container.
    
    Args:
        args: Arguments for docker run command.
        rm: Whether to automatically remove the container when it exits.
        log_file: Optional log file to write output.
        
    Returns:
        True if run succeeded, False otherwise.
    """
  if rm:
    cmd = ['docker', 'run', '--rm', '--privileged']
  else:
    cmd = ['docker', 'run', '--privileged']

  cmd.extend(args)
  info("Docker Run: \n" + " ".join(cmd))

  if log_file:
    with open(log_file, 'w', encoding='utf-8') as f:
      result = check_call(cmd, stdout=f, stderr=f)
      f.write("\n" + " ".join(cmd) + "\n")
      return result
  else:
    return check_call(cmd)


def clean_dir(directory: Path) -> bool:
  """Remove a directory and all its contents.
    
    Args:
        directory: Directory to remove.
        
    Returns:
        True if removal succeeded, False otherwise.
    """
  if not directory.exists():
    return True

  try:
    shutil.rmtree(directory)
    return True
  except OSError:
    warn(f"[FAILED] to remove tmp file {directory}")
    return False


def leave_ret(return_val: Any, tmp_dirs: Union[Path, List[Path]]) -> Any:
  """Clean up temporary directories and return a value.
    
    Args:
        return_val: Value to return.
        tmp_dirs: Temporary directory or list of directories to clean up.
        
    Returns:
        The return_val parameter.
    """
  if isinstance(tmp_dirs, list):
    for tmp_dir in tmp_dirs:
      clean_dir(tmp_dir)
  else:
    clean_dir(tmp_dirs)
  return return_val


if __name__ == "__main__":
  pass
