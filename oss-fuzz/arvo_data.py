"""ARVO data management module.

This module provides data management functions for ARVO reproducer,
including configuration mappings and Docker/build script fixes.
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from arvo_utils import DockerfileModifier


def load_repo_map(file_name: str) -> Dict[str, Any]:
  """Load repository mapping from JSON file.
    
    Args:
        file_name: Name of the JSON file to load.
        
    Returns:
        Dictionary containing the loaded JSON data.
    """
  json_path = os.path.join(os.path.dirname(__file__), file_name)
  with open(json_path, encoding='utf-8') as f:
    return json.load(f)


# Configuration constants - Order matters
GLOBAL_STR_REPLACE = load_repo_map("string_replacement.json")
UPDATE_TABLE = load_repo_map("component_fixes.json")

# Only include non git project
CHANGED_TYPE = {'/src/graphicsmagick': 'hg'}

CHANGED_KEY = {
    '/src/mdbtools/test': '/src/mdbtools',
}

PNAME_TABLE = {
    'libpng-proto': "libprotobuf-mutator",
    'pcapplusplus': "PcapPlusPlus",
    'skia-ftz': 'skia',
}

def update_resource_info(item_name: str, item_url: str,
                         item_type: str) -> Tuple[str, str, str]:
  """Update resource information based on configuration tables.
    
    Args:
        item_name: Name of the resource item.
        item_url: URL of the resource.
        item_type: Type of the resource.
        
    Returns:
        Tuple of (updated_name, updated_url, updated_type).
    """
  if item_name in CHANGED_KEY:
    item_name = CHANGED_KEY[item_name]

  if item_name in UPDATE_TABLE:
    resource_type = CHANGED_TYPE.get(item_name, 'git')
    return item_name, UPDATE_TABLE[item_name], resource_type
  else:
    return item_name, item_url, item_type


def dockerfile_cleaner(dockerfile_path: Union[str, Path]) -> None:
  """Clean dockerfile by removing git branch-specific arguments.
    
    Args:
        dockerfile_path: Path to the Dockerfile to clean.
    """
  dft = DockerfileModifier(dockerfile_path)
  dft.replace(r'(--single-branch\s+)', "")  # --single-branch
  dft.replace(r'(--branch\s+\S+\s+|-b\s\S+\s+|--branch=\S+\s+)',
              "")  # remove --branch or -b
  dft.flush()


def fix_dockerfile(dockerfile_path: Union[str, Path],
                   project: Optional[str] = None) -> bool:
  """Fix the dockerfile for specific projects and general issues.
    
    Args:
        dockerfile_path: Path to the Dockerfile to fix.
        project: Name of the project for project-specific fixes.
        
    Returns:
        True if fixes were applied successfully, False otherwise.
    """

  def _x265_fix(dft: DockerfileModifier) -> None:
    """Apply x265-specific fixes to the dockerfile modifier."""
    # The order of following two lines matters
    dft.replace(
        r'RUN\shg\sclone\s.*bitbucket.org/multicoreware/x265\s*(x265)*',
        "RUN git clone "
        "https://bitbucket.org/multicoreware/x265_git.git x265\n")
    dft.replace(
        r'RUN\shg\sclone\s.*hg.videolan.org/x265\s*(x265)*',
        "RUN git clone "
        "https://bitbucket.org/multicoreware/x265_git.git x265\n")

  dockerfile_cleaner(dockerfile_path)
  dft = DockerfileModifier(dockerfile_path)

  # Some dockerfile forgets to apt update before apt install
  # and we have to install/set ca-certificate/git sslVerify to avoid
  # certificates issues
  # TODO: improve regex
  dft.replace_once(
      r'RUN apt',
      "RUN apt update -y && apt install git ca-certificates -y && "
      "git config --global http.sslVerify false && "
      "git config --global --add safe.directory '*'\nRUN apt")
  dft.str_replace_all(GLOBAL_STR_REPLACE)

  # Apply project-specific hacks that solve building/compiling problems
  if project == "lcms":
    # TODO: improve this tmp patch
    dft.replace(r'#add more seeds from the testbed dir.*\n', "")
  elif project == 'wolfssl':
    dft.str_replace(
        'RUN gsutil cp '
        'gs://wolfssl-backup.clusterfuzz-external.appspot.com/'
        'corpus/libFuzzer/wolfssl_cryptofuzz-disable-fastmath/public.zip '
        '$SRC/corpus_wolfssl_disable-fastmath.zip',
        "RUN touch 0xdeadbeef && "
        "zip $SRC/corpus_wolfssl_disable-fastmath.zip 0xdeadbeef")
  elif project == 'skia':
    dft.str_replace('RUN wget', "# RUN wget")
    dft.insert_line_after('COPY build.sh $SRC/',
                          "RUN sed -i 's/cp.*zip.*//g' $SRC/build.sh")
  elif project == 'libreoffice':
    dft.str_replace(
        'RUN ./bin/oss-fuzz-setup.sh',
        "RUN sed -i 's|svn export --force -q https://github.com|"
        "#svn export --force -q https://github.com|g' "
        "./bin/oss-fuzz-setup.sh")
    dft.str_replace('RUN svn export', '# RUN svn export')
    dft.str_replace('ADD ', '# ADD ')
    dft.str_replace('RUN zip', '# RUN zip')
    dft.str_replace('RUN mkdir afl-testcases', "# RUN mkdir afl-testcases")
    dft.str_replace(
        'RUN ./bin/oss-fuzz-setup.sh',
        "# RUN ./bin/oss-fuzz-setup.sh")  # Avoid downloading not related
  elif project == 'graphicsmagick':
    dft.replace(
        r'RUN hg clone .* graphicsmagick',
        'RUN (CMD="hg clone --insecure '
        'https://foss.heptapod.net/graphicsmagick/graphicsmagick '
        'graphicsmagick" && '
        'for x in `seq 1 100`; do $($CMD); '
        'if [ $? -eq 0 ]; then break; fi; done)')
    _x265_fix(dft)
  elif project == 'libheif':
    _x265_fix(dft)
  elif project == 'ffmpeg':
    _x265_fix(dft)
  elif project == 'imagemagick':
    dft.replace(
        r'RUN svn .*heic_corpus.*',
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
    dft.insert_line_before(
        "RUN cd $SRC/libressl && ./update.sh",
        "RUN sed -n -i '/^# setup source paths$/,$p' $SRC/libressl/update.sh")
  elif project == 'libyang':
    dft.str_replace(
        'RUN git clone https://github.com/PCRE2Project/pcre2 pcre2 &&',
        "RUN git clone https://github.com/PCRE2Project/pcre2 pcre2\n"
        "RUN ")
  elif project == "yara":
    if 'bison' not in dft.content:
      dft.insert_line_before(
          "RUN git clone https://github.com/VirusTotal/yara.git",
          "RUN apt install -y bison")
  elif project == "lwan":
    dft.str_replace('git://github.com/lpereira/lwan',
                    'https://github.com/lpereira/lwan.git')
  elif project == "radare2":
    dft.str_replace(
        "https://github.com/radare/radare2-regressions",
        'https://github.com/rlaemmert/radare2-regressions.git')
  elif project == "wireshark":
    dft.replace(r"RUN git clone .*wireshark.*", "")

  dft.clean_comments()
  return dft.flush()


def fix_build_script(file_path: Path, project_name: str) -> bool:
  """Fix the build script for specific projects.
    
    Args:
        file_path: Path to the build script file.
        project_name: Name of the project.
        
    Returns:
        True if fixes were applied successfully, False otherwise.
    """
  if not file_path.exists():
    return True

  dft = DockerfileModifier(file_path)

  if project_name == "uwebsockets":
    # https://github.com/alexhultman/zlib -> https://github.com/madler/zlib.git
    script = "sed -i 's/alexhultman/madler/g' fuzzing/Makefile"
    dft.insert_line_at(0, script)
  elif project_name == 'libreoffice':
    # If you don't want to destroy your life.
    # Please leave this project alone. too hard to fix and the compiling
    # takes several hours
    line = '$SRC/libreoffice/bin/oss-fuzz-build.sh'
    dft.insert_line_before(
        line,
        "sed -i 's/make fuzzers/make fuzzers -i/g' "
        "$SRC/libreoffice/bin/oss-fuzz-build.sh")
    dft.insert_line_before(
        line,
        "sed -n -i '/#starting corpuses/q;p' "
        "$SRC/libreoffice/bin/oss-fuzz-build.sh")
    dft.insert_line_before(
        line,
        r"sed -n -i '/pushd instdir\/program/q;p' "
        r"$SRC/libreoffice/bin/oss-fuzz-build.sh")
    dft.insert_line_before(
        line,
        'echo "pushd instdir/program && mv *fuzzer $OUT" >> '
        '$SRC/libreoffice/bin/oss-fuzz-build.sh')
  elif project_name == 'jbig2dec':
    dft.replace('unzip.*', 'exit 0')
  elif project_name == "ghostscript":
    old = r"mv \$SRC\/freetype freetype"
    new = "cp -r $SRC/freetype freetype"
    dft.replace(old, new)
  elif project_name == 'openh264':
    lines = dft.content.split("\n")
    starts = -1
    ends = -1
    for num, line in enumerate(lines):
      if "# prepare corpus" in line:
        starts = num
      elif "# build" in line:
        ends = num
        break
    if starts != -1 and ends != -1:
      dft.remove_range(starts, ends)
  elif project_name in ['libredwg', 'duckdb']:
    dft.replace(r'^make$', 'make -j`nproc`\n')

  return dft.flush()


def extra_scripts(project_name: str, source_dir: Path) -> bool:
  """Execute extra scripts for specific projects.
    
    TODO: migrate these hacks to fix_dockerfile
    This function allows us to modify build.sh scripts and other stuff
    to modify the compiling setting.
    
    Args:
        project_name: Name of the project.
        source_dir: Path to the source directory.
        
    Returns:
        True if scripts executed successfully, False otherwise.
    """
  if project_name == 'imagemagick':
    # TODO: Improve this hack
    target = (source_dir / "src" / project_name / "Magick++" /
              "fuzz" / "build.sh")
    if target.exists():
      with open(target, encoding='utf-8') as f:
        lines = f.readlines()
      for x in range(3):
        if lines and "zip" in lines[-x - 1]:
          del lines[-x - 1]
      with open(target, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
  return True


def special_component(project_name: str, item_key: str, item: Dict[str, Any],
                      dockerfile: Union[str, Path]) -> bool:
  """Check if a component requires special handling.
    
    TODO: Theoretically, we can remove this func since other parts gonna
    handle the submodule, but not tested.
    These components are submodules, but their info are in srcmap.
    
    Args:
        project_name: Name of the project.
        item_key: Key of the item in srcmap.
        item: Item data from srcmap.
        dockerfile: Path to the dockerfile.
        
    Returns:
        True if component should be skipped, False otherwise.
    """
  # These components are submodules, but their info are in srcmap
  if project_name == 'libressl' and item_key == '/src/libressl/openbsd':
    return False

  if project_name == 'gnutls' and item_key == '/src/gnutls/nettle':
    # Just Ignore since we have submodule update --init
    with open(dockerfile, encoding='utf-8') as f:
      dt = f.read()
    if item['rev'] not in dt:
      return True
    else:
      return False

  return False


def skip_component(project_name: str, item_name: str) -> bool:
  """Check if a component should be skipped during processing.
    
    TODO: solve the submodule problem in a decent way
    
    Args:
        project_name: Name of the project.
        item_name: Name of the item/component.
        
    Returns:
        True if component should be skipped, False otherwise.
    """
  no_operation = [
      "/src",
      "/src/LPM/external.protobuf/src/external.protobuf",
      "/src/libprotobuf-mutator/build/external.protobuf/src/external.protobuf",
  ]
  item_name = item_name.strip(" ")

  # Special for skia, Skip since they are done by submodule init
  if project_name in ['skia', 'skia-ftz']:
    if item_name.startswith("/src/skia/"):
      return True

  if item_name in no_operation:
    return True

  return False


if __name__ == "__main__":
  pass
