from arvo_utils import *

update_table = {
    '/src/freetype2':
        'git://git.sv.nongnu.org/freetype/freetype2.git',
    '/src/pcre2':
        "https://github.com/PCRE2Project/pcre2",
    '/src/skia/third_party/externals/libjpeg-turbo':
        'https://github.com/libjpeg-turbo/libjpeg-turbo.git',
    '/src/radare2-regressions':
        'https://github.com/rlaemmert/radare2-regressions.git',
    '/src/x264':
        'https://code.videolan.org/videolan/x264.git',
    '/src/x265':
        'https://bitbucket.org/multicoreware/x265_git.git',
    '/src/vorbis':
        'https://github.com/xiph/vorbis.git',
    '/src/theora':
        'https://github.com/xiph/theora.git',
    '/src/opus':
        'https://github.com/xiph/opus.git',
    '/src/ogg':
        'https://github.com/xiph/ogg.git',
    '/src/libxml2':
        'https://gitlab.gnome.org/GNOME/libxml2.git',
    '/src/libmicrohttpd':
        'https://github.com/Karlson2k/libmicrohttpd.git',
    '/src/wireshark':
        'https://github.com/wireshark/wireshark.git',
    '/src/kimageformats':
        'https://github.com/KDE/kimageformats.git',
    '/src/extra-cmake-modules':
        'https://github.com/KDE/extra-cmake-modules.git',
    '/src/kcodecs':
        'https://github.com/KDE/kcodecs.git',
    '/src/karchive':
        'https://github.com/KDE/karchive.git',
    '/src/libtheora':
        'https://github.com/xiph/theora.git',
    '/src/libva':
        "https://github.com/intel/libva.git",
    '/src/libssh2':
        "https://github.com/libssh2/libssh2.git",
    '/src/quickjs':
        "https://github.com/bellard/quickjs",
    '/src/lwan':
        "https://github.com/lpereira/lwan.git",
    '/src/graphicsmagick':
        "https://foss.heptapod.net/graphicsmagick/graphicsmagick",
    '/src/llvm':
        'https://github.com/llvm/llvm-project.git',
    '/src/pcre':
        'https://github.com/PhilipHazel/pcre2',
    '/src/gnulib':
        'https://github.com/coreutils/gnulib.git',
    '/src/net-snmp':
        'https://github.com/net-snmp/net-snmp.git',
    '/src/harfbuzz':
        'https://github.com/harfbuzz/harfbuzz.git',
    '/src/matio':
        'https://github.com/tbeu/matio.git',
    '/src/aspell':
        'https://github.com/gnuaspell/aspell.git',
    '/src/libsndfile':
        "https://github.com/libsndfile/libsndfile.git",
    '/src/poppler':
        'https://gitlab.freedesktop.org/poppler/poppler.git',
    '/src/gdal/poppler':
        'https://gitlab.freedesktop.org/poppler/poppler.git',
    '/src/gdal/curl':
        'https://github.com/curl/curl.git',
    '/src/ghostpdl':
        'https://cgit.ghostscript.com/ghostpdl.git',
}
# Only include non git project
changed_type = {'/src/graphicsmagick': 'hg'}
changed_key = {
    '/src/mdbtools/test': '/src/mdbtools',
}
# Order matters
global_str_replace = {
    'git://git.gnome.org/libxml2':
        "https://gitlab.gnome.org/GNOME/libxml2.git",
    'svn co svn://vcs.exim.org/pcre2/code/trunk pcre2':
        'git clone https://github.com/PCRE2Project/pcre2 pcre2',
    "https://git.savannah.nongnu.org/r/freetype/freetype2.git":
        "git://git.sv.nongnu.org/freetype/freetype2.git",
    'https://git.savannah.nongnu.org/r/freetype/freetype2':
        'git://git.sv.nongnu.org/freetype/freetype2.git',
    'ftp://ftp.unidata.ucar.edu/pub/netcdf/netcdf-4.4.1.1.tar.gz':
        'http://ppmcore.mpi-cbg.de/upload/netcdf-4.4.1.1.tar.gz',
    'https://github.com/01org/libva':
        'https://github.com/intel/libva.git',
    'http://www.zlib.net/zlib-1.2.11.tar.gz':
        'https://www.zlib.net/fossils/zlib-1.2.11.tar.gz',
    'https://dl.bintray.com/boostorg/release/1.74.0/source/boost_1_74_0.tar.bz2':
        'https://boostorg.jfrog.io/artifactory/main/release/1.74.0/source/boost_1_74_0.tar.bz2',
    'https://jannau.net/dav1d_fuzzer_seed_corpus.zip':
        'https://download.videolan.org/pub/videolan/testing/contrib/dav1d/dav1d_fuzzer_seed_corpus.zip',
    'git://git.xiph.org/ogg.git':
        'https://github.com/xiph/ogg.git',
    'git://git.xiph.org/opus.git':
        'https://github.com/xiph/opus.git',
    'git://git.xiph.org/theora.git':
        'https://github.com/xiph/theora.git',
    'git://git.videolan.org/git/x264.git':
        'https://code.videolan.org/videolan/x264.git',
    'git://git.xiph.org/vorbis.git':
        'https://github.com/xiph/vorbis.git',
    'svn co http://svn.xiph.org/trunk/ogg':
        "git clone https://github.com/xiph/ogg.git",
    'http://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz':
        'https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz',
    'https://downloads.apache.org/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip':
        'https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.6.3/apache-maven-3.6.3-bin.zip',
    'https://dlcdn.apache.org/maven/maven-3/3.8.6/binaries/apache-maven-3.8.6-bin.zip':
        'https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.8.6/apache-maven-3.8.6-bin.zip',
    "https://dlcdn.apache.org/maven/maven-3/3.8.5/binaries/apache-maven-3.8.5-bin.zip":
        'https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.8.5/apache-maven-3.8.5-bin.zip',
    "https://opus-codec.org/static/testvectors/opus_testvectors.tar.gz":
        "http://opus-codec.org/static/testvectors/opus_testvectors.tar.gz",
    "https://anongit.freedesktop.org/git/harfbuzz.git":
        "https://github.com/harfbuzz/harfbuzz.git",
    "git://anongit.kde.org/extra-cmake-modules":
        "https://github.com/KDE/extra-cmake-modules.git",
    'git://anongit.kde.org/kimageformats':
        'https://github.com/KDE/kimageformats.git',
    "git://anongit.kde.org/karchive":
        "https://github.com/KDE/karchive.git",
    "git://git.savannah.gnu.org/gnulib.git":
        "https://github.com/coreutils/gnulib.git",
    'svn co http://llvm.org/svn/llvm-project/llvm/trunk':
        "git clone https://github.com/llvm/llvm-project.git",
    'svn co svn://vcs.exim.org/pcre/code/trunk':
        'git clone https://github.com/PhilipHazel/pcre2',
    'https://github.com/cmeister2/libssh2.git':
        'https://github.com/libssh2/libssh2.git',
    'git://git.code.sf.net/p/matio/matio':
        'https://github.com/tbeu/matio.git',
    'https://github.com/cmeister2/aspell.git':
        'https://github.com/gnuaspell/aspell.git',
    'https://github.com/erikd/libsndfile.git':
        "https://github.com/libsndfile/libsndfile.git",
    "https://anongit.freedesktop.org/git/poppler/poppler.git":
        'https://gitlab.freedesktop.org/poppler/poppler.git',
    'git.ghostscript.com/ghostpdl.git':
        'cgit.ghostscript.com/ghostpdl.git',
    " --depth=1":
        "",
    " --depth 1":
        "",
    " --depth ":
        " --jobs ",
}

pname_table = {
    'libpng-proto': "libprotobuf-mutator",
    'pcapplusplus': "PcapPlusPlus",
    'skia-ftz': 'skia',
}


def update_resource_info(item_name, item_url, item_type):
  if item_name in changed_key:
    item_name = changed_key[item_name]
  if item_name in update_table:
    if item_name in changed_type:
      type = changed_type[item_name]
    else:
      type = 'git'
    return item_name, update_table[item_name], type
  else:
    return item_name, item_url, item_type


# Reproducing related functions
def dockerfile_cleaner(dockerfile_path):
  dft = DockerfileModifier(dockerfile_path)
  dft.replace(r'(--single-branch\s+)', "")  # --single-branch
  dft.replace(r'(--branch\s+\S+\s+|-b\s\S+\s+|--branch=\S+\s+)',
              "")  # remove --branch or -b
  dft.flush()


# This function fixes the dockerfile
def fix_dockerfile(dockerfile_path, project=None):

  def _x265Fix(dft):
    # The order of following two lines matters
    dft.replace(
        r'RUN\shg\sclone\s.*bitbucket.org/multicoreware/x265\s*(x265)*',
        "RUN git clone https://bitbucket.org/multicoreware/x265_git.git x265\n")
    dft.replace(
        r'RUN\shg\sclone\s.*hg.videolan.org/x265\s*(x265)*',
        "RUN git clone https://bitbucket.org/multicoreware/x265_git.git x265\n")

  dockerfile_cleaner(dockerfile_path)
  dft = DockerfileModifier(dockerfile_path)
  # Some dockerfile forgets to apt update before apt install
  # and we have to install/set ca-certificate/git sslVerify to avoid certificates issues
  # TODO: improve regex
  dft.replace_once(
      r'RUN apt',
      "RUN apt update -y && apt install git ca-certificates -y && git config --global http.sslVerify false && git config --global --add safe.directory '*'\nRUN apt"
  )
  dft.str_replace_all(global_str_replace)

  # The following are project hacks that solve building/compiling problems
  if project == "lcms":
    # TODO: improve this tmp patch
    dft.replace(r'#add more seeds from the testbed dir.*\n', "")
  elif project == 'wolfssl':
    dft.str_replace(
        'RUN gsutil cp gs://wolfssl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/wolfssl_cryptofuzz-disable-fastmath/public.zip $SRC/corpus_wolfssl_disable-fastmath.zip',
        "RUN touch 0xdeadbeef && zip $SRC/corpus_wolfssl_disable-fastmath.zip 0xdeadbeef"
    )
  elif project == 'skia':
    dft.str_replace('RUN wget', "# RUN wget")
    dft.insert_line_after('COPY build.sh $SRC/',
                          "RUN sed -i 's/cp.*zip.*//g' $SRC/build.sh")
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
  elif project == 'graphicsmagick':
    dft.replace(
        r'RUN hg clone .* graphicsmagick',
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
    dft.insert_line_before(
        "RUN cd $SRC/libressl && ./update.sh",
        "RUN sed -n -i '/^# setup source paths$/,$p' $SRC/libressl/update.sh")
  elif project == 'libyang':
    dft.str_replace(
        'RUN git clone https://github.com/PCRE2Project/pcre2 pcre2 &&',
        "RUN git clone https://github.com/PCRE2Project/pcre2 pcre2\nRUN ")
  elif project == "yara":
    if 'bison' not in dft.content:
      dft.insert_line_before(
          "RUN git clone https://github.com/VirusTotal/yara.git",
          "RUN apt install -y bison")
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


# This function fixes the build script
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


def extra_scritps(pname, source_dir):
  # TODO: migrate these hacks to fix_dockerfile
  """
    This function allows us to modify build.sh scripts and other stuff to modify the compiling setting
    """
  if pname == 'imagemagick':
    # TODO: Improve this hack
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


def special_component(pname, itemKey, item, dockerfile):
  # TODO: Theoritically, we can remove this func since other parts gonna handle the submodule, but not tested
  # These components are submodules, but their info are in srcmap
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


def skip_component(pname, itemName):
  # TODO: solve the submodule proble in a decent way
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


if __name__ == "__main__":
  pass
