from .utils import *
from dateutil.parser import parse
from bisect import bisect_right
import time
from . import _profile
from .transform import globalStrReplace
#########################################
# Core Area for reproducing
#########################################
NoOperation = [
    "/src",
    "/src/LPM/external.protobuf/src/external.protobuf",
    "/src/libprotobuf-mutator/build/external.protobuf/src/external.protobuf",
]
def fixDockerfile(dockerfile_path,project,commit_date):
    if _profile.EVAL_NOURLFIX:
        return True
    # todo: if you want to make it faster, implement it. And it's a liitle complex
    # DO not want to modify dockerfile
    # It comsumes TIME! 
    def _x265Fix(dft):
        # The order of following two lines matters 
        dft.replace(r'RUN\shg\sclone\s.*bitbucket.org/multicoreware/x265\s*(x265)*',"RUN git clone https://bitbucket.org/multicoreware/x265_git.git x265\n")
        dft.replace(r'RUN\shg\sclone\s.*hg.videolan.org/x265\s*(x265)*',"RUN git clone https://bitbucket.org/multicoreware/x265_git.git x265\n")
        
    dft = DfTool(dockerfile_path)
    dft.replaceOnce(r'RUN apt',"RUN apt update -y && apt install git ca-certificates -y && git config --global http.sslVerify false && git config --global --add safe.directory '*'\nRUN apt")
    dft.strReplaceAll(globalStrReplace)
    # Global fix: old base images have pip 8-19.x which can't parse newer
    # pyproject.toml (ninja, meson).  Upgrade pip inline before installing meson.
    # Pin pip<21 for Python 3.5/3.6 compat (pip 20.3.4 is last for py3.5).
    # Also pin ninja<1.11 because ninja 1.11+ uses Python 3.6+ type annotations
    # in its wrapper script, breaking on Python 3.5 base images.
    dft.replace(r'pip3 install ([^&\n]*?)meson([^\n]*)', r'pip3 install --upgrade "pip<21" && pip3 install \1meson\2')
    # Pin ninja in pip install lines only (not apt-get install ninja-build etc.)
    dft.replace(r'(pip3 install\s[^\n]*) ninja', r'\1 "ninja<1.11"')
    dft.strReplace('pip3 install ninja', 'pip3 install "ninja<1.11"')
    def repl(match):
        ver_us = match.group(1)
        ver_dot = ver_us.replace('_', '.')
        return f'RUN wget https://archives.boost.io/release/{ver_dot}/source/boost_{ver_us}.tar.bz2'
    pattern = r'RUN wget .*?/boost_(\d+_\d+_\d+)\.tar\.bz2'
    replacement = r'RUN wget https://archives.boost.io/release/\1/source/boost_\1.tar.bz2'
    dft.replace(pattern,repl)
    if project == "lcms":
        dft.replace(r'#add more seeds from the testbed dir.*\n',"")
    elif project =='wolfssl':
        pattern = r'RUN gsutil cp .*? (\$SRC/[^ ]+\.zip)'
        replacement = r'RUN touch dummy && zip -j \1 dummy'
        dft.replace(pattern,replacement)
        # The WORKDIR wolfssl can break after ADD replaces the directory;
        # reset to /src so build.sh cd commands work properly
        dft.strReplace("WORKDIR wolfssl","WORKDIR /src")
        # Older fuzzing-headers revisions lack install.sh; create one that
        # copies the headers (what the real install.sh does).
        dft.appendLine('''RUN [ -f /src/fuzzing-headers/install.sh ] || printf '#!/bin/sh\\nrm -rf /usr/include/fuzzing\\ncp -R include/fuzzing/ /usr/include/\\n' > /src/fuzzing-headers/install.sh && chmod +x /src/fuzzing-headers/install.sh''')
        # Newer base images don't have 'python' (Python 2); replace with python3.
        dft.strReplace(' python ', ' python3 python-is-python3 ')
    elif project == 'skia':
        dft.strReplace('RUN wget',"# RUN wget")
        line = 'COPY build.sh $SRC/'
        dft.insertLineAfter(line,"RUN sed -i 's/cp.*zip.*//g' $SRC/build.sh")
    elif project == 'gdal':
        dft.appendLine(f'ARG ARVO_TS="{commit_date.isoformat()}"')
        """
        1. remove all --depth
        2. checkout the cloned repo in build.sh
        """
        build_clone_fix = r'''RUN awk -v ts="$ARVO_TS" '\
    /git clone/ { \
        gsub(/--depth[= ][0-9]+/, "", $0); \
        if (NF == 3) dir = $3; \
        else { \
            repo = $NF; \
            gsub(/.*\//, "", repo); \
            gsub(/\.git$/, "", repo); \
            dir = repo; \
        } \
        print $0 " && (pushd " dir " && commit=$(git log --before=\"" ts "\" --format=\"%H\" -n1) && git reset --hard $commit || exit 99 && popd) && (pushd " dir " && git submodule init && git submodule update --force && popd)"; \
        next \
    } \
    { print }' $SRC/build.sh > $SRC/build.sh.tmp && mv $SRC/build.sh.tmp $SRC/build.sh
    '''
        dft.appendLine(build_clone_fix)
        line = '''RUN [ -f /src/gdal/gdal/GNUmakefile ] && sed -i 's|(cd frmts; $(MAKE))|(cd frmts; $(MAKE) clean; $(MAKE))|' /src/gdal/gdal/GNUmakefile || true'''
        dft.appendLine(line)
        dft.appendLine('''RUN sed -i 's|BUILD_SH_FROM_REPO="$SRC/gdal/fuzzers/build.sh"|BUILD_SH_FROM_REPO=$0|g' $SRC/build.sh''')
        # Fix flaky freetype tarball download: add retry and fallback mirror
        dft.appendLine(r'''RUN sed -i 's|curl -L https://download.savannah.gnu.org/releases/freetype/freetype-\([0-9.]*\)\.tar\.xz|curl --retry 5 --retry-delay 3 -L https://download.savannah.gnu.org/releases/freetype/freetype-\1.tar.xz|g' $SRC/build.sh''')
        
    elif project == 'curl':
        # Check if download_zlib.sh exists and replace zlib URL
        dft.appendLine('RUN [ -f "/src/curl_fuzzer/scripts/download_zlib.sh" ] && sed -i \'s|https://www.zlib.net/zlib-1.2.11.tar.gz|https://www.zlib.net/fossils/zlib-1.2.11.tar.gz|g\' /src/curl_fuzzer/scripts/download_zlib.sh || true')
    elif project == 'freeradius':
        dft.strReplace('sha256sum -c','pwd')
        dft.strReplace("curl -s -O ",'curl -s -O -L ')
    elif project == 'libreoffice':
        dft.strReplace('RUN ./bin/oss-fuzz-setup.sh',\
        "RUN sed -i 's|svn export --force -q https://github.com|#svn export --force -q https://github.com|g' ./bin/oss-fuzz-setup.sh")
        dft.strReplace('RUN svn export','# RUN svn export')
        dft.strReplace('ADD ','# ADD ')
        dft.strReplace('RUN zip','# RUN zip')
        dft.strReplace('RUN mkdir afl-testcases',"# RUN mkdir afl-testcases")
        dft.strReplace('RUN ./bin/oss-fuzz-setup.sh',"# RUN ./bin/oss-fuzz-setup.sh") # Avoid downloading not related stuff
    elif project == 'graphicsmagick': # Done
        line = r'RUN hg clone .* graphicsmagick'
        dft.replace(line,'RUN (CMD="hg clone --insecure https://foss.heptapod.net/graphicsmagick/graphicsmagick graphicsmagick" && for x in `seq 1 100`; do $($CMD); if [ $? -eq 0 ]; then break; fi; done)')
        _x265Fix(dft)        
    elif project == 'libheif':
        _x265Fix(dft)
    elif project == 'ffmpeg':
        _x265Fix(dft)
        # Single replacement
        dft.appendLine('''RUN sed -i '/^[[:space:]]*make[[:space:]]\\{1,\\}fate-rsync[[:space:]]\\{1,\\}SAMPLES=\\$TEST_SAMPLES_PATH[[:space:]]*$/c\\echo ARVO' /src/build.sh && \
            (grep -n "echo ARVO" /src/build.sh || echo "[info] no fate-rsync line; nothing replaced")''')

        # Both replacements - be specific to avoid replacing configure --samples=fate-suite/ line
        dft.appendLine('''RUN sed -i \
        -e '/^[[:space:]]*make[[:space:]]\\{1,\\}fate-rsync[[:space:]]\\{1,\\}SAMPLES=\\$TEST_SAMPLES_PATH[[:space:]]*$/c\\echo ARVO' \
        -e '/^[[:space:]]*export.*fate-suite/c\\echo ARVO' \
        -e '/^[[:space:]]*rm.*fate-suite/c\\echo ARVO' \
        -e '/^[[:space:]]*zip.*fate-suite/c\\echo ARVO' \
        /src/build.sh && \
        (grep -nE 'echo ARVO|fate-rsync' /src/build.sh || echo "[info] no matching lines; nothing replaced")''')

        # Neutralize direct rsync calls to samples.ffmpeg.org (IP gets blocked)
        dft.appendLine('''RUN sed -i '/rsync.*samples\\.ffmpeg\\.org/c\\echo ARVO' /src/build.sh''')

        # Neutralize zip commands for test corpora that depend on downloaded samples
        dft.appendLine('''RUN sed -i '/zip.*ffv1testset/c\\echo ARVO' /src/build.sh''')

    elif project == 'ruby':
        # file2lastrev.rb fails with exit 128 because .git is incomplete after ADD.
        # Replace file2lastrev.rb with a no-op so the make recipe succeeds,
        # and pre-create revision.h with all defines that vcs.rb normally generates:
        # RUBY_REVISION, RUBY_FULL_REVISION, RUBY_RELEASE_YEAR/MONTH/DAY.
        dft.appendLine('''RUN echo 'exit 0' > /src/ruby/tool/file2lastrev.rb && \
        touch /src/ruby/.revision.time && \
        printf '#define RUBY_REVISION "arvo"\\n#define RUBY_FULL_REVISION "arvo"\\n#define RUBY_RELEASE_YEAR 2024\\n#define RUBY_RELEASE_MONTH 1\\n#define RUBY_RELEASE_DAY 1\\n' > /src/ruby/revision.h || true''')
    elif project == 'mpv':
        # Neutralize rsync calls to samples.ffmpeg.org (IP gets blocked)
        dft.appendLine('''RUN sed -i '/rsync.*samples\\.ffmpeg\\.org/c\\echo ARVO' /src/build.sh''')
    elif project == 'imagemagick':
        dft.replace(r'RUN svn .*heic_corpus.*',"RUN mkdir /src/heic_corpus && touch /src/heic_corpus/XxX")
        # libtiff requires autoconf >= 2.71; install a newer autoconf if the base image has an older one
        dft.appendLine('''RUN if ! autoconf --version 2>/dev/null | head -1 | awk '{split($NF,v,"."); if (v[1]>2 || (v[1]==2 && v[2]>=71)) exit 0; else exit 1}'; then \
            apt-get install -y wget && \
            wget -q https://ftp.gnu.org/gnu/autoconf/autoconf-2.72.tar.gz && \
            tar xzf autoconf-2.72.tar.gz && cd autoconf-2.72 && \
            ./configure --prefix=/usr && make && make install && \
            cd .. && rm -rf autoconf-2.72 autoconf-2.72.tar.gz; \
        fi''')
    elif project == 'kimageformats':
        # libjxl's bundled skcms uses __builtin_ia32_vcvtph2ps256 which was
        # removed in clang 22+.  Replace with the equivalent _mm256_cvtph_ps
        # intrinsic at build time (source is volume-mounted).
        dft.appendLine(r'''RUN sed -i '1s|^|sed -i "s/__builtin_ia32_vcvtph2ps256((I16)half)/(F)_mm256_cvtph_ps((__m128i)half)/" /src/libjxl/third_party/skcms/src/Transform_inl.h 2>/dev/null\n|' $SRC/build.sh || true''')
    elif project == "jbig2dec":
        dft.replace(r'RUN cd tests .*',"")
    elif project == 'dlplibs':
        dft.replace(r"ADD",'# ADD')
        dft.replace(r"RUN wget",'#RUN wget')
    elif project == 'quickjs':
        dft.strReplace('https://github.com/horhof/quickjs','https://github.com/bellard/quickjs')
    elif project == 'cryptofuzz':
        line = "RUN cd $SRC/libressl && ./update.sh"
        dft.insertLineBefore(line,"RUN sed -n -i '/^# setup source paths$/,$p' $SRC/libressl/update.sh")
        dft.replace(r".*https://github.com/guidovranken/cryptofuzz-corpora.*","")
    elif project == 'flac':
        if not dft.locateStr('guidovranken/flac-fuzzers') == False:
            return False # Not fixable since the repo is removed and there is no mirror
    elif project =='libyang':
        dft.strReplace('RUN git clone https://github.com/PCRE2Project/pcre2 pcre2 &&',"RUN git clone https://github.com/PCRE2Project/pcre2 pcre2\nRUN ")
        # build.sh does "git checkout <branch>" but the branch doesn't exist
        # after we reset to the srcmap revision.  Replace with no-op.
        dft.appendLine(r'''RUN sed -i 's/^git checkout .*/true/g' $SRC/build.sh || true''')
        # Older revisions lack tools/CMakeLists.txt; guard the sed that
        # modifies it so it doesn't abort the build under set -e.
        dft.appendLine(r'''RUN sed -i '/sed.*tools\/CMakeLists/s/$/ || true/' $SRC/build.sh || true''')
        # Older libyang (pre-libyang2) needs PCRE v1, not PCRE2.
        # Install libpcre3-dev so cmake find_package(PCRE) succeeds.
        dft.appendLine('''RUN apt-get update && apt-get install -y libpcre3-dev || true''')
        # ASan doesn't support static linking; yang2yin tool link fails.
        # Disable yang2yin and yanglint targets in CMakeLists.txt at build time.
        dft.appendLine(r'''RUN sed -i '1s|^|sed -i "/add_executable(yang/,/)/s/^/#/" /src/libyang/CMakeLists.txt 2>/dev/null; sed -i "s/add_subdirectory(tools/#add_subdirectory(tools/g" /src/libyang/CMakeLists.txt 2>/dev/null; sed -i "/target_link_libraries(yang/s/^/#/" /src/libyang/CMakeLists.txt 2>/dev/null; sed -i "/install(TARGETS yang/s/^/#/" /src/libyang/CMakeLists.txt 2>/dev/null\n|' $SRC/build.sh || true''')
    elif project == "yara":
        if 'bison' not in dft.content:
            line = "RUN git clone https://github.com/VirusTotal/yara.git"
            dft.insertLineBefore(line,"RUN apt install -y bison")
    elif project == "lwan":
        dft.strReplace('git://github.com/lpereira/lwan','https://github.com/lpereira/lwan.git')
    elif project == "radare2":
        dft.strReplace("https://github.com/radare/radare2-regressions",'https://github.com/rlaemmert/radare2-regressions.git')
    elif project == "wireshark":
        dft.replace(r"RUN git clone .*wireshark.*","")
        # Older revisions of wsutil/file_compressed.c miss #include <errno.h>,
        # causing 'undeclared identifier errno/ENOMEM' errors.  Patch at build time.
        dft.appendLine(r'''RUN sed -i '1s|^|sed -i "1i #include <errno.h>" /src/wireshark/wsutil/file_compressed.c 2>/dev/null\n|' $SRC/build.sh || true''')
    elif project == 'gnutls':
        dft.strReplace(" libnettle6 "," ")
        dft.replace(r".*client_corpus_no_fuzzer_mode.*","")
        dft.replace(r".*server_corpus_no_fuzzer_mode.*","")
    elif project == 'pcapplusplus':
        # Multiple Makefiles expect Obj/ directories to exist; source is
        # volume-mounted at compile time so we must create them in build.sh.
        # Use find to create all needed Obj/ dirs recursively.
        dft.appendLine(r'''RUN sed -i '1s|^|find /src/PcapPlusPlus -name Makefile -exec grep -l "Obj/" {} \; | while read f; do mkdir -p "$(dirname "$f")/Obj"; done\n|' $SRC/build.sh || true''')
    elif project == 'libarchive':
        # Disable -Werror to avoid -Wsingle-bit-bitfield-constant-conversion
        # and -Wunused-but-set-variable errors on older source revisions.
        # Source is volume-mounted so modify at build.sh runtime, not Dockerfile.
        dft.appendLine(r'''RUN sed -i '1s|^|sed -i "s/-Werror/-Wno-error/g" /src/libarchive/CMakeLists.txt 2>/dev/null; sed -i "s/-Werror/-Wno-error/g" /src/libarchive/Makefile.am 2>/dev/null\n|' $SRC/build.sh || true''')
    # spirv-tools: SPIRV-Headers and spirv-tools revisions are mismatched
    # (generated .inc files reference undeclared identifiers). Not fixable
    # with simple -Werror removal.
    elif project == 'openssl':
        # build.sh zips seed corpora; some dirs may be empty causing "zip error:
        # Nothing to do!" which is treated as fatal.  Append "|| true".
        dft.appendLine(r'''RUN sed -i 's/zip -j .*seed_corpus.zip/& || true/g' $SRC/build.sh || true''')
    # neomutt: old revisions lack fuzzing support entirely (no --fuzzing
    # in configure, no "make fuzz" target).  Not fixable.
    elif project == 'poppler':
        # Upgrade meson in case the base image has an old version.
        dft.appendLine('''RUN pip3 install --upgrade meson || true''')
        # Pango requires harfbuzz >= 2.0 but old base images have 1.0.1.
        # Meson tries to git-clone harfbuzz with --branch master which fails
        # (renamed to main).  Create a helper script that pre-clones harfbuzz
        # into pango's subprojects dir (source is volume-mounted at build time).
        # Create helper script to pre-clone harfbuzz into pango subprojects dir
        # and disable gobject/introspection/docs/tests to avoid glib codegen issues.
        # Using base64 to avoid multi-layer escaping issues.
        import base64
        script = b'''#!/bin/sh
for d in /src/pango-*/subprojects; do
  if [ -d "$d" ] && [ ! -d "$d/harfbuzz" ]; then
    git clone --depth 1 --branch 2.7.0 https://github.com/harfbuzz/harfbuzz.git "$d/harfbuzz" 2>/dev/null
    sed -i "/^option('gobject/s/auto/disabled/" "$d/harfbuzz/meson_options.txt" 2>/dev/null
    sed -i "/^option('introspection/s/auto/disabled/" "$d/harfbuzz/meson_options.txt" 2>/dev/null
    sed -i "/^option('docs/s/auto/disabled/" "$d/harfbuzz/meson_options.txt" 2>/dev/null
    sed -i "/^option('tests/s/enabled/disabled/" "$d/harfbuzz/meson_options.txt" 2>/dev/null
  fi
done
find /src -name "harfbuzz.wrap" -exec sed -i "s/revision = master/revision = main/g" {} + 2>/dev/null
'''
        b64 = base64.b64encode(script).decode()
        dft.appendLine(f'RUN echo "{b64}" | base64 -d > /src/fix_harfbuzz.sh && chmod +x /src/fix_harfbuzz.sh')
        dft.appendLine(r'''RUN sed -i '1s|^|/src/fix_harfbuzz.sh\n|' $SRC/build.sh || true''')
        # Newer build.sh expects fuzzer sources inside the poppler source tree
        # (cpp/tests/fuzzing/, glib/tests/fuzzing/, qt5/tests/fuzzing/) but
        # older poppler revisions don't have them.  Embed pre-packaged fuzzer
        # sources from a recent poppler and extract them if missing.
        import subprocess
        fuzzers_b64 = subprocess.check_output(
            ['base64', '-w0', '/home/n132/ARVO/arvo/assets/poppler_fuzzers.tar.gz']
        ).decode().strip()
        dft.appendLine(f'RUN echo "{fuzzers_b64}" | base64 -d > /src/poppler_fuzzers.tar.gz')
        fuzz_setup = b'''#!/bin/sh
for d in cpp/tests/fuzzing glib/tests/fuzzing qt5/tests/fuzzing qt6/tests/fuzzing; do
  mkdir -p "/src/poppler/$d"
done
if [ -f /src/poppler_fuzzers.tar.gz ]; then
  for d in cpp/tests/fuzzing glib/tests/fuzzing qt5/tests/fuzzing; do
    count=$(ls /src/poppler/$d/*_fuzzer.cc 2>/dev/null | wc -l)
    if [ "$count" -eq 0 ]; then
      tar xzf /src/poppler_fuzzers.tar.gz -C /src/poppler/ "$d/" 2>/dev/null || true
    fi
  done
fi
'''
        fuzz_b64 = base64.b64encode(fuzz_setup).decode()
        dft.appendLine(f'RUN echo "{fuzz_b64}" | base64 -d > /src/fix_poppler_fuzzers.sh && chmod +x /src/fix_poppler_fuzzers.sh')
        dft.appendLine(r'''RUN sed -i '1s|^|/src/fix_poppler_fuzzers.sh\n|' $SRC/build.sh || true''')
    elif project == 'fwupd':
        # Old base images have pip 19.x on Python 3.8 which can't parse
        # newer pyproject.toml (ninja, meson).  Upgrade pip first.
        dft.insertLineBefore('RUN pip3 install -U meson ninja', 'RUN pip3 install --upgrade pip || true')
        # glib's meson.build removed the "internal_pcre" option in newer
        # versions.  The fwupd build script passes it unconditionally.
        # Remove the stale option from the meson command line.
        dft.appendLine(r"""RUN sed -i "s/'-Dinternal_pcre', 'true',\s*//g" $SRC/fwupd/contrib/ci/oss-fuzz.py || true""")
        dft.appendLine(r"""RUN sed -i "s/'-Dinternal_pcre=true',\s*//g" $SRC/fwupd/contrib/ci/oss-fuzz.py || true""")
        dft.appendLine(r"""RUN sed -i "s/-Dinternal_pcre=true//g" $SRC/fwupd/contrib/ci/oss-fuzz.py || true""")
        # glib HEAD drops internal_pcre and uses pcre2 as a subproject.
        # Install pcre2-dev so glib uses system pcre2, and add -lpcre2-8 to
        # the fwupd oss-fuzz.py link flags via build.sh (source is volume-mounted).
        dft.appendLine('''RUN apt-get update && apt-get install -y libpcre2-dev || true''')
        # Create a helper script that patches oss-fuzz.py at compile time
        # Use base64 to avoid shell quoting issues with nested sed
        dft.appendLine(r'''RUN echo "IyEvYmluL3NoCnNlZCAtaSAiL2FkZF9idWlsZF9sZGZsYWcuKmxpYnhtbGIvYVwgICAgYmxkLmxkZmxhZ3MuYXBwZW5kKCctbHBjcmUyLTgnKSIgZnd1cGQvY29udHJpYi9jaS9vc3MtZnV6ei5weSAyPi9kZXYvbnVsbAo=" | base64 -d > /src/fix_fwupd_pcre2.sh && chmod +x /src/fix_fwupd_pcre2.sh''')
        dft.appendLine(r'''RUN sed -i '1s|^|/src/fix_fwupd_pcre2.sh\n|' $SRC/build.sh || true''')
    elif project == 'tmux':
        # libevent HEAD may have compile errors in test code (PATH_MAX undeclared).
        # Disable test/sample builds since we only need the library.
        dft.strReplace('cmake -DEVENT__DISABLE_MBEDTLS=ON -DEVENT__DISABLE_OPENSSL=ON -DEVENT__LIBRARY_TYPE=STATIC',
                       'cmake -DEVENT__DISABLE_MBEDTLS=ON -DEVENT__DISABLE_OPENSSL=ON -DEVENT__LIBRARY_TYPE=STATIC -DEVENT__DISABLE_TESTS=ON -DEVENT__DISABLE_SAMPLES=ON')
    elif project == 'qemu':
        # glib HEAD may fail to build; upgrade meson/pip and pass
        # -Dtests=false explicitly (already in Dockerfile but glib version may need it).
        dft.appendLine('''RUN pip3 install --upgrade meson || true''')
    elif project == 'dav1d':
        # build.sh uses `find ${build} -name 'dav1d_fuzzer*'` which also matches
        # the meson .p build directories (dav1d_fuzzer_mt.p/).  The cp then fails
        # because it tries to copy a directory.  Patch find to use -type f.
        dft.appendLine(r'''RUN sed -i "s/find \${build} -name/find \${build} -type f -name/g" $SRC/build.sh || true''')
    elif project == 'libical':
        # Install pkg-config so cmake's GObject/GLIB checks pass.
        dft.appendLine('''RUN apt-get update && apt-get install -y pkg-config || true''')
    dft.cleanComments()
    assert(dft.flush()==True)
    return True
def rebaseDockerfile(dockerfile_path,commit_date):
    if _profile.EVAL_NOREBASE:
        return True
    def _getBase(date,repo="gcr.io/oss-fuzz-base/base-builder"):
        cache_name = repo.split("/")[-1]
        CACHE_FILE = f"/tmp/{cache_name}_cache.json"
        CACHE_TTL = 86400  # 24 hours
        if os.path.exists(CACHE_FILE) and (time.time() - os.path.getmtime(CACHE_FILE)) < CACHE_TTL:
            with open(CACHE_FILE, 'r') as f: res = json.load(f)
        else:
            cmd = [
                "gcloud", "container", "images", "list-tags",
                repo, "--format=json", "--sort-by=timestamp"
            ]
            res = execute(cmd).decode()
            res = json.loads(res)
            with open(CACHE_FILE, 'w') as f: f.write(json.dumps(res,indent=4))
        ts = []
        for x in res: ts.append(int(parse(x['timestamp']['datetime']).timestamp()))
        target_ts = int(parse(date).timestamp())
        return res[bisect_right(ts, target_ts - 1) - 1]['digest'].split(":")[1]
    # Load the Dockerfile
    try:
        with open(dockerfile_path) as f: data = f.read()
    except:
        eventLog(f"[-] rebaseDockerfile: No such a dockerfile: {dockerfile_path}")
        return False
    # Locate the Repo
    res = re.search(r'FROM .*',data)
    if(res == None):
        eventLog(f"[-] rebaseDockerfile: Failed to get the base-image: {dockerfile_path}")
        return False
    else: repo = res[0][5:]
    if "@sha256" in repo: repo = repo.split("@sha256")[0]
    if repo == 'ossfuzz/base-builder' or repo == 'ossfuzz/base-libfuzzer': repo = "gcr.io/oss-fuzz-base/base-builder"
    if ":" in repo: repo = repo.split(":")[0]
    image_hash = _getBase(commit_date,repo)
    data = re.sub(r"FROM .*",f"FROM {repo}@sha256:"+image_hash+"\nRUN apt-get update -y\n",data)
    with open(dockerfile_path,'w') as f: f.write(data)
    return True
def extraScritps(pname,oss_dir,source_dir):
    """
    This function allows us to modify build.sh scripts and other stuff to modify the compiling setting
    """
    if pname == 'imagemagick':
        target = source_dir/"src"/pname/"Magick++"/"fuzz"/"build.sh"
        if target.exists():
            with open(target) as f:
                lines = f.readlines()
            for x in range(3):
                if "zip" in lines[-x]:
                    del(lines[-x])
            with open(target,'w') as f:
                f.write("\n".join(lines))
    return True
def fixBuildScript(file,pname):
    if _profile.EVAL_NOURLFIX:
        return True
    if not file.exists():
        return True
    dft = DfTool(file)
    # Experimental Feat
    dft.strReplaceAll(globalStrReplace)
    if   pname == "uwebsockets":
        '''
        https://github.com/alexhultman/zlib
        ->
        https://github.com/madler/zlib.git
        '''
        script = "sed -i 's/alexhultman/madler/g' fuzzing/Makefile"
        dft.insertLineat(0,script)     
    elif pname == 'libreoffice':
        '''
        If you don't want to destroy your life. 
        Please leave this project alone.
        '''
        line = '$SRC/libreoffice/bin/oss-fuzz-build.sh'
        dft.insertLineBefore(line,"sed -i 's/make fuzzers/make fuzzers -i/g' $SRC/libreoffice/bin/oss-fuzz-build.sh")
        dft.insertLineBefore(line,"sed -n -i '/#starting corpuses/q;p' $SRC/libreoffice/bin/oss-fuzz-build.sh")
        dft.insertLineBefore(line,r"sed -n -i '/pushd instdir\/program/q;p' $SRC/libreoffice/bin/oss-fuzz-build.sh")
        dft.insertLineBefore(line,'echo "pushd instdir/program && mv *fuzzer $OUT" >> $SRC/libreoffice/bin/oss-fuzz-build.sh')
    elif pname == 'jbig2dec':
        dft.replace('unzip.*','exit 0')
    elif pname == "ghostscript":
        old = r"mv \$SRC\/freetype freetype"
        new = "cp -r $SRC/freetype freetype"
        dft.replace(old,new)
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
            dft.removeRange(starts,ends)
        dft.strReplace("svn export https://github.com/mozillasecurity/fuzzdata.git/trunk/samples/h264 corpus/","mkdir corpus")
    elif pname in ['libredwg','duckdb']:
        dft.replace(r'^make$','make -j`nproc`\n')
    elif pname == "cryptofuzz":
        # The repo was deleted
        dft.replace(r'\scp .*cryptofuzz-corpora .*\n?', '', flags=re.MULTILINE)
    elif pname == 'wolfssl':
        # The main build.sh cds into /src/cryptofuzz_seed_corpus then
        # rm -rfs it, leaving CWD dangling.  The subsequent call to the
        # wolf-ssl-ssh-fuzzers build.sh then fails with "getcwd: cannot
        # access parent directories".  Insert "cd /src" before the call.
        dft.strReplace('NEW_SRC=$SRC/wolf-ssl-ssh-fuzzers', 'cd /src\n    NEW_SRC=$SRC/wolf-ssl-ssh-fuzzers')
    elif pname == 'libical':
        # Different revisions use different cmake option names for GLib.
        # Add all variants so the build passes regardless of revision.
        # Also disable glib docs which conflict with static-only builds.
        dft.strReplace('cmake .', 'cmake . -DLIBICAL_GLIB=False -DLIBICAL_GOBJECT_INTROSPECTION=False -DLIBICAL_GLIB_BUILD_DOCS=False')

    assert(dft.flush()==True)
    return True
def skipComponent(pname,itemName):
    itemName = itemName.strip(" ")
    # Special for skia, Skip since they are done by submodule init
    if  pname in ['skia','skia-ftz']:
        if itemName.startswith("/src/skia/"):
            return True
    if itemName in NoOperation:
        return True
    return False
def specialComponent(pname,itemKey,item,dockerfile,commit_date):
    if pname == 'libressl' and itemKey == '/src/libressl/openbsd':
        return False
    if pname == 'gnutls' and itemKey == '/src/gnutls/nettle' :
        # Just Ignore since we have submodule update --init
        with open(dockerfile) as f: dt = f.read()
        if item['rev'] not in dt:  return True
        else: return False
    return False
def combineLines(lines):
    res = []
    flag = 0
    for line in lines:
        if flag==1:
            if not line.endswith("\\\n"):
                buf+= line
                res.append(buf)
                flag=0
            else:
                buf+=line[:-1]
        else:
            if not line.endswith("\\\n"):
                res.append(line) 
            else:
                buf = line[:-1]
                flag=1
    return res
def dockerfileCleaner(dockerfile):
    dft = DfTool(dockerfile)
    dft.replace(r'(--single-branch[ \t]*)',"") # --single-branch
    dft.replace(r'(--branch\s+\S+[ \t]*|-b\s\S+[ \t]*|--branch=\S+[ \t]*)',"") # remove --branch or -b
    dft.flush()
def parse_git_clone(dockerfile_line):
    # Comprehensive git clone pattern
    pattern = r'RUN\s+git\s+clone\s+(?P<flags>(?:(?:--?\w+(?:[=\s]\S+)?)\s+)*)?(?P<url>\S+?)(?:\s+(?P<dest>\S+))?\s*$'

    
    match = re.search(pattern, dockerfile_line.strip())
    if not match:
        return None
    
    url = match.group('url')
    explicit_dest = match.group('dest')

    # Get default repo name from URL
    if explicit_dest:
        repo_dir = explicit_dest
    else:
        # Extract repo name from various URL formats
        if url.endswith('.git'):
            repo_name = url.split('/')[-1][:-4]  # Remove .git
        else:
            if url.endswith("/"):
                url = url[:-1]
            repo_name = url.split('/')[-1]
        repo_dir = repo_name
    
    return repo_dir
def updateRevisionInfo(dockerfile,localId,src_path,item,commit_date,approximate):
    """
    ins the dockerfile to perform minial changes while reproducing
    """ 
    item_url    = item['url']
    item_rev    = item['rev']
    item_type   = item['type']

    dft = DfTool(dockerfile)

    keyword = item['url'].strip()
    if keyword.startswith("http:"):
        keyword = keyword[4:]
    elif keyword.startswith("https:"):
        keyword = keyword[5:]
    elif keyword.startswith("git://git"):
        keyword = keyword[9:]
    if keyword.endswith(".git"):
        keyword = keyword[:-4]
    
    hits, ct = dft.getLine(keyword)
    if len(hits) == 0:
        if item_url not in ['https://github.com/google/AFL.git','https://chromium.googlesource.com/chromium/llvm-project/llvm/lib/Fuzzer','https://github.com/ossf/fuzz-introspector.git']:
            WARN(f"Not Found {item_url=} for {localId=}  ({keyword=})")
        return False
    src_name = src_path.split("/")[-1]
    if len(hits) > 1:
        WARN(f"Found more than one lines containing {item_url=} for {localId=}")
        for x in range(len(hits)):
            if src_name in hits[x]:
                line = hits[x]
                ct = ct[x]
                break
    else:
        line = hits[0]
        ct = ct[0]
    if item_type == 'git':
        pat = re.compile(rf"{item_type}\s+clone")
    elif item_type == 'hg':
        pat = re.compile(rf"{item_type}\s+clone")
    elif item_type == 'svn':
        pat = re.compile(rf"RUN\s+svn\s+(co|checkout)+")
    else:
        WARN(f"No support for {item_type=}, {localId=}")
        return False

    if len(pat.findall(line)) != 1:
        WARN(f"Mismatch the type of component downloading, where {item_type=} for {localId=}")
        return False
    
    if type(commit_date) == type(Path("/tmp")):
        rep_path = commit_date
        """
        Replace the original line with ADD/COPY command
        Then RUN init/update the submodule
        """
        dft.replaceLineat(ct-1,f"ADD {rep_path.name} {src_path}")
        dft.insertLineat(ct,f"RUN bash -cx 'pushd {src_path} ;(git submodule init && git submodule update --force) ;popd'")
        dft.flush()
        return True
    else:
        # Insert Mode
        if item_type == "git":
            repo_dir = parse_git_clone(dft.content.split("\n")[ct-1])
            
            if repo_dir!=None and "/" in repo_dir:
                repo_dir = repo_dir.split("/")[-1]
            if ARVO_Turbo and repo_dir!=None:
                clone_res = clone(item_url,None,dockerfile.parent,repo_dir,commit_date=commit_date)
            else:
                clone_res = False
            if approximate == '-':
                if  clone_res not in [None, False]: # Cache Path
                    dft.replaceLineat(ct-1,f"ADD {repo_dir} {src_path}")
                    dft.insertLineat(ct,f"RUN bash -cx 'pushd {src_path} ; (git reset --hard {item_rev}) || (commit=$(git log --before='{commit_date.isoformat()}' --format='%H' -n1) && git reset --hard $commit || exit 99) ;  (git submodule init && git submodule update --force) ;popd'")
                else:
                    dft.insertLineat(ct,f"RUN bash -cx 'pushd {src_path} ; (git reset --hard {item_rev}) || (commit=$(git log --before='{commit_date.isoformat()}' --format='%H' -n1) && git reset --hard $commit || exit 99) ;  (git submodule init && git submodule update --force) ;popd'")
            else:
                if  clone_res not in [None, False]: # Cache Path
                    dft.replaceLineat(ct-1,f"ADD {repo_dir} {src_path}")
                    dft.insertLineat(ct,f"RUN bash -cx 'pushd {src_path} ; (git reset --hard {item_rev}) || (commit=$(git log --since='{commit_date.isoformat()}' --format='%H' --reverse | head -n1) && git reset --hard $commit || exit 99) ;  (git submodule init && git submodule update --force) ;popd'")
                else:
                    dft.insertLineat(ct,f"RUN bash -cx 'pushd {src_path} ; (git reset --hard {item_rev}) || (commit=$(git log --since='{commit_date.isoformat()}' --format='%H' --reverse | head -n1) && git reset --hard $commit || exit 99) ;  (git submodule init && git submodule update --force) ;popd'")
            dft.flush()
            return True
        elif item_type == 'hg':
            dft.insertLineat(ct,f'''RUN bash -cx "pushd {src_path} ; (hg update --clean -r {item_rev} && hg purge --config extensions.purge=)|| exit 99 ; popd"''')
            dft.flush()
            return True
        elif item_type == "svn":
            dft.replace(pat,f"RUN svn checkout -r {item_rev}")
            dft.flush()
            return True
        else:
            return False

if __name__ == "__main__":
    pass