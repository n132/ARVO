from .utils import *
from dateutil.parser import parse
from bisect import bisect_right
import time
from .transform import globalStrReplace
#########################################
# Core Area for reproducing
#########################################
def fixDockerfile(dockerfile_path,project=None):
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

    if project == "lcms":
        dft.replace(r'#add more seeds from the testbed dir.*\n',"")
    elif project =='wolfssl':
        dft.strReplace('RUN gsutil cp gs://wolfssl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/wolfssl_cryptofuzz-disable-fastmath/public.zip $SRC/corpus_wolfssl_disable-fastmath.zip',"RUN touch 0xdeadbeef && zip $SRC/corpus_wolfssl_disable-fastmath.zip 0xdeadbeef")
    elif project == 'skia':
        dft.strReplace('RUN wget',"# RUN wget")
        line = 'COPY build.sh $SRC/'
        dft.insertLineAfter(line,"RUN sed -i 's/cp.*zip.*//g' $SRC/build.sh")
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
    elif project == 'imagemagick':
        dft.replace(r'RUN svn .*heic_corpus.*',"RUN mkdir /src/heic_corpus && touch /src/heic_corpus/XxX")
    elif project == "jbig2dec":
        dft.replace(r'RUN cd tests .*',"")
    elif project == 'dlplibs':
        dft.replace(r"ADD",'# ADD')
        dft.replace(r"RUN wget",'#RUN wget')
    elif project == 'quickjs':
        dft.strReplace('https://github.com/horhof/quickjs','https://github.com/bellard/quickjs')
    elif project =="dav1d":
        pass
    elif project == 'cryptofuzz':
        line = "RUN cd $SRC/libressl && ./update.sh"
        dft.insertLineBefore(line,"RUN sed -n -i '/^# setup source paths$/,$p' $SRC/libressl/update.sh")
    elif project =='libyang':
        dft.strReplace('RUN git clone https://github.com/PCRE2Project/pcre2 pcre2 &&',"RUN git clone https://github.com/PCRE2Project/pcre2 pcre2\nRUN ")
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
    dft.cleanComments()
    assert(dft.flush()==True)
    return True
def rebaseDockerfile(dockerfile_path,commit_date):
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
    if not file.exists():
        return True
    dft = DfTool(file)
    if   pname == "uwebsockets":
        '''
        https://github.com/alexhultman/zlib
        ->
        https://github.com/madler/zlib.git
        '''
        script = "sed -i 's/alexhultman/madler/g' fuzzing/Makefile"
        dft.insertLineat(0,script)     
    elif pname == 'serenity':
        # script = "sed -i 's/UCD_VERSION 15.0.0/UCD_VERSION 15.1.0/g' /src/serenity/Meta/CMake/unicode_data.cmake"
        # dft.insertLineat(0,script)    
        pass
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
    elif pname in ['libredwg','duckdb']:
        dft.replace(r'^make$','make -j`nproc`\n')
    assert(dft.flush()==True)
    return True
NoOperation = [
    "/src",
    "/src/LPM/external.protobuf/src/external.protobuf",
    "/src/libprotobuf-mutator/build/external.protobuf/src/external.protobuf",
]
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

updateRevDir = ARVO / "matches" 
Match_DIR = updateRevDir / "hit"
MisMatch_DIR = updateRevDir / "miss"

dir_check(updateRevDir)
dir_check(Match_DIR)
dir_check(MisMatch_DIR)


def reportMiss(localId,s):
    with open(MisMatch_DIR / f"{localId}.json", 'a+') as f:
        f.write(s+"\n")
    return False
    
def reportHit(localId,s):
    with open(Match_DIR / f"{localId}.json", 'a+') as f:
        f.write(s+"\n")
    return True
def dockerfileCleaner(dockerfile):
    dft = DfTool(dockerfile)
    dft.replace(r'(--single-branch\s+)',"") # --single-branch
    dft.replace(r'(--branch\s+\S+\s+|-b\s\S+\s+|--branch=\S+\s+)',"") # remove --branch or -b
    dft.flush()
def updateRevisionInfo(dockerfile,localId,src_path,item,commit_date,approximate):
    item_url    = item['url']
    item_rev    = item['rev']
    item_type   = item['type']
    dft = DfTool(dockerfile)
    keyword = item_url
    if keyword.startswith("http:"):
        keyword = keyword[4:]
    elif keyword.startswith("https:"):
        keyword = keyword[5:]
    hits, ct = dft.getLine(keyword)
    d = dict()
    d['localId'] = localId
    d['url'] = item_url
    d['type'] = item_type
    # Case Miss
    if len(hits) == 0:
        d['reason'] = "Not Found"
        return reportMiss(localId,json.dumps(d,indent=4))
    # Case MisMatch
    elif len(hits) != 1:
        d['reason'] = "More then one results"
        return reportMiss(localId,json.dumps(d,indent=4))
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
            return reportMiss(localId,json.dumps(d,indent=4))
        else:
            if type(commit_date) == type(Path("/tmp")):
                rep_path = commit_date
                # Replace mode
                """
                Replace the original line with ADD/COPY command
                Then RUN init/update the submodule
                """
                dft.replaceLineat(ct-1,f"ADD {rep_path.name} {src_path}")
                dft.insertLineat(ct,f"RUN bash -cx 'pushd {src_path} ;(git submodule init && git submodule update --force) ;popd'")
                dft.flush()
                return reportHit(localId,json.dumps(d,indent=4))
            else:
                # Insert Mode
                if item_type == "git":
                    if approximate == '-':
                        dft.insertLineat(ct,f"RUN bash -cx 'pushd {src_path} ; (git reset --hard {item_rev}) || (commit=$(git log --before='{commit_date.isoformat()}' --format='%H' -n1) && git reset --hard $commit || exit 99) ;  (git submodule init && git submodule update --force) ;popd'")
                    else:
                        dft.insertLineat(ct,f"RUN bash -cx 'pushd {src_path} ; (git reset --hard {item_rev}) || (commit=$(git log --since='{commit_date.isoformat()}' --format='%H' --reverse | head -n1) && git reset --hard $commit || exit 99) ;  (git submodule init && git submodule update --force) ;popd'")
                    dft.flush()
                    return reportHit(localId,json.dumps(d,indent=4))
                elif item_type == 'hg':
                    dft.insertLineat(ct,f'''RUN bash -cx "pushd {src_path} ; (hg update --clean -r {item_rev} && hg purge --config extensions.purge=)|| exit 99 ; popd"''')
                    dft.flush()
                    return reportHit(localId,json.dumps(d,indent=4))
                elif item_type == "svn":
                    dft.replace(pat,f"RUN svn checkout -r {item_rev}")
                    dft.flush()
                    return reportHit(localId,json.dumps(d,indent=4))
                else:
                    return False

if __name__ == "__main__":
    pass