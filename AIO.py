from arvo import *
from arvo.utils_diff import *
from glob import glob
import sys
import argparse
def doSpawn(pocs,diff_rev,log_fd,to_check,finished=[]):
    # 1. create gt
    print(diff_rev)
    dummy_localId = int(list(diff_rev.iterdir())[0].name.split(".")[1])
    pname = getPname(dummy_localId)
    if pname == False: return False
    _,info2 = get_projectInfo(dummy_localId,pname)
    protocol = info2['type']
    # 2. Probe: reset then try to apply bug patches
    commits = to_check
    for commit in commits:
        if commit in finished: continue
        
        # Init The Var
        ct  = vul_ct = try2rev = 0
        done = []
        localId = commits[commit][0]

        gt = GitTool(info2['url'],protocol,commit)
        if not gt: continue
        cur_ts = gt.timestamp(commit)

        # loop the patches to apply
        for diff_file in diff_rev.iterdir():
            cur_try = diff_file.name.split(".")[0]
            if cur_try not in done:
                done.append(cur_try)  
                patched_time = gt.timestamp(cur_try)
                if patched_time >= cur_ts:
                    # we don't need to rev a future patch
                    vul_ct+=1
                    continue
                try2rev+=1
                if (patched_time < cur_ts ) and (gt.patch(diff_file)==True):
                    ct+=1
        flushLog(log_fd,f"[+] Pname: {pname} Commit: {commit} Vulnerable to {vul_ct} Vulnerabilities, ARVO appllied {ct}/{try2rev} reversed patch.\n",True)
        # Compile with Mounting
        repo_dir = gt.repo
        srcmap,issue = getIssueTuple(localId)
        # build_res = silentRun(build_from_srcmap,srcmap[commits[commit][1]],issue,replace_dep=[pname,repo_dir])
        build_res = build_from_srcmap(srcmap[commits[commit][1]],issue,replace_dep=[pname,repo_dir])
        if not build_res:
            if(RM_IMAGES): remove_oss_fuzz_img(localId)
            shutil.rmtree(gt.repo)
            flushLog(log_fd,f"[+] Pname: {pname} Commit: {commit} Failed to compile\n",True)
            continue
        for x in glob(f"./Log/AIO_EXE/{localId}_AIO_{commit}_*"):
            os.remove(x)
        for poc in pocs:
            # localId = int(poc.name.split(".")[0])
            issue = getIssue(localId)
            idx = pocs.index(poc)
            issue['localId'] = localId
            # silentRun(crashVerify,issue,poc,tag= LOG / "AIO_EXE"/ f"AIO_{commit}_{idx}.log",timeout=180)
            crashVerify(issue,poc,tag= LOG / "AIO_EXE"/ f"AIO_{commit}_{idx}.log",timeout=180)
        total = getTotalCrashes(glob(str(LOG/"AIO_EXE")+ f"/AIO_{commit}_*"))
        uniq = set(total)
        flushLog(log_fd,f"[+] Pname: {pname} Commit: {commit} Total: {len(total)}, Dedup: {len(uniq)}\n",True)
        for x in uniq:
            flushLog(log_fd,f"[*] \t\t\t\t {x}\n",True)
        # Clean
        shutil.rmtree(gt.repo)
        check_call(['sudo',"rm","-rf",str(OSS_OUT/str(localId))])
        check_call(['sudo',"rm","-rf",str(OSS_WORK/str(localId))])
def getTotalCrashes(crashList):
    uniq = []
    for item in crashList:
        res = parseCrash(Path(item))
        if not res: 
            continue
        else : 
            uniq.append(res[1])
    
    return uniq
def flushLog(f,s,out=False):
    if f:
        f.write(s)
        f.flush()
    if out:
        INFO(s.strip())
def buildTargetRepo(pname,commit,diff_rev,remote_repo,targets):
    # Locat the localId
    INFO(f"[+] Building target source repo for {pname}: {commit} -> {remote_repo}")
    INFO(f'[+] Rev diff dir: {diff_rev}')
    localIds = listProject(pname)
    component_name = getPname(localIds[0])

    localId = tag = info = None    
    for x in localIds:
        info1,info2 = get_projectInfo(x,component_name)
        if info1['rev'] == commit:
            localId = x
            tag = 'vul'
            info = info1
            break
        if info2['rev'] == commit:
            localId = x
            tag = 'fix'
            info = info2
            break
    if not localId or not tag or not info:
        PANIC("[Invalid] args")
    gt = GitTool(info['url'],info['type'],commit)
    if not gt:
        PANIC("[FAILED] to download the source")
    # replace the remote repo with the new one
    assert(check_call(['git','remote','set-url','origin',remote_repo],cwd=gt.repo))

    # loop the patches to apply
    done = []
    cur_ts = gt.timestamp(commit)
    for diff_file in diff_rev.iterdir():
        cur_try = diff_file.name.split(".")[0]
        if cur_try in done:
            continue
        done.append(cur_try)  
        patched_time = gt.timestamp(cur_try)
        if patched_time >= cur_ts: 
            # INFO("Future patch doesn't need to be canceled")
            continue
        else: 
            if gt.patch(diff_file):
                # adding the patch as history commit
                assert(check_call(['git','add', '.'],cwd=gt.repo))
                assert(check_call(['git','commit', '-m',"bot: ARVO target builder"],cwd=gt.repo))

    # push to the remote
    assert(check_call(['git','branch', '-M','main'],cwd=gt.repo))
    assert(check_call(['git','push','-u', 'origin','main','-f'],cwd=gt.repo))


    if not (targets / pname).exists():
        oss_fuzz = GitTool("https://github.com/google/oss-fuzz.git")
        oss_fuzz.reset(oss_fuzz.getCommitbyTimestamp(cur_ts))
        shutil.copytree(oss_fuzz.repo / "projects" / pname, targets/pname)
        INFO("[INFO] Inited the OSS Fuzz project folder")
        shutil.rmtree(oss_fuzz.repo)
    # clean out
    shutil.rmtree(gt.repo)
def mostVulCommit(log_dir = ARVO/ f"Log/AIO"):
    res = {}
    for x in log_dir.iterdir():
        ct_max = 0
        proj = x.name.split("_")[0]
        with open(x) as f:
            lines = f.readlines()
        for line in lines:
            if "Dedup: " in line:
                pname,commit = line.split(" Commit: ")
                pname = pname.split(": ")[-1]
                commit, ct = commit.strip().split(" Dedup: ")
                ct = int(ct)
                ct_max = ct if ct >= ct_max else ct_max
        if ct_max != 0:
            res[proj] = {'commit': commit,'intended_bugs': ct_max}
    return res
def fetchBugs(pname='mupdf',work_dir = None,LOG_OUTPUT=None):
    if isinstance(pname,str):
        done = getReports()
        done = [ x for x in listProject(pname) if x in done]
    elif isinstance(pname,list):
        done = pname
        pname = getPname(pname[0])
    else:
        PANIC("[PANIC] PNAME could only be list ")
    
    if len(done)<10:
        return "TOO LESS SKIP"
    
    # We assume we already have these reported bugs on docker hub
    if LOG_OUTPUT and not LOG_OUTPUT.exists():
        LOG_OUTPUT.touch()
        log_fd = open(LOG_OUTPUT,'w')
        finished = []
    else:
        with open(LOG_OUTPUT,"r") as f:
            lines = f.readlines()
        finished = []
        for x in lines:
            if "Reproduced" in x:
                hash_val = x.split("Commit: ")[1].split(" ")[0]
                finished.append(hash_val)
        log_fd = open(LOG_OUTPUT,'a')
    
    diff_rev = work_dir if work_dir else tmpDir()
    diff_rev.mkdir(exist_ok=True,parents=True)

    # 1. Try to collect the bugs' revdiff
    if len(done) != len(list(diff_rev.iterdir())):
        shutil.rmtree(diff_rev)
        diff_rev.mkdir(exist_ok=True,parents=True)
        for x in done:
            fixCommit   = getFixCommit(x)
            if fixCommit == False: 
                continue
            if getReport(x)['submodule_bug']:
                continue
            if isinstance(fixCommit,list):
                fixCommit = fixCommit[-1]
            fname = f"{fixCommit}.{x}.rev.diff"
            if (diff_rev/fname).exists():
                continue
            revDiffFile = getRevDiff(x)
            if revDiffFile:
                print(f"Done: {revDiffFile}")
                shutil.copy(revDiffFile , diff_rev/fname)
                shutil.rmtree(revDiffFile.parent)
            else:
                print(f"Failed: {x}")

    flushLog(log_fd,f"[+] Project: {pname}\n",True)
    
    # 2. Find Target Commits
    to_check = {}
    for x in done:
        info1, info2 = get_projectInfo(x,getPname(x))
        to_check[info1['rev']] = (x,0) # we need 0/1 to tell the 
        to_check[info2['rev']] = (x,1)
    flushLog(log_fd,f"Append {len(to_check)} commits to the queue\n",True)
    # 3. Spwan the Binary
    poc_dir = ARVO/ "Log" / "AIO_POC" / pname
    if not poc_dir.exists():
        pocs = [ (x,getPoc(x)) for x in done ]
        pocs = [ x for x in pocs if x[1] ]
        poc_dir.mkdir(parents=True)
        for x in pocs:
            shutil.copyfile(x[1],poc_dir/f"{x[0]}.poc")
            shutil.rmtree(x[1].parent)
    pocs = list(poc_dir.iterdir())
    INFO(f"Spwaning the Binary")
    if doSpawn(pocs,diff_rev,log_fd,to_check,finished) == False:
        PANIC(f"Failed to spawn {pname}")
    flushLog(log_fd,str(diff_rev.absolute())+"\n")
    log_fd.close()
    INFO(diff_rev)

done_pj = {"freetype2": 14,     "json": 4,     "file": 24,     "lcms": 42,     "pcre2": 22,     "libreoffice": 10,     "ots": 9,     "libxml2": 84,     "grpc": 7,     "wireshark": 97,     "gnutls": 31,     "ffmpeg": 383,     "gdal": 175,     "harfbuzz": 148,     "libpsl": 4,     "librawspeed": 58,     "libteken": 1,     "expat": 4,     "h2o": 5,     "boringssl": 9,     "openthread": 63,     "openjpeg": 4,     "proj4": 11,     "openssl": 7,     "wpantund": 4,     "zstd": 13,     "open62541": 59,     "libpng": 1,     "yara": 32,     "tpm2": 3,     "curl": 19,     "gstreamer": 7,     "unrar": 20,     "imagemagick": 469,     "mupdf": 82,     "skia": 161,     "bloaty": 3,     "irssi": 5,     "skcms": 5,     "botan": 3,     "resiprocate": 1,     "graphicsmagick": 130,     "tor": 2,     "poppler": 40,     "capstone": 30,     "libaom": 23,     "openvswitch": 26,     "radare2": 27,     "xmlsec": 1,     "unicorn": 21,     "libssh": 1,     "libgit2": 11,     "libarchive": 24,     "tinyxml2": 1,     "libidn2": 2,     "readstat": 8,     "kimageformats": 56,     "libpng-proto": 1,     "perfetto": 16,     "gnupg": 1,     "picotls": 2,     "lwan": 18,     "wget2": 5,     "net-snmp": 21,     "karchive": 16,     "mbedtls": 4,     "libspng": 7,     "libpcap": 3,     "leptonica": 32,     "c-ares": 8,     "hostap": 5,     "icu": 16,     "mruby": 83,     "libxslt": 36,     "libsass": 4,     "lz4": 4,     "clamav": 8,     "libvips": 56,     "flac": 16,     "libavc": 52,     "aspell": 3,     "postgis": 3,     "libmpeg2": 6,     "opensc": 122,     "libhevc": 25,     "matio": 64,     "ghostscript": 153,     "libfdk-aac": 4,     "usrsctp": 9,     "jbig2dec": 7,     "php": 117,     "jsoncpp": 2,     "htslib": 23,     "binutils": 155,     "qpdf": 10,     "ndpi": 146,     "libheif": 11,     "samba": 16,     "uwebsockets": 24,     "libspectre": 6,     "njs": 19,     "wavpack": 4,     "llvm": 22,     "arrow": 41,     "wabt": 9,     "janus-gateway": 1,     "stb": 8,     "libucl": 9,     "libfmt": 3,     "oniguruma": 11,     "fluent-bit": 68,     "libzmq": 4,     "envoy": 29,     "pcapplusplus": 58,     "rdkit": 37,     "firestore": 2,     "muparser": 7,     "libraw": 48,     "json-c": 1,     "haproxy": 3,     "c-blosc2": 91,     "hermes": 2,     "hoextdown": 1,     "c-blosc": 3,     "glib": 7,     "immer": 2,     "rnp": 7,     "assimp": 55,     "arduinojson": 1,     "libavif": 4,     "util-linux": 3,     "sleuthkit": 35,     "alembic": 3,     "libsndfile": 10,     "nginx": 2,     "openexr": 13,     "opencv": 6,     "wolfssl": 100,     "libcoap": 4,     "libass": 2,     "miniz": 5,     "simdjson": 7,     "libjpeg-turbo": 14,     "libtiff": 3,     "draco": 9,     "serenity": 83,     "dropbear": 1,     "selinux": 37,     "mongoose": 9,     "mdbtools": 8,     "hiredis": 1,     "qt": 15,     "igraph": 8,     "valijson": 3,     "fio": 2,     "lua": 4,     "libssh2": 5,     "relic": 10,     "sudoers": 7,     "wolfmqtt": 37,     "libusb": 1,     "flatbuffers": 10,     "tesseract-ocr": 2,     "tmux": 3,     "p11-kit": 3,     "md4c": 6,     "libiec61850": 2,     "libredwg": 76,     "freeimage": 8,     "gpac": 52,     "pcl": 24,     "wuffs": 1,     "lxc": 7,     "wasm3": 38,     "geos": 5,     "jsoncons": 3,     "bitcoin-core": 10,     "cpython3": 4,     "dovecot": 1,     "duckdb": 12,     "espeak-ng": 16,     "tinygltf": 4,     "vlc": 4,     "fribidi": 2,     "pidgin": 1,     "libjxl": 37,     "libwebp": 1,     "re2": 1,     "dnsmasq": 15,     "h3": 4,     "rapidjson": 1,     "libtpms": 2,     "tidy-html5": 1,     "apache-httpd": 3,     "spice-usbredir": 4,     "knot-dns": 2,     "libexif": 11,     "libgd": 1,     "kamailio": 8,     "dav1d": 8,     "freeradius": 18,     "libsrtp": 1,     "s2geometry": 1,     "brunsli": 2,     "tint": 8,     "gdbm": 1,     "mysql-server": 7,     "opensips": 10,     "libbpf": 7,     "libdwarf": 34,     "qpid-proton": 2,     "clickhouse": 7,     "elfutils": 10,     "simd": 1,     "libplist": 10,     "bls-signatures": 1,     "fmt": 2,     "systemd": 4,     "exiv2": 10,     "quickjs": 5,     "ostree": 1,     "xs": 4,     "libical": 1,     "libvpx": 4,     "libwebsockets": 1,     "e2fsprogs": 1,     "s2opc": 2,     "zlib": 1,     "osquery": 1,     "bluez": 1,     "hunspell": 35,     "cyclonedds": 5,     "upb": 1,     "mapserver": 7,     "ntpsec": 3,     "coturn": 2,     "krb5": 5,     "skia-ftz": 20,     "lldpd": 3,     "gpsd": 2,     "msquic": 1,     "trafficserver": 3,     "cryptofuzz": 3,     "cups": 1,     "pjsip": 4,     "zeek": 8,     "nodejs": 1,     "hdf5": 19,     "libzip": 1,     "mosquitto": 9,     "rabbitmq-c": 1,     "glog": 4,     "croaring": 2,     "qemu": 4,     "simdutf": 5,     "python3-libraries": 2,     "faad2": 6,     "libecc": 2,     "tcmalloc": 2,     "nccl": 1,     "open5gs": 1,     "ntopng": 21,     "freerdp": 1,     "liblouis": 1,     "tarantool": 3,     "jq": 4,     "oss-fuzz-example": 1,     "libxaac": 17,     "wasmedge": 3,     "bind9": 1,     "libultrahdr": 2,     "pigweed": 1,     "upx": 14 }
todo    = ["lcms","libxml2","wireshark","ffmpeg","gdal","librawspeed","openthread","open62541","imagemagick","skia","graphicsmagick","poppler","kimageformats","mruby","libxslt","libvips","libavc","opensc","matio","ghostscript","php","binutils","ndpi","arrow","fluent-bit","pcapplusplus","rdkit","libraw","c-blosc2","assimp","sleuthkit","wolfssl","serenity","selinux","wolfmqtt","libredwg","gpac","wasm3","libjxl","libdwarf","hunspell"]
if __name__=='__main__':
    parser = argparse.ArgumentParser(description='ARVO Bug Analysis Tool')
    parser.add_argument('project', help='Project name to analyze')
    args = parser.parse_args()
    
    project_name = args.project
    work_dir = Path(f'./arvo/Log/AIO/{project_name}')
    log_file = Path(f'./arvo/Log/AIO/{project_name}.log')
    
    work_dir.mkdir(parents=True, exist_ok=True)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    fetchBugs(project_name, work_dir, log_file)