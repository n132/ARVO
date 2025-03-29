from .utils import *
from .reproducer import *
from .utils_diff import getRevDiff, getFixCommit
from .utils_log import *
import os
import sys

def silentRun(func, *args, **kwargs):
    original_stdout = sys.stdout
    sys.stdout = open(os.devnull, 'w')
    # sys.stderr = open(os.devnull, 'w')
    result = func(*args, **kwargs)
    sys.stdout = original_stdout
    return result

from .fx import *
'''
1. [Done]  Get all the diffs/ts 
2. [Doing] Try to revert them on all the commits and see how many can we apply
'''

def doSpawn(meta,pocs,fd,LOG_OUTPUT,finished=[]):
    # 1. create gt
    dummy_localId = int(list(fd.iterdir())[0].name.split(".")[1])
    pname = getPname(dummy_localId)
    if pname == False:
        return False
    _,info2 = get_projectInfo(dummy_localId,pname)
    protocol = info2['type']
    
    '''
    1. Why not do all the commits? 
        -> Too long time.
    2. Why not do all the commits between start and end? 
        -> There is no big advantage I can see.
    '''
    # 2. Probe: reset then try to apply bug patches
    for commit in meta:
        if commit in finished:
            INFO(f"[+] Skip {commit}")
            continue
        gt = GitTool(info2['url'],protocol,commit)
        if not gt:
            continue
        # git apply path/to/patchfile.patch
        ct  = 0 
        done = []
        # select the possible patches to apply
        for diff_file in fd.iterdir():
            cur_try = diff_file.name.split(".")[0]
            if cur_try not in done:
                done.append(cur_try)
                if(gt.patch(diff_file)==True):
                    ct+=1
        
        if LOG_OUTPUT:
            LOG_OUTPUT.write(f"[+] Pname: {pname} Commit: {commit} DryRun: {ct}\n")
        INFO(f"[+] Pname: {pname} Commit: {commit} DryRun: {ct}")
        # Compile with Mounting
        localId = meta[commit][0] # Just a random one
        repo_dir = gt.repo
        srcmap,issue = getIssueTuple(localId)
        srcmap =  srcmap[0]
        build_res = silentRun(build_from_srcmap,srcmap,issue,replace_dep=[pname,repo_dir])
        # build_res = build_from_srcmap(srcmap,issue,replace_dep=[pname,repo_dir])
        if not build_res:
            if(RM_IMAGES):
                remove_oss_fuzz_img(localId)
            shutil.rmtree(gt.repo)
            if LOG_OUTPUT:
                LOG_OUTPUT.write(f"[+] Pname: {pname} Commit: {commit} Failed to compile\n")
            FAIL(f"[+] Pname: {pname} Commit: {commit} Failed to compile")
            continue
        ct = 0
        for poc in pocs:
            idx = pocs.index(poc)
            not_crash = silentRun(crashVerify,issue,poc,tag=f"BreakingBadBinary_{commit}_{idx}",timeout=30)
            if not_crash == True:
                ct+=0
            else:
                ct+=1
        
        if LOG_OUTPUT:
            LOG_OUTPUT.write(f"[+] Pname: {pname} Commit: {commit} Reproduced: {ct}\n")
        INFO(f"[+] Pname: {pname} Commit: {commit} Reproduced: {ct}")
        # Dedup
        uniq = verifyCrahes(glob(f"./Log/FuzzerExecution/{localId}_BreakingBadBinary_{commit}_*"))
        if uniq:
            INFO(f"[+] Pname: {pname} Commit: {commit} Dedup: {len(uniq)}")
            if LOG_OUTPUT:
                LOG_OUTPUT.write(f"[+] Pname: {pname} Commit: {commit} Dedup: {len(uniq)}\n")
        
        shutil.rmtree(gt.repo)
        check_call(['sudo',"rm","-rf",str(OSS_OUT/str(localId))])
        check_call(['sudo',"rm","-rf",str(OSS_WORK/str(localId))])
def analyzeBBB(meta,pocs,fd,commit,LOG_OUTPUT=None):
    # 1. create gt
    dummy_localId = int(list(fd.iterdir())[0].name.split(".")[1])
    pname = getPname(dummy_localId)
    if pname == False:
        return False
    _,info2 = get_projectInfo(dummy_localId,pname)
    protocol = info2['type']
    gt = GitTool(info2['url'],protocol,commit)
    if not gt:
        return False
    # 2. Try to apply bug patches
    ct  = 0 
    done = []
    for diff_file in fd.iterdir():
        cur_try = diff_file.name.split(".")[0]
        if cur_try not in done:
            done.append(cur_try)
            if(gt.patch(diff_file)==True):
                ct+=1
    if LOG_OUTPUT:
        LOG_OUTPUT.write(f"[+] Pname: {pname} Commit: {commit} DryRun: {ct}\n")
    INFO(f"[+] Pname: {pname} Commit: {commit} DryRun: {ct}")

    all_localIds =  []
    for x in meta:
        all_localIds+=meta[x]
    # 3. Compile
    localId = meta[commit][0] # Just a random one
    repo_dir = gt.repo
    srcmap,issue = getIssueTuple(localId)
    srcmap =  srcmap[0]
    build_res = silentRun(build_from_srcmap,srcmap,issue,replace_dep=[pname,repo_dir])
    if not build_res:
        if(RM_IMAGES):
            remove_oss_fuzz_img(localId)
        if(CLEAN_TMP):
            shutil.rmtree(gt.repo)
        if LOG_OUTPUT:
            LOG_OUTPUT.write(f"[+] Pname: {pname} Commit: {commit} Failed to compile\n")
        FAIL(f"[+] Pname: {pname} Commit: {commit} Failed to compile")
        return False
    ct  = 0 
    for poc in pocs:
        idx = poc.name.split(".")[0]
        crash_type = getReport(int(idx))['crash_type']
        tmp_uuv = True if "uninitialized-value" in crash_type else False
        print(idx,tmp_uuv)
        not_crash = silentRun(crashVerify,issue,poc,tag=f"BBB_{commit}_{idx}",timeout=30,UUV=tmp_uuv)
        if not_crash == True:
            ct+=0
        else:
            ct+=1
    if LOG_OUTPUT:
        LOG_OUTPUT.write(f"[+] Pname: {pname} Commit: {commit} Reproduced: {ct}\n")
    INFO(f"[+] Pname: {pname} Commit: {commit} Reproduced: {ct}")
    shutil.rmtree(gt.repo)
    with open("/dev/null",'w') as f:
        check_call(['sudo',"rm",str(OSS_TMP/"oss-out"/str(localId))],stdout=f,stderr=f)
        check_call(['sudo',"rm",str(OSS_TMP/"oss-work"/str(localId))],stdout=f,stderr=f)
    uniq = verifyCrahes(glob(f"./Log/FuzzerExecution/{localId}_BBB_{commit}_*"))
    return len(uniq)
def verifyCrahes(crashList):
    uniq = []
    for item in crashList:
        res = parseCrash(Path(item))
        if res == None:
            continue
        uniq.append(res[1])
    uniq = set(uniq)
    return uniq
def fetchBugs(pname='mupdf',work_dir = None,LOG_OUTPUT=None,probe=None):
    if LOG_OUTPUT and not LOG_OUTPUT.exists():
        LOG_OUTPUT.touch()
        dump_log = open(LOG_OUTPUT,'w')
        finished = []
    else:
        with open(LOG_OUTPUT,"r") as f:
            lines = f.readlines()
        finished = []
        for x in lines:
            if "Reproduced" in x:
                hash_val = x.split("Commit: ")[1].split(" ")[0]
                finished.append(hash_val)
        dump_log = open(LOG_OUTPUT,'a')
    fd = work_dir if work_dir else tmpDir()
    fd.mkdir(exist_ok=True,parents=True)
    done = getDone()
    
    done = [ x for x in listProject(pname) if x in done]
    # Trial of remove shallow bugs
    done = [ x for x in done if getReport(x) and getReport(x)['crash_type']!='Use-of-uninitialized-value']
    if len(done) != len(list(fd.iterdir())):
        for x in done:
            fixCommit   = getFixCommit(x)
            if fixCommit == False:
                continue
            if isinstance(fixCommit,list):
                fixCommit = fixCommit[-1]
            fname = f"{fixCommit}.{x}.rev.diff"
            if (fd/fname).exists():
                continue
            revDiffFile = getRevDiff(x)
            shutil.copy(revDiffFile,fd/fname)
            shutil.rmtree(revDiffFile.parent)
    if LOG_OUTPUT:
        dump_log.write("Initialized the Meta Data for AIO\n")
        dump_log.write(f"Project: {pname}\n")
    INFO("Initialized the Meta Data for AIO")
    WARN(f"Project: {pname}")
    # 2. Deduplication
    meta = {}
    for x in list(fd.iterdir()):
        commit = x.name.split('.')[0]
        localId = int(x.name.split('.')[1])
        if commit not in meta:
            meta[commit] =  [localId]
        else:
            meta[commit]+=  [localId]
    if LOG_OUTPUT:
        dump_log.write(f"Found {len(meta)} issues AFTER Deduplication\n")
    WARN(f"Found {len(meta)} issues AFTER Deduplication")
    # 3. Spwan the Breaking Bad Binary
    POC_DIR = ARVO/ "Log" / "AIO_POC" / pname
    if not POC_DIR.exists():
        pocs = [ (x,getPoc(x)) for x in done ]
        pocs = [ x for x in pocs if x[1] ]
        POC_DIR.mkdir(parents=True)
        for x in pocs:
            shutil.copyfile(x[1],POC_DIR/f"{x[0]}.poc")
            shutil.rmtree(x[1].parent)
    pocs = list(POC_DIR.iterdir())
    if LOG_OUTPUT:
        dump_log.write(f"Spwaning the Breaking Bad Binary\n")
    INFO(f"Spwaning the Breaking Bad Binary")
    res = None
    if not probe:
        if doSpawn(meta,pocs,fd,dump_log,finished) == False:
            panic(f"Failed to spawn {localId}")
    else:
        res = analyzeBBB(meta,pocs,fd,probe,dump_log)
        if not res:
            panic(f"Failed to analyzeBBB {commit}")
    
    if LOG_OUTPUT:
        dump_log.write(str(fd.absolute()))
        dump_log.write("\n")
    dump_log.close()
    INFO(fd)
    return res
done_pj = {
    "freetype2": 14,
    "json": 4,
    "file": 24,
    "lcms": 42,
    "pcre2": 22,
    "libreoffice": 10,
    "ots": 9,
    "libxml2": 84,
    "grpc": 7,
    "wireshark": 97,
    "gnutls": 31,
    "ffmpeg": 383,
    "gdal": 175,
    "harfbuzz": 148,
    "libpsl": 4,
    "librawspeed": 58,
    "libteken": 1,
    "expat": 4,
    "h2o": 5,
    "boringssl": 9,
    "openthread": 63,
    "openjpeg": 4,
    "proj4": 11,
    "openssl": 7,
    "wpantund": 4,
    "zstd": 13,
    "open62541": 59,
    "libpng": 1,
    "yara": 32,
    "tpm2": 3,
    "curl": 19,
    "gstreamer": 7,
    "unrar": 20,
    "imagemagick": 469,
    "mupdf": 82,
    "skia": 161,
    "bloaty": 3,
    "irssi": 5,
    "skcms": 5,
    "botan": 3,
    "resiprocate": 1,
    "graphicsmagick": 130,
    "tor": 2,
    "poppler": 40,
    "capstone": 30,
    "libaom": 23,
    "openvswitch": 26,
    "radare2": 27,
    "xmlsec": 1,
    "unicorn": 21,
    "libssh": 1,
    "libgit2": 11,
    "libarchive": 24,
    "tinyxml2": 1,
    "libidn2": 2,
    "readstat": 8,
    "kimageformats": 56,
    "libpng-proto": 1,
    "perfetto": 16,
    "gnupg": 1,
    "picotls": 2,
    "lwan": 18,
    "wget2": 5,
    "net-snmp": 21,
    "karchive": 16,
    "mbedtls": 4,
    "libspng": 7,
    "libpcap": 3,
    "leptonica": 32,
    "c-ares": 8,
    "hostap": 5,
    "icu": 16,
    "mruby": 83,
    "libxslt": 36,
    "libsass": 4,
    "lz4": 4,
    "clamav": 8,
    "libvips": 56,
    "flac": 16,
    "libavc": 52,
    "aspell": 3,
    "postgis": 3,
    "libmpeg2": 6,
    "opensc": 122,
    "libhevc": 25,
    "matio": 64,
    "ghostscript": 153,
    "libfdk-aac": 4,
    "usrsctp": 9,
    "jbig2dec": 7,
    "php": 117,
    "jsoncpp": 2,
    "htslib": 23,
    "binutils": 155,
    "qpdf": 10,
    "ndpi": 146,
    "libheif": 11,
    "samba": 16,
    "uwebsockets": 24,
    "libspectre": 6,
    "njs": 19,
    "wavpack": 4,
    "llvm": 22,
    "arrow": 41,
    "wabt": 9,
    "janus-gateway": 1,
    "stb": 8,
    "libucl": 9,
    "libfmt": 3,
    "oniguruma": 11,
    "fluent-bit": 68,
    "libzmq": 4,
    "envoy": 29,
    "pcapplusplus": 58,
    "rdkit": 37,
    "firestore": 2,
    "muparser": 7,
    "libraw": 48,
    "json-c": 1,
    "haproxy": 3,
    "c-blosc2": 91,
    "hermes": 2,
    "hoextdown": 1,
    "c-blosc": 3,
    "glib": 7,
    "immer": 2,
    "rnp": 7,
    "assimp": 55,
    "arduinojson": 1,
    "libavif": 4,
    "util-linux": 3,
    "sleuthkit": 35,
    "alembic": 3,
    "libsndfile": 10,
    "nginx": 2,
    "openexr": 13,
    "opencv": 6,
    "wolfssl": 100,
    "libcoap": 4,
    "libass": 2,
    "miniz": 5,
    "simdjson": 7,
    "libjpeg-turbo": 14,
    "libtiff": 3,
    "draco": 9,
    "serenity": 83,
    "dropbear": 1,
    "selinux": 37,
    "mongoose": 9,
    "mdbtools": 8,
    "hiredis": 1,
    "qt": 15,
    "igraph": 8,
    "valijson": 3,
    "fio": 2,
    "lua": 4,
    "libssh2": 5,
    "relic": 10,
    "sudoers": 7,
    "wolfmqtt": 37,
    "libusb": 1,
    "flatbuffers": 10,
    "tesseract-ocr": 2,
    "tmux": 3,
    "p11-kit": 3,
    "md4c": 6,
    "libiec61850": 2,
    "libredwg": 76,
    "freeimage": 8,
    "gpac": 52,
    "pcl": 24,
    "wuffs": 1,
    "lxc": 7,
    "wasm3": 38,
    "geos": 5,
    "jsoncons": 3,
    "bitcoin-core": 10,
    "cpython3": 4,
    "dovecot": 1,
    "duckdb": 12,
    "espeak-ng": 16,
    "tinygltf": 4,
    "vlc": 4,
    "fribidi": 2,
    "pidgin": 1,
    "libjxl": 37,
    "libwebp": 1,
    "re2": 1,
    "dnsmasq": 15,
    "h3": 4,
    "rapidjson": 1,
    "libtpms": 2,
    "tidy-html5": 1,
    "apache-httpd": 3,
    "spice-usbredir": 4,
    "knot-dns": 2,
    "libexif": 11,
    "libgd": 1,
    "kamailio": 8,
    "dav1d": 8,
    "freeradius": 18,
    "libsrtp": 1,
    "s2geometry": 1,
    "brunsli": 2,
    "tint": 8,
    "gdbm": 1,
    "mysql-server": 7,
    "opensips": 10,
    "libbpf": 7,
    "libdwarf": 34,
    "qpid-proton": 2,
    "clickhouse": 7,
    "elfutils": 10,
    "simd": 1,
    "libplist": 10,
    "bls-signatures": 1,
    "fmt": 2,
    "systemd": 4,
    "exiv2": 10,
    "quickjs": 5,
    "ostree": 1,
    "xs": 4,
    "libical": 1,
    "libvpx": 4,
    "libwebsockets": 1,
    "e2fsprogs": 1,
    "s2opc": 2,
    "zlib": 1,
    "osquery": 1,
    "bluez": 1,
    "hunspell": 35,
    "cyclonedds": 5,
    "upb": 1,
    "mapserver": 7,
    "ntpsec": 3,
    "coturn": 2,
    "krb5": 5,
    "skia-ftz": 20,
    "lldpd": 3,
    "gpsd": 2,
    "msquic": 1,
    "trafficserver": 3,
    "cryptofuzz": 3,
    "cups": 1,
    "pjsip": 4,
    "zeek": 8,
    "nodejs": 1,
    "hdf5": 19,
    "libzip": 1,
    "mosquitto": 9,
    "rabbitmq-c": 1,
    "glog": 4,
    "croaring": 2,
    "qemu": 4,
    "simdutf": 5,
    "python3-libraries": 2,
    "faad2": 6,
    "libecc": 2,
    "tcmalloc": 2,
    "nccl": 1,
    "open5gs": 1,
    "ntopng": 21,
    "freerdp": 1,
    "liblouis": 1,
    "tarantool": 3,
    "jq": 4,
    "oss-fuzz-example": 1,
    "libxaac": 17,
    "wasmedge": 3,
    "bind9": 1,
    "libultrahdr": 2,
    "pigweed": 1,
    "upx": 14
}
todo = ["lcms","libxml2","wireshark","ffmpeg","gdal","librawspeed","openthread","open62541","imagemagick","skia","graphicsmagick","poppler","kimageformats","mruby","libxslt","libvips","libavc","opensc","matio","ghostscript","php","binutils","ndpi","arrow","fluent-bit","pcapplusplus","rdkit","libraw","c-blosc2","assimp","sleuthkit","wolfssl","serenity","selinux","wolfmqtt","libredwg","gpac","wasm3","libjxl","libdwarf","hunspell"]
if __name__=='__main__':
    pass