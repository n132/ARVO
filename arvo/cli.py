import argparse
import json
import sys
from pathlib import Path
from .reproducer import verify
from .utils import *
from .Locator import report
from .utils_log import *

def cli_reproduce(localId):
    res = verify(localId, False)
    if res:
        out = OSS_IMG / f"{localId}"
        print(f"[+] Successfully reproduced {localId=}, see: {out}")
        return out
    else:
        print("[-] Failed to Reproduce")
        return False

def cli_report(localId):
    target = Path(f"./Reports/{localId}.json")
    if target.exists():
        print(f"[+] Report exists: {target}")
        return json.loads(target.read_text())
    res = report(localId)
    if res:
        print(f"[+] Generated report: {target}")
        return json.loads(target.read_text())
    else:
        print("[-] Failed to Report")
        return False
def cli_list(pname):
    res = listProject(pname)
    if not res:
        WARN(f"Not found, check the provided project name {pname=}")
    else:
        print(res)
def cli_check_localId(localId):
    reproduciable = True if localId in getDone() else False
    patch_located = True if localId in getReports() else False
    pname = getPname(localId)
    INFO(f"{pname=} {localId=}")
    if reproduciable:
        SUCCESS("Reproduced: \tTrue")
    else:
        WARN("Reproduced: \tFalse")
    if patch_located:
        SUCCESS("Patch Located: \tTrue")
    else:
        WARN("Patch Located: \tFalse")
def cli_check(localId_project):
    if localId_project.isdigit():
        localId = int(localId_project)
        cli_check_localId(localId)
    else:
        pname = localId_project
        for x in listProject(pname):
            cli_check_localId(x)
    
def cli_show(localId):
    res = getReport(localId)
    if not res:
        WARN(f"No Report Found for {localId=}")
    else:
        print(json.dumps(res,indent=4))
def cli_summary():
    pass
    # done            = getDone()
    # reports         = getReports()
    # cache = {'libxml2': 112, 'pcre2': 55, 'file': 40, False: 173, 'icu': 25, 'freetype2': 21, 'gnutls': 57, 'json': 11, 'libreoffice': 359, 'libarchive': 44, 'grpc': 26, 'ffmpeg': 532, 'libvpx': 7, 'lcms': 48, 'nss': 1, 'ots': 16, 'libe-book': 5, 'libabw': 5, 'wireshark': 112, 'libetonyek': 13, 'tpm2': 4, 'gdal': 364, 'harfbuzz': 171, 'opus': 11, 'libpsl': 7, 'librawspeed': 63, 'libteken': 1, 'expat': 4, 'h2o': 6, 'boringssl': 13, 'openthread': 74, 'llvm_libcxxabi': 7, 'wget2': 9, 'strongswan': 2, 'openjpeg': 7, 'openssl': 16, 'llvm': 58, 'proj.4': 13, 'libwps': 2, 'libqxp': 9, 'wpantund': 6, 'zstd': 15, 'libmwaw': 1, 'curl': 54, 'open62541': 71, 'libpng': 1, 'libcxx': 1, 'yara': 48, 'gstreamer': 9, 'tor': 3, 'unrar': 24, 'boost': 5, 'imagemagick': 570, 'mupdf': 100, 'skia': 246, 'bloaty': 4, 'irssi': 6, 'skcms': 5, 'botan': 6, 'resiprocate': 1, 'systemd': 36, 'graphicsmagick': 147, 'envoy': 92, 'poppler': 88, 'capstonemaster': 1, 'capstonenext': 34, 'aom': 27, 'libwebp': 10, 'openvswitch': 37, 'freetype2-testing': 30, 'glib': 17, 'zlib-ng': 3, 'libstaroffice': 2, 'radare2': 69, 'unicorn': 54, 'libssh': 3, 'libgit2': 11, 'zlib': 3, 'dav1d': 45, 'tinyxml2': 1, 'libidn2': 2, 'readstat': 10, 'kimageformats': 62, 'libprotobuf-mutator': 1, 'openh264': 56, 'perfetto': 26, 'gnupg': 2, 'php-src': 161, 'tessdata': 2, 'picotls': 2, 'openbsd': 4, 'karchive': 18, 'lwan': 20, 'cryptofuzz': 134, 'net-snmp': 25, 'libical': 6, 'qtbase': 1, 'mbedtls': 6, 'libspng': 11, 'hostap': 13, 'nestegg': 1, 'njs': 46, 'libpcap': 6, 'leptonica': 34, 'c-ares': 9, 'qpdf': 12, 'mruby': 92, 'libxslt': 30, 'libsass': 5, 'lz4': 7, 'clamav-devel': 11, 'aspell': 11, 'libvips': 61, 'flac': 26, 'libavc': 59, 'postgis': 3, 'libtiff': 4, 'libmpeg2': 8, 'opensc': 134, 'libhevc': 29, 'libssh2': 12, 'matio': 107, 'ghostpdl': 230, 'aac': 4, 'cpython': 1, 'oss-fuzz-fuzzers': 16, 'libtheora': 2, 'usrsctp': 10, 'jbig2dec': 10, 'jsoncpp': 2, 'htslib': 27, 'binutils-gdb': 197, 'osquery': 10, 'mysql-server': 29, 'ndpi': 161, 'libheif': 26, 'firebase-ios-sdk': 5, 'neomutt': 3, 'wabt': 25, 'samba': 17, 'uWebSockets': 33, 'libspectre': 6, 'wavpack': 4, 'llvm-project': 34, 'unbound': 2, 'arrow': 76, 'rapidjson': 3, 'fuzzdata': 1, 'qt': 33, 'janus-gateway': 1, 'extra-cmake-modules': 1, 'fuzzing-headers': 2, 'esp-v2': 1, 'libressl': 8, 'stb': 14, 'clamav-fuzz-corpus': 1, 'libcbor': 2, 'quickjs': 23, 'libucl': 22, 'solidity': 2, 'fmt': 12, 'libsodium': 3, 'libzmq': 8, 'oniguruma': 12, 'libavif': 14, 'fluent-bit': 91, 'PcapPlusPlus': 91, 'libusb': 2, 'keystone': 10, 'rdkit': 47, 'tremor': 1, 'muparser': 8, 'libraw': 71, 'git': 4, 'draco': 15, 'minizip': 2, 'dovecot': 3, 'monero': 5, 'json-c': 1, 'haproxy': 4, 'c-blosc2': 102, 'hermes': 2, 'hoextdown': 1, 'c-blosc': 3, 'libevt': 1, 'immer': 5, 'rnp': 7, 'libscca': 2, 'libfwnt': 1, 'libqcow': 3, 'assimp': 97, 'libvmdk': 8, 'nanopb': 3, 'arduinojson': 2, 'libfshfs': 6, 'openexr': 46, 'util-linux': 3, 'libyaml': 1, 'sleuthkit': 56, 'libvslvm': 4, 'alembic': 4, 'libsndfile': 13, 'nginx': 3, 'astc-encoder': 3, 'opencv': 9, 'wolfssl': 127, 'libcoap': 4, 'zeek': 28, 'libass': 2, 'miniz': 7, 'qemu': 63, 'exprtk': 7, 'simdjson': 11, 'grok': 48, 'librdkafka': 3, 'libjpeg-turbo': 9, 'serenity': 128, 'gdk-pixbuf': 12, 'zydis': 1, 'dropbear': 2, 'selinux': 49, 'mongoose': 9, 'mdbtools': 9, 'hiredis': 3, 'libfido2': 1, 'igraph': 14, 'valijson': 3, 'fio': 2, 'lua': 7, 'tesseract': 3, 'relic': 14, 'sudo': 12, 'wolfmqtt': 46, 'flatbuffers': 19, 'ogg': 1, 'fwupd': 16, 'tmux': 3, 'p11-kit': 4, 'md4c': 6, 'libiec61850': 2, 'w3m': 3, 'libredwg': 128, 'libyang': 16, 'freeimage-svn': 9, 'gpac': 84, 'pcl': 37, 'wuffs': 1, 'lxc': 8, 'openbabel': 3, 'tinygltf': 5, 'wasm3': 47, 'jasper': 3, 'geos': 12, 'jsoncons': 3, 'libvshadow': 4, 'libpg_query': 1, 'bitcoin-core': 26, 'cpython3': 6, 'libecc': 1, 'libmodi': 4, 'duckdb': 16, 'espeak-ng': 16, 'vlc': 20, 'fribidi': 3, 'openweave-core': 1, 'Simd': 3, 'fuzzing': 2, 'libjxl': 47, 'netcdf-c': 3, 'libigl': 2, 're2': 1, 'dnsmasq': 20, 'h3': 4, 'openvpn': 2, 'libtpms': 3, 'libfsxfs': 2, 'frr': 15, 'tidy-html5': 1, 'httpd': 7, 'spice-usbredir': 4, 'knot-dns': 2, 'libexif': 13, 'ClickHouse': 10, 'libgd': 1, 'tdengine': 2, 'kamailio': 12, 'gdbm': 2, 'freeradius-server': 20, 'libsrtp': 2, 'spirv-tools': 14, 's2geometry': 1, 'brunsli': 2, 'tint': 6, 'opensips': 10, 'libbpf': 13, 'libdwarf': 42, 'qpid-proton': 3, 'elfutils': 15, 'binutils-preconditions': 6, 'libwrc': 1, 'tcmalloc': 5, 'Little-CMS': 1, 'qtqa': 2, 'clamav': 16, 'libplist': 13, 'mcl': 1, 'freetype': 2, 'upb': 9, 'exiv2': 11, 'ostree': 2, 'moddable': 7, 'dawn': 4, 'ruby': 42, 'libwebsockets': 1, 'e2fsprogs': 2, 'S2OPC': 2, 'libsmraw': 2, 'libjpeg-turbo.dev': 5, 'libewf': 4, 'trezor-firmware': 6, 'centipede': 1, 'hunspell': 36, 'libodraw': 2, 'cyclonedds': 6, 'bluez': 1, 'MapServer': 7, 'ntpsec': 2, 'oss-fuzz-bloat': 3, 'coturn': 2, 'krb5': 5, 'lldpd': 4, 'gpsd': 5, 'msquic': 1, 'cryptsetup': 4, 'unit': 3, 'jwt_verify_lib': 1, 'trafficserver': 9, 'cups': 5, 'pjsip': 5, 'node': 1, 'hdf5': 27, 'libzip': 2, 'libjpeg-turbo.main': 8, 'libfsapfs': 1, 'mosquitto': 10, 'librabbitmq': 1, 'glog': 4, 'croaring': 2, 'simdutf': 7, 'libregf': 1, 'python-library-fuzzers': 3, 'faad2': 6, 'ada-url': 1, 'nccl': 2, 'liblouis': 2, 'open5gs': 1, 'ntopng': 22, 'qt/qtqa': 5, 'FreeRDP': 8, 'libjpeg-turbo.2.1.x': 1, 'libjpeg-turbo.2.0.x': 2, 'tarantool': 9, 'jq': 7, 'oss-fuzz-example': 1, 'flex': 3, 'libxaac': 23, 'noble-secp256k1': 1, 'WasmEdge': 4, 'glslang': 10, 'bind9': 1, 'libultrahdr': 6, 'testdir': 1, 'pigweed': 5, 'upx': 14, 'wt': 1, 'inchi': 15, 'libvsgpt': 1, 'libspdm': 5, 'LibRaw': 1, 'ninja': 4, 'speex': 3, 'xz': 2, 'edk2': 7, 'mpv': 7, 'spicy': 1, 'pacemaker': 1, 'libcups': 2, 'wamr': 2, 'llama.cpp': 1, 'rtpproxy': 3}
    # for pname in cache:
    #     proj_issues = listProject(x)
    #     print(f"{x:<20}: Failed on {failed:<8} out of {all_issues[x]:<8} issues")
    #     for localId in proj_issues:
    #         reproduced = "True" if localId in done else "False"
    #         reported   = "True" if localId in reports else "False"

    #         print(f"{localId} | {reproduced} | {reported} | {}")
def main():
    parser = argparse.ArgumentParser(prog="arvo", description="ARVO CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # reproduce
    p_reproduce = subparsers.add_parser("reproduce", help="Reproduce a bug")
    p_reproduce.add_argument("localId", type=int)

    # report
    p_report = subparsers.add_parser("report", help="Generate a report")
    p_report.add_argument("localId", type=int)

    # list
    p_list = subparsers.add_parser("list", help="List the localIds belong to a specific project in meta")
    p_list.add_argument("pname", type=str)

    # check status
    p_check = subparsers.add_parser("check", help="Check the reproducing status")
    p_check.add_argument("localId_project", type=str)

    # show report
    p_show = subparsers.add_parser("show", help="Print the report")
    p_show.add_argument("localId", type=int)

    # summary
    p_summary = subparsers.add_parser("summary", help="Print the summary of current reproducing process")

    args = parser.parse_args()

    if args.command == "reproduce":
        cli_reproduce(args.localId)
    elif args.command == "report":
        cli_report(args.localId)
    elif args.command == "list":
        cli_list(args.pname)
    elif args.command == "check":
        cli_check(args.localId_project)
    elif args.command == "show":
        cli_show(args.localId)
    elif args.command == 'summary':
        cli_summary()

if __name__ == "__main__":
    main()
