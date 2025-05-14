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


if __name__ == "__main__":
  pass
