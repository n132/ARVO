from ._profile      import *
import os, json
from pathlib        import Path
#==================================================================
#
#                          Global Settings
#
#==================================================================
REBUTTAL_EXP = False
DEBUG = DEBUG


STAMP_DELAY = "-0300"
# Options: oss-fuzz/infra/base-images/base-runner/Dockerfile
ASAN_OPTIONS    =   'ASAN_OPTIONS=alloc_dealloc_mismatch=0:allocator_may_return_null=1:allocator_release_to_os_interval_ms=500:check_malloc_usable_size=0:detect_container_overflow=1:detect_odr_violation=0:detect_leaks=0:detect_stack_use_after_return=1:fast_unwind_on_fatal=0:handle_abort=1:handle_segv=1:handle_sigill=1:max_uar_stack_size_log=16:print_scariness=1:quarantine_size_mb=10:strict_memcmp=1:strip_path_prefix=/workspace/:symbolize=1:use_sigaltstack=1:dedup_token_length=3'
MSAN_OPTIONS    =   'MSAN_OPTIONS=print_stats=1:strip_path_prefix=/workspace/:symbolize=1:dedup_token_length=3'
UBSAN_OPTIONS   =   'UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:silence_unsigned_overflow=1:strip_path_prefix=/workspace/:symbolize=1:dedup_token_length=3'
FUZZER_ARGS     =   'FUZZER_ARGS="-rss_limit_mb=2560 -timeout=25"'
AFL_FUZZER_ARGS =   'AFL_FUZZER_ARGS="-m none"'

os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = gcloud_key
OSS_TMP     = Path(TMP)
ARVO        = Path(ARVO_DIR)
REPORTS_DIR = Path(REPORTS_DIR)
OSS_OUT     = Path(OSS_OUT_DIR)
OSS_WORK    = Path(OSS_WORK_DIR)
OSS_IMG     = Path(OSS_SAVED_IMG)
OSS_LOCK    = Path(OSS_LOCK_DIR)
OSS_ERR     = ARVO / 'CrashLog'
ARVO_ZDC    = Path(ZDC)
UserName    = UserName
CLEAN_TMP   = CLEAN_TMP
TIME_ZONE   = TIME_ZONE
DATADIR     = ARVO / NEW_ISSUE_TRACKER if NEW_ISSUE_TRACKER else ARVO / DATA_FOLD
MetaDataFile= DATADIR / "metadata.jsonl"
ExeLog      = ARVO  / "Log" / "FuzzerExecution"
RM_IMAGES   = RM_IMAGES
SORTED_IMAGES  = False
MAPPING     = None
DOCKER_PUSH_QUEUE = Path(DOCKER_PUSH_QUEUE)
with open(ARVO/'PLanguage.json') as f:
    PLanguage = json.loads(f.read())

