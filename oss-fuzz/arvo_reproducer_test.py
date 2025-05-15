"""
Test the functionality of the arvo reprodcer.
The will consist of the following functional tests:
  1. The functionality of reproducer components.
  2. The building of a projects fuzzers from a vulnerability found on OSS-Fuzz.
"""

import tempfile
import unittest
from pathlib import Path
from arvo_utils import *
from arvo_reproducer import *

warnings.filterwarnings("ignore",
                        category=UserWarning,
                        module="google.auth._default")
REPRODUCE_TEST_LOCALID = 42487096
UNITEST_LOCALID = 42498388


class arvoReproducingTest(unittest.TestCase):

  def test_reproduce(self):
    res = arvo_reproducer(REPRODUCE_TEST_LOCALID, 'vul')
    self.assertEqual(res, True)
    case_dir = Path(tempfile.mkdtemp())
    issue = fetch_issue(REPRODUCE_TEST_LOCALID)  # TODO, refactor a fast way
    download_poc(issue, case_dir, "crash_case")
    (case_dir / "stderr").touch()
    with open(case_dir / "stderr", 'wb') as f:
      res = execute([
          f'/tmp/{REPRODUCE_TEST_LOCALID}_OUT/set_eval_fuzzer',
          case_dir / "crash_case"
      ],
                    stdout=f,
                    stderr=f)
    with open(case_dir / "stderr", 'rb') as f:
      crash_info = f.read()
    self.assertEqual(
        b"SUMMARY: AddressSanitizer: heap-buffer-overflow /src/muparser/src/muParserBase.cpp"
        in crash_info, True)
    shutil.rmtree(case_dir)


class arvoUnitTests(unittest.TestCase):

  def test_fetch_issue(self):
    """Test if we can get issues from OSS-Fuzz"""
    issue_CVE_2021_38593 = {
        'project':
            'qt',
        'job_type':
            'libfuzzer_asan_i386_qt',
        'platform':
            'linux',
        'crash_type':
            'UNKNOWN WRITE',
        'crash_address':
            '0x10000000',
        'severity':
            'High',
        'regressed':
            'https://oss-fuzz.com/revisions?job=libfuzzer_asan_i386_qt&range=202106240616:202106250624',
        'reproducer':
            'https://oss-fuzz.com/download?testcase_id=6379642528333824',
        'verified_fixed':
            'https://oss-fuzz.com/revisions?job=libfuzzer_asan_i386_qt&range=202107280604:202107290609',
        'localId':
            42498388,
        'sanitizer':
            'address',
        'fuzz_target':
            'qtsvg_svg_qsvgrenderer_render'
    }
    issue = fetch_issue(UNITEST_LOCALID)
    self.assertEqual(issue_CVE_2021_38593, issue)

  def test_download_poc(self):
    """Test if we can download pocs"""
    issue = fetch_issue(UNITEST_LOCALID)
    case_dir = Path(tempfile.mkdtemp())
    res = download_poc(issue, case_dir, "crash_case")
    self.assertEqual(res.name, "crash_case")
    shutil.rmtree(case_dir)

  def test_rebase_dockerfile(self):
    """Test if we get the historical dockerfile and rebase the dockerfile"""
    commit_date = datetime.strptime("202409200607" + " +0000", '%Y%m%d%H%M %z')
    res = prepare_ossfuzz("libxml2", commit_date)
    commit_date = str(commit_date).replace(" ", "-")
    rebase_res = rebase_dockerfile(res[1] / "Dockerfile", commit_date)
    self.assertEqual(rebase_res, True)
    shutil.rmtree(res[0])


if __name__ == '__main__':
  unittest.main()
