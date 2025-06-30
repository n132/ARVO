# ARVO

ARVO: an Atlas of Reproducible Vulnerabilities in
Open source software.

By sourcing vulnerabilities from C/C++ projects that [Google’s OSS-Fuzz][2] discovered and
implementing a reliable re-compilation system, we successfully reproduce more than 5,000 memory vulnerabilities across over 250 projects (May 2024), each with a triggering input, the canonical developer-written patch for fixing the vulnerability, and the ability to automatically rebuild the project from source and run it at its vulnerable and patched revisions. Moreover, our dataset can be automatically updated as OSS-Fuzz finds new vulnerabilities, allowing it to grow over time. We provide a thorough characterization of the ARVO dataset, and show that it can locate fixes more accurately than Google’s own OSV reproduction effort.

# 🚀 Quickstart via Docker (Recommended)

If you need the interactive docker images:

```shell
# Reproduce Vul/Fix
docker run --rm -it n132/arvo:42487096-vul arvo
docker run --rm -it n132/arvo:42487096-fix arvo
# Re-compile Vul/Fix
docker run --rm -it n132/arvo:42487096-vul arvo compile 
docker run --rm -it n132/arvo:42487096-fix arvo compile
```

ARVO metadata and dataset is store in: [ARVO-meta][3]

# 🛠️ Rebuild the Database (Optional)

See [GitHub Action Example][4] for an example of the database rebuild. Full functionality requires:

- Google Cloud SDK (gcloud)
- Filling in arvo/_profile.py with credentials
- OSS-Fuzz metadata (included in this repo but not including recent bugs)

An example of rebuilding case-42487096:
```sh
git clone https://github.com/n132/ARVO.git
cd ARVO
python3 -m venv arvo-run # create the venv
source ./arvo-run/bin/activate # enable venv
pip3 install -e . # install arvo
cp ./profile.template ./arvo/_profile.py
cp ./.github/workflows/base-builder_cache.json /tmp/
sed -i "s|/src/ARVO/arvo|$(pwd)/arvo|g" ./arvo/_profile.py
arvo report 25402 # regenerate the report
```

# 🐞 Bug Report/Fix
- Open an issue/pr for this repo
- MSAN has a bug that makes some bugs not reproducible while ASLR is on.


[2]: https://github.com/google/oss-fuzz
[3]: https://github.com/n132/ARVO-Meta
[4]: https://github.com/n132/ARVO/blob/main/.github/workflows/arvo-ci.yml
[5]: https://github.com/google/oss-fuzz/issues/12732
