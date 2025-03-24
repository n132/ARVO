# ARVO

ARVO: an Atlas of Reproducible Vulnerabilities in
Open source software.

By sourcing vulnerabilities from C/C++ projects that [Google’s OSS-Fuzz][2] discovered and
implementing a reliable re-compilation system, we successfully reproduce more than 5,000 memory vulnerabilities across over 250 projects (May 2024), each with a triggering input, the canonical developer-written patch for fixing the vulnerability, and the ability to automatically rebuild the project from source and run it at its vulnerable and patched revisions. Moreover, our dataset can be automatically updated as OSS-Fuzz finds new vulnerabilities, allowing it to grow over time. We provide a thorough characterization of the ARVO dataset, and show that it can locate fixes more accurately than Google’s own OSV reproduction effort.

# 🚀 Quickstart via Docker (Recommended)

If you only need the metadata (interactive docker images):

```shell
# Reproduce Vul/Fix
docker run --rm -it n132/arvo:25402-vul arvo
docker run --rm -it n132/arvo:25402-fix arvo
# Re-compile Vul/Fix
docker run --rm -it n132/arvo:25402-vul arvo compile 
docker run --rm -it n132/arvo:25402-fix arvo compile
```

More metadata is store in: [ARVO-meta][3]
# 🛠️ Rebuild the Database (Optional)

See [GitHub Action Example][5] for an example of the database rebuild. Full functionality requires:

- Google Cloud SDK (gcloud)
- Filling in _profile.py with credentials
- OSS-Fuzz metadata (currently blocked by [a recent change][5])

# 🔧 Example GitHub Action for ARVO

```yaml
name: ARVO CI
on:
  pull_request:
  workflow_dispatch:

jobs:
  arvo-reproducer-ci:
    runs-on: ubuntu-24.04
    steps:
    - name: Checkout ARVO
      uses: actions/checkout@v3

    - name: Install dependencies
      run: |
        sudo apt-get update && sudo apt-get install -y \
          vim gdb wget curl python3 python3-pip python3.12-venv \
          git-lfs tmux ipython3 lsb-release gnupg

    - name: Setup /src/ARVO
      run: |
        sudo mkdir /src
        sudo cp -a $GITHUB_WORKSPACE /src/ARVO
        sudo chown -R $USER:$USER /src /data

    - name: Clone OSS-Fuzz
      run: git clone https://github.com/google/oss-fuzz.git /src/oss-fuzz

    - name: Setup Python venv
      run: |
        python3 -m venv /src/arvo_venv
        source /src/arvo_venv/bin/activate
        pip install -r /src/ARVO/requirements.txt

    - name: Pull metadata
      run: |
        cd /src/ARVO
        git lfs pull
        cp profile.template _profile.py
        tar -xvf oss_fuzz_meta.tar

    - name: Install docker-cli
      run: |
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
          gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
          https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
          sudo tee /etc/apt/sources.list.d/docker.list
        sudo apt-get update && sudo apt-get install -y docker-ce-cli

    - name: Run ARVO test
      run: |
        source /src/arvo_venv/bin/activate
        cd /src/ARVO
        rm -f ./Reports/25402.json
        python3 ./cli.py report 25402
        grep "322716256d60e316c9a3b905a387be36d4e47368" ./Reports/25402.json
```
# Bug Report/Fix
- Open an issue/pr for this repo


[2]: https://github.com/google/oss-fuzz
[3]: https://github.com/n132/ARVO-Meta
[4]: https://github.com/n132/ARVO-Pub/blob/main/.github/workflows/arvo-ci.yml
[5]: https://github.com/google/oss-fuzz/issues/12732