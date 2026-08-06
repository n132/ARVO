# ARVO

[ARVO: Atlas of Reproducible Vulnerabilities for Open-Source Software](./2026155803.pdf).

```bibtex
@INPROCEEDINGS{11624217,
  author={Mei, Xiang and Castillo, Jordi Del and Singh Singaria, Pulkit and Xi, Haoran and Benchikh, Abdelouahab and Bao, Tiffany and Wang, Ruoyu and Shoshitaishvili, Yan and Doupé, Adam and Pearce, Hammond and Dolan-Gavitt, Brendan},
  booktitle={2026 IEEE 11th European Symposium on Security and Privacy (EuroS&P)}, 
  title={ARVO: Atlas of Reproducible Vulnerabilities for Open-Source Software}, 
  year={2026},
  volume={},
  number={},
  pages={860-873},
  keywords={Fuzzing;Security;Computer bugs;Printing;Software;Manuals;Codes;Accuracy;Labeling;Open source software;vulnerability dataset;reproducibility;open-source software},
  doi={10.1109/EuroSP68448.2026.00060}}
```

The code to generate the ARVO dataset is public on [ARVO][8]. The generated dokcer images and related metadata are updated on [dockerhub][10] and [the release page][9].


## Abstract

Achieving reproducibility, quantity, and diversity in vulnerability datasets has long been viewed as an inherent three-way trade-off, where improving one dimension often comes at the cost of the others. In practice, reproducibility has been the dimension most often neglected. This has limited what can be automatically extracted from historical bug datasets, and has reduced their utility for downstream security research.

In this work, we propose a method to produce a new security dataset which ensures reproducibility for diverse vulnerabilities at scale by identifying the key obstacles to large-scale bug reproduction and addressing them with general solutions. Using this method, we introduce full reproducibility to the largest open source software vulnerability dataset (OSS-Fuzz) and construct the ARVO dataset (an Atlas of Reproducible Vulnerabilities in Open-source software). ARVO is a large-scale dataset consisting of over 6,100 real-world vulnerabilities across 311 projects. Focusing on reproducibility, ARVO differs from existing datasets by providing each vulnerability in a form that can be consistently rebuilt, triggered, and analyzed across versions. Reproducibility also enables automatic identification of the corresponding patch for each vulnerability and supports direct interaction with vulnerabilities after code changes, capabilities that existing large-scale datasets do not provide. In our evaluation, ARVO successfully reproduces 81% of vulnerabilities and achieves 89.4% accuracy on the located patches. We also discuss ARVO's influence on both upstream practices and downstream security research.

## Artifact

- Source code: https://github.com/n132/arvo
- Dataset: https://github.com/n132/ARVO-Meta

## Paper

Accepted at IEEE European Symposium on Security and Privacy (EuroS&P) 2026 

[ARVO paper (PDF)](./2026155803.pdf)

# 🚀 Quickstart via Docker (Recommended)

If you need the interactive Docker images:

```shell
# Reproduce Vul/Fix
docker run --rm -it n132/arvo:42487096-vul arvo
docker run --rm -it n132/arvo:42487096-fix arvo
# Re-compile Vul/Fix
docker run --rm -it n132/arvo:42487096-vul arvo compile 
docker run --rm -it n132/arvo:42487096-fix arvo compile
```

ARVO metadata and dataset are stored in: [ARVO-meta][3]

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
[3]: https://github.com/n132/ARVO-Meta/releases
[4]: https://github.com/n132/ARVO/blob/main/.github/workflows/arvo-ci.yml
[5]: https://github.com/google/oss-fuzz/issues/12732

