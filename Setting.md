
## Basic Setting

Creat `arvo/_profile.py` to init your setting. 

[Example](./profile.template)

- DATA_FOLD: The name to store meta data of OSS-Fuzz cases.
- TIME_ZONE: Your time zone, which is related to reproducing, since it's sensitive to time.
- CLEAN_TMP: If you want to keep tmp files.
- gcloud_key: The oss resource is on gcloud, we need that to download/using APIs from gcloud. 
- oss_fuzz_dir: We need some functions in oss_fuzz_dir, we have almost implemented them in AEVO version, but I think there are still some left
- oss_reproducer_dir: Path of ARVO.

- OPENAI_TOKEN: You don't need it if you don't want to benchmark OpenAI models.
- OSS_LOCK_DIR: Filesystem Level Lock system
- OSS_SAVED_IMG: Path to store compiled cases
- OSS_OUT_DIR: The fold to store the compiled fuzz-targets
- OSS_WORK_DIR:  The fold to store the compiling components
- OSS_DB_DIR: To make compiling faster, we made a hash map to avoid re-download.
- TMP: TMP fold
