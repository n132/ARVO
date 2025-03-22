
## Basic Setting

Creat `_profile.py` to init your setting. 

Example:

```python
# You can keep these settings as default
DATA_FOLD = "Type.Bug-Security_label.Reproducible_status.Verified"
TIME_ZONE = "Etc/Greenwich"
CLEAN_TMP = True
User      = # <Your UserName>
# Config
gcloud_key          = f'/home/{User}/oss-pro-key.json' # Path of your gcloud key
oss_fuzz_dir        = f"/home/{User}/oss-fuzz/" # Path of oss-fuzz
ARVO_DIR            = f"/home/{User}/ARVO/" # Path of ARVO


OPENAI_TOKEN = 'sk-...' # Your OpenAI API key

# Create a tmp directory to Save ARVO data
OSS_LOCK_DIR    = f'/data/{User}/oss-lock/'
OSS_SAVED_IMG   = f'/data/{User}/oss-img/'
OSS_OUT_DIR     = f'/data/{User}/oss-out/'
OSS_WORK_DIR    = f'/data/{User}/oss-work/'
OSS_DB_DIR      = f'/data/{User}/oss-db/'
TMP             = f'/data/{User}/tmp/'


CPU_LIMIT       = False
DEBUG           = False


```
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
