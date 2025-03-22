# Update the ARVO database
"""
1. Update the metadata from metaDataCollect.py
2. Try to Reproduce
3. Try to Archive
"""
from utils import getAllLocalIds, ARVO
from metaDataCollect import *

import json
from reproducer import verify
from Locator import report
RESULTS = ARVO / "Results.json"
UpdateDir = ARVO / "UpdateData"
if not UpdateDir.exists():
    UpdateDir.mkdir()
def getUpdateIssues():
    data_download(Dodownload=True,Update=True)
    # Get the range we should update [last_reproduced, latest one]
    with open(RESULTS,'r') as f:
        last_reproduced = json.loads(f.readlines()[-1])['localId']
    issues = getAllLocalIds()
    issues = [x for x in issues if x > last_reproduced]
    return issues
def logUpdate(localId,res,fname):
    with open(UpdateDir/fname,'a+') as f:
        f.write(f"{localId}: {res}\n")
def performUpdate(issues):
    # Run this function on in Signle Thread 
    ct_reproduce    = 0
    ct_report       = 0 
    for localId in issues:
        try:
            res = verify(localId,True)
            logUpdate(localId,res,"reproduce.log")
        except:
            res = False
            logUpdate(localId,res,"reproduce.log")
            continue
        if res!=True:
            continue
        ct_reproduce+=1
        try:
            res = report(localId,True)
            logUpdate(localId,res,"report.log")
        except:
            res = False
            logUpdate(localId,res,"report.log")
            continue
        if res:
            ct_report+=1
    print(f"Found {ct_reproduce} new produciable cases")
    print(f"Focated the fix for {ct_report} cases")

if __name__ == "__main__":
    res = [67560, 67585, 67586, 67588, 67589, 67600, 67610, 67611, 67641, 67670, 67676, 67678, 67708, 67725, 67743, 67747, 67753, 67755, 67756, 67759, 67760, 67766, 67767, 67777, 67790, 67791, 67794, 67796, 67806, 67815, 67827, 67842, 67854, 67862, 67881, 67891, 67895, 67901, 67905, 67923, 67932, 67941, 67944, 67953, 67968, 68004, 68028, 68041, 68047, 68049, 68051, 68065, 68069, 68071, 68081, 68085, 68091, 68105, 68112, 68117, 68128, 68143, 68159, 68165, 68182, 68189, 68204, 68211, 68216, 68223, 68227, 68229, 68242, 68255, 68258, 68261, 68269, 68272, 68297, 68315, 68328, 68345, 68361, 68391, 68397, 68402, 68406, 68407, 68418, 68426, 68432, 68435, 68441, 68444, 68445, 68446, 68449, 68450, 68452, 68455, 68461, 68464, 68468, 68469, 68473, 68477, 68478, 68481, 68486, 68487, 68493, 68506, 68509, 68519, 68524, 68535, 68566, 68568, 68569, 68581, 68599, 68613, 68629, 68663, 68680, 68685, 68691, 68703, 68716, 68723, 68725, 68775, 68798, 68871, 68911, 68924, 68932, 68933, 68946, 68976, 69042]
    performUpdate(res)
