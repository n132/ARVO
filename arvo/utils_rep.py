# Functions to Reproduction Test
import json
from pathlib import Path
import random
from .utils import OSS_LOCK,ARVO
from .reproducer import verify
from filelock import Timeout, FileLock
# from report_gen import getReports
from .Locator import report
from .utils import *
Explorer = Path(ARVO/ "Explorer")
if not Explorer.exists():
    Explorer.mkdir()
def removeSucceed(issues):
    with open("Results.json") as f:
        data = f.readlines()
    done    = [json.loads(x)['localId'] for x in data]
    return [_  for _ in issues if _ not in done]
def removeReported(issues):
    reports = getReports()
    return [_  for _ in issues if _ not in reports]
def touchLogfile(log_file):
    if not log_file.exists():
        log_file.touch()
    return log_file
def updateLogfile(localid,res,log_file):
    tmp = dict()
    tmp[localid] = res
    with open(log_file,'a') as f:
        f.write(json.dumps(tmp)+"\n")
def updateTodo(issues,log_file):
    with open(log_file,'r') as f:
        done = [ int(list(json.loads(x).keys())[0]) for x in f.readlines()]
    return [_  for _ in issues if _ not in done]
def reportExplore(issues,log_file,remove_reported=True):
    log_file    = Explorer / log_file
    log_file    = touchLogfile(log_file)
    if remove_reported:
        issues      = removeReported(issues)
    todo        = updateTodo(issues,log_file)
    doing = []
    while len(todo)> 0 :
        choice = random.choice(todo)
        print(f"[+] Locating the patch of {choice}")
        print(f"[+] {len(todo)} issues left")
        lock = FileLock(OSS_LOCK / f"{choice}.lock")
        try:
            with lock.acquire(timeout=.3):
                res   = report(choice)
        except Timeout:
            doing.append(choice)
            print(f"[+] Another thead is working on this issue, skip...")
            todo = [x for x in todo if x not in doing]
            continue
        updateLogfile(choice,res,log_file)
        todo = updateTodo(issues,log_file)
        doing = []
def unitExplore(issues,log_file,remove_result=True):
    log_file    = Explorer / log_file
    log_file    = touchLogfile(log_file)
    if remove_result:
        issues      = removeSucceed(issues)
    todo        = updateTodo(issues,log_file)
    doing = []
    while len(todo)> 0 :
        choice = random.choice(todo)
        print(f"[+] Verfiying {choice}")
        print(f"[+] {len(todo)} issues left")
        lock = FileLock(OSS_LOCK / f"{choice}.lock")
        try:
            with lock.acquire(timeout=.3):
                res   = verify(choice)
        except Timeout:
            doing.append(choice)
            print(f"[+] Another thead is working on this issue, skip...")
            todo = [x for x in todo if x not in doing]
            continue
        updateLogfile(choice,res,log_file)
        todo = updateTodo(issues,log_file)
        doing = []
def xExplore(issues, log_file, hook):
    log_file    = Explorer / log_file
    log_file    = touchLogfile(log_file)
    todo        = updateTodo(issues,log_file)
    doing = []
    while len(todo)> 0 :
        choice = random.choice(todo)
        print(f"[+] Checking {choice}")
        print(f"[+] {len(todo)} issues left")
        lock = FileLock(OSS_LOCK / f"{choice}.lock")
        try:
            with lock.acquire(timeout=.3):
                res     = hook(choice)
        except Timeout:
            doing.append(choice)
            print(f"[+] Another thead is working on this issue, skip...")
            todo = [x for x in todo if x not in doing]
            continue
        updateLogfile(choice,res,log_file)
        todo = updateTodo(issues,log_file)
        doing = []
def archive(issues,log_file):
    log_file    = Explorer / log_file
    log_file    = touchLogfile(log_file)
    todo        = updateTodo(issues,log_file)
    doing = []
    while len(todo)> 0 :
        choice = random.choice(todo)
        print(f"[+] Verfiying {choice}")
        print(f"[+] {len(todo)} issues left")
        lock = FileLock(OSS_LOCK / f"{choice}.lock")
        try:
            with lock.acquire(timeout=.3):
                res   = verify(choice,True)
        except Timeout:
            doing.append(choice)
            print(f"[+] Another thead is working on this issue, skip...")
            todo = [x for x in todo if x not in doing]
            continue
        updateLogfile(choice,res,log_file)
        todo = updateTodo(issues,log_file)
        doing = []

def extractSucceedIssues(log_file):
    with open(log_file,'r') as f:
        res = [ int(list(json.loads(x).keys())[0]) for x in f.readlines() if list(json.loads(x).values())[0]== True]
    res = list(set(res))
    return res

if __name__ == "__main__":
    pass
