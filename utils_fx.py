# Functions to Fx Test
# The Fx test should not be multi threads
from fx import *
from filelock import Timeout, FileLock
import random

def _updateLog(localId,result,log_file):
    d = dict()
    d[localId] = result
    with open(log_file,'a') as f:
        f.write(json.dumps(d)+"\n")
def _loadLog(log_file):
    with open(log_file) as f:
        lines  = f.readlines()
    return [ int(x.split('":')[0][2:]) for x in lines[4:]]
def _updateTodo(todo, log_file):
    done = _loadLog(log_file)
    todo = [ x for x in todo if x not in done]
    return todo

def fxProbeTurbo(localIds,model,round_tag,tag="",lite=False):
    log_file = ARVO / "Data" / "Data" / round_tag / ("n132FxLog_"+model+"_"+tag)
    print(log_file)
    if log_file.exists():
        pass
    else:
        log_file.parent.mkdir(parents=True,exist_ok=True)
        log_file.touch()
        # Head
        with open(log_file,'w') as f:
            tmp = [str(x) for x in localIds]
            tmp = " ".join(tmp)
            f.write(f"LocalIds: {tmp}\n")
            f.write(f"Time: {datetime.now()}\n")
            f.write(f"Model: {model}\n")
            f.write("="*0x20)
            f.write("\n")
    todo = _updateTodo(localIds,log_file)
    # Body
    doing = []
    while len(todo) > 0:
        choice = random.choice(todo)
        print(f"[+] Verfiying {choice}")
        lock = FileLock(OSS_LOCK / f"{choice}.lock")
        try:
            with lock.acquire(timeout=.3):
                res   = runFix(choice, model, lite, log_file.parent ,tag=tag)
        except Timeout:
            doing.append(choice)
            print(f"[+] Another thead is working on this issue, skip...")
            todo = [x for x in todo if x not in doing]
            continue
        _updateLog(choice,res,log_file)
        todo = _updateTodo(localIds,log_file)
        doing = []

    # Tail
    print(f"[+] Model {model} has finished running.")
    print(log_file)



if __name__ == "__main__":
    pass