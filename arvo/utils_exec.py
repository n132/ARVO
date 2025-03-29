import subprocess
from pathlib import Path
def execute(cmd,cwd=None,stdin=None,stderr=None,return_code=[0],mute_log=False):
    if not cwd:
        p = subprocess.Popen(cmd,stdin=stdin,stdout=subprocess.PIPE,stderr=stderr)
    else:
        p = subprocess.Popen(cmd,cwd = cwd,stdin=stdin,stdout=subprocess.PIPE,stderr=stderr)
    out,_ = p.communicate()
    if p.returncode in return_code:
        return out.strip()
    else:
        if mute_log:
            return False
        cmd = " ".join(cmd)
        print(f"[!] Failed to execute the command:\n\t{cmd}\n\tpwd: {cwd}")
        return False
def execute_ret(cmd,cwd=None,stdin=None,stdout=None,stderr=None):
    if not cwd:
        p = subprocess.Popen(cmd,stdin=stdin,stdout=stdout,stderr=stderr)
    else:
        p = subprocess.Popen(cmd,cwd =cwd,stdin=stdin,stdout=stdout,stderr=stderr)
    __,_ = p.communicate()
    return p.returncode
def check_call(cmd,cwd=Path("/tmp"),stdin=None,stdout=None,stderr=None,verbose=True):
    try:
        subprocess.check_call(cmd,stdin=stdin,stdout=stdout,stderr=stderr,cwd=cwd) 
    except:
        if verbose:
            cmd = [str(x) for x in cmd]
            cmd = " ".join(cmd)
            print(f"[!] Failed to execute the command:\n\t{cmd}\n\tpwd: {cwd}")
        return False
    return True
def run_stderr(cmd,cwd=None,stdin=None,stdout=None,stderr=subprocess.PIPE):
    if not cwd:
        result = subprocess.run(cmd,stdin=stdin,stdout=stdout,stderr=stderr)
    else:
        result = subprocess.run(cmd,cwd =cwd,stdin=stdin,stdout=stdout,stderr=stderr)
    return_code     = result.returncode
    stderr_output   = result.stderr.decode('utf-8')
    return return_code, stderr_output
if __name__ == "__main__":
    x = 'git diff -W /data/n132/tmp/ARVO_U9aqBrs8CeuJw2o1PZzr6F/4j1grsmdr3HhcDiYRBjD4L /data/n132/tmp/ARVO_J3FxRcQtw4XavXkcAXSdNw/FSzqmxUrZjpsHmy7FJ7Ggi'
    res  = execute(x.split(" "),return_code=[0,1])
    print(res)