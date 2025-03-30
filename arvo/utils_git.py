from .utils_exec import check_call, execute, execute_ret
import shutil
import os
from .utils import tmpDir, tmpFile, eventLog, git_pull, hg_pull, svn_pull, clone, hg_clone, svn_clone
from pathlib import Path
from datetime import datetime
import re
import pytz
from .utils_log import *
# fmt: off

def timeTransfer(original_str):
    # Parse the datetime string to a datetime object, specifying the original format
    original_dt = datetime.strptime(original_str, "%Y-%m-%d %H:%M:%S %z")
    # Convert the datetime object to UTC
    utc_dt = original_dt.astimezone(pytz.utc)
    # Format the UTC datetime object to the new string format without timezone information
    formatted_str = utc_dt.strftime("%Y%m%d%H%M")
    return formatted_str
def stamp2Date(unix_timestamp):
    # Convert Unix timestamp to datetime in UTC
    dt_utc = datetime.utcfromtimestamp(unix_timestamp)

    # Format the datetime object to the desired format
    return dt_utc.strftime('%Y%m%d%H%M')

def stamp2Date2(unix_timestamp):
    dt = datetime.utcfromtimestamp(unix_timestamp)
    # Convert datetime to the desired format
    formatted_date = dt.strftime("%a %b %d %H:%M:%S %Y %z")
    return formatted_date

class GitTool():
    def __init__(self,oriRepo,vctype='git',revision=None,latest=False) -> None:
        if vctype not in ['git','hg','svn']:
            eventLog(f'[-] GitTool: Does not support {vctype}',ext=True)
        self.type = vctype

        if type(oriRepo) == str:
            repoPath = Path(oriRepo)
        else:
            repoPath = oriRepo
        if not repoPath.exists():
            repoPath = self.clone(oriRepo,revision)
        if not repoPath:
            eventLog(f'[-] GitTool: Failed to init {oriRepo}',ext=True)
        self.repo = repoPath
        self.name = self.repo.name
        if latest and not self.pull():
            eventLog(f'[-] GitTool: Failed to Update {oriRepo}',ext=True)

    def pull(self):
        if self.type == 'git':
            return git_pull(self.repo)
        elif self.type == 'hg':
            return hg_pull(self.repo)
        else:
            return svn_pull(self.repo)
        
    def clone(self,url,revision=None):
        if self.type == 'git':
            repo = clone(url,revision)
            if repo!=False:
                self.repo = list(repo.iterdir())[0]
            else:
                return False
        elif self.type == 'hg':
            repo = hg_clone(url,revision)
            if repo!=False:
                self.repo = list(repo.iterdir())[0]
            else:
                return False
        else:
            repo = svn_clone(url,revision)
            if repo!=False:
                self.repo = list(repo.iterdir())[0]
            else:
                return False
        return self.repo
    def commitDate(self,commit):
        if self.type == 'git':
            res = execute(['git','show','-s','--format=%ci',commit],self.repo)
            if res !=False:
                return timeTransfer(res.decode())
        elif self.type == 'hg':
            res = execute(['hg','log','-r',commit,
                '--template', '{date}'],self.repo)
            if res !=False:
                return stamp2Date(int(res.decode().split(".")[0]))
        else:
            res = execute(['svn','log','-r',commit,
                '-q'],self.repo)
            if res !=False:
                res = res.decode()
                res = res.split('\n')
                if len(res)==1:
                    return False
                res = res[1].split(' | ')[2].split(' (')[0]
                return timeTransfer(res)

        return False
    def _copy(self):
        try:
            org = self.repo
            new = tmpDir()
            shutil.copytree(org,new/self.name,symlinks=True)
            return new/self.name
        except:
            return False
    def getRecentCommit(self,commits_list,time_seconds=3600*24*(2.5)):
        '''
        We can do it more precisly but I don't want to 
        spend time on this.
        '''
        t1 = self.timestamp(commits_list[0])
        t2 = self.timestamp(commits_list[-1])

        if t1 is False or t2 is False:
            return False

        if int(t2-t1)/(3600*24) < 5:
            '''
            The bugs is fixed in 5 days:
            The fix happened very fast so there is no
            need to shrink the range
            '''
            return False
        else:

            targetTS = t2 - time_seconds
            commit = self.getCommitbyTimestamp(targetTS)
            if (commit in commits_list) and (commit != commits_list[0]):
                return commit
            else:
                return False
    def comment(self,commit):
        if self.type == 'git':
            cmd = ['git', 'show', '--no-patch',  commit]
            res = execute(cmd,self.repo,stderr=open('/dev/null','w'),mute_log=True)
            if res == False:
                return False
            try:
                return res
            except:
                return False
        else:
            return False
    def timestamp(self,commit):
        if self.type == 'git':
            cmd = ['git', 'show', '--no-patch', '--format=%ct', commit]
            res = execute(cmd,self.repo,stderr=open('/dev/null','w'),mute_log=True)

            if res == False:
                return False
            try:
                return int(res)
            except:
                return False
        elif self.type == 'hg':
            cmd = ['hg', 'log', '-r', commit, '--template', '{date|isodate}']
            res = execute(cmd,self.repo)
            if res == False:
                return False
            date_obj = datetime.strptime(res.decode(), "%Y-%m-%d %H:%M %z")
            return int(date_obj.timestamp())
        else:
            cmd = ['svn', 'log', '-r', commit]
            res = execute(cmd,self.repo)
            
            if res == False:
                return False
            if len(res.decode().split('\n'))==1:
                return False
            res = " ".join(res.decode().split('\n')[1].split("|")[2].strip(" ").split(" ")[:3])
            date_obj = datetime.strptime(res, "%Y-%m-%d %H:%M:%S %z")
            return int(date_obj.timestamp())
    def reset(self,commit):
        if self.type == 'git':
            cmd = ['git','reset','--hard', commit]
            with open('/dev/null','w') as f:
                return check_call(cmd,self.repo,stdout=f)
        elif self.type == 'hg':
            cmd1 = ['hg','update', '--clean', '-r', commit]
            cmd2 = ['hg',"purge", '--config', 'extensions.purge=']
            if check_call(cmd1,self.repo) and check_call(cmd2,self.repo):
                return True
            else:
                return False
        elif self.type == "svn":
            return check_call(['svn',"up",'--force','-r', commit], cwd = self.repo)
        else:
            return False
    
    def listCommits(self,commit1,commit2):
        """
        # return a list includes commits between two commits (inclusively)
        # but not include branch nodes
        # The return value are ordered by time (old -> new)

        If the commit is ts we list by ts.
        If two  
        """
        # TODO hg/svn: timestamp support
        if isinstance(commit1,str) and isinstance(commit2,str):
            t1 = self.timestamp(commit1)
            t2 = self.timestamp(commit2)
            if t1 == False or t2 == False or t1==None or t2==None:
                if self.type !='svn':
                    return False
                else:
                    # Assume the commit is the older one
                    pass
            elif t1 >= t2:
                commit1, commit2 = commit2, commit1
                t1, t2 = t2, t1
            else:
                pass
        elif isinstance(commit1,int) and isinstance(commit2,int) and self.type=='git':
            if commit1 >= commit2:
                t1, t2 = commit2, commit1 
            else:
                t1, t2 = commit1, commit2
            t1 -= 24*3600 # OSS Fuzz everyday so to make sure we include the fix commit
        else:
            print("[+] Weird Case")
            return False

        if self.type == 'git':
            '''
            Check reachability if they can reach each other we do simple list
            '''
            cmd = ['git','merge-base','--is-ancestor',commit1,commit2]
            
            if isinstance(commit1,str) and isinstance(commit2,str) and execute_ret(cmd, cwd = self.repo)==0:
                cmd = ['git','log','--format=%H',f'{commit1}..{commit2}','--no-merges']
                res = execute(cmd,self.repo)
                if not res:
                    return False
                res = res.decode().split('\n')
                if len(res)==0:
                    print("[-] None commits between found")
                    return None
                
                if commit2 != res[0]:
                    res = [commit2]+res 
                if commit1 != res[-1]:
                    res.append(commit1)
                return res[::-1]
            else:
                # cmd = ['git','log', "--ancestry-path",f"{commit1}..{commit2}",'--pretty=format:%H']
                dt1 = datetime.fromtimestamp(t1).strftime("%Y-%m-%d %H:%M:%S")
                dt2 = datetime.fromtimestamp(t2).strftime("%Y-%m-%d %H:%M:%S")
                cmd = ['git','log','--no-merges', f'--since="{dt1}"',f'--until="{dt2}"','--format=%H']
                res = execute(cmd,self.repo)
                if not res:
                    return False
                res = res.decode().split('\n')
                if len(res)==0:
                    print("[-] None commits between found")
                    return None
                if isinstance(commit1,str) and isinstance(commit2,str):
                    if commit2 != res[0]:
                        res = [commit2]+res
                    if commit1 != res[-1]:
                        res.append(commit1)
                return res[::-1]
        elif self.type == 'hg':
            # TODO: Support CommitList Overbranch
            # hg log -r '123::456'
            cmd = ['hg','log','-r', f'{commit1}::{commit2}', "--no-merges",'--template', '{node}\\n']
            # cmd = ['hg', 'log', '-r', f'"ancestor({commit1},{commit2})::{commit2}"', "--no-merges", "--template", '{node}\\n']
            # cmd = ['hg', 'log', '--rev', f'"ancestors({commit1}) - ancestors({commit2}) - merge()"', '--template', '{node}\n']
            res = execute(cmd,self.repo)
            res = res.decode().split('\n') if res else res
            return res
        elif self.type == 'svn':
            # TODO: Support CommitList Overbranch
            # svn log -r 100:200 http://example.com/svn/repo
            cmd = ['svn','log','-r',f'{commit1}:{commit2}',self.repo]
            res = execute(cmd,self.repo)
            if res == False:
                return False
            lines = res.decode().split("\n")
            pattern = re.compile(r'^r[0-9]')
            res = []
            for line in lines:
                if len(pattern.findall(line))!=0:
                    res.append(line.split(" | ")[0][1:])
            if len(res) == 0:
                return [commit1,commit2]
            if commit1 != res[0]:
                res = [commit1]+res
            if commit2 != res[-1]:
                res = res+[commit2]
            return res
        else:
            return False
    def showCommits(self,commits):
        tmp_file = tmpFile()
        prev = self.prevCommit(commits[0])
        if not prev:
            return False
        if self.type == 'git':
            cmd = ['timeout','30','git','diff',f'{prev}..{commits[-1]}','-W']
        elif self.type == 'svn':
            cmd = ['timeout','30','svn','diff','-r',f'{prev}:{commits[-1]}']
        elif self.type == 'hg': 
            cmd = ['timeout','30','hg','diff',"-r", f'{prev}', '-r', f'{commits[-1]}']
        if check_call(cmd,self.repo,stdout=open(tmp_file,'w'),stderr=open("/dev/null",'w')):
            return tmp_file
        return False
    def showCommit(self,commit,tmp_file=None,rev=False):
        # return the path of the diff file
        tmp_file = tmpFile() if not tmp_file else tmp_file
        if self.type == 'git':
            # -W to show the whole function
            # -m for merged commits
            # add timeout to avoid spending too much time on merging diff
            cmd = ['timeout','30','git','show','--diff-merges=first-parent','-W',commit]
            cmd += ["-R"] if rev else []
            # cmd = ['timeout','30','git','show','-W',commit]
        elif self.type == 'hg':
            cmd = ['timeout','30','hg', 'diff','-c', commit, '--show-function']
            cmd += ['--reverse'] if rev else []
        elif self.type == 'svn':
            commit = int(commit)
            if rev:
                # svn commits are numbers 
                commit  = f"{commit}:{commit-1}"
            else:
                commit  = f"{commit-1}:{commit}"
            cmd = ['timeout','30','svn','diff','-r',commit,'--diff-cmd=diff']

        if check_call(cmd,self.repo,stdout=open(tmp_file,'a'),stderr=open("/dev/null",'w')):
            return tmp_file
        return False
    def patch(self,diff_file):
        if not diff_file.exists():
            return False
        cmd = ['git','apply','--whitespace=nowarn',diff_file.absolute()]
        with open("/dev/null",'wb') as f:
            if not check_call(cmd,self.repo,stderr=f,verbose=False):
                return False
        return True
    def prevCommit(self,commit=None):
        # reutrn the previous commit hash
        tmp_file = tmpFile()
        if self.type == 'git':
            cmd = ['git','log','-2','--pretty=format:%H']
            if commit:
                cmd.append(commit)
        elif self.type == 'hg':
            # TODO
            return False
        elif self.type == 'svn':
            # TODO
            return False
        if not check_call(cmd,self.repo,stdout=open(tmp_file,'w')):
            return False
        with open(tmp_file) as f:
            res = [x.strip() for x in f.readlines()][-1]
        shutil.rmtree(os.path.dirname(tmp_file))
        return res
    def createdCommit(self, path):
        # return the first commit when the the file is introduced.
        tmp_file = tmpFile()
        if self.type == 'git':
            res = execute(["git", "log", "--diff-filter=A", "--", path], self.repo)
            res = res.decode() if isinstance(res, bytes) else False
            if res == False:
                return False
            res = [x.strip() for x in res.split('\n')]
            if len(res) == 0:
                return False
            shutil.rmtree(tmp_file.parent)
            return res[0].split()[1].strip()

        elif self.type == 'hg':
            res = execute(["hg", "log", "--follow", path, '--template', '{node}\n'], self.repo)
            res = res.decode() if isinstance(res, bytes) else False
            if res == False:
                return False
            res = [x.strip() for x in res.split('\n')]
            if len(res) == 0:
                return False
            res = res[-1].split('\n')
            if len(res) == 0:
                return False
            res = res[0]
            shutil.rmtree(tmp_file.parent)
            return res

        elif self.type == 'svn':
            res = execute(["svn", "log", "--verbose", path], self.repo)
            res = res.decode() if isinstance(res, bytes) else False
            if res == False:
                return False
            res = res.split("-"*72)[-2].split('\n')[1].split()[0]
            if res[0] == 'r':
                res = res[1:]
            shutil.rmtree(tmp_file.parent)
            return res
    def getCommitbyTimestamp(self, timestamp):
        # return the commit by date
        tmp_file = tmpFile()
        if self.type == 'git':
            dt1 = stamp2Date2(timestamp)
            res = execute(["git", "log", '--pretty=format:%H', "--until=%s" % dt1], self.repo)
            res = res.decode() if isinstance(res, bytes) else False
            if res == False:
                return res
            lines = [x for x in res.split("\n") if len(x) > 0]
            if len(lines) == 0:
                return False
            commit = lines[0].strip()
            shutil.rmtree(tmp_file.parent)
            return commit
        elif self.type == 'hg':
            # hg log --date
            dt1 = stamp2Date2(timestamp)
            res = execute(["hg", "log", "--date", f"<{dt1}", '--template', '{node}\n'], self.repo)
            res = res.decode() if isinstance(res, bytes) else False
            if res == False:
                return res
            res = [x.strip() for x in res.split('\n') if len(x) > 0]
            if len(res) == 0:
                return False
            commit = res[0]
            shutil.rmtree(tmp_file.parent)
            return commit

        elif self.type == 'svn':
            # svn log --search 
            # svn returns revision after the timestamp we give
            # so we increment timestamp by 1
            timestamp += 1
            cdt = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%dT%H:%M:%S")
            res = execute(["svn", "log", "-r", "{%s}" % cdt], self.repo)
            res = res.decode() if isinstance(res, bytes) else False
            if res == False:
                return res
            res = [x.strip() for x in res.split("-"*72) if len(x) > 0][0].split("\n")
            if len(res) == 0:
                return False
            commit = res[0].split()[0].strip()
            if commit[0] == 'r':
                commit = commit[1:]

            shutil.rmtree(tmp_file.parent)
            return commit
    def curCommit(self):
        if self.type == 'git':
            cmd = ['git','rev-parse','HEAD']
            res = execute(cmd,self.repo)
            res = res.decode() if res else res
            return res
        elif self.type == 'svn':
            cmd = ['svn','info','--show-item','last-changed-revision']
            res = execute(cmd,self.repo)
            res = res.decode() if res else res
            return res
        elif self.type == 'hg':
            res = execute(["hg", "log", '--template', '{node}\n'], self.repo)
            res = res.decode() if isinstance(res, bytes) else False
            if res == False:
                return res
            res = [x.strip() for x in res.split('\n') if len(x) > 0] + [False]
            commit = res[0]
            return commit
        else:
            return False
def _TEST():
    for vtype in ['git','hg','svn']:
        INFO(f"T: Testing {vtype}")
        if vtype == 'hg':
            URL = 'https://foss.heptapod.net/graphicsmagick/graphicsmagick'
        elif vtype == 'git':
            URL = 'https://github.com/ArtifexSoftware/mupdf.git'
        elif vtype == 'svn':
            URL = 'https://svn.code.sf.net/p/freeimage/svn'
        else:
            print("Unknown TYPE")
            exit(1)
        repo = GitTool(URL,vtype,latest=True)
        assert(repo)
        SUCCESS("T: [GitTools][Clone][Pass]")
        if vtype == 'hg':
            assert(repo.getCommitbyTimestamp(1710660583) == 'e4c7133e571165bb84e861755f808a437b999e39')
        elif vtype == 'git':
            assert(repo.getCommitbyTimestamp(1710416667) == '4218456a1de2619abd54451801bb02624d483c04')
        else:
            assert(repo.getCommitbyTimestamp(1648950832) == '1902')
        SUCCESS("T: [GitTools][getCommitbyTimestamp][Pass]")
        res = repo.curCommit()
        assert(res)
        SUCCESS("T: [GitTools][curCommit][Pass]")
        assert(repo.showCommit(res))
        SUCCESS("T: [GitTools][showCommit][Pass]")
        assert(repo.showCommit(res,rev=True))
    return True

if __name__ == "__main__":
    _TEST()