from .utils import *
from .utils_GPT import oss_fuzz_get_patch
def get_all_single_mods(DEBUG=True):
    reports = getReports()
    res = []
    for r in reports:
        if(DEBUG):
            print("[*] Testing localID: " + str(r))
        diff_file = oss_fuzz_get_patch(r)
        if diff_file == False:
            continue
        diff_content = str(diff_file).split("\n")    
        
        mod_cnt = 0
        for z in range(len(diff_content)):
            if(diff_content[z].startswith("@@ ")):
                mod_cnt+=1
                if mod_cnt > 1: # stop when over 2
                    break
        if(DEBUG):
            print("mod: "+str(mod_cnt))
        if mod_cnt==1:
            res.append(r) # localID
            if(DEBUG):
                print("[+] "+ str(r) +" added")
        else:
            if(DEBUG):
                print("[-] "+ str(r) +" skipped")
    print("[!] Done")
    if(DEBUG):
        print(res)
        print("Total: "+str(len(res)))
    return res
