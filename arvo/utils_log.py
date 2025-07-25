DEBUG = True
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def WARN(s):    
    if(DEBUG): print(f"{bcolors.WARNING}{s}{bcolors.ENDC}")
def FAIL(s):    print(f"{bcolors.FAIL}{s}{bcolors.ENDC}")
def INFO(s):    
    if(DEBUG): print(f"{bcolors.OKBLUE}{s}{bcolors.ENDC}")
def SUCCESS(s): print(f"{bcolors.OKGREEN}{s}{bcolors.ENDC}")
def LOGO(s):    print(f"{bcolors.OKCYAN}{s}{bcolors.ENDC}")
def PANIC(s):
    FAIL(s)
    exit(1)
if __name__ == "__main__":
    pass