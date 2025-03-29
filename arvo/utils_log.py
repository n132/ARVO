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
    print(f"{bcolors.WARNING}{s}{bcolors.ENDC}")

def FAIL(s):
    print(f"{bcolors.FAIL}{s}{bcolors.ENDC}")

def INFO(s):
    print(f"{bcolors.OKBLUE}{s}{bcolors.ENDC}")

def SUCCESS(s):
    print(f"{bcolors.OKGREEN}{s}{bcolors.ENDC}")

def _TEST():
    WARN("WARN")
    FAIL("FAIL")
    INFO("INFO")
    SUCCESS('SUCCESS')
    return True

if __name__ == "__main__":
    _TEST()