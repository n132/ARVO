# Options related to data
from .fx import *
from .resultData import *
from .utils import *

def addNewcase(localIds):
    matric_ins(localIds,len(localIds)*[True])

if __name__ == '__main__':
    cmd = 0
    localIds = []
    if cmd==0:
        matric_del(localIds)
    elif cmd==1:
        addNewcase(localIds)
