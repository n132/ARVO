# Patch Verification

from .utils import *
from random import choice
from .utils_diff import *



DEBUG = True
if not DEBUG:
    issues = getReports()
    one = choice(issues)
    print(one)
else:
    one = 18745

diff = getDiff(one) 
with open(diff) as f:
    diff_data = f.read()
print(diff_data)