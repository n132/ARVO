from .OpenAI_gpt import GPT4,GPT4_Preview
from pathlib import Path
from .utils_diff import getDiff
def oss_fuzz_get_patch(localID):
    diff_file = getDiff(localID)
    if diff_file == False:
        return False
    with open(diff_file, mode="rb") as f:
        content = f.read()
        try:
            return content.decode()
        except UnicodeDecodeError as e:
            return content.decode('latin-1')
    
def GPTLabeler(localID):
    print(f"[+] Labeling case {localID}...")
    diff = oss_fuzz_get_patch(localID)
    if diff == False:
        return False
    message = f"Can you describe what vulnerability could be patched in following diff file?\nDiff information:\n```\n{diff}\n```"
    res = GPT4().api_call(message)
    if res == False:
        res = GPT4_Preview().api_call(message)
        print(res)
    return res
if __name__ == "__main__":
    pass