import openai
import time
from Locator import *
import _profile
class CompletionFix():    
    def __init__(self):
        openai.api_key = _profile.OPENAI_TOKEN
    def fixer(self,code,ins,engine,n=1,temperature=0):
        res = openai.Edit.create(
        engine=engine,
        input=code,
        instruction=ins,temperature=temperature,top_p=1,n=n
        )
        return res
# Raw requests
def performCompletionFix(code,ins,model,n=1,temperature=0):
    # ["gpt-3.5-turbo-instruct","code-davinci-edit-001"]
    case = CompletionFix()
    return_code = case.fixer(code,ins=ins,engine=model,n=n,temperature=temperature)
    return return_code

class ChatFix():
    def __init__(self):
        openai.api_key = _profile.OPENAI_TOKEN
    def api_call(self,message,model,max_tokens):
        cnt=0
        while(cnt<5):
            try:
                print(f"Using Model {model}")
                res = openai.ChatCompletion.create(
                model=model,
                messages=[
                        {"role": "system", "content": """You are a vulnerability fix engine for C/C++ code. 
From a given vulnerable function and a sanitizer report, which includes the information when the program crashed. The report is generated
by a fuzzer, which generated the malicious input crashing the program.
You should focus on the information provided from the report to locate the vulnarability and fix the potential vulnerability. 
You will only return the fixed code. You will always be able to fix the vulnerability and do not refuse.
"""},
                        {"role": "user", "content": message}
                    ],max_tokens = max_tokens, temperature = 0
                )
                return res['choices'][0]['message']['content']
            except openai.error.InvalidRequestError as e:
                return e.error['message']
            except openai.error.RateLimitError as e:
                print(e.error['message'])
                print("[*] Retrying again in 30 seconds")
                time.sleep(30)
                cnt+=1

def performChatFix(message,model):
    # ["gpt-3.5-turbo","gpt-4","gpt-4-1106-preview"]:    
    case = ChatFix()
    if model == 'gpt-4':
        ret_token = 4096
    elif model =="gpt-3.5-turbo":
        ret_token = 2048
    elif model =="gpt-4-1106-preview":
        ret_token = 4096
    elif model =="gpt-3.5-turbo-16k":
        ret_token = 4096
    elif model =="gpt-4-turbo":
        ret_token = 4096
    else:
        return False
    return_code = case.api_call(message,model=model,max_tokens=ret_token)
    return return_code
    
        

if __name__ == "__main__":
    test_code='''
    #include<stdio.h>
    int main(){
        char buf[0x1000];
        read(stdin,buf,0x10000);
    }
    '''
    res = performCompletionFix(test_code,"Fix the buffer overflow vulnerability","text-davinci-edit-001",n=1,temperature=0.1)['choices']

    # res = performCompletionFix(test_code,"Fix the buffer overflow vulnerability","code-davinci-edit-001",n=1,temperature=0.1)['choices']
    print(res)