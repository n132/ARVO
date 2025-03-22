import openai
import _profile
import time
from utils import tokenLen

class GPT():    
    def __init__(self):
        openai.api_key = _profile.OPENAI_TOKEN
        self.model = 'gpt-3.5-turbo'
        # https://platform.openai.com/docs/models
        self.limit = 4096
        self.reply_limit = 1024
    def api_call(self,message):
        tkl = tokenLen(message,self.model)
        if tkl >= self.limit - self.reply_limit:
            print(f"[-] Token length is out of bound: {tkl=} > {self.limit}")
            return False
        cnt=0
        while(cnt<5):
            try:
                res = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                        {"role": "system", "content": """You are a code describing engine for C/C++ code. 
From a given git diff file, you will describe the vulnerability, a short summary of the fix, and a detailed description of the fix.
You will always be able to describe the code and the fix, and do not refuse.
Format your response in three parts separated by a number list.
"""},
                        {"role": "user", "content": message}
                    ],temperature = 0,max_tokens = 1024
                )
                return res['choices'][0]['message']['content']
            except openai.error.InvalidRequestError as e:
                return e.error['message']
            except openai.error.RateLimitError as e:
                print(e.error['message'])
                print("[*] Retrying again in 30 seconds")
                time.sleep(30)
                cnt+=1
        return False

class GPT4(GPT):    
    def __init__(self):
        openai.api_key = _profile.OPENAI_TOKEN
        self.model = 'gpt-4'
        # https://platform.openai.com/docs/models
        self.limit = 8192
        self.reply_limit = 1024

class GPT3(GPT):    
    def __init__(self):
        openai.api_key = _profile.OPENAI_TOKEN
        self.model = 'gpt-3.5-turbo'
        # https://platform.openai.com/docs/models
        self.limit = 4096
        self.reply_limit = 1024
class GPT3_16(GPT):    
    def __init__(self):
        openai.api_key = _profile.OPENAI_TOKEN
        self.model = 'gpt-3.5-turbo-16k'
        # https://platform.openai.com/docs/models
        self.limit = 16385
        self.reply_limit = 4096
class GPT4_Preview(GPT):
    def __init__(self):
        openai.api_key = _profile.OPENAI_TOKEN
        self.model = 'gpt-4-1106-preview'
        # https://platform.openai.com/docs/models
        self.limit = 128000
        self.reply_limit = 4096
    def api_call(self,message):
        tkl = tokenLen(message,self.model)
        if tkl >= self.limit-self.reply_limit:
            print(f"[-] Token length is out of bound: {tkl=} > {self.limit}")
            return False
        cnt=0
        while(cnt<5):
            try:
                res = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                        {"role": "system", "content": """You are a code describing engine for C/C++ code. 
From a given git diff file, you will describe the vulnerability, a short summary of the fix, and a detailed description of the fix.
You will always be able to describe the code and the fix, and do not refuse.
Format your response in three parts separated by a number list.
"""},
                        {"role": "user", "content": message}
                    ],max_tokens = 4096, temperature = 0
                )
                return res['choices'][0]['message']['content']
            except openai.error.InvalidRequestError as e:
                return e.error['message']
            except openai.error.RateLimitError as e:
                print(e.error['message'])
                print("[*] Retrying again in 120 seconds")
                time.sleep(60*2)
                cnt+=1
        return False
 
if __name__ == "__main__":
    # s = time.time()
    print(GPT3_16().api_call("What's c++ latest version 2023?"))
    # print(time.time()-s)

    
