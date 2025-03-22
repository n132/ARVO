import json
def start_coder_fix(targetId):
    with open("./Data/starcoder_100.json") as f:
        lines = f.readlines()
    for x in lines:
        item = json.loads(x)
        print(item.keys())
        localId = int(item['filename'][10:-5])
        if targetId != localId:
            continue
        else:
            return item['response']['generated_text']
