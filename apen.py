import os, json, argparse, requests
import libtmux, htb
from box import Box

parser = argparse.ArgumentParser(description='What box do you want to pwn?')
parser.add_argument('--box', required=True)
name = parser.parse_args()
api = htb.HTB('OwBnueBa1zprFdqbWRQnNiXpyr0T1lIkZFQrwGUK0xnjD4Rs3yQxuUEGlHec')
BASE_URL = 'https://www.hackthebox.eu/api'
listOfBoxes = []
#print(a.get_machine(7))
#print(type(a.get_machine(7)))
#list = a.get_machine(7).get("ip")
#print(list)

def initBoxes():
    rawBoxes = api.get_machines()
    for rawBox in rawBoxes:
        listOfBoxes.append(Box(rawBox))

def printAllBoxes():
    for box in listOfBoxes:
        print(box.__repr__())
    #print(all)
    #print(*all, sep='\n')

        #print(el)
        #print(el.get("name"))
        #print(el["ip"])

    #formatlist = str(a.get_machines()).strip('[]')
    #print(type(formatlist))
    #formatlist = formatlist.replace("'", "\"")
    #res = json.loads(formatlist)
    #print(res)
    #list = res.get("name")

def getBoxIP(name: str) -> str:
    for box in listOfBoxes:
        #for attribute, value in box.__dict__.items():
        if box.name == name.box:
            print(box.ip)
            return box.ip
            #box.spawned
        #if box.get("name") == name:
        #    print(box["ip"])

def getBoxID(name: str) -> str:
    for box in listOfBoxes:
        #for attribute, value in box.__dict__.items():
        if box.name == name.box:
            print(box.id)
            return box.id
            #box.spawned
        #if box.get("name") == name:
        #    print(box["ip"])

def auth(path: str) -> str:
        """
        Helper function to generate an authenticated URL
        :params self: HTB object in use
        :params path: string containing path to query
        :returns: path to authenticated query
        """
        print("{}?api_token={}".format(path, api.api_key))
        return "{}?api_token={}".format(path, api.api_key)


def controlBox(name: str, action: str):
    mid = getBoxID(name)
    print(mid)
    r = requests.post(BASE_URL + auth('/vm/vip/{}/{}'.format(action, mid)), headers=api.headers).json()
    if r["success"] != 1:
        print("Error:" + (r["status"]))

def workflow():
    os.system("xfce4-terminal -e 'tmux new-session -s sisc'")
    #time.sleep(1)
    server = libtmux.Server()
    session = server.get_by_id('$0')
    window = session.attached_window
    window.rename_window('vpn')
    session.new_window(attach=False, window_name="nmap")

initBoxes()
#Switch to assign/remove box
controlBox(name, "remove")
#printAllBoxes()
#workflow()
