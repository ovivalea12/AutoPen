import os, json, argparse
import libtmux, htb
from box import Box

parser = argparse.ArgumentParser(description='What box do you want to pwn?')
parser.add_argument('--box', required=True)
name = parser.parse_args()
api = htb.HTB('OwBnueBa1zprFdqbWRQnNiXpyr0T1lIkZFQrwGUK0xnjD4Rs3yQxuUEGlHec')
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

def getBoxIP(name: str):
    for box in listOfBoxes:
        #for attribute, value in box.__dict__.items():
        if box.__dict__.get("name") == name.box:
            print(box.__dict__.get("ip"))
        #if box.get("name") == name:
        #    print(box["ip"])


def workflow():
    os.system("xfce4-terminal -e 'tmux new-session -s sisc'")
    #time.sleep(1)
    server = libtmux.Server()
    session = server.get_by_id('$0')
    window = session.attached_window
    window.rename_window('vpn')

    session.new_window(attach=False, window_name="nmap")

initBoxes()
print_all_boxes()
#workflow()
getBoxIP(name)
