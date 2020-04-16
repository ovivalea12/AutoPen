import os, json, time
import libtmux, htb
from box import Box
api = htb.HTB('OwBnueBa1zprFdqbWRQnNiXpyr0T1lIkZFQrwGUK0xnjD4Rs3yQxuUEGlHec')
listOfBoxes = []
#print(a.get_machine(7))
#print(type(a.get_machine(7)))
#list = a.get_machine(7).get("ip")
#print(list)
def print_all_boxes():
    rawBoxes = api.get_machines()
    #print(all)
    #print(*all, sep='\n')
    for rawBox in rawBoxes:
        listOfBoxes.append(Box(rawBox))
        #print(el)
        #print(el.get("name"))
        #print(el["ip"])
    for box in listOfBoxes:
        print(box.__repr__())
    #formatlist = str(a.get_machines()).strip('[]')
    #print(type(formatlist))
    #formatlist = formatlist.replace("'", "\"")
    #res = json.loads(formatlist)
    #print(res)
    #list = res.get("name")

def workflow():
    os.system("xfce4-terminal -e 'tmux new-session -s sisc'")
    #time.sleep(1)
    server = libtmux.Server()
    session = server.get_by_id('$0')
    window = session.attached_window
    window.rename_window('vpn')
    
    session.new_window(attach=False, window_name="nmap")

#print_all_boxes()
workflow()
