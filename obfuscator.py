import argparse
import zlib
import base64
import os
import random
import string
import logging
import hashlib
import sys
import platform
import time
import inspect
import traceback
from datetime import datetime
import uuid
import textwrap
import subprocess

try:
    from cryptography.fernet import Fernet 
except:
    subprocess.run('python -m pip install cryptography', shell=True)
    from cryptography.fernet import Fernet

BUILD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build")
TEMP_FILE_PATH = os.path.join(BUILD_PATH, "temp.py")
XOR_KEY = int.from_bytes(os.urandom(32), byteorder='big') % 255 + 1

logging.basicConfig(level=logging.INFO)

def rand_string(length):
    first = random.choice(string.ascii_letters)
    rest = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length - 1))
    return first + rest

def xor_encrypt(data, xor_key):
    return bytes([b ^ xor_key for b in data])

def multi_layer_encrypt(data, key):
    bytes_data = data.encode()
    
    rolling_key = bytes([((i % 94) + 32) for i in range(len(bytes_data))])
    xored = bytes(a ^ b for a, b in zip(bytes_data, rolling_key))
    
    encoded = base64.b85encode(xored)
    
    cipher_suite = Fernet(key)
    encrypted = cipher_suite.encrypt(encoded)
    
    return base64.b85encode(encrypted).decode('utf-8')

def generate_fake_code():
    operations = [
        f"def {rand_string(8)}(): return {rand_string(8)}",
        f"class {rand_string(8)}: pass",
        f"{rand_string(8)} = lambda x: x + {random.randint(1, 1000)}",
        f"try: import {rand_string(8)}\nexcept: pass",
        f"if False: assert True is False"
    ]
    
    return '\n'.join([random.choice(operations) for _ in range(random.randint(10, 20))])

def generate_junk_code():
    operations = [
        "gc.collect()",
        "id(object())",
        "socket.gethostname()",
        "os.getpid()",
        f"[{random.randint(1,10)} ** 2 for _ in range(2)]",
        f"''.join([chr(ord(c) ^ {random.randint(1,255)}) for c in '{rand_string(4)}'])",
        f"isinstance({random.randint(1,100)}, int)",
    ]
    return random.choice(operations)

def generate_mutation_code():
    mutations = []
    for _ in range(random.randint(2, 4)):
        var = rand_string(8)
        val = random.randint(1, 1000)
        mutations.extend([
            f"{var} = {val}",
            f"globals()['{var}'] = {var} ^ {random.randint(1, 1000)}"
        ])
    return '\n'.join(mutations)

def generate_control_flow():
    states = [rand_string(8) for _ in range(2)]
    flow = []
    flow.append(f"state = '{states[0]}'")
    flow.append("while True:")
    for i, state in enumerate(states):
        next_state = states[(i + 1) % len(states)]
        flow.append(f"    if state == '{state}':")
        flow.append(f"        {generate_junk_code()}")
        flow.append(f"        state = '{next_state}'")
        if i == len(states) - 1:
            flow.append("        break")
    return '\n'.join(flow)

def main():
    parser = argparse.ArgumentParser(description='Python script obfuscator')
    parser.add_argument('output', help='Output file name')
    args = parser.parse_args()

    if not os.path.exists(BUILD_PATH):
        os.makedirs(BUILD_PATH)

    uuid_val = str(uuid.uuid4())

    encryption_key = Fernet.generate_key()
    
    class_name = rand_string(8)
    decrypt_method = rand_string(8)
    debug_check1 = rand_string(8)
    debug_check2 = rand_string(8)
    main_method = rand_string(8)
    key_attr = rand_string(8)

    if not os.path.exists(TEMP_FILE_PATH):
        with open(TEMP_FILE_PATH, 'w') as f:
            f.write('print("Hello from obfuscated code!")')

    with open(TEMP_FILE_PATH, 'r', encoding='utf-8') as f:
        source_code = f.read()

    fake_code = generate_fake_code()

    imports = [
        'import base64', 'import sys', 'import os', 'import time',
        'import socket', 'import platform', 'import inspect',
        'import random', 'import gc', 'import marshal', 'import zlib'
    ]
    encoded_imports = base64.b85encode(('\n'.join(imports)).encode()).decode()

    encrypted_code = multi_layer_encrypt(source_code, encryption_key)
    encrypted_code = f'''""{encrypted_code}""'''

    names = {
        'f': rand_string(8),
        'd': rand_string(8),
        'b': rand_string(8),
        'r': rand_string(8),
        'res': rand_string(8),
        'i': rand_string(8),
        'x': rand_string(8),
        'y': rand_string(8),
        'e': rand_string(8),
        'p': rand_string(8),
        'c': rand_string(8),
        'co': rand_string(8),
        'sy': rand_string(8),
        'bs': rand_string(8),
        'sf': rand_string(8)   , 
        'tt': rand_string(8)    ,
        'rd': rand_string(8)    ,
        'frn': rand_string(8)  , 
    }

    obfuscated_script = f
    """
import base64 as {names['bs']};import sys as {names['sy']};import subprocess;import os;import time as {names['tt']};import socket;import platform;import inspect;import random as {names['rd']};import gc;import marshal;import zlib;
try:from cryptography.fernet import Fernet as {names['frn']}
except ImportError:subprocess.run('python -m pip install cryptography', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE);from cryptography.fernet import Fernet as {names['frn']}


def check_debug():
{textwrap.indent(generate_mutation_code(), ' ' * 4)}
    return bool(globals().get('__debug__', False))

def run_checks():
{textwrap.indent(generate_control_flow(), ' ' * 4)}

class {class_name}:
    def __init__(self):
{textwrap.indent(generate_mutation_code(), ' ' * 8)}
        self.{key_attr} = b"{encryption_key.decode('utf-8')}"
        {generate_junk_code()}
    
    def {decrypt_method}(self, data, key):
        try:
{textwrap.indent(generate_control_flow(), ' ' * 12)}
            {names['f']} = {names['frn']}(key)
            {names['d']} = {names['f']}.decrypt({names['bs']}.b85decode(data))
            {names['b']} = {names['bs']}.b85decode({names['d']})
            {names['r']} = bytes([((i % 94) + 32) for i in range(len({names['b']}))])
            {names['res']} = bytes({names['x']} ^ {names['y']} for {names['x']}, {names['y']} in zip({names['b']}, {names['r']}))
            return {names['res']}.decode('utf-8')
        except Exception as {names['e']}:
            {names['sy']}.exit({names['rd']}.randint(1, 255))
    
    def {debug_check1}(self):
        try:
{textwrap.indent(generate_mutation_code(), ' ' * 12)}
            return len(inspect.stack()) > 3 or {names['sy']}.gettrace() is not None
        except:
            return False
    
    def {debug_check2}(self):
        try:
            start = {names['tt']}.time()
            [hash(str(x)) for x in range(1000)]
            return ({names['tt']}.time() - start) > 0.1
        except:
            return False
    
    def {main_method}(self):
        if self.{debug_check1}() or self.{debug_check2}():
            {names['sy']}.exit({names['rd']}.randint(1, 255))
        try:
{textwrap.indent(generate_control_flow(), ' ' * 12)}
            {names['p']} = "{encrypted_code}"
            {names['c']} = self.{decrypt_method}({names['p']}, self.{key_attr})
            {names['co']} = compile({names['c']}, f'<{uuid_val}>', 'exec')
            exec(marshal.loads(marshal.dumps({names['co']})))
        except Exception as {names['e']}:
            {names['sy']}.exit({names['rd']}.randint(1, 255))

if __name__ == "__main__":
    try:
        {class_name}().{main_method}()
    except Exception as {names['e']}:
        {names['sy']}.exit({names['rd']}.randint(1, 255))
"""

    output_path = os.path.join(BUILD_PATH, f"{args.output}.py")
    with open(output_path, 'w') as f:
        f.write(obfuscated_script)

    print(f"Successfully created obfuscated file: {output_path}")

if __name__ == "__main__":
    main()
