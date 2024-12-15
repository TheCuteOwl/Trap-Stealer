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

def string_encryption(text):
    reversed_text = text[::-1]
    
    xor_key = random.randint(1, 255)
    xored_text = ''.join(chr(ord(c) ^ xor_key) for c in reversed_text)
    
    shuffled_base64 = base64.b64encode(xored_text.encode()).decode()
    shuffled_chars = list(shuffled_base64)
    random.shuffle(shuffled_chars)
    
    return {
        'encrypted': ''.join(shuffled_chars),
        'xor_key': xor_key
    }

def generate_anti_debugging_code():
    anti_debug_funcs = []
    t = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
    anti_debug_funcs.append(f"""
def {t}():
    import time;s=time.time();[hash(str(x)) for x in range(10000)];return time.time()-s>0.5
""")
    m = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
    anti_debug_funcs.append(f"""
def {m}():
    import os;x=lambda p:p.split()[1] if len(p.split())>1 else'0';
    try:
        with open('/proc/self/status','r')as f:
            return int(x(next(l for l in f if l.startswith('VmSize:'))))>100*1024
    except:return False
""")
    e = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
    anti_debug_funcs.append(f"""
def {e}():
    import os,sys;v=['PYCHARM_HOSTED','VSCODE_PID','DEBUGGER_PORT','PYTHONBREAKPOINT','WING_DEBUGGER'];
    n=['gdb','lldb','windbg','ida','x64dbg'];
    return any(x in os.environ for x in v) or any(x in sys.argv[0].lower() for x in n)
""")
    return '\n'.join(anti_debug_funcs)

def generate_code_morphing():

    morphing_techniques = []
    
    code_template = textwrap.dedent(f"""
    def {{func_name}}(x):
        transformed_x = x * {{mult1}} + {{const}}
        
        operations = [
            lambda val: val + {{add1}},
            lambda val: val * {{mult1}},
            lambda val: val ** 2,
            lambda val: val % {{const}} if {{const}} != 0 else val
        ]
        
        selected_op = random.choice(operations)
        return selected_op(transformed_x)
""")
    
    for _ in range(random.randint(3, 7)):
        func_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
        mult1 = random.randint(1, 10)
        const = random.randint(-100, 100)
        add1 = random.randint(1, 50)
        
        modified_code = code_template.format(
            func_name=func_name, 
            mult1=mult1, 
            const=const, 
            add1=add1
        )
        exec(modified_code, globals())
        morphing_techniques.append(modified_code)
    
    metamorph_template = textwrap.dedent(f"""
    def {{func_name}}(data):
        def dynamic_transformer(input_data):
            transforms = [
                lambda x: base64.b64encode(x.encode()).decode(),
                lambda x: zlib.compress(x.encode()),
                lambda x: ''.join(chr(ord(c) ^ {{xor_key}}) for c in x),
                lambda x: x[::-1] 
            ]
            
            result = input_data
            for _ in range(random.randint(1, 3)):
                result = random.choice(transforms)(result)
            
            return result
        
        return dynamic_transformer(data)
""")
    
    for _ in range(random.randint(2, 5)):
        func_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
        xor_key = random.randint(1, 255)
        
        metamorph_code = metamorph_template.format(
            func_name=func_name,
            xor_key=xor_key
        )
        exec(metamorph_code, globals())
        morphing_techniques.append(metamorph_code)
    
    control_flow_template = textwrap.dedent(f"""
    def {{func_name}}(x):
        def complex_branching(val):
            branches = [
                lambda v: v * {{mult1}} if v > {{threshold}} else v + {{add1}},
                lambda v: v ** 2 if v < {{threshold}} else v - {{const}},
                lambda v: v % {{const}} if {{const}} != 0 else v,
                lambda v: v << 1 if v > 0 else v >> 1
            ]
            return random.choice(branches)(val)
        
        return complex_branching(x)
""")
    
    for _ in range(random.randint(2, 4)):
        func_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
        mult1 = random.randint(1, 10)
        const = random.randint(-100, 100)
        add1 = random.randint(1, 50)
        threshold = random.randint(0, 100)
        
        control_flow_code = control_flow_template.format(
            func_name=func_name,
            mult1=mult1,
            const=const,
            add1=add1,
            threshold=threshold
        )
        exec(control_flow_code, globals())
        morphing_techniques.append(control_flow_code)
    
    return '\n'.join(morphing_techniques)

def generate_code_camouflage():
    camouflage_templates = [
        "def {func_name}(data):\n    try:\n        return [x for x in data if isinstance(x, (int, float)) and x > {threshold}]\n    except:\n        return data",
        "def {func_name}(obj):\n    try:\n        return {conversion_type}(obj) if obj is not None else None\n    except (ValueError, TypeError):\n        return obj",
        "def {func_name}(value):\n    def validate_{validation_type}(v):\n        try:\n            return {validation_logic}\n        except:\n            return False\n    return validate_{validation_type}(value)",
        "class {class_name}:\n    def __init__(self, **kwargs):\n        self._config = {{\n            'debug': {debug_flag},\n            'timeout': {timeout},\n            'max_retries': {max_retries}\n        }}\n    def get_config(self, key=None):\n        return self._config.get(key, self._config) if key else self._config",
        "{func_name} = lambda {args}: {lambda_expr}",
        "class {class_name}:\n    def __enter__(self):\n        {enter_logic}\n        return self\n    def __exit__(self, exc_type, exc_val, exc_tb):\n        {exit_logic}\n        return False",
        "def {decorator_name}(func):\n    def wrapper(*args, **kwargs):\n        {pre_call_logic}\n        result = func(*args, **kwargs)\n        {post_call_logic}\n        return result\n    return wrapper"
    ]
    
    camouflage_code = []
    for _ in range(random.randint(5, 10)):
        template = random.choice(camouflage_templates)
        
        func_name = f'{rand_string(8)}'
        class_name = f'{rand_string(6)}'
        
        template_params = {
            'func_name': func_name,
            'class_name': class_name,
            'threshold': random.randint(0, 100),
            'conversion_type': random.choice(['str', 'int', 'float', 'list', 'set']),
            'validation_type': random.choice(['email', 'number', 'length', 'range']),
            'validation_logic': random.choice([
                'len(str(v)) > 0',
                '0 <= v <= 100',
                'isinstance(v, (int, float))',
                'v.isalnum()'
            ]),
            'debug_flag': random.choice([True, False]),
            'timeout': random.randint(10, 300),
            'max_retries': random.randint(1, 5),
            'args': ', '.join([f'arg{i}' for i in range(random.randint(1, 3))]),
            'lambda_expr': random.choice([
                'arg0 * arg1 if arg0 and arg1 else 0',
                'sum([arg0, arg1]) if len([arg0, arg1]) > 0 else None',
                'max([arg0, arg1]) if all(isinstance(x, (int, float)) for x in [arg0, arg1]) else None'
            ]),
            'decorator_name': f'trace_{rand_string(6)}',
            'enter_logic': 'pass',
            'exit_logic': 'pass',
            'pre_call_logic': 'pass',
            'post_call_logic': 'pass'
        }
        
        camouflage_code.append(template.format(**template_params))
    
    return '\n\n'.join(camouflage_code)

def obfuscate_file(input_file, output_file):
    parser = argparse.ArgumentParser(description='Python script obfuscator')
    parser.add_argument('output', help='Output file name')
    args = parser.parse_args([output_file])

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

    with open(input_file, 'r', encoding='utf-8') as f:
        source_code = f.read()

    fake_code = generate_fake_code()

    imports = [
        'import base64', 'import sys', 'import os', 'import time',
        'import socket', 'import platform', 'import inspect',
        'import random', 'import gc', 'import marshal', 'import zlib'
    ]
    encrypted_imports = string_encryption('\n'.join(imports))

    encrypted_code = multi_layer_encrypt(source_code, encryption_key)
    encrypted_code = f'''"{encrypted_code}"'''

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
        'obf_code': rand_string(8),
        'exec_func': rand_string(8),
    }

    anti_debug_code = generate_anti_debugging_code()
    code_morphing = generate_code_morphing()
    code_camouflage = generate_code_camouflage()
    code_morphing2 = generate_code_morphing()
    code_camouflage2 = generate_code_camouflage()

    obfuscated_script = f'''
import base64 as {names['bs']};import sys as {names['sy']};import subprocess;import os;import time as {names['tt']};import socket;import platform;import inspect;import random as {names['rd']};import gc;import marshal;import zlib;
try:from cryptography.fernet import Fernet as {names['frn']}
except ImportError:subprocess.run('python -m pip install cryptography', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE);from cryptography.fernet import Fernet as {names['frn']}

{anti_debug_code}

{code_morphing}

{code_camouflage}

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
            {names['p']} = {encrypted_code}
            {names['c']} = self.{decrypt_method}({names['p']}, self.{key_attr})
            
            {names['co']} = compile({names['c']}, '<obfuscated>', 'exec')
            exec_globals = {{}}
            exec(marshal.loads(marshal.dumps({names['co']})), exec_globals)
            
            if 'main' in exec_globals:
                exec_globals['main']()
        except Exception as {names['e']}:
            {names['sy']}.exit({names['rd']}.randint(1, 255))

if __name__ == "__main__":
    try:
        {class_name}().{main_method}()
    except Exception as {names['e']}:
        {names['sy']}.exit({names['rd']}.randint(1, 255))

def {rand_string(8)}():
    if detect_debugger_timing() or detect_debugger_resources() or detect_debugger_environment():
        sys.exit(random.randint(1, 255))

{code_morphing2}

{code_camouflage2}


'''

    with open(output_file, 'w') as f:
        f.write(obfuscated_script)

def cleanup_build_directory(output_filename, temp_filename):
    build_path = os.path.join(os.path.dirname(__file__), 'build')
    
    if not os.path.exists(build_path):
        return
    
    files = os.listdir(build_path)
    
    keep_files = {output_filename, temp_filename, 
                  os.path.basename(temp_filename), 
                  os.path.basename(output_filename)}
    
    for file in files:
        if file not in keep_files and file.endswith('.py'):
            file_path = os.path.join(build_path, file)
            try:
                os.remove(file_path)
                print(f"Removed unnecessary file: {file}")
            except Exception as e:
                print(f"Could not remove {file}: {e}")

# DONT USE RECURSIVE IT DOES NOT WORK AT ALL
def main(input_file=None, output_file=None, recursive_obfuscation=None):
    current_input = input_file or TEMP_FILE_PATH
    
    if recursive_obfuscation is None:
        recursive_obfuscation = 1
    
    for current_iteration in range(recursive_obfuscation):
        current_output = os.path.join(
            BUILD_PATH, 
            f'recursive_obfuscated_{current_iteration}.py'
        )
        
        obfuscate_file(current_input, current_output)
        
        current_input = current_output
            
    if output_file:
        if os.path.basename(output_file) == output_file:
            output_file = os.path.join(BUILD_PATH, output_file)
        
        if current_output != output_file:
            if os.path.exists(output_file):
                os.remove(output_file)
            os.rename(current_output, output_file)
    
    cleanup_build_directory(os.path.basename(output_file), os.path.basename(TEMP_FILE_PATH))
    
    print(f"Final output: {output_file or current_output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Obfuscator")
    parser.add_argument("output", help="Output file name (saved in build directory)")
    parser.add_argument("-r", "--recursive", type=int, default=1, help="Number of recursive obfuscation iterations")
    
    args = parser.parse_args()
    
    output_filename = args.output if args.output.endswith('.py') else f"{args.output}.py"
    output_file = os.path.join(BUILD_PATH, output_filename)
    
    main(TEMP_FILE_PATH, output_file, args.recursive)
