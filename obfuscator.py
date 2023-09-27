import string
import base64
import codecs
import os
import sys
import random
from textwrap import wrap
from lzma import compress
from marshal import dumps

class Obfuscator:
    def __init__(self, code, outpath):
        self.code = code.encode()
        self.outpath = outpath
        self.varlen = 3
        self.vars = {}

        self.marshal()
        self.encrypt1()
        self.encrypt2()
        self.finalize()

    def generate(self, name):
        res = self.vars.get(name)
        if res is None:
            res = "_" + "".join(["_" for _ in range(self.varlen)])
            self.varlen += 1
            self.vars[name] = res
        return res
    
    def encryptstring(self, string, config={}, func=False):
        b64 = list(b"base64")
        b64decode = list(b"b64decode")
        __import__ = config.get("__import__", "__import__")
        getattr = config.get("getattr", "getattr")
        bytes = config.get("bytes", "bytes")
        eval = config.get("eval", "eval")
        if not func:
            return f'{getattr}({__import__}({bytes}({b64}).decode()),{bytes}({b64decode}).decode())({bytes}({list(base64.b64encode(string.encode()))})).decode()'
        else:
            attrs = string.split(".")
            base = self.encryptstring(attrs[0], config)
            attrs = list(map(lambda x: self.encryptstring(x, config, False), attrs[1:]))
            newattr = ""
            for i, val in enumerate(attrs):
                if i == 0:
                    newattr = f'{getattr}({eval}({base}),{val})'
                else:
                    newattr = f'{getattr}({newattr},{val})'
            return newattr

    def encryptor(self, config):
        def func_(string, func=False):
            return self.encryptstring(string, config, func)
        return func_

    def compress(self):
        self.code = compress(self.code)

    def marshal(self):
        self.code = dumps(compile(self.code, "<string>", "exec"))

    def encrypt1(self):
        code = base64.b64encode(self.code).decode()
        partlen = int(len(code) / 4)
        code = wrap(code, partlen)
        var1 = self.generate("e")
        var2 = self.generate("f")
        var3 = self.generate("z")
        var4 = self.generate("c")
        init = [f'{var1}="{codecs.encode(code[0], "rot13")}"', f'{var2}="{code[1]}"', f'{var3}="{code[2][::-1]}"', f'{var4}="{code[3]}"']

        # Add randomization to the order of initialization
        random.shuffle(init)
        init = ";".join(init)

        # Introduce random noise in variable names
        noise = ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(5, 10)))

        # Add more random code lines
        random_code = ''.join([f'{self.generate("rnd" + str(i))} = {random.randint(1, 100)}\n' for i in range(10)])

        # Randomize and distribute the random useless commands
        useless_commands = ''
        for i in range(5):
            cmd_var = self.generate("cmd" + str(i))
            useless_commands += f'{cmd_var} = "This is a useless command {i}"\n'

        self.code = f'''
{init}
{random_code}
{useless_commands}
__import__({self.encryptstring("builtins")}).exec(__import__({self.encryptstring("marshal")}).loads(__import__({self.encryptstring("base64")}).b64decode(__import__({self.encryptstring("codecs")}).decode({var1}, __import__({self.encryptstring("base64")}).b64decode("{base64.b64encode(b'rot13').decode()}").decode())+{var2}+{var3}[::-1]+{var4})))
'''.strip().encode()

    def encrypt2(self):
        self.compress()
        var1 = self.generate("dn")
        var2 = self.generate("sv")
        var3 = self.generate("nQ")
        var4 = self.generate("hb")
        var5 = self.generate("iz")
        var6 = self.generate("jz")
        var7 = self.generate("ks")
        var8 = self.generate("lq")
        var9 = self.generate("mf")

        conf = {
            "getattr" : var4,
            "eval" : var3,
            "__import__" : var8,
            "bytes" : var9
        }
        encryptstring = self.encryptor(conf)

        # Add more random code lines
        random_code = ''.join([f'{self.generate("rnd" + str(i))} = {random.randint(1, 100)}\n' for i in range(10)])

        # Randomize and distribute the random useless commands
        useless_commands = ''
        for i in range(5):
            cmd_var = self.generate("cmd" + str(i + 5))  # Start from 5 to avoid name conflicts
            useless_commands += f'{cmd_var} = "This is another useless command {i}"\n'

        self.code = f'''
{var3} = eval({self.encryptstring("eval")});{var4} = {var3}({self.encryptstring("getattr")});{var8} = {var3}({self.encryptstring("__import__")});{var9} = {var3}({self.encryptstring("bytes")});{var5} = lambda {var7}: {var3}({encryptstring("compile")})({var7}, {encryptstring("<string>")}, {encryptstring("exec")});{var1} = {self.code}
{var2} = {encryptstring('__import__("builtins").list', func= True)}({var1})
try:
    {encryptstring('__import__("builtins").exec', func= True)}({var5}({encryptstring('__import__("lzma").decompress', func= True)}({var9}({var2})))) or {encryptstring('__import__("os")._exit', func= True)}(0)
except {encryptstring('__import__("lzma").LZMAError', func= True)}:...
{random_code}
{useless_commands}
'''.strip().encode()

    def encrypt3(self):
        self.compress()
        data = base64.b64encode(self.code)
        self.code = f'import base64, lzma; exec(compile(lzma.decompress(base64.b64decode({data})), "<string>", "exec"))'.encode()

    def finalize(self):
        build_folder = "build"
        if not os.path.exists(build_folder):
            os.makedirs(build_folder)

        out_file_path = os.path.join(build_folder, os.path.basename(self.outpath))
        with open(out_file_path, "w", encoding="utf-8") as file:
            file.write(self.code.decode())

        print(f"Obfuscated file saved to: {out_file_path}")

if __name__ == "__main__":
    if not os.path.isfile(src := sys.argv[1]):
        print('No such file!')
        os._exit(1)
    elif not src.endswith((".py", ".pyw")):
        print('The file does not have a valid python script extension!')
        os._exit(1)
    name = input('Enter how you want the file to be named (Do not put the extension): ')
    outpath = name + ".py"

    with open(src, encoding='utf8') as sourcefile:
        code = sourcefile.read()

    Obfuscator(code, outpath)
    
    input('Successfully Obfuscated!')
