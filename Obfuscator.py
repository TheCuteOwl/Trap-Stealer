import os
import sys
import subprocess
import argparse
import random
import time
import marshal
import zlib


def install_dependencies():
    requirements_file = 'requirements.txt'
    python_executable = 'python' + '.'.join(str(i) for i in sys.version_info[:2])
    if subprocess.run([python_executable, '-m', 'pip', 'install', '-r', requirements_file]).returncode == 0:
        print('[+] Dependencies installed. Please run the program again.')
        sys.exit()
    else:
        print('[!] An error occurred while installing dependencies. Make sure pip is installed or requirements.txt is available.')
        sys.exit()


def encode(source):
    selected_mode = random.choice((zlib,))
    marshal_encoded = marshal.dumps(compile(source, 'Modi-Fuscate', 'exec'))
    encoded = selected_mode.compress(marshal_encoded)
    tmp_code = 'import marshal, zlib; exec(marshal.loads({}.decompress({})))'
    return tmp_code.format(selected_mode.__name__, encoded)

def parse_args():
    parser = argparse.ArgumentParser(description='Obfuscate Python programs')
    parser.add_argument('-r', '--recursion', dest='r', action='store_true',
                        help='Recursion encoding. Provides stronger obfuscation.')
    parser.add_argument('-i', '--input', type=str, help='Input file name', required=True)
    parser.add_argument('-o', '--output', type=str, help='Output file name', required=True)
    parser.add_argument('-s', '--strength', type=int, help='Strength of the obfuscation. 100 recommended', required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    print(f'[+] Encoding {args.input}')
    if not args.r:
        print('[!] You have not selected recursion mode.')
    with open(args.input, encoding='utf-8') as input_file:
        encoded = input_file.read()
        for _ in range(args.strength):
            encoded = encode(source=encoded) if args.r else encode(source=encode(source=encoded))
            time.sleep(0.1)
    with open(args.output, 'w') as output:
        output.write(f"try:\n\t{encoded}\nexcept KeyboardInterrupt:\n\tpass")
    print(f'[+] Encoding successful!\nSaved as {args.output}')


if __name__ == '__main__':
    try:
        import requests, colorama
    except ModuleNotFoundError:
        install_dependencies()
    main()
