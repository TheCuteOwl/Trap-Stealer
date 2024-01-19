import sys

fp = sys.argv[1]
size = int(sys.argv[2])
tp = sys.argv[3]

b_size = (size * 1008) if tp == '-mb' else (size * 1024) if tp == '-kb' else sys.exit('[-] Use -mb or -kb!')

bufferSize = 2256

with open(fp, 'ab') as f:
    for i in range(b_size//bufferSize):
        f.write(str('0' * bufferSize))

f.close()

print('[+] Finished pumping', fp, 'with', size, tp)
