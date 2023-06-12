#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
from pwn import *
import pow as pw

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

if __name__ == '__main__':
    r = remote('up23.zoolab.org', 10363)
    solve_pow(r)

    r.recvline()
    r.recvline()
    r.recvline()
    num = r.recvline()
    r.recvline()
    r.recvline()
    r.recvline()
    r.recvline()
    target = "= ?"
    n = (int(num[20])-48)*100+(int(num[21])-48)*10+(int(num[22])-48)
    print( str(n) + "tasks")
    base8 = (2**8)-1

    for i in range(0,n):
        q = r.recvuntil(target.encode())
        print(q.decode())#question

        num = q.decode().split(" ")
        n1 = int(hex(int(num[-5])),16)
        n2 = int(hex(int(num[-3])),16)
        op = num[-4]

        if op == "//":
            answer = n1//n2
            print(answer)
        elif op == "**":
            answer = n1**n2
            print(answer)      
        elif op == "*":
            answer = n1*n2
            print(answer)
        elif op == "%":
            answer = n1%n2
            print(answer)
        elif op == "+":
            answer = n1+n2
            print(answer)
        else : 
            answer = n1-n2
            print(answer)

        answer = answer
        #start from here
        s7 = answer & int(base8)
        answer = answer >> 8
        b = p8(s7)
        while answer > 0:
            s7 = answer & int(base8)
            answer = answer >>8
            b = b + p8(s7)

        print(base64.b64encode(b))#answer  
        r.sendline(base64.b64encode(b))

    r.interactive()
    r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
