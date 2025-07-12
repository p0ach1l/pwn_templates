#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic PWN Template - basis Template 
Author: p0ach1l
Date: {{date}}
description: {{description}}
"""

from pwn import *
from ctypes import *
from LibcSearcher import *
from pwnscript import *


filename = "./{{binary_name}}"
url = '{{url}}'
gdbscript = '''
  b * main
'''
set_context(log_level='debug', arch='amd64', os='linux', endian='little', timeout=5)
p = pr(url=url , filename=filename , gdbscript=gdbscript , framepath='')
elf = ELF(filename)




p.interactive()
