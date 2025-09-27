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
set_context(log_level='debug', arch='amd64')
p = pr(url=url , filename=filename , gdbscript=gdbscript)
elf = ELF(filename)
set_binary(elf)




ia()
