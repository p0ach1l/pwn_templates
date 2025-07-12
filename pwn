#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PWN Templates - 主执行脚本
"""

import sys
import os

# 添加项目根目录到Python路径
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from pwn_templates.cli import main

if __name__ == "__main__":
    main()
