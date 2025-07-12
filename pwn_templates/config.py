#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PWN Templates Configuration
模板映射配置文件
"""

import os
from datetime import datetime

# 模板映射字典 - 数字到模板文件的映射
TEMPLATE_MAPPING = {
    1: {
        "file": "template1.py",
        "name": "Basic Template",
        "description": "基础模板，适用于各个方向"
    },
    2: {
        "file": "template2.py", 
        "name": "Format String",
        "description": "格式化字符串漏洞模板，适用于printf类漏洞"
    },
    3: {
        "file": "template3.py",
        "name": "Format String",
        "description": "格式化字符串漏洞模板，适用于printf类漏洞"
    },
    4: {
        "file": "template4.py",
        "name": "Heap Exploitation", 
        "description": "堆利用模板，适用于UAF、Double Free等堆漏洞"
    },
    5: {
        "file": "template5.py",
        "name": "Shellcode Injection",
        "description": "Shellcode注入模板，适用于可执行栈的情况"
    }
}

# 默认替换变量
DEFAULT_REPLACEMENTS = {
    "date": datetime.now().strftime("%Y-%m-%d"),
    "description": "no description",
    "binary_name": "target",
    "url": ""
}



def get_template_path(template_num):
    """获取模板文件的完整路径"""
    if template_num not in TEMPLATE_MAPPING:
        return None
    
    # 获取当前脚本所在目录的父目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    template_file = TEMPLATE_MAPPING[template_num]["file"]
    
    return os.path.join(project_root, "templates", template_file)

def get_template_info(template_num):
    """获取模板信息"""
    return TEMPLATE_MAPPING.get(template_num, None)

def list_all_templates():
    """列出所有可用的模板"""
    return TEMPLATE_MAPPING


