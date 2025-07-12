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
        "name": "Stack Buffer Overflow",
        "description": "基础栈溢出模板，适用于简单的返回地址覆盖"
    },
    2: {
        "file": "template2.py", 
        "name": "ROP Chain",
        "description": "ROP链模板，适用于需要绕过NX保护的情况"
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
    "remote_host": "127.0.0.1",
    "remote_port": "9999",
    # "offset": "72",
    # "return_address": "0x401234",
    # "pop_rdi_gadget": "0x401234",
    # "pop_rsi_gadget": "0x401235",
    # "pop_rdx_gadget": "0x401236",
    # "format_offset": "6",
    # "target_address": "0x601020",
    # "target_value": "0x401234",
    # "libc_offset": "0x3c4b20",
    # "nop_length": "100",
    # "shellcode_address": "0x7fffffffe000"
}

# 参数验证规则
VALIDATION_RULES = {
    "remote_port": {"type": int, "min": 1, "max": 65535},
    # "offset": {"type": int, "min": 0, "max": 10000},
    # "format_offset": {"type": int, "min": 1, "max": 50},
    # "nop_length": {"type": int, "min": 0, "max": 1000},
    # "return_address": {"type": str, "pattern": r"^0x[0-9a-fA-F]+$"},
    # "pop_rdi_gadget": {"type": str, "pattern": r"^0x[0-9a-fA-F]+$"},
    # "pop_rsi_gadget": {"type": str, "pattern": r"^0x[0-9a-fA-F]+$"},
    # "pop_rdx_gadget": {"type": str, "pattern": r"^0x[0-9a-fA-F]+$"},
    # "target_address": {"type": str, "pattern": r"^0x[0-9a-fA-F]+$"},
    # "target_value": {"type": str, "pattern": r"^0x[0-9a-fA-F]+$"},
    # "libc_offset": {"type": str, "pattern": r"^0x[0-9a-fA-F]+$"},
    # "shellcode_address": {"type": str, "pattern": r"^0x[0-9a-fA-F]+$"},
}

# 模板特定的参数
TEMPLATE_SPECIFIC_PARAMS = {
    1: ["offset", "return_address"],  # Stack Buffer Overflow
    2: ["offset", "pop_rdi_gadget", "pop_rsi_gadget", "pop_rdx_gadget"],  # ROP Chain
    3: ["format_offset", "target_address", "target_value"],  # Format String
    4: ["libc_offset"],  # Heap Exploitation
    5: ["offset", "nop_length", "shellcode_address"],  # Shellcode Injection
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

def validate_parameter(key, value):
    """
    验证参数值是否符合规则

    Args:
        key (str): 参数名
        value (str): 参数值

    Returns:
        tuple: (is_valid, error_message)
    """
    import re

    if key not in VALIDATION_RULES:
        return True, None

    rule = VALIDATION_RULES[key]

    # 类型验证
    if rule["type"] == int:
        try:
            int_value = int(value)
            if "min" in rule and int_value < rule["min"]:
                return False, f"{key} 必须大于等于 {rule['min']}"
            if "max" in rule and int_value > rule["max"]:
                return False, f"{key} 必须小于等于 {rule['max']}"
        except ValueError:
            return False, f"{key} 必须是数字"

    elif rule["type"] == str:
        if "pattern" in rule:
            if not re.match(rule["pattern"], value):
                return False, f"{key} 格式不正确，应该是十六进制地址格式 (如: 0x401234)"

    return True, None

# def get_template_specific_params(template_id):
#     """获取模板特定的参数列表"""
#     return TEMPLATE_SPECIFIC_PARAMS.get(template_id, [])

def validate_all_parameters(params):
    """
    验证所有参数

    Args:
        params (dict): 参数字典

    Returns:
        tuple: (is_valid, error_messages)
    """
    errors = []

    for key, value in params.items():
        is_valid, error_msg = validate_parameter(key, value)
        if not is_valid:
            errors.append(error_msg)

    return len(errors) == 0, errors
