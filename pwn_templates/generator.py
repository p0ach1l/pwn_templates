#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PWN Template Generator
模板生成器核心功能
"""

import os
import shutil
from datetime import datetime
from .config import get_template_path, get_template_info, DEFAULT_REPLACEMENTS, list_all_templates

class TemplateGenerator:
    def __init__(self):
        self.replacements = DEFAULT_REPLACEMENTS.copy()
    
    def set_replacement(self, key, value):
        """设置替换变量"""
        self.replacements[key] = value
    
    def set_replacements(self, replacements_dict):
        """批量设置替换变量"""
        self.replacements.update(replacements_dict)
    
    def generate_template(self, template_num):
        """
        生成模板文件

        Args:
            template_num (int): 模板编号

        Returns:
            str: 生成的文件路径，如果失败返回None
        """
        # 获取模板路径
        template_path = get_template_path(template_num)
        if not template_path or not os.path.exists(template_path):
            print(f"错误: 模板 {template_num} 不存在")
            return None

        # 获取模板信息
        template_info = get_template_info(template_num)

        # 读取模板内容
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
        except Exception as e:
            print(f"错误: 无法读取模板文件 {template_path}: {e}")
            return None

        # 确定输出文件名
        output_file = f"exploit_{template_num}.py"

        # 写入生成的文件（不做变量替换，保持原样）
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(template_content)

            print(f"✅ 成功生成模板文件: {output_file}")
            print(f"📝 模板类型: {template_info['name']}")
            print(f"📄 描述: {template_info['description']}")

            return output_file

        except Exception as e:
            print(f"错误: 无法写入文件 {output_file}: {e}")
            return None
    

