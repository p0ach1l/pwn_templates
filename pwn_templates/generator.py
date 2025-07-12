#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PWN Template Generator
模板生成器核心功能
"""

import os
import shutil
from datetime import datetime
from .config import get_template_path, get_template_info, DEFAULT_REPLACEMENTS

class TemplateGenerator:
    def __init__(self):
        self.replacements = DEFAULT_REPLACEMENTS.copy()
    
    def set_replacement(self, key, value):
        """设置替换变量"""
        self.replacements[key] = value
    
    def set_replacements(self, replacements_dict):
        """批量设置替换变量"""
        self.replacements.update(replacements_dict)
    
    def generate_template(self, template_num, output_file=None):
        """
        生成模板文件

        Args:
            template_num (int): 模板编号
            output_file (str, optional): 输出文件名，如果为None则使用默认名称

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
        if not output_file:
            output_file = f"exploit_{template_num}.py"
        elif not output_file.endswith('.py'):
            output_file += '.py'

        # 进行变量替换
        processed_content = self._replace_variables(template_content)

        # 写入生成的文件
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(processed_content)

            return output_file

        except Exception as e:
            print(f"错误: 无法写入文件 {output_file}: {e}")
            return None
    
    def _replace_variables(self, content):
        """
        替换模板中的变量占位符
        
        Args:
            content (str): 模板内容
            
        Returns:
            str: 替换后的内容
        """
        # 更新日期
        self.replacements['date'] = datetime.now().strftime("%Y-%m-%d")
        
        # 进行变量替换
        for key, value in self.replacements.items():
            placeholder = f"{{{{{key}}}}}"  # 格式: {{variable_name}}
            content = content.replace(placeholder, str(value))
        
        return content
