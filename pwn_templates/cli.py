#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PWN Templates Command Line Interface (Simplified)
精简版命令行接口，只支持两个命令格式
"""

import sys
from .generator import TemplateGenerator
from .config import list_all_templates

def show_templates():
    """显示所有可用模板"""
    templates = list_all_templates()
    print("可用模板:")
    for num, info in templates.items():
        print(f"  {num}. {info['name']:<25} - {info['description']}")

def show_help():
    """显示帮助信息"""
    print("PWN模板生成工具")
    print("\n用法:")
    print("  pwnt <二进制文件> <模板编号>    # 生成指定二进制文件的模板")
    print("  pwnt <模板编号>              # 生成默认模板")
    print("\n示例:")
    print("  pwnt challenge 1            # 为challenge程序生成模板1")
    print("  pwnt 2                      # 生成模板2（使用默认二进制名）")
    print("\n")
    show_templates()

def main():
    """主命令行入口"""
    try:
        # 如果没有参数，显示帮助信息
        if len(sys.argv) == 1:
            show_help()
            return

        args = sys.argv[1:]
        
        # 判断命令格式
        if len(args) == 1:
            # 格式: pwnt <模板编号>
            try:
                template_id = int(args[0])
                binary_name = None
            except ValueError:
                print("❌ 错误: 模板编号必须是数字")
                show_help()
                return
        elif len(args) == 2:
            # 格式: pwnt <二进制文件> <模板编号>
            try:
                binary_name = args[0]
                template_id = int(args[1])
            except ValueError:
                print("❌ 错误: 模板编号必须是数字")
                show_help()
                return
        else:
            print("❌ 错误: 参数数量不正确")
            show_help()
            return

        # 验证模板编号
        templates = list_all_templates()
        if template_id not in templates:
            print(f"❌ 错误: 模板编号必须在 {min(templates.keys())}-{max(templates.keys())} 之间")
            print("\n")
            show_templates()
            return

        # 生成模板
        generator = TemplateGenerator()
        
        # 设置二进制文件名（如果提供）
        if binary_name:
            generator.set_replacement('binary_name', binary_name)
            output_file = binary_name
        else:
            output_file = None

        result = generator.generate_template(template_id, output_file)

        if result:
            template_info = templates[template_id]
            print(f"✅ 模板已生成: {result}")
            print(f"🔧 模板类型: {template_info['name']}")
            print(f"📄 描述: {template_info['description']}")
            if binary_name:
                print(f"🎯 目标程序: {binary_name}")
            print("💡 提示: 请根据实际情况进一步修改模板中的参数!")
        else:
            print("❌ 模板生成失败")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n👋 用户取消操作，程序退出")
        sys.exit(0)

if __name__ == "__main__":
    main()