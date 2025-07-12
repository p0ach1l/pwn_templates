#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PWN Templates Command Line Interface
完整的命令行接口，支持所有参数选项
"""

import sys
import argparse
from .generator import TemplateGenerator
from .config import list_all_templates, validate_all_parameters

def create_parser():
    """创建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog='pwn',
        description='PWN模板生成工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  pwn new 1                                   # 生成基础栈溢出模板
  pwn new 2 -o my_exploit.py                  # 指定输出文件名
  pwn new 3 --binary target --offset 64       # 指定二进制文件名和偏移
  pwn new 4 --host 192.168.1.100 --port 1337  # 指定远程主机和端口
  pwn new 5 -i                                # 交互式配置参数
  pwn new 1 --description "Ubuntu 20.04 x64"       # 指定目标描述
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='可用命令')

    # new 子命令
    new_parser = subparsers.add_parser('new', help='生成新的PWN模板')
    new_parser.add_argument('template_id', type=int, help='模板编号 (1-5)')

    # 输出选项
    new_parser.add_argument('-o', '--output',
                           help='指定输出文件名 (默认: exploit_<模板编号>.py)')

    # 交互式配置
    new_parser.add_argument('-i', '--interactive', action='store_true',
                           help='交互式配置模板参数')

    # 目标程序相关参数
    new_parser.add_argument('--elf' , '--binary',
                           help='目标程序名称')

    # 远程连接参数
    new_parser.add_argument('--host',
                           help='远程主机地址 (默认: 127.0.0.1)')
    new_parser.add_argument('-p' , '--port', type=int,
                           help='远程端口 (默认: 9999)')

    # 目标描述
    new_parser.add_argument('--description',
                           help='目标描述信息')

    return parser

def show_templates():
    """显示所有可用模板"""
    templates = list_all_templates()
    print("可用模板:")
    for num, info in templates.items():
        print(f"  {num}. {info['name']:<25} - {info['description']}")

def main():
    """主命令行入口"""
    parser = create_parser()

    # 如果没有参数，显示帮助信息
    if len(sys.argv) == 1:
        parser.print_help()
        print("\n")
        show_templates()
        return

    args = parser.parse_args()

    # 处理命令
    if args.command == 'new':
        handle_new_command(args)
    else:
        parser.print_help()

def handle_new_command(args):
    """处理 new 命令"""
    # 验证模板编号
    templates = list_all_templates()
    if args.template_id not in templates:
        print(f"❌ 错误: 模板编号必须在 {min(templates.keys())}-{max(templates.keys())} 之间")
        print("\n")
        show_templates()
        return

    # 创建生成器
    generator = TemplateGenerator()

    # 设置参数
    params = {}
    if args.binary:
        params['binary_name'] = args.binary
    if args.host:
        params['remote_host'] = args.host
    if args.port:
        params['remote_port'] = str(args.port)
    # if args.offset:
    #     params['offset'] = str(args.offset)
    # if args.description:
    #     params['description'] = args.description

    # 设置输出文件名
    output_file = args.binary
    # 交互式配置
    if args.interactive:
        params.update(interactive_config(args.template_id))
        if not output_file:
            output_file = params['binary_name']
            output_file = input("输出文件名 (回车使用默认): ").strip()

    # 验证参数
    if params:
        is_valid, errors = validate_all_parameters(params)
        if not is_valid:
            print("❌ 参数验证失败:")
            for error in errors:
                print(f"   {error}")
            return
        generator.set_replacements(params)

    # 生成模板
    result = generator.generate_template(args.template_id, output_file)

    if result:
        template_info = templates[args.template_id]
        print(f"✅ 模板已生成: {result}")
        print(f"� 模板类型: {template_info['name']}")
        print(f"📄 描述: {template_info['description']}")
        if params:
            print("🔧 已应用的参数:")
            for key, value in params.items():
                print(f"   {key}: {value}")
        print("�💡 提示: 请根据实际情况进一步修改模板中的参数!")
    else:
        print("❌ 模板生成失败")
        sys.exit(1)

def interactive_config(template_id):
    """交互式参数配置"""
    from .config import DEFAULT_REPLACEMENTS, validate_parameter

    templates = list_all_templates()
    template_info = templates[template_id]

    print(f"\n🔧 交互式配置模板 {template_id} - {template_info['name']}")
    print(f"📄 {template_info['description']}")
    print("提示: 直接回车使用默认值，输入 'skip' 跳过可选参数\n")

    params = {}

    # 基础参数
    binary = input(f"目标程序名称 [{DEFAULT_REPLACEMENTS['binary_name']}]: ").strip()
    if binary and binary != 'skip':
        params['binary_name'] = binary

    target_desc = input(f"目标描述 [{DEFAULT_REPLACEMENTS['description']}]: ").strip()
    if target_desc and target_desc != 'skip':
        params['description'] = target_desc

    # 远程连接参数
    host = input(f"远程主机地址 [{DEFAULT_REPLACEMENTS['remote_host']}]: ").strip()
    if host and host != 'skip':
        params['remote_host'] = host

    port = input(f"远程端口 [{DEFAULT_REPLACEMENTS['remote_port']}]: ").strip()
    if port and port != 'skip':
        is_valid, error_msg = validate_parameter('remote_port', port)
        if is_valid:
            params['remote_port'] = port
        else:
            print(f"⚠️  {error_msg}，使用默认值")

    # # 根据模板类型询问特定参数
    # specific_params = get_template_specific_params(template_id)

    # for param in specific_params:
    #     default_value = DEFAULT_REPLACEMENTS.get(param, "")
    #     param_name = param.replace('_', ' ').title()

    #     value = input(f"{param_name} [{default_value}]: ").strip()
    #     if value and value != 'skip':
    #         is_valid, error_msg = validate_parameter(param, value)
    #         if is_valid:
    #             params[param] = value
    #         else:
    #             print(f"⚠️  {error_msg}，使用默认值")

    # # 模板特定的额外参数
    # if template_id == 2:  # ROP链 - 额外的gadget地址
    #     pop_rsi = input(f"pop rsi gadget地址 [{DEFAULT_REPLACEMENTS['pop_rsi_gadget']}]: ").strip()
    #     if pop_rsi and pop_rsi != 'skip':
    #         is_valid, error_msg = validate_parameter('pop_rsi_gadget', pop_rsi)
    #         if is_valid:
    #             params['pop_rsi_gadget'] = pop_rsi
    #         else:
    #             print(f"⚠️  {error_msg}，使用默认值")

    #     pop_rdx = input(f"pop rdx gadget地址 [{DEFAULT_REPLACEMENTS['pop_rdx_gadget']}]: ").strip()
    #     if pop_rdx and pop_rdx != 'skip':
    #         is_valid, error_msg = validate_parameter('pop_rdx_gadget', pop_rdx)
    #         if is_valid:
    #             params['pop_rdx_gadget'] = pop_rdx
    #         else:
    #             print(f"⚠️  {error_msg}，使用默认值")

    # elif template_id == 3:  # 格式化字符串 - 额外参数
    #     target_val = input(f"目标写入值 [{DEFAULT_REPLACEMENTS['target_value']}]: ").strip()
    #     if target_val and target_val != 'skip':
    #         is_valid, error_msg = validate_parameter('target_value', target_val)
    #         if is_valid:
    #             params['target_value'] = target_val
    #         else:
    #             print(f"⚠️  {error_msg}，使用默认值")

    print()
    return params

if __name__ == "__main__":
    main()
