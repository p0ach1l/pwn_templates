#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PWN Templates Command Line Interface
完整的命令行接口，支持所有参数选项
"""

import sys
import argparse
from .generator import TemplateGenerator
from .config import list_all_templates

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
  pwn new 4 --url 192.168.1.100:1337          # 指定远程主机和端口
  pwn new 5 -i                                # 交互式配置参数
  pwn new 1 --description "Ubuntu 20.04 x64"  # 指定目标描述
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
    new_parser.add_argument('--binary',
                           help='目标程序名称')

    new_parser.add_argument('--url',
                           help='目标URL')

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
    if args.url:
        params['url'] = args.url
    
    # 设置输出文件名    output_file = args.binary
    # 交互式配置
    if args.interactive:
        params.update(interactive_config(args.template_id))
        if not output_file:
            default_name = params['binary_name']
            user_input = input(f"输出文件名 (回车使用默认: {default_name}): ").strip()
            output_file = user_input or default_name


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
    from .config import DEFAULT_REPLACEMENTS

    templates = list_all_templates()
    template_info = templates[template_id]

    print(f"\n🔧 交互式配置模板 {template_id} - {template_info['name']}")
    print(f"📄 {template_info['description']}")
    print("提示: 直接回车使用默认值，输入 'skip' 跳过可选参数\n")

    params = {}

    # 基础参数
    binary = input(f"目标程序名称 [{DEFAULT_REPLACEMENTS['binary_name']}]: ").strip()
    if binary.lower() != 'skip':
        params['binary_name'] = binary or DEFAULT_REPLACEMENTS['binary_name']

    target_desc = input(f"目标描述 [{DEFAULT_REPLACEMENTS['description']}]: ").strip()
    if target_desc.lower() != 'skip':
        params['description'] = target_desc or DEFAULT_REPLACEMENTS['description']

<<<<<<< HEAD
    url = input(f"目标URL [{DEFAULT_REPLACEMENTS['url']}]: ").strip()
    if url.lower() != 'skip':
        params['url'] = url or DEFAULT_REPLACEMENTS['url']

=======
    # 远程连接参数
    host = input(f"远程主机地址 [{DEFAULT_REPLACEMENTS['remote_host']}]: ").strip()
    if host.lower() != 'skip':
        params['remote_host'] = host or DEFAULT_REPLACEMENTS['remote_host']

    port = input(f"远程端口 [{DEFAULT_REPLACEMENTS['remote_port']}]: ").strip()
    if port.lower() != 'skip':
        port = port or DEFAULT_REPLACEMENTS['remote_port']
        is_valid, error_msg = validate_parameter('remote_port', port)
        if is_valid:
            params['remote_port'] = port
        else:
            print(f"⚠️  {error_msg}，使用默认值")
            params['remote_port'] = DEFAULT_REPLACEMENTS['remote_port']

>>>>>>> 035f4a2f0d06dcff1a01c63e8ae1f31da8800a2c
    return params


if __name__ == "__main__":
    main()
