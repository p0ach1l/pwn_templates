#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PWN Templates Command Line Interface
简化的命令行接口 - 只支持 pwn new <数字>
"""

import sys
from .generator import TemplateGenerator

def main():
    """主命令行入口"""
    if len(sys.argv) < 3:
        print("使用方法: pwn new <模板编号>")
        print("\n可用模板:")
        print("  1. Stack Buffer Overflow     - 基础栈溢出")
        print("  2. ROP Chain                 - ROP链利用")
        print("  3. Format String             - 格式化字符串漏洞")
        print("  4. Heap Exploitation         - 堆利用")
        print("  5. Shellcode Injection       - Shellcode注入")
        print("\n示例: pwn new 1")
        return

    if sys.argv[1] != 'new':
        print("❌ 错误: 只支持 'new' 命令")
        print("使用方法: pwn new <模板编号>")
        return

    try:
        template_num = int(sys.argv[2])
    except ValueError:
        print("❌ 错误: 模板编号必须是数字")
        return

    # 验证模板编号
    if template_num < 1 or template_num > 5:
        print("❌ 错误: 模板编号必须在1-5之间")
        return

    generator = TemplateGenerator()

    # 生成模板
    result = generator.generate_template(template_num)

    if result:
        print(f"✅ 模板已生成: {result}")
        print("💡 提示: 请根据实际情况修改模板中的参数!")
    else:
        print("❌ 模板生成失败")
        sys.exit(1)

if __name__ == "__main__":
    main()
