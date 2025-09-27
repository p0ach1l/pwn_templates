# PWN Templates - CTF PWN题目模板生成工具

🚀 一个专为CTF比赛设计的PWN exploit模板快速生成工具，支持多种常见的PWN利用技术模板。

## ✨ 特性

- 🎯 **常用PWN模板**: 包含5种常见PWN模板，适用于不同漏洞类型
- 🔧 **简单易用**: 两条简单命令即可生成exploit模板
- 📝 **详细注释**: 每个模板都包含详细的中文注释和使用说明
- 🔄 **智能变量替换**: 自动替换模板中的目标程序名和其他变量

## 📦 安装

### 安装到系统（推荐）
```bash
# 安装依赖
pip install pwntools

# 安装项目
pip install -e .

# 使用系统命令
pwnt 1
```

## 🎮 使用方法

### 两种简单命令

```bash
# 命令格式1: 生成默认模板
pwnt <模板编号>

# 命令格式2: 指定二进制文件生成模板
pwnt <二进制文件> <模板编号>
```

### 使用示例

```bash
# 生成模板1（使用默认二进制名target）
pwnt 1

# 为challenge程序生成模板1
pwnt challenge 1

# 生成模板2（格式化字符串）
pwnt 2

# 为binary程序生成模板3
pwnt binary 3
```


## 📁 项目结构

```
PWN_templates/
├── pwn_templates/          # 核心包
│   ├── __init__.py        # 包初始化文件
│   ├── cli.py             # 命令行接口（精简版）
│   ├── generator.py       # 模板生成器
│   └── config.py          # 配置文件
├── templates/              # 模板文件目录
│   ├── template1.py       # 基础模板
│   ├── template2.py       # 
│   ├── template3.py       # 
│   ├── template4.py       #
│   └── template5.py       # 
├── setup.py               # 
└── README.md              # 
```

## 🔧 模板变量

每个模板都包含可替换的变量：

- `{date}`: 自动填入当前日期
- `{binary_name}`: 目标程序名称（通过命令行指定或使用默认值"target"）
- `{description}`: 目标描述（默认为"no description"）
- `{url}`: 远程连接URL（默认为空）

### 自定义默认值

编辑 `pwn_templates/config.py` 中的 `DEFAULT_REPLACEMENTS` 字典来修改默认值。

## 🛠️ 开发和扩展

### 添加新模板

1. 在 `templates/` 目录下创建新的模板文件
2. 在 `pwn_templates/config.py` 的 `TEMPLATE_MAPPING` 字典中添加映射配置
3. 模板中使用 `{{变量名}}` 格式的占位符（双大括号）

### 模板文件示例

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Your Template Name
Author: your_name
Date: {{date}}
description: {{description}}
"""

from pwn import *

filename = "./{{binary_name}}"
url = '{{url}}'

# 你的exploit代码
```

## 🤝 贡献

欢迎提交Issue和Pull Request来改进这个项目！

## 📄 许可证

MIT License

## 🙏 致谢

- [pwntools](https://github.com/Gallopsled/pwntools) - 强大的PWN工具库
- CTF社区的各位大佬们的模板和经验分享
