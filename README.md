# PWN Templates - CTF PWN题目模板生成工具

🚀 一个专为CTF比赛设计的PWN exploit模板快速生成工具，支持多种常见的PWN利用技术模板。

## ✨ 特性

- 🎯 **常用PWN模板**: 远程本地丝滑切换，支持自定义
- 🔧 **简单易用**: 一条命令即可生成完整的exploit模板
- 🎨 **高度可定制**: 支持自定义参数和交互式配置
- 📝 **详细注释**: 每个模板都包含详细的中文注释和使用说明
- 🔄 **变量替换**: 智能替换模板中的占位符变量

## 📦 安装

### 安装到系统（推荐）
```bash
# 安装依赖
pip install pwntools

# 安装项目
pip install -e .

# 使用系统命令
pwnt new 1
```

## 🎮 使用方法

### 基本命令

```bash
# 生成模板1 (栈溢出)
pwnt new 1

# 指定二进制文件
pwnt new 1 -b tartge

# 生成模板2并指定输出文件名
pwnt new 2 -o my_exploit.py

# 交互式配置后生成模板
pwnt new 3 --interactive

# 自定义参数生成模板
pwnt new 1 --binary target --url 192.168.1.100:9999
```

### 自定义模板

修改目录`templates`中模板文件，修改`pwn_templates`文件`config.py`中的映射表。

### 命令行参数

```bash
./pwn new <模板编号> [选项]

选项:
  -o, --output FILE     指定输出文件名
  -i, --interactive     交互式配置模板参数
  -b, --binary NAME         目标程序名称
  --url URL           远程主机地址和端口
  --description DESCRIPTION       目标描述
```

## 📁 项目结构

```
PWN_templates/
├── pwn                     # 主执行脚本
├── pwn_templates/          # 核心包
│   ├── __init__.py
│   ├── cli.py             # 命令行接口
│   ├── generator.py       # 模板生成器
│   └── config.py          # 配置文件
├── templates/              # 模板文件目录
│   ├── template1.py       # 基础模板
│   ├── template2.py       # 格式化字符串模板
│   ├── template3.py       # 
│   ├── template4.py       # 
│   └── template5.py       # 
├── setup.py               # 安装脚本
└── README.md              # 项目文档
```

## 🔧 模板自定义

每个模板都包含可替换的变量，你可以通过以下方式自定义:

### 1. 命令行参数
```bash
./pwn new 1 --binary target --url 192.168.1.10:9999
```

### 2. 交互式配置
```bash
./pwn new 1 --interactive
```

### 3. 修改默认配置
编辑 `pwn_templates/config.py` 中的 `DEFAULT_REPLACEMENTS` 字典。

## 🛠️ 开发和扩展

### 添加新模板

1. 在 `templates/` 目录下创建新的模板文件
2. 在 `pwn_templates/config.py` 中添加映射配置
3. 模板中使用 `{变量名}` 格式的占位符

### 模板变量

常用的模板变量包括:
- `{date}`: 当前日期
- `{description}`: 目标描述
- `{binary_name}`: 程序名称
- `{url}`: 远程主机和端口

## 🤝 贡献

欢迎提交Issue和Pull Request来改进这个项目！

## 📄 许可证

MIT License

## 🙏 致谢

- [pwntools](https://github.com/Gallopsled/pwntools) - 强大的PWN工具库
- CTF社区的各位大佬们的模板和经验分享
