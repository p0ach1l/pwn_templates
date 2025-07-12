# PWN Templates - CTF PWN题目模板生成工具

🚀 一个专为CTF比赛设计的PWN exploit模板快速生成工具，支持多种常见的PWN利用技术模板。

## ✨ 特性

- 🎯 **5种常用PWN模板**: 栈溢出、ROP链、格式化字符串、堆利用、Shellcode注入
- 🔧 **简单易用**: 一条命令即可生成完整的exploit模板
- 🎨 **高度可定制**: 支持自定义参数和交互式配置
- 📝 **详细注释**: 每个模板都包含详细的中文注释和使用说明
- 🔄 **变量替换**: 智能替换模板中的占位符变量

## 📦 安装

### 方法1: 直接使用 (推荐)
```bash
# 克隆项目
git clone <repository-url>
cd PWN_templates

# 给pwn脚本添加执行权限
chmod +x pwn

# 直接使用
./pwn list
./pwn new 1
```

### 方法2: 安装到系统
```bash
# 安装依赖
pip install pwntools

# 安装项目
pip install -e .

# 使用系统命令
pwn-templates list
pwn-templates new 1
```

## 🎮 使用方法

### 基本命令

```bash
# 列出所有可用模板
./pwn list

# 生成模板1 (栈溢出)
./pwn new 1

# 生成模板2并指定输出文件名
./pwn new 2 -o my_exploit.py

# 交互式配置后生成模板
./pwn new 3 --interactive

# 自定义参数生成模板
./pwn new 1 --binary target --offset 88 --host 192.168.1.100
```

### 可用模板

| 编号 | 模板名称 | 描述 | 适用场景 |
|------|----------|------|----------|
| 1 | Stack Buffer Overflow | 基础栈溢出模板 | 简单的返回地址覆盖 |
| 2 | ROP Chain | ROP链利用模板 | 绕过NX保护的情况 |
| 3 | Format String | 格式化字符串漏洞模板 | printf类漏洞利用 |
| 4 | Heap Exploitation | 堆利用模板 | UAF、Double Free等堆漏洞 |
| 5 | Shellcode Injection | Shellcode注入模板 | 可执行栈的情况 |

### 命令行参数

```bash
./pwn new <模板编号> [选项]

选项:
  -o, --output FILE     指定输出文件名
  -i, --interactive     交互式配置模板参数
  --binary NAME         目标程序名称
  --host HOST           远程主机地址
  --port PORT           远程端口
  --offset OFFSET       溢出偏移量
  --target TARGET       目标描述
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
│   ├── template1.py       # 栈溢出模板
│   ├── template2.py       # ROP链模板
│   ├── template3.py       # 格式化字符串模板
│   ├── template4.py       # 堆利用模板
│   └── template5.py       # Shellcode注入模板
├── setup.py               # 安装脚本
└── README.md              # 项目文档
```

## 🔧 模板自定义

每个模板都包含可替换的变量，你可以通过以下方式自定义:

### 1. 命令行参数
```bash
./pwn new 1 --binary target --offset 72 --host 192.168.1.100 --port 9999
```

### 2. 交互式配置
```bash
./pwn new 1 --interactive
```

### 3. 修改默认配置
编辑 `pwn_templates/config.py` 中的 `DEFAULT_REPLACEMENTS` 字典。

## 📝 使用示例

### 示例1: 生成栈溢出模板
```bash
./pwn new 1 --binary vuln --offset 72
```

生成的文件将包含:
- 完整的pwntools导入
- 目标程序设置
- 调试配置
- 基础的栈溢出payload构造

### 示例2: 生成ROP链模板
```bash
./pwn new 2 --binary rop_challenge --interactive
```

将提示你输入:
- 目标程序名称
- 远程连接信息
- 溢出偏移量
- 其他相关参数

## 🛠️ 开发和扩展

### 添加新模板

1. 在 `templates/` 目录下创建新的模板文件
2. 在 `pwn_templates/config.py` 中添加映射配置
3. 模板中使用 `{变量名}` 格式的占位符

### 模板变量

常用的模板变量包括:
- `{date}`: 当前日期
- `{target}`: 目标描述
- `{binary_name}`: 程序名称
- `{remote_host}`: 远程主机
- `{remote_port}`: 远程端口
- `{offset}`: 溢出偏移量
- 更多变量请查看 `config.py`

## 🤝 贡献

欢迎提交Issue和Pull Request来改进这个项目！

## 📄 许可证

MIT License

## 🙏 致谢

- [pwntools](https://github.com/Gallopsled/pwntools) - 强大的PWN工具库
- CTF社区的各位大佬们的模板和经验分享
