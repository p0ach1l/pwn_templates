# PWN Templates 使用示例

## 快速开始

### 1. 查看所有可用模板
```bash
./pwn list
```

输出示例:
```
🔧 可用的PWN模板:
==================================================
1. Stack Buffer Overflow
   📄 基础栈溢出模板，适用于简单的返回地址覆盖
   📁 文件: template1.py

2. ROP Chain
   📄 ROP链模板，适用于需要绕过NX保护的情况
   📁 文件: template2.py

3. Format String
   📄 格式化字符串漏洞模板，适用于printf类漏洞
   📁 文件: template3.py

4. Heap Exploitation
   📄 堆利用模板，适用于UAF、Double Free等堆漏洞
   📁 文件: template4.py

5. Shellcode Injection
   📄 Shellcode注入模板，适用于可执行栈的情况
   📁 文件: template5.py
```

### 2. 生成基础栈溢出模板
```bash
./pwn new 1
```

这将生成 `exploit_1.py` 文件，包含完整的栈溢出利用模板。

### 3. 自定义参数生成模板
```bash
./pwn new 1 --binary vuln --offset 72 --host 192.168.1.100 --port 9999 -o my_exploit.py
```

### 4. 交互式配置
```bash
./pwn new 2 --interactive
```

系统会提示你输入各种参数:
```
🔧 交互式模板配置
==============================
目标程序名称 (当前: target): vuln
远程主机地址 (当前: 127.0.0.1): 192.168.1.100
远程端口 (当前: 9999): 1337
溢出偏移量 (当前: 72): 88
✅ 配置完成!
```

## 实际CTF题目示例

### 示例1: 简单栈溢出题目

假设有一个CTF题目 `easy_overflow`，通过调试发现溢出偏移为88字节：

```bash
./pwn new 1 --binary easy_overflow --offset 88 -o solve.py
```

生成的模板会自动填入这些参数，你只需要:
1. 找到合适的gadget地址
2. 构造ROP链或直接跳转
3. 运行脚本

### 示例2: ROP链题目

对于开启了NX保护的题目 `rop_challenge`：

```bash
./pwn new 2 --binary rop_challenge --offset 72 --interactive
```

模板会包含:
- libc地址泄露
- ROP链构造
- 二次利用获取shell

### 示例3: 格式化字符串题目

```bash
./pwn new 3 --binary format_vuln -o fmt_exploit.py
```

生成的模板包含:
- 格式化字符串偏移查找
- 地址泄露
- 任意地址写入

## 高级用法

### 1. 批量生成多个模板
```bash
# 为同一个题目生成多种可能的利用方式
./pwn new 1 --binary target -o stack_exploit.py
./pwn new 2 --binary target -o rop_exploit.py
./pwn new 5 --binary target -o shellcode_exploit.py
```

### 2. 团队协作
```bash
# 队友A负责栈溢出方向
./pwn new 1 --binary challenge --offset 64 -o teamA_stack.py

# 队友B负责ROP方向  
./pwn new 2 --binary challenge --offset 64 -o teamB_rop.py
```

### 3. 不同环境配置
```bash
# 本地测试版本
./pwn new 1 --binary ./vuln --host 127.0.0.1 --port 1234 -o local_exploit.py

# 远程比赛版本
./pwn new 1 --binary ./vuln --host ctf.example.com --port 9999 -o remote_exploit.py
```

## 模板修改建议

生成模板后，通常需要根据具体题目进行以下修改:

### 1. 栈溢出模板 (template1)
- 修改 `offset` 为实际溢出偏移
- 替换 `return_address` 为目标地址
- 根据需要添加canary绕过

### 2. ROP链模板 (template2)  
- 查找并替换实际的gadget地址
- 修改libc版本和偏移
- 调整ROP链构造逻辑

### 3. 格式化字符串模板 (template3)
- 确定正确的格式化字符串偏移
- 设置要修改的目标地址
- 计算要写入的值

### 4. 堆利用模板 (template4)
- 根据堆题类型调整利用方式
- 修改chunk大小和操作序列
- 适配不同的libc版本

### 5. Shellcode模板 (template5)
- 根据架构选择合适的shellcode
- 调整NOP滑板长度
- 确定shellcode存放地址

## 调试技巧

### 1. 使用GDB调试
生成的模板都包含GDB调试支持:
```bash
python3 exploit.py GDB
```

### 2. 本地测试
```bash
python3 exploit.py
```

### 3. 远程攻击
```bash
python3 exploit.py REMOTE
```

### 4. 详细日志
模板默认开启详细日志，可以看到所有的交互过程。
