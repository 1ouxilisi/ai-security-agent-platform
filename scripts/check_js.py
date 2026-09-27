#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_js脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

"""检查console_v7.html的JS语法"""
import re

with open('api_server/console_v7.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 提取script内容
script_match = re.search(r'<script>(.*?)</script>', content, re.DOTALL)
if script_match:
    js = script_match.group(1)
    print(f'JS代码长度: {len(js)} 字符')
    print(f'JS行数: {js.count(chr(10))} 行')

    # 检查括号匹配
    brackets = {'(': ')', '[': ']', '{': '}'}
    stack = []
    in_string = False
    string_char = ''
    in_comment = False
    in_line_comment = False

    errors = []
    for i, char in enumerate(js):
        if in_line_comment:
            if char == '\n':
                in_line_comment = False
            continue
        if in_comment:
            if char == '*' and i+1 < len(js) and js[i+1] == '/':
                in_comment = False
            continue
        if in_string:
            if char == string_char and js[i-1] != '\\':
                in_string = False
            continue
        if char == '/' and i+1 < len(js) and js[i+1] == '/':
            in_line_comment = True
            continue
        if char == '/' and i+1 < len(js) and js[i+1] == '*':
            in_comment = True
            continue
        if char in ['"', "'", '`']:
            in_string = True
            string_char = char
            continue
        if char in brackets:
            stack.append((char, i))
        elif char in brackets.values():
            if not stack:
                errors.append(f'多余的闭合括号 {char} at position {i}')
            else:
                open_char, pos = stack.pop()
                if brackets[open_char] != char:
                    errors.append(f'括号不匹配: 期望 {brackets[open_char]}, 实际 {char} at position {i}')

    if stack:
        for char, pos in stack:
            errors.append(f'未闭合的括号 {char} at position {pos}')

    if errors:
        print(f'发现 {len(errors)} 个括号问题:')
        for e in errors[:10]:
            print(f'  - {e}')
    else:
        print('括号匹配: 通过')

    # 检查函数定义
    functions = re.findall(r'function\s+(\w+)\s*\(', js)
    print(f'定义的函数数量: {len(functions)}')

    # 检查async函数
    async_functions = re.findall(r'async\s+function\s+(\w+)\s*\(', js)
    print(f'异步函数数量: {len(async_functions)}')

    # 检查模板字符串
    template_strings = re.findall(r'`[^`]*`', js)
    print(f'模板字符串数量: {len(template_strings)}')

    # 检查是否有明显的语法错误
    # 检查每行末尾
    lines = js.split('\n')
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith('//') and not stripped.startswith('*'):
            # 检查是否有未闭合的引号
            quotes = stripped.count('"') - stripped.count('\\"')
            if quotes % 2 != 0 and not stripped.endswith('\\'):
                # 可能是模板字符串或跨行字符串
                pass

else:
    print('未找到script标签')
