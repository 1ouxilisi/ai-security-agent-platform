#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_html脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

"""检查console_v7.html结构"""
with open('api_server/console_v7.html', 'r', encoding='utf-8') as f:
    content = f.read()

checks = {
    'DOCTYPE': '<!DOCTYPE html>' in content,
    'html标签': '<html' in content and '</html>' in content,
    'head标签': '<head>' in content and '</head>' in content,
    'body标签': '<body>' in content and '</body>' in content,
    'script标签': '<script>' in content and '</script>' in content,
    'style标签': '<style>' in content and '</style>' in content,
    '侧边栏': 'sidebar' in content,
    '仪表盘页面': 'page-dashboard' in content,
    '内网渗透页面': 'page-internal' in content,
    '漏洞利用页面': 'page-exploit' in content,
    '分布式页面': 'page-distributed' in content,
    'API调用函数': 'apiCall' in content,
    '页面切换函数': 'showPage' in content,
}

print('=== HTML结构检查 ===')
all_pass = True
for name, result in checks.items():
    status = 'PASS' if result else 'FAIL'
    if not result:
        all_pass = False
    print(f'[{status}] {name}')

print()
print(f'文件大小: {len(content)} 字节')
print(f'全部通过: {"是" if all_pass else "否"}')
