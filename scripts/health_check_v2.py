#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
health_check_v2脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import sys
import ast
import importlib

sys.path.insert(0, '.')

results = {'passed': [], 'failed': [], 'warnings': []}

def check(name, condition, detail=''):
    """检查相关状态。

        Args:
            name: 相关参数。
            condition: 相关参数。
            detail: 相关参数。

        Returns:
            操作结果。
    """
    if condition:
        results['passed'].append((name, detail))
        print(f'[PASS] {name}')
    else:
        results['failed'].append((name, detail))
        print(f'[FAIL] {name} - {detail}')

def warn(name, detail=''):
    """执行相关操作。

        Args:
            name: 相关参数。
            detail: 相关参数。

        Returns:
            操作结果。
    """
    results['warnings'].append((name, detail))
    print(f'[WARN] {name} - {detail}')

print('=' * 60)
print('AI Hacking Agent 项目全面健康检查 v2')
print('=' * 60)

# 1. 项目目录结构
print()
print('--- 1. 核心目录结构 ---')
core_dirs = ['agent', 'api_server', 'config', 'core', 'data', 'exploit',
             'internal', 'knowledge', 'report', 'scripts', 'tests', 'tools',
             'distributed', 'web', 'workflow']
for d in core_dirs:
    check(f'目录: {d}', os.path.isdir(d))

# 统计所有目录
all_dirs = [d for d in os.listdir('.') if os.path.isdir(d) and not d.startswith('.') and d != '__pycache__']
print(f'  总目录数: {len(all_dirs)}')

# 2. Python文件语法检查（用ast.parse）
print()
print('--- 2. Python语法检查 ---')
py_files = []
for root, dirs, files in os.walk('.'):
    dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
    for f in files:
        if f.endswith('.py'):
            py_files.append(os.path.join(root, f))

print(f'找到 {len(py_files)} 个Python文件')
syntax_errors = []
for pf in py_files:
    try:
        with open(pf, 'r', encoding='utf-8') as f:
            source = f.read()
        ast.parse(source, filename=pf)
    except SyntaxError as e:
        syntax_errors.append((pf, str(e)[:100]))
    except Exception as e:
        syntax_errors.append((pf, f'{type(e).__name__}: {str(e)[:80]}'))

check('Python语法全部通过', len(syntax_errors) == 0, f'错误数: {len(syntax_errors)}')
for pf, err in syntax_errors[:10]:
    print(f'  语法错误: {pf}')
    print(f'    {err}')

# 3. 核心模块导入
print()
print('--- 3. 核心模块导入 ---')
core_modules = [
    'core.task_queue', 'api_server.app', 'tools.tool_manager',
    'agent.multi_agent', 'agent.super_agent',
]
import_errors = []
for mod in core_modules:
    try:
        importlib.import_module(mod)
    except Exception as e:
        import_errors.append((mod, f'{type(e).__name__}: {str(e)[:100]}'))

check('核心模块导入通过', len(import_errors) == 0, f'错误数: {len(import_errors)}')
for mod, err in import_errors:
    print(f'  导入失败: {mod} - {err}')

# 4. v7.0新模块导入
print()
print('--- 4. v7.0新模块导入 ---')
v7_modules = [
    'internal.smb_scanner', 'internal.ldap_query', 'internal.kerberos',
    'internal.hash_pass', 'internal.lateral_movement', 'internal.port_forward',
    'internal.dns_enum', 'internal.ad_assessment',
    'exploit.payload_generator', 'exploit.post_exploitation',
    'exploit.metasploit', 'exploit.poc_library',
    'distributed.scheduler', 'distributed.worker_node',
    'distributed.result_aggregator', 'distributed.proxy_pool',
    'api_server.internal_routes', 'api_server.exploit_routes',
    'api_server.tools_routes', 'api_server.distributed_routes',
]
v7_errors = []
for mod in v7_modules:
    try:
        importlib.import_module(mod)
    except Exception as e:
        v7_errors.append((mod, f'{type(e).__name__}: {str(e)[:120]}'))

check('v7.0新模块全部导入', len(v7_errors) == 0, f'错误数: {len(v7_errors)}')
for mod, err in v7_errors:
    print(f'  导入失败: {mod} - {err}')

# 5. API路由检查
print()
print('--- 5. API路由检查 ---')
try:
    from api_server.app import app
    routes = [r for r in app.routes if hasattr(r, 'path')]
    api_routes = [r for r in routes if r.path.startswith('/api/')]
    page_routes = [r for r in routes if not r.path.startswith('/api/') and not r.path.startswith('/docs') and r.path != '/openapi.json' and r.path != '/redoc']
    check('API路由>100', len(api_routes) > 100, f'API路由: {len(api_routes)}')
    check('页面路由>10', len(page_routes) > 10, f'页面路由: {len(page_routes)}')
    print(f'  总路由: {len(routes)}, API: {len(api_routes)}, 页面: {len(page_routes)}')
except Exception as e:
    check('API路由检查', False, str(e)[:100])

# 6. HTML页面检查
print()
print('--- 6. HTML页面检查 ---')
html_files = []
for root, dirs, files in os.walk('.'):
    dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
    for f in files:
        if f.endswith('.html'):
            html_files.append(os.path.join(root, f))

print(f'找到 {len(html_files)} 个HTML文件')
html_errors = []
for hf in html_files:
    try:
        with open(hf, 'r', encoding='utf-8') as f:
            content = f.read()
        if '<!DOCTYPE html>' not in content or '<html' not in content:
            html_errors.append((hf, '缺少DOCTYPE或html标签'))
    except Exception as e:
        html_errors.append((hf, str(e)[:50]))

check('HTML页面结构完整', len(html_errors) == 0, f'错误数: {len(html_errors)}')
for hf, err in html_errors[:5]:
    print(f'  HTML问题: {hf} - {err}')

# 7. 配置文件检查
print()
print('--- 7. 配置文件检查 ---')
config_files = ['config/settings.yaml', '.env', 'requirements.txt', 'README.md']
for cf in config_files:
    exists = os.path.isfile(cf)
    check(f'配置: {cf}', exists)
    if not exists:
        warn(f'缺失: {cf}')

# 8. 单元测试检查
print()
print('--- 8. 单元测试检查 ---')
test_files = []
for root, dirs, files in os.walk('tests'):
    for f in files:
        if f.startswith('test_') and f.endswith('.py'):
            test_files.append(os.path.join(root, f))
check('测试文件>=10', len(test_files) >= 10, f'测试文件: {len(test_files)}')
print(f'  测试文件: {len(test_files)}个')

# 9. 工具管理器检查
print()
print('--- 9. 安全工具检查 ---')
try:
    from tools.tool_manager import tool_manager
    tools = tool_manager.list_tools()
    check('工具>=50', len(tools) >= 50, f'工具数: {len(tools)}')
    print(f'  已注册工具: {len(tools)}个')
except Exception as e:
    check('工具检查', False, str(e)[:100])

# 10. 代码统计
print()
print('--- 10. 代码统计 ---')
total_lines = 0
total_py_files = 0
for pf in py_files:
    try:
        with open(pf, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        total_lines += len(lines)
        total_py_files += 1
    except:
        pass
print(f'  Python文件: {total_py_files}个')
print(f'  代码行数: {total_lines:,}行')
print(f'  HTML文件: {len(html_files)}个')
print(f'  目录数: {len(all_dirs)}个')

# 总结
print()
print('=' * 60)
print('检查总结')
print('=' * 60)
print(f'通过: {len(results["passed"])} 项')
print(f'失败: {len(results["failed"])} 项')
print(f'警告: {len(results["warnings"])} 项')
print()

if results['failed']:
    print('--- 失败项 ---')
    for name, detail in results['failed']:
        print(f'  [FAIL] {name}: {detail}')

if results['warnings']:
    print()
    print('--- 警告项 ---')
    for name, detail in results['warnings']:
        print(f'  [WARN] {name}: {detail}')

print()
status = '全部通过' if not results['failed'] else f'{len(results["failed"])}项失败'
print(f'最终状态: {status}')
