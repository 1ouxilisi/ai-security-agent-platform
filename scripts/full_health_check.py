#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
full_health_check脚本工具模块，提供相关的命令行工具和自动化脚本。

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
import py_compile
import importlib
import traceback

sys.path.insert(0, '.')

results = {
    'passed': [],
    'failed': [],
    'warnings': [],
}

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
print('AI Hacking Agent 项目全面健康检查')
print('=' * 60)
print()

# 1. 检查项目目录结构
print('--- 1. 项目目录结构 ---')
required_dirs = [
    'agents', 'api_server', 'config', 'core', 'data', 'exploit',
    'internal', 'knowledge_base', 'models', 'reports', 'scripts',
    'tests', 'tools', 'distributed', 'web',
]
for d in required_dirs:
    check(f'目录存在: {d}', os.path.isdir(d), f'路径: {os.path.abspath(d)}')

# 2. 检查Python文件语法
print()
print('--- 2. Python文件语法检查 ---')
py_files = []
for root, dirs, files in os.walk('.'):
    if '.venv' in root or '__pycache__' in root or '.git' in root:
        continue
    for f in files:
        if f.endswith('.py'):
            py_files.append(os.path.join(root, f))

print(f'找到 {len(py_files)} 个Python文件')
syntax_errors = []
for pf in py_files:
    try:
        py_compile.compile(pf, doraise=True)
    except py_compile.PyCompileError as e:
        syntax_errors.append((pf, str(e)))

check('Python语法全部通过', len(syntax_errors) == 0, f'错误数: {len(syntax_errors)}')
for pf, err in syntax_errors[:5]:
    print(f'  语法错误: {pf}')
    print(f'    {err[:100]}')

# 3. 检查核心模块导入
print()
print('--- 3. 核心模块导入检查 ---')
core_modules = [
    'core.task_queue', 'core.user_manager', 'core.plugin_system',
    'models.scan', 'models.vulnerability', 'models.report',
    'agents.recon_agent', 'agents.exploit_agent',
    'agents.verification_agent', 'agents.report_agent',
    'api_server.app',
    'tools.tool_manager',
    'knowledge_base.cve_database',
]
import_errors = []
for mod in core_modules:
    try:
        importlib.import_module(mod)
    except Exception as e:
        import_errors.append((mod, str(e)[:100]))

check('核心模块导入全部通过', len(import_errors) == 0, f'错误数: {len(import_errors)}')
for mod, err in import_errors:
    print(f'  导入失败: {mod} - {err}')

# 4. 检查v7.0新模块导入
print()
print('--- 4. v7.0新模块导入检查 ---')
v7_modules = [
    'internal.smb_scanner', 'internal.ldap_query', 'internal.kerberos',
    'internal.hash_pass', 'internal.lateral_movement', 'internal.port_forward',
    'internal.dns_enum', 'internal.ad_assessment',
    'exploit.payload_generator', 'exploit.post_exploitation',
    'exploit.metasploit', 'exploit.poc_library',
    'tools.network_scanners', 'tools.directory_bruteforce',
    'tools.password_attacks', 'tools.web_scanners',
    'distributed.scheduler', 'distributed.worker_node',
    'distributed.result_aggregator', 'distributed.proxy_pool',
    'api_server.internal_routes', 'api_server.exploit_routes',
    'api_server.tools_routes', 'api_server.distributed_routes',
]
v7_import_errors = []
for mod in v7_modules:
    try:
        importlib.import_module(mod)
    except Exception as e:
        v7_import_errors.append((mod, str(e)[:150]))

check('v7.0新模块导入全部通过', len(v7_import_errors) == 0, f'错误数: {len(v7_import_errors)}')
for mod, err in v7_import_errors:
    print(f'  导入失败: {mod} - {err}')

# 5. 检查配置文件
print()
print('--- 5. 配置文件检查 ---')
config_files = [
    'config/settings.yaml', 'config/logging.yaml',
    '.env', 'requirements.txt', 'README.md',
]
for cf in config_files:
    exists = os.path.isfile(cf)
    check(f'配置文件存在: {cf}', exists)
    if not exists:
        warn(f'配置文件缺失: {cf}', '可能需要创建')

# 6. 检查API路由数量
print()
print('--- 6. API路由检查 ---')
try:
    from api_server.app import app
    routes = [r for r in app.routes if hasattr(r, 'path')]
    api_routes = [r for r in routes if r.path.startswith('/api/')]
    page_routes = [r for r in routes if not r.path.startswith('/api/') and r.path != '/docs' and r.path != '/openapi.json']
    check(f'API路由数量充足', len(api_routes) > 50, f'API路由: {len(api_routes)}个')
    check(f'页面路由数量充足', len(page_routes) > 5, f'页面路由: {len(page_routes)}个')
    print(f'  总路由数: {len(routes)}')
    print(f'  API路由: {len(api_routes)}')
    print(f'  页面路由: {len(page_routes)}')
except Exception as e:
    check('API路由检查', False, str(e)[:100])

# 7. 检查HTML页面
print()
print('--- 7. HTML页面检查 ---')
html_files = []
for root, dirs, files in os.walk('api_server'):
    for f in files:
        if f.endswith('.html'):
            html_files.append(os.path.join(root, f))
for root, dirs, files in os.walk('web'):
    for f in files:
        if f.endswith('.html'):
            html_files.append(os.path.join(root, f))

print(f'找到 {len(html_files)} 个HTML文件')
for hf in html_files:
    try:
        with open(hf, 'r', encoding='utf-8') as f:
            content = f.read()
        has_doctype = '<!DOCTYPE html>' in content
        has_html = '<html' in content and '</html>' in content
        has_body = '<body>' in content and '</body>' in content
        check(f'HTML结构完整: {hf}', has_doctype and has_html and has_body, f'大小: {len(content)}字节')
    except Exception as e:
        check(f'HTML可读: {hf}', False, str(e)[:50])

# 8. 检查单元测试
print()
print('--- 8. 单元测试检查 ---')
test_files = []
for root, dirs, files in os.walk('tests'):
    for f in files:
        if f.startswith('test_') and f.endswith('.py'):
            test_files.append(os.path.join(root, f))

print(f'找到 {len(test_files)} 个测试文件')
check('测试文件数量充足', len(test_files) >= 5, f'测试文件: {len(test_files)}个')

# 9. 检查数据模型
print()
print('--- 9. 数据模型检查 ---')
model_files = []
for root, dirs, files in os.walk('models'):
    for f in files:
        if f.endswith('.py') and not f.startswith('__'):
            model_files.append(os.path.join(root, f))
check('数据模型文件充足', len(model_files) >= 5, f'模型文件: {len(model_files)}个')

# 10. 检查工具数量
print()
print('--- 10. 安全工具检查 ---')
try:
    from tools.tool_manager import tool_manager
    tools = tool_manager.list_tools()
    check('安全工具数量充足', len(tools) >= 50, f'工具数: {len(tools)}个')
    print(f'  已注册工具: {len(tools)}个')
    print(f'  分类: {tool_manager.list_categories()}')
except Exception as e:
    check('安全工具检查', False, str(e)[:100])

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
    print('--- 失败项详情 ---')
    for name, detail in results['failed']:
        print(f'  [FAIL] {name}: {detail}')

if results['warnings']:
    print()
    print('--- 警告项详情 ---')
    for name, detail in results['warnings']:
        print(f'  [WARN] {name}: {detail}')

print()
print(f'检查完成: {"全部通过" if not results["failed"] else "存在失败项"}')
