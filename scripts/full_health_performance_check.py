#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
full_health_performance_check脚本工具模块，提供相关的命令行工具和自动化脚本。

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
import time
import ast
import importlib
import subprocess
import json
from datetime import datetime

sys.path.insert(0, '.')

# 颜色输出
class Colors:
    """Colors类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def cprint(text, color=''):
    """在...中。

        Args:
            text: 相关参数。
            color: 相关参数。

        Returns:
            操作结果。
    """
    print(f'{color}{text}{Colors.END}')

results = {
    'passed': [],
    'failed': [],
    'warnings': [],
    'performance': {},
}

def check(name, condition, detail='', category='general'):
    """检查相关状态。

        Args:
            name: 相关参数。
            condition: 相关参数。
            detail: 相关参数。
            category: 相关参数。

        Returns:
            操作结果。
    """
    if condition:
        results['passed'].append((name, detail, category))
        cprint(f'  [PASS] {name}', Colors.GREEN)
    else:
        results['failed'].append((name, detail, category))
        cprint(f'  [FAIL] {name} - {detail}', Colors.RED)
    return condition

def warn(name, detail='', category='general'):
    """执行相关操作。

        Args:
            name: 相关参数。
            detail: 相关参数。
            category: 相关参数。

        Returns:
            操作结果。
    """
    results['warnings'].append((name, detail, category))
    cprint(f'  [WARN] {name} - {detail}', Colors.YELLOW)

def perf_record(name, value, unit='', threshold=None):
    """或...。

        Args:
            name: 相关参数。
            value: 相关参数。
            unit: 相关参数。
            threshold: 相关参数。

        Returns:
            操作结果。
    """
    results['performance'][name] = {'value': value, 'unit': unit, 'threshold': threshold}
    status = 'OK' if threshold is None or value <= threshold else 'SLOW'
    color = Colors.GREEN if status == 'OK' else Colors.RED
    cprint(f'  [{status}] {name}: {value:.4f}{unit}', color)

print()
cprint('=' * 70, Colors.CYAN)
cprint('  AI Hacking Agent 项目全面大体检与性能检测', Colors.BOLD + Colors.CYAN)
cprint(f'  检测时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', Colors.CYAN)
cprint('=' * 70, Colors.CYAN)
print()

# ============================================
# 1. Python语法检查
# ============================================
cprint('【1/8】Python语法检查', Colors.BOLD + Colors.BLUE)
start_time = time.time()

py_files = []
for root, dirs, files in os.walk('.'):
    dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__' and d != 'venv' and d != '.venv']
    for f in files:
        if f.endswith('.py'):
            py_files.append(os.path.join(root, f))

syntax_errors = []
for pf in py_files:
    try:
        with open(pf, 'r', encoding='utf-8') as f:
            ast.parse(f.read(), filename=pf)
    except SyntaxError as e:
        syntax_errors.append((pf, str(e)[:100]))
    except Exception as e:
        syntax_errors.append((pf, f'{type(e).__name__}: {str(e)[:80]}'))

syntax_time = time.time() - start_time
check(f'Python文件语法全部通过 ({len(py_files)}个文件)', len(syntax_errors) == 0, f'错误数: {len(syntax_errors)}', 'syntax')
if syntax_errors:
    for pf, err in syntax_errors[:5]:
        cprint(f'    - {pf}: {err}', Colors.RED)

perf_record('语法检查耗时', syntax_time, 's', 5.0)
print()

# ============================================
# 2. 模块导入检查
# ============================================
cprint('【2/8】模块导入检查', Colors.BOLD + Colors.BLUE)
start_time = time.time()

core_modules = [
    'api_server.app',
    'tools.tool_manager',
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

import_times = {}
import_errors = []
for mod in core_modules:
    t0 = time.time()
    try:
        importlib.import_module(mod)
        import_times[mod] = time.time() - t0
    except Exception as e:
        import_errors.append((mod, f'{type(e).__name__}: {str(e)[:100]}'))
        import_times[mod] = time.time() - t0

import_time = time.time() - start_time
check(f'核心模块全部导入成功 ({len(core_modules)}个)', len(import_errors) == 0, f'失败: {len(import_errors)}个', 'import')
if import_errors:
    for mod, err in import_errors:
        cprint(f'    - {mod}: {err}', Colors.RED)

# 导入最慢的5个模块
slow_imports = sorted(import_times.items(), key=lambda x: x[1], reverse=True)[:5]
cprint('  导入最慢的5个模块:', Colors.YELLOW)
for mod, t in slow_imports:
    cprint(f'    - {mod}: {t:.4f}s', Colors.YELLOW)

perf_record('模块导入总耗时', import_time, 's', 10.0)
perf_record('平均模块导入时间', import_time / len(core_modules), 's', 0.5)
print()

# ============================================
# 3. API服务检查
# ============================================
cprint('【3/8】API服务检查', Colors.BOLD + Colors.BLUE)
start_time = time.time()

try:
    import urllib.request
    api_checks = []

    # 健康检查
    t0 = time.time()
    try:
        req = urllib.request.Request('http://127.0.0.1:8000/health')
        with urllib.request.urlopen(req, timeout=5) as resp:
            health_data = json.loads(resp.read().decode('utf-8'))
            health_time = time.time() - t0
            api_checks.append(('健康检查 /health', resp.status == 200, f'{resp.status} ({health_time:.3f}s)'))
            perf_record('健康检查响应时间', health_time, 's', 1.0)
    except Exception as e:
        api_checks.append(('健康检查 /health', False, str(e)[:50]))

    # OpenAPI文档
    t0 = time.time()
    try:
        req = urllib.request.Request('http://127.0.0.1:8000/openapi.json')
        with urllib.request.urlopen(req, timeout=5) as resp:
            openapi_data = json.loads(resp.read().decode('utf-8'))
            api_time = time.time() - t0
            paths_count = len(openapi_data.get('paths', {}))
            api_checks.append(('OpenAPI文档', resp.status == 200, f'{paths_count}个端点 ({api_time:.3f}s)'))
            perf_record('OpenAPI加载时间', api_time, 's', 2.0)
    except Exception as e:
        api_checks.append(('OpenAPI文档', False, str(e)[:50]))

    # console-v7页面
    t0 = time.time()
    try:
        req = urllib.request.Request('http://127.0.0.1:8000/console-v7')
        with urllib.request.urlopen(req, timeout=5) as resp:
            content = resp.read().decode('utf-8')
            page_time = time.time() - t0
            has_sidebar = 'sidebar' in content
            has_dashboard = 'page-dashboard' in content
            api_checks.append(('console-v7页面', resp.status == 200 and has_sidebar, f'{len(content)}字节, 侧边栏:{"有" if has_sidebar else "无"}'))
            perf_record('console-v7加载时间', page_time, 's', 2.0)
    except Exception as e:
        api_checks.append(('console-v7页面', False, str(e)[:50]))

    for name, passed, detail in api_checks:
        check(name, passed, detail, 'api')

except Exception as e:
    warn('API服务检查', f'无法连接: {e}', 'api')

api_time = time.time() - start_time
perf_record('API检查总耗时', api_time, 's', 10.0)
print()

# ============================================
# 4. 单元测试检查
# ============================================
cprint('【4/8】单元测试检查', Colors.BOLD + Colors.BLUE)
start_time = time.time()

test_files = []
for root, dirs, files in os.walk('tests'):
    for f in files:
        if f.startswith('test_') and f.endswith('.py'):
            test_files.append(os.path.join(root, f))

check(f'测试文件存在 ({len(test_files)}个)', len(test_files) >= 5, f'测试文件: {len(test_files)}个', 'test')

# 运行v7.0测试
try:
    result = subprocess.run(
        [sys.executable, '-m', 'pytest', 'tests/test_v7_upgrade.py', '-v', '--tb=short', '-q'],
        capture_output=True, text=True, timeout=120, cwd='.'
    )
    test_output = result.stdout + result.stderr
    passed = 'passed' in test_output and 'failed' not in test_output
    check('v7.0单元测试全部通过', result.returncode == 0, f'返回码: {result.returncode}', 'test')

    # 提取测试数量
    import re
    passed_match = re.search(r'(\d+)\s+passed', test_output)
    if passed_match:
        cprint(f'  测试通过数: {passed_match.group(1)}个', Colors.GREEN)
except Exception as e:
    warn('单元测试运行', f'运行失败: {e}', 'test')

test_time = time.time() - start_time
perf_record('单元测试耗时', test_time, 's', 60.0)
print()

# ============================================
# 5. 代码质量检查
# ============================================
cprint('【5/8】代码质量检查', Colors.BOLD + Colors.BLUE)
start_time = time.time()

# 代码行数统计
total_lines = 0
total_comments = 0
total_blank = 0
total_functions = 0
total_classes = 0

for pf in py_files:
    try:
        with open(pf, 'r', encoding='utf-8') as f:
            file_content = f.read()
            lines = file_content.split('\n')
        total_lines += len(lines)
        for line in lines:
            stripped = line.strip()
            if not stripped:
                total_blank += 1
            elif stripped.startswith('#'):
                total_comments += 1
            elif stripped.startswith('def ') or stripped.startswith('    def '):
                total_functions += 1
            elif stripped.startswith('class '):
                total_classes += 1
        # 统计文档字符串行数
        try:
            tree = ast.parse(file_content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    docstring = ast.get_docstring(node)
                    if docstring:
                        total_comments += len(docstring.split('\n')) + 2
        except:
            pass
    except:
        pass

comment_ratio = (total_comments / total_lines * 100) if total_lines > 0 else 0
check('代码注释率 >= 10%', comment_ratio >= 10, f'{comment_ratio:.1f}% ({total_comments}/{total_lines}行)', 'quality')
check('函数数量充足', total_functions >= 100, f'{total_functions}个函数', 'quality')
check('类数量充足', total_classes >= 20, f'{total_classes}个类', 'quality')

cprint(f'  代码总行数: {total_lines:,}', Colors.CYAN)
cprint(f'  注释行数: {total_comments:,} ({comment_ratio:.1f}%)', Colors.CYAN)
cprint(f'  空行数: {total_blank:,}', Colors.CYAN)
cprint(f'  函数数: {total_functions}', Colors.CYAN)
cprint(f'  类数: {total_classes}', Colors.CYAN)

# 检查大文件
large_files = []
for pf in py_files:
    try:
        size = os.path.getsize(pf)
        if size > 50000:  # >50KB
            large_files.append((pf, size))
    except:
        pass

if large_files:
    warn(f'大文件数量 ({len(large_files)}个 >50KB)', '建议拆分', 'quality')
    for pf, size in large_files[:3]:
        cprint(f'    - {pf}: {size/1024:.1f}KB', Colors.YELLOW)

quality_time = time.time() - start_time
perf_record('代码质量检查耗时', quality_time, 's', 5.0)
print()

# ============================================
# 6. 依赖项检查
# ============================================
cprint('【6/8】依赖项检查', Colors.BOLD + Colors.BLUE)
start_time = time.time()

# 检查requirements.txt
if os.path.isfile('requirements.txt'):
    with open('requirements.txt', 'r', encoding='utf-8') as f:
        req_lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    check(f'requirements.txt存在 ({len(req_lines)}个依赖)', len(req_lines) >= 10, f'{len(req_lines)}个依赖', 'deps')
else:
    check('requirements.txt存在', False, '文件缺失', 'deps')

# 检查开发依赖
if os.path.isfile('requirements-dev.txt'):
    with open('requirements-dev.txt', 'r', encoding='utf-8') as f:
        dev_lines = [l.strip() for l in f if l.strip() and not l.startswith('#') and not l.startswith('-')]
    check(f'requirements-dev.txt存在 ({len(dev_lines)}个依赖)', len(dev_lines) >= 10, f'{len(dev_lines)}个开发依赖', 'deps')
else:
    check('requirements-dev.txt存在', False, '文件缺失', 'deps')

# 检查关键依赖
key_deps = ['fastapi', 'uvicorn', 'pydantic', 'requests', 'aiohttp', 'pyyaml', 'python-dotenv']
missing_deps = []
for dep in key_deps:
    found = any(dep.lower() in line.lower() for line in req_lines)
    if not found:
        missing_deps.append(dep)

check(f'关键依赖全部存在 ({len(key_deps)}个)', len(missing_deps) == 0, f'缺失: {missing_deps}', 'deps')

deps_time = time.time() - start_time
perf_record('依赖检查耗时', deps_time, 's', 3.0)
print()

# ============================================
# 7. 配置文件检查
# ============================================
cprint('【7/8】配置文件检查', Colors.BOLD + Colors.BLUE)
start_time = time.time()

config_files = [
    ('.env', '环境变量'),
    ('.env.example', '环境变量示例'),
    ('config.example.yaml', '配置示例'),
    ('Dockerfile', 'Docker构建'),
    ('docker-compose.yml', 'Docker编排'),
    ('setup.py', 'Python打包'),
    ('pytest.ini', '测试配置'),
    ('.gitignore', 'Git忽略'),
    ('Makefile', '构建工具'),
    ('.editorconfig', '编辑器配置'),
    ('.flake8', '代码检查'),
    ('.pre-commit-config.yaml', '预提交'),
]

for cf, desc in config_files:
    exists = os.path.isfile(cf)
    check(f'{desc} ({cf})', exists, '存在' if exists else '缺失', 'config')

config_time = time.time() - start_time
perf_record('配置检查耗时', config_time, 's', 3.0)
print()

# ============================================
# 8. 文档检查
# ============================================
cprint('【8/8】文档检查', Colors.BOLD + Colors.BLUE)
start_time = time.time()

doc_files = [
    ('README.md', '项目说明'),
    ('QUICKSTART.md', '快速开始'),
    ('API_DOCUMENTATION.md', 'API文档'),
    ('ARCHITECTURE.md', '架构文档'),
    ('CONTRIBUTING.md', '贡献指南'),
    ('CHANGELOG.md', '变更日志'),
    ('SECURITY.md', '安全政策'),
    ('CODE_OF_CONDUCT.md', '行为准则'),
    ('LICENSE', '许可证'),
]

for df, desc in doc_files:
    exists = os.path.isfile(df)
    if exists:
        size = os.path.getsize(df)
        check(f'{desc} ({df})', size > 100, f'{size}字节', 'docs')
    else:
        check(f'{desc} ({df})', False, '缺失', 'docs')

docs_time = time.time() - start_time
perf_record('文档检查耗时', docs_time, 's', 3.0)
print()

# ============================================
# 性能汇总
# ============================================
cprint('=' * 70, Colors.CYAN)
cprint('  性能检测汇总', Colors.BOLD + Colors.CYAN)
cprint('=' * 70, Colors.CYAN)
print()

total_time = sum(v['value'] for v in results['performance'].values())
for name, data in results['performance'].items():
    status = 'OK' if data['threshold'] is None or data['value'] <= data['threshold'] else 'SLOW'
    color = Colors.GREEN if status == 'OK' else Colors.RED
    cprint(f'  [{status}] {name}: {data["value"]:.4f}{data["unit"]}', color)

cprint(f'\n  总检测耗时: {total_time:.2f}s', Colors.BOLD)
print()

# ============================================
# 最终总结
# ============================================
cprint('=' * 70, Colors.CYAN)
cprint('  体检最终报告', Colors.BOLD + Colors.CYAN)
cprint('=' * 70, Colors.CYAN)
print()

total_checks = len(results['passed']) + len(results['failed'])
pass_rate = (len(results['passed']) / total_checks * 100) if total_checks > 0 else 0

cprint(f'  总检查项: {total_checks}', Colors.BOLD)
cprint(f'  通过: {len(results["passed"])}项', Colors.GREEN)
cprint(f'  失败: {len(results["failed"])}项', Colors.RED)
cprint(f'  警告: {len(results["warnings"])}项', Colors.YELLOW)
cprint(f'  通过率: {pass_rate:.1f}%', Colors.BOLD)
print()

if results['failed']:
    cprint('  失败项详情:', Colors.RED)
    for name, detail, category in results['failed']:
        cprint(f'    [{category}] {name}: {detail}', Colors.RED)
    print()

if results['warnings']:
    cprint('  警告项详情:', Colors.YELLOW)
    for name, detail, category in results['warnings']:
        cprint(f'    [{category}] {name}: {detail}', Colors.YELLOW)
    print()

# 健康评级
if pass_rate >= 95:
    grade = 'A+ (优秀)'
    grade_color = Colors.GREEN
elif pass_rate >= 90:
    grade = 'A (良好)'
    grade_color = Colors.GREEN
elif pass_rate >= 80:
    grade = 'B (合格)'
    grade_color = Colors.YELLOW
elif pass_rate >= 70:
    grade = 'C (一般)'
    grade_color = Colors.YELLOW
else:
    grade = 'D (需改进)'
    grade_color = Colors.RED

cprint(f'  项目健康评级: {grade}', Colors.BOLD + grade_color)
cprint(f'  检测时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', Colors.CYAN)
print()
cprint('=' * 70, Colors.CYAN)

# 保存报告
report = {
    'timestamp': datetime.now().isoformat(),
    'summary': {
        'total_checks': total_checks,
        'passed': len(results['passed']),
        'failed': len(results['failed']),
        'warnings': len(results['warnings']),
        'pass_rate': pass_rate,
        'grade': grade,
    },
    'performance': results['performance'],
    'failed_items': [{'name': n, 'detail': d, 'category': c} for n, d, c in results['failed']],
    'warning_items': [{'name': n, 'detail': d, 'category': c} for n, d, c in results['warnings']],
}

os.makedirs('reports', exist_ok=True)
report_file = f'reports/health_check_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
with open(report_file, 'w', encoding='utf-8') as f:
    json.dump(report, f, ensure_ascii=False, indent=2)

cprint(f'  详细报告已保存: {report_file}', Colors.CYAN)
print()
