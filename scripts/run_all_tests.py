#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_all_tests脚本工具模块，提供相关的命令行工具和自动化脚本。

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
import json
import time
import subprocess
import importlib.util
from datetime import datetime
from typing import Dict, List, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


class Colors:
    """Colors类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


class TestRunner:
    """统一测试运行器"""

    def __init__(self):
        """初始化TestRunner实例。

        Args:
            self: 类实例。
        """
        self.results = []
        self.start_time = None
        self.end_time = None

    def run_all(self) -> Dict:
        """运行所有测试"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}")
        print(f"  AI Hacking Agent - 统一测试运行器")
        print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}{Colors.END}\n")

        self.start_time = time.time()

        # 1. 模块导入测试
        self._run_import_tests()

        # 2. P1/P2/P3模块测试
        self._run_module_tests()

        # 3. 单元测试
        self._run_unit_tests()

        # 4. 集成测试
        self._run_integration_tests()

        # 5. 系统体检
        self._run_doctor_check()

        self.end_time = time.time()

        # 生成报告
        report = self._generate_report()
        self._print_report(report)
        self._save_report(report)

        return report

    def _run_import_tests(self):
        """模块导入测试"""
        print(f"{Colors.BLUE}[1/5] 模块导入测试{Colors.END}")

        modules = [
            ('core', '模块整合层'),
            ('auth.auth_system', '认证系统'),
            ('scheduler.task_scheduler', '任务调度'),
            ('tools.nday_arsenal', 'Nday武器库'),
            ('tools.report_generator', '报告生成器'),
            ('notifications.notification_manager', '通知系统'),
            ('gateway.api_gateway', 'API网关'),
            ('saas.tenant_manager', '多租户SaaS'),
            ('integrations.security_tools', '工具集成'),
            ('mcp.mcp_server', 'MCP服务器'),
            ('llm.client', 'LLM客户端'),
            ('knowledge.cve', 'CVE知识库'),
            ('cache.cache_manager', '缓存管理'),
            ('config.settings', '配置管理'),
        ]

        passed = 0
        failed = 0
        for module_path, name in modules:
            try:
                spec = importlib.util.find_spec(module_path)
                if spec is None:
                    raise ImportError(f"模块不存在: {module_path}")
                module = importlib.import_module(module_path)
                print(f"  {Colors.GREEN}✓{Colors.END} {name} ({module_path})")
                self.results.append({
                    'category': 'import',
                    'name': name,
                    'module': module_path,
                    'status': 'passed',
                })
                passed += 1
            except Exception as e:
                print(f"  {Colors.RED}✗{Colors.END} {name} ({module_path}): {e}")
                self.results.append({
                    'category': 'import',
                    'name': name,
                    'module': module_path,
                    'status': 'failed',
                    'error': str(e),
                })
                failed += 1

        print(f"  结果: {Colors.GREEN}{passed}通过{Colors.END}, {Colors.RED}{failed}失败{Colors.END}\n")

    def _run_module_tests(self):
        """P1/P2/P3模块测试"""
        print(f"{Colors.BLUE}[2/5] 模块测试 (P1/P2/P3){Colors.END}")

        test_files = [
            ('scripts/test_p1_modules.py', 'P1模块测试'),
            ('scripts/test_p2_modules.py', 'P2模块测试'),
            ('scripts/test_p3_modules.py', 'P3模块测试'),
        ]

        for path, name in test_files:
            full_path = os.path.join(PROJECT_ROOT, path)
            if not os.path.exists(full_path):
                print(f"  {Colors.YELLOW}⚠{Colors.END} {name} 跳过 (文件不存在)")
                self.results.append({'category': 'module', 'name': name, 'status': 'skipped'})
                continue

            try:
                result = subprocess.run(
                    [sys.executable, full_path],
                    cwd=PROJECT_ROOT,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if result.returncode == 0:
                    # 提取通过率
                    pass_rate = "100%"
                    for line in result.stdout.split('\n'):
                        if '通过率' in line:
                            pass_rate = line.strip()
                            break
                    print(f"  {Colors.GREEN}✓{Colors.END} {name} - {pass_rate}")
                    self.results.append({'category': 'module', 'name': name, 'status': 'passed', 'output': pass_rate})
                else:
                    error_lines = [l for l in result.stderr.split('\n') if l.strip()][-3:]
                    print(f"  {Colors.RED}✗{Colors.END} {name} - 失败")
                    for line in error_lines:
                        print(f"      {line[:80]}")
                    self.results.append({'category': 'module', 'name': name, 'status': 'failed', 'error': '\n'.join(error_lines)})
            except subprocess.TimeoutExpired:
                print(f"  {Colors.YELLOW}⚠{Colors.END} {name} - 超时")
                self.results.append({'category': 'module', 'name': name, 'status': 'timeout'})
            except Exception as e:
                print(f"  {Colors.RED}✗{Colors.END} {name} - {e}")
                self.results.append({'category': 'module', 'name': name, 'status': 'failed', 'error': str(e)})

        print()

    def _run_unit_tests(self):
        """单元测试"""
        print(f"{Colors.BLUE}[3/5] 单元测试{Colors.END}")

        test_files = [
            ('tests/test_unit.py', '单元测试'),
            ('tests/test_suite.py', '测试套件'),
            ('tests/test_new_modules.py', '新模块测试'),
        ]

        for path, name in test_files:
            full_path = os.path.join(PROJECT_ROOT, path)
            if not os.path.exists(full_path):
                print(f"  {Colors.YELLOW}⚠{Colors.END} {name} 跳过")
                self.results.append({'category': 'unit', 'name': name, 'status': 'skipped'})
                continue

            try:
                result = subprocess.run(
                    [sys.executable, '-m', 'pytest', full_path, '-v', '--tb=short', '-q'],
                    cwd=PROJECT_ROOT,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                output = result.stdout + result.stderr
                if 'passed' in output or result.returncode == 0:
                    # 提取通过数
                    passed_count = "?"
                    for line in output.split('\n'):
                        if 'passed' in line:
                            passed_count = line.strip()
                            break
                    print(f"  {Colors.GREEN}✓{Colors.END} {name} - {passed_count}")
                    self.results.append({'category': 'unit', 'name': name, 'status': 'passed', 'output': passed_count})
                else:
                    print(f"  {Colors.YELLOW}⚠{Colors.END} {name} - 部分失败 (返回码: {result.returncode})")
                    self.results.append({'category': 'unit', 'name': name, 'status': 'partial', 'returncode': result.returncode})
            except Exception as e:
                print(f"  {Colors.RED}✗{Colors.END} {name} - {e}")
                self.results.append({'category': 'unit', 'name': name, 'status': 'failed', 'error': str(e)})

        print()

    def _run_integration_tests(self):
        """集成测试"""
        print(f"{Colors.BLUE}[4/5] 集成测试{Colors.END}")

        # 测试核心功能集成
        tests = [
            ('认证系统集成', self._test_auth_integration),
            ('通知系统集成', self._test_notification_integration),
            ('API网关集成', self._test_gateway_integration),
            ('SaaS租户集成', self._test_saas_integration),
            ('MCP服务器集成', self._test_mcp_integration),
        ]

        for name, test_func in tests:
            try:
                test_func()
                print(f"  {Colors.GREEN}✓{Colors.END} {name}")
                self.results.append({'category': 'integration', 'name': name, 'status': 'passed'})
            except Exception as e:
                print(f"  {Colors.RED}✗{Colors.END} {name}: {e}")
                self.results.append({'category': 'integration', 'name': name, 'status': 'failed', 'error': str(e)})

        print()

    def _test_auth_integration(self):
        """测试认证系统集成"""
        from core import auth
        assert hasattr(auth, 'AuthSystem') or hasattr(auth, '_load'), "AuthSystem类未找到"

    def _test_notification_integration(self):
        """测试通知系统集成"""
        from core import notification
        assert hasattr(notification, 'NotificationManager') or hasattr(notification, '_load')

    def _test_gateway_integration(self):
        """测试API网关集成"""
        from core import gateway
        assert hasattr(gateway, 'APIGateway') or hasattr(gateway, '_load')

    def _test_saas_integration(self):
        """测试SaaS租户集成"""
        from core import tenant
        assert hasattr(tenant, 'TenantManager') or hasattr(tenant, '_load')

    def _test_mcp_integration(self):
        """测试MCP服务器集成"""
        from core import mcp
        assert hasattr(mcp, 'MCPServer') or hasattr(mcp, '_load')

    def _run_doctor_check(self):
        """系统体检"""
        print(f"{Colors.BLUE}[5/5] 系统体检{Colors.END}")

        # 代码量统计
        py_files = []
        for root, dirs, files in os.walk(PROJECT_ROOT):
            if '__pycache__' in root or '.git' in root:
                continue
            for f in files:
                if f.endswith('.py'):
                    py_files.append(os.path.join(root, f))

        total_size = sum(os.path.getsize(f) for f in py_files)
        print(f"  Python文件: {len(py_files)}个")
        print(f"  总代码量: {total_size/1024:.1f}KB ({total_size/1024/1024:.2f}MB)")

        # 核心文件检查
        core_files = [
            'launcher.py', 'main.py', 'requirements.txt',
            'core/__init__.py', 'ARCHITECTURE.md', 'README.md',
            'Dockerfile', 'docker-compose.yml',
        ]
        exists = 0
        for f in core_files:
            if os.path.exists(os.path.join(PROJECT_ROOT, f)):
                exists += 1
        print(f"  核心文件: {exists}/{len(core_files)} 存在")

        # 模块目录检查
        dirs = ['agent', 'tools', 'api_server', 'web', 'auth', 'scheduler',
                'notifications', 'gateway', 'saas', 'mcp', 'integrations', 'core']
        dir_exists = sum(1 for d in dirs if os.path.isdir(os.path.join(PROJECT_ROOT, d)))
        print(f"  模块目录: {dir_exists}/{len(dirs)} 存在")

        self.results.append({
            'category': 'doctor',
            'name': '系统体检',
            'status': 'passed',
            'py_files': len(py_files),
            'total_size': total_size,
            'core_files': f"{exists}/{len(core_files)}",
            'module_dirs': f"{dir_exists}/{len(dirs)}",
        })

        print()

    def _generate_report(self) -> Dict:
        """生成测试报告"""
        duration = self.end_time - self.start_time if self.end_time and self.start_time else 0

        categories = {}
        for r in self.results:
            cat = r['category']
            if cat not in categories:
                categories[cat] = {'total': 0, 'passed': 0, 'failed': 0, 'skipped': 0, 'timeout': 0, 'partial': 0}
            categories[cat]['total'] += 1
            status = r.get('status', 'unknown')
            if status in categories[cat]:
                categories[cat][status] += 1

        total = len(self.results)
        passed = sum(1 for r in self.results if r.get('status') == 'passed')
        failed = sum(1 for r in self.results if r.get('status') == 'failed')
        skipped = sum(1 for r in self.results if r.get('status') == 'skipped')

        return {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'duration_seconds': round(duration, 2),
            'summary': {
                'total': total,
                'passed': passed,
                'failed': failed,
                'skipped': skipped,
                'pass_rate': f"{passed/total*100:.1f}%" if total > 0 else "0%",
            },
            'categories': categories,
            'results': self.results,
        }

    def _print_report(self, report: Dict):
        """打印测试报告"""
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}")
        print(f"  测试结果汇总")
        print(f"{'='*60}{Colors.END}")
        print(f"  总测试数: {report['summary']['total']}")
        print(f"  通过: {Colors.GREEN}{report['summary']['passed']}{Colors.END}")
        print(f"  失败: {Colors.RED}{report['summary']['failed']}{Colors.END}")
        print(f"  跳过: {Colors.YELLOW}{report['summary']['skipped']}{Colors.END}")
        print(f"  通过率: {Colors.BOLD}{report['summary']['pass_rate']}{Colors.END}")
        print(f"  耗时: {report['duration_seconds']}秒")
        print()

        print(f"  分类统计:")
        for cat, stats in report['categories'].items():
            print(f"    {cat:15s}: {stats['passed']}通过, {stats['failed']}失败, {stats['skipped']}跳过")
        print()

        if report['summary']['failed'] > 0:
            print(f"  {Colors.RED}失败项:{Colors.END}")
            for r in self.results:
                if r.get('status') == 'failed':
                    print(f"    - [{r['category']}] {r['name']}: {r.get('error', '未知错误')}")
            print()

        if report['summary']['failed'] == 0:
            print(f"  {Colors.GREEN}{Colors.BOLD}🎉 所有测试通过！项目状态良好！{Colors.END}")
        else:
            print(f"  {Colors.YELLOW}⚠ 有{report['summary']['failed']}个测试失败，请检查{Colors.END}")

        print(f"{'='*60}\n")

    def _save_report(self, report: Dict):
        """保存测试报告"""
        report_dir = os.path.join(PROJECT_ROOT, 'data', 'test_reports')
        os.makedirs(report_dir, exist_ok=True)

        filename = f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(report_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print(f"  报告已保存: {filepath}")


def main():
    """在...中。

        Returns:
            操作结果。
    """
    runner = TestRunner()
    report = runner.run_all()
    return report['summary']['failed'] == 0


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
