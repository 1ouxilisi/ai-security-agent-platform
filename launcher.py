#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Hacking Agent - 统一启动入口
整合 main.py / api_server/app.py / web_ui/app.py 三个入口
用法:
  python launcher.py              # 显示帮助
  python launcher.py api          # 启动API服务 (FastAPI)
  python launcher.py web          # 启动Web UI (Streamlit)
  python launcher.py console      # 启动控制台
  python launcher.py all          # 同时启动API+Web
  python launcher.py mcp          # 启动MCP服务器
  python launcher.py test         # 运行全部测试
  python launcher.py doctor       # 系统体检
"""

import os
import sys
import subprocess
import argparse
import importlib.util
from datetime import datetime

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

# 颜色输出
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

def print_banner():
    """打印横幅"""
    print(f"""
{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗
║           AI Hacking Agent v4.0 - 统一启动器              ║
║     企业级AI安全测试平台 | 2.56MB代码 | 211个文件        ║
╚══════════════════════════════════════════════════════════╝{Colors.END}
""")

def check_dependencies():
    """检查依赖"""
    print(f"\n{Colors.BLUE}[检查]{Colors.END} 依赖检查...")
    required = {
        'fastapi': 'fastapi',
        'uvicorn': 'uvicorn',
        'pydantic': 'pydantic',
        'requests': 'requests',
        'loguru': 'loguru',
        'rich': 'rich',
        'click': 'click',
        'openai': 'openai',
        'playwright': 'playwright',
        'streamlit': 'streamlit',
        'pandas': 'pandas',
        'yaml': 'pyyaml',
        'dotenv': 'python-dotenv',
        'aiohttp': 'aiohttp',
    }

    missing = []
    for module, package in required.items():
        try:
            importlib.import_module(module)
            print(f"  {Colors.GREEN}✓{Colors.END} {package}")
        except ImportError:
            print(f"  {Colors.RED}✗{Colors.END} {package} (未安装)")
            missing.append(package)

    if missing:
        print(f"\n{Colors.YELLOW}警告: 缺少 {len(missing)} 个依赖包{Colors.END}")
        print(f"  运行: pip install {' '.join(missing)}")
        return False
    print(f"\n{Colors.GREEN}所有核心依赖已安装 ✓{Colors.END}")
    return True

def check_modules():
    """检查核心模块"""
    print(f"\n{Colors.BLUE}[检查]{Colors.END} 核心模块检查...")
    modules = [
        ('auth/auth_system.py', '认证系统'),
        ('scheduler/task_scheduler.py', '任务调度'),
        ('tools/nday_arsenal.py', 'Nday武器库'),
        ('tools/report_generator.py', '报告生成器'),
        ('agent/super_agent.py', '超级智能体'),
        ('api_server/app.py', 'API服务'),
        ('web_ui/app.py', 'Web UI'),
        ('mcp/mcp_server.py', 'MCP服务器'),
        ('gateway/api_gateway.py', 'API网关'),
        ('saas/tenant_manager.py', '多租户SaaS'),
        ('notifications/notification_manager.py', '通知系统'),
        ('integrations/security_tools.py', '工具集成'),
    ]

    ok = 0
    for path, name in modules:
        full = os.path.join(PROJECT_ROOT, path)
        if os.path.exists(full):
            print(f"  {Colors.GREEN}✓{Colors.END} {name} ({path})")
            ok += 1
        else:
            print(f"  {Colors.RED}✗{Colors.END} {name} (缺失: {path})")

    print(f"\n  核心模块: {ok}/{len(modules)} 可用")
    return ok == len(modules)

def start_api(host='127.0.0.1', port=8000):
    """启动API服务"""
    print(f"\n{Colors.GREEN}[启动]{Colors.END} API服务: http://{host}:{port}")
    print(f"  API文档: http://{host}:{port}/docs")
    print(f"  健康检查: http://{host}:{port}/health")
    print(f"  按 Ctrl+C 停止\n")

    # 优先使用 api_server/app.py
    api_app = os.path.join(PROJECT_ROOT, 'api_server', 'app.py')
    if os.path.exists(api_app):
        cmd = [sys.executable, '-m', 'uvicorn', 'api_server.app:app',
               '--host', host, '--port', str(port), '--reload']
    else:
        cmd = [sys.executable, 'main.py', 'api-server', '--host', host, '--port', str(port)]

    try:
        subprocess.run(cmd, cwd=PROJECT_ROOT)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}API服务已停止{Colors.END}")

def start_web(port=8501):
    """启动Web UI (Streamlit)"""
    print(f"\n{Colors.GREEN}[启动]{Colors.END} Web UI: http://localhost:{port}")
    print(f"  按 Ctrl+C 停止\n")

    web_app = os.path.join(PROJECT_ROOT, 'web_ui', 'app.py')
    if os.path.exists(web_app):
        cmd = [sys.executable, '-m', 'streamlit', 'run', web_app,
               '--server.port', str(port), '--server.headless', 'true']
        try:
            subprocess.run(cmd, cwd=PROJECT_ROOT)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Web UI已停止{Colors.END}")
    else:
        print(f"{Colors.RED}错误: web_ui/app.py 不存在{Colors.END}")

def start_mcp(port=8002):
    """启动MCP服务器"""
    print(f"\n{Colors.GREEN}[启动]{Colors.END} MCP服务器: http://localhost:{port}")
    print(f"  按 Ctrl+C 停止\n")

    mcp_server = os.path.join(PROJECT_ROOT, 'mcp', 'mcp_server.py')
    if os.path.exists(mcp_server):
        cmd = [sys.executable, mcp_server]
        try:
            subprocess.run(cmd, cwd=PROJECT_ROOT)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}MCP服务器已停止{Colors.END}")
    else:
        print(f"{Colors.RED}错误: mcp/mcp_server.py 不存在{Colors.END}")

def start_all():
    """同时启动API+Web"""
    print(f"\n{Colors.GREEN}[启动]{Colors.END} 全模式启动 (API + Web + MCP)")

    processes = []
    try:
        # API服务
        api_app = os.path.join(PROJECT_ROOT, 'api_server', 'app.py')
        if os.path.exists(api_app):
            p1 = subprocess.Popen(
                [sys.executable, '-m', 'uvicorn', 'api_server.app:app',
                 '--host', '127.0.0.1', '--port', '8000'],
                cwd=PROJECT_ROOT
            )
            processes.append(('API', p1))
            print(f"  {Colors.GREEN}✓{Colors.END} API服务: http://127.0.0.1:8000")

        # Web UI
        web_app = os.path.join(PROJECT_ROOT, 'web_ui', 'app.py')
        if os.path.exists(web_app):
            p2 = subprocess.Popen(
                [sys.executable, '-m', 'streamlit', 'run', web_app,
                 '--server.port', '8501', '--server.headless', 'true'],
                cwd=PROJECT_ROOT
            )
            processes.append(('Web', p2))
            print(f"  {Colors.GREEN}✓{Colors.END} Web UI: http://localhost:8501")

        print(f"\n{Colors.GREEN}所有服务已启动，按 Ctrl+C 停止{Colors.END}")
        while True:
            import time
            time.sleep(1)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}正在停止所有服务...{Colors.END}")
        for name, p in processes:
            p.terminate()
            print(f"  {name} 已停止")

def run_tests():
    """运行全部测试"""
    print(f"\n{Colors.BLUE}[测试]{Colors.END} 运行全部测试...")

    test_files = [
        ('scripts/test_p1_modules.py', 'P1模块测试'),
        ('scripts/test_p2_modules.py', 'P2模块测试'),
        ('scripts/test_p3_modules.py', 'P3模块测试'),
        ('tests/test_unit.py', '单元测试'),
        ('tests/test_suite.py', '测试套件'),
        ('tests/test_new_modules.py', '新模块测试'),
    ]

    passed = 0
    failed = 0
    for path, name in test_files:
        full = os.path.join(PROJECT_ROOT, path)
        if os.path.exists(full):
            print(f"\n  {Colors.CYAN}▶ {name}{Colors.END} ({path})")
            result = subprocess.run(
                [sys.executable, full],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                print(f"    {Colors.GREEN}✓ 通过{Colors.END}")
                passed += 1
            else:
                print(f"    {Colors.RED}✗ 失败{Colors.END}")
                # 显示最后几行错误
                lines = result.stderr.strip().split('\n')[-5:]
                for line in lines:
                    if line.strip():
                        print(f"      {line[:100]}")
                failed += 1
        else:
            print(f"  {Colors.YELLOW}⚠ {name} 跳过 (文件不存在){Colors.END}")

    print(f"\n{'='*50}")
    print(f"  测试结果: {Colors.GREEN}{passed}通过{Colors.END}, {Colors.RED}{failed}失败{Colors.END}")
    print(f"{'='*50}")
    return failed == 0

def doctor():
    """系统体检"""
    print(f"\n{Colors.BLUE}[体检]{Colors.END} 系统全面体检...")

    issues = []
    warnings = []

    # 1. 代码量统计
    py_files = []
    for root, dirs, files in os.walk(PROJECT_ROOT):
        if '__pycache__' in root or '.git' in root:
            continue
        for f in files:
            if f.endswith('.py'):
                py_files.append(os.path.join(root, f))

    total_size = sum(os.path.getsize(f) for f in py_files)
    print(f"\n  {Colors.CYAN}代码统计:{Colors.END}")
    print(f"    Python文件: {len(py_files)}个")
    print(f"    总代码量: {total_size/1024:.1f}KB ({total_size/1024/1024:.2f}MB)")

    # 2. 重复模块检测
    print(f"\n  {Colors.CYAN}重复模块检测:{Colors.END}")
    duplicate_patterns = {
        'tenant_manager': ['saas/tenant_manager.py', 'tools/tenant_manager.py'],
        'auth_system': ['auth/auth_system.py', 'tools/auth_manager.py', 'enterprise/auth.py', 'utils/auth.py'],
        'report_generator': ['tools/report_generator.py', 'reporting/professional_report.py', 'agent/reporter.py'],
    }
    for name, paths in duplicate_patterns.items():
        existing = [p for p in paths if os.path.exists(os.path.join(PROJECT_ROOT, p))]
        if len(existing) > 1:
            print(f"    {Colors.YELLOW}⚠ {name}: {len(existing)}个重复版本{Colors.END}")
            for p in existing:
                print(f"      - {p}")
            warnings.append(f"{name}有{len(existing)}个重复版本")

    # 3. 入口文件
    print(f"\n  {Colors.CYAN}入口文件:{Colors.END}")
    entries = ['main.py', 'api_server/app.py', 'web_ui/app.py']
    for e in entries:
        if os.path.exists(os.path.join(PROJECT_ROOT, e)):
            size = os.path.getsize(os.path.join(PROJECT_ROOT, e))
            print(f"    {Colors.GREEN}✓{Colors.END} {e} ({size/1024:.1f}KB)")

    # 4. 依赖检查
    print(f"\n  {Colors.CYAN}依赖检查:{Colors.END}")
    req_file = os.path.join(PROJECT_ROOT, 'requirements.txt')
    if os.path.exists(req_file):
        with open(req_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        print(f"    requirements.txt: {len(lines)}个依赖")
    else:
        issues.append("requirements.txt不存在")

    # 5. 测试覆盖
    print(f"\n  {Colors.CYAN}测试文件:{Colors.END}")
    test_count = 0
    for root, dirs, files in os.walk(PROJECT_ROOT):
        if '__pycache__' in root:
            continue
        for f in files:
            if f.startswith('test_') and f.endswith('.py'):
                test_count += 1
    print(f"    测试文件: {test_count}个")

    # 6. 文档
    print(f"\n  {Colors.CYAN}文档:{Colors.END}")
    docs = ['README.md', '部署文档.md', 'MCP_TOOLKIT.md']
    for d in docs:
        if os.path.exists(os.path.join(PROJECT_ROOT, d)):
            print(f"    {Colors.GREEN}✓{Colors.END} {d}")
        else:
            print(f"    {Colors.RED}✗{Colors.END} {d} (缺失)")
            issues.append(f"文档缺失: {d}")

    # 总结
    print(f"\n{'='*50}")
    print(f"  体检结果:")
    print(f"    问题: {len(issues)}个")
    print(f"    警告: {len(warnings)}个")
    if issues:
        print(f"\n  {Colors.RED}需要修复的问题:{Colors.END}")
        for i in issues:
            print(f"    - {i}")
    if warnings:
        print(f"\n  {Colors.YELLOW}建议优化:{Colors.END}")
        for w in warnings:
            print(f"    - {w}")
    if not issues and not warnings:
        print(f"\n  {Colors.GREEN}系统健康，无问题 ✓{Colors.END}")
    print(f"{'='*50}")

def main():
    """在...中。

        Returns:
            操作结果。
    """
    parser = argparse.ArgumentParser(
        description='AI Hacking Agent - 统一启动器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python launcher.py api          # 启动API服务
  python launcher.py web          # 启动Web UI
  python launcher.py all          # 同时启动所有服务
  python launcher.py test         # 运行全部测试
  python launcher.py doctor       # 系统体检
        """
    )
    parser.add_argument('command', nargs='?', default='help',
                        choices=['api', 'web', 'console', 'all', 'mcp', 'test', 'doctor', 'help'],
                        help='要执行的命令')
    parser.add_argument('--host', default='127.0.0.1', help='监听地址')
    parser.add_argument('--port', type=int, default=8000, help='API端口')

    args = parser.parse_args()

    if args.command == 'help':
        print_banner()
        parser.print_help()
        return

    print_banner()

    if args.command == 'api':
        check_dependencies()
        start_api(args.host, args.port)
    elif args.command == 'web':
        check_dependencies()
        start_web()
    elif args.command == 'mcp':
        start_mcp()
    elif args.command == 'all':
        check_dependencies()
        check_modules()
        start_all()
    elif args.command == 'test':
        run_tests()
    elif args.command == 'doctor':
        doctor()
    elif args.command == 'console':
        # 启动交互式控制台
        print(f"{Colors.CYAN}交互式控制台 (输入 help 查看命令){Colors.END}")
        print(f"输入 exit 退出\n")
        while True:
            try:
                cmd = input(f"{Colors.GREEN}aihacking> {Colors.END}").strip()
                if cmd == 'exit':
                    break
                elif cmd == 'help':
                    print("  可用命令: status, scan <target>, tools, report, exit")
                elif cmd == 'status':
                    doctor()
                elif cmd.startswith('scan '):
                    target = cmd[5:]
                    print(f"  启动扫描: {target}")
                    print(f"  (请使用 API 服务进行完整扫描)")
                else:
                    print(f"  未知命令: {cmd}")
            except (EOFError, KeyboardInterrupt):
                break

if __name__ == '__main__':
    main()
