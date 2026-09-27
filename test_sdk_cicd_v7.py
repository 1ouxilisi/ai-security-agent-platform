"""
AI Hacking Agent 第7轮升级验证测试
=====================================

验证SDK和CI/CD模块的完整性和正确性。
不实际调用API，仅验证导入、初始化、参数解析等。
"""

import os
import sys
import traceback

# 确保项目根目录在Python路径中
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

# 测试结果收集
results = []

def test(name, func):
    """运行单个测试用例。"""
    try:
        func()
        results.append((name, True, "通过"))
        print(f"  [PASS] {name}")
    except Exception as e:
        results.append((name, False, str(e)))
        print(f"  [FAIL] {name}: {e}")
        traceback.print_exc()


def main():
    print("=" * 70)
    print("AI Hacking Agent 第7轮升级 - SDK + CI/CD 模块验证测试")
    print("=" * 70)
    print()

    # ============================================================
    # 测试1：SDK导入
    # ============================================================
    print("【测试组1：SDK导入与初始化】")

    def test_sdk_import():
        from sdk.python.ai_hacking_sdk import (
            AIAgentClient, APIError, AuthenticationError,
            NotFoundError, RateLimitError, ServerError, ValidationError,
        )
        assert AIAgentClient is not None
        assert APIError is not None
        assert AuthenticationError is not None
        assert NotFoundError is not None
        assert RateLimitError is not None
        assert ServerError is not None
        assert ValidationError is not None
    test("SDK核心模块导入", test_sdk_import)

    def test_sdk_init():
        from sdk.python.ai_hacking_sdk import AIAgentClient
        c = AIAgentClient(base_url="http://localhost:9999", api_key="test", timeout=5)
        assert c.base_url == "http://localhost:9999"
        assert c.api_key == "test"
        assert c.timeout == 5
        assert c.max_retries == 3  # 默认值
        c.close()
    test("SDK客户端初始化", test_sdk_init)

    def test_sdk_methods_count():
        from sdk.python.ai_hacking_sdk import AIAgentClient
        c = AIAgentClient(base_url="http://localhost:9999", api_key="test", timeout=5)
        methods = [m for m in dir(c) if not m.startswith('_') and callable(getattr(c, m))]
        # 排除close和__enter__/__exit__（内部方法）
        public_methods = [m for m in methods if not m.startswith('__')]
        print(f"         公开方法数: {len(public_methods)}")
        for m in sorted(public_methods):
            print(f"           - {m}")
        assert len(public_methods) >= 30, f"公开方法数{len(public_methods)} < 30"
        c.close()
    test("SDK公开方法数 >= 30", test_sdk_methods_count)

    # ============================================================
    # 测试2：异常类体系
    # ============================================================
    print()
    print("【测试组2：异常类体系】")

    def test_exception_hierarchy():
        from sdk.python.ai_hacking_sdk import (
            APIError, AuthenticationError, NotFoundError,
            RateLimitError, ServerError, ValidationError,
        )
        # 验证继承关系
        assert issubclass(AuthenticationError, APIError)
        assert issubclass(NotFoundError, APIError)
        assert issubclass(RateLimitError, APIError)
        assert issubclass(ServerError, APIError)
        assert issubclass(ValidationError, APIError)
    test("异常类继承关系", test_exception_hierarchy)

    def test_exception_attributes():
        from sdk.python.ai_hacking_sdk import APIError
        err = APIError(404, "Not Found", "req-123")
        assert err.status_code == 404
        assert err.message == "Not Found"
        assert err.request_id == "req-123"
        assert "404" in str(err)
        assert "Not Found" in str(err)
    test("异常类属性和字符串表示", test_exception_attributes)

    # ============================================================
    # 测试3：SDK __init__.py 导出
    # ============================================================
    print()
    print("【测试组3：SDK包导出】")

    def test_sdk_package_init():
        import sdk.python as sdk_pkg
        assert hasattr(sdk_pkg, 'AIAgentClient')
        assert hasattr(sdk_pkg, 'APIError')
        assert hasattr(sdk_pkg, 'AuthenticationError')
        assert hasattr(sdk_pkg, 'NotFoundError')
        assert hasattr(sdk_pkg, 'RateLimitError')
        assert hasattr(sdk_pkg, 'ServerError')
        assert hasattr(sdk_pkg, 'ValidationError')
        assert sdk_pkg.__version__ == "1.0.0"
    test("SDK包__init__导出完整", test_sdk_package_init)

    # ============================================================
    # 测试4：examples导入
    # ============================================================
    print()
    print("【测试组4：示例模块】")

    def test_examples_import():
        from sdk.python.examples import example_quickstart
        assert callable(example_quickstart)
    test("examples模块导入", test_examples_import)

    def test_examples_count():
        from sdk.python.examples import EXAMPLES
        assert len(EXAMPLES) >= 10, f"示例数{len(EXAMPLES)} < 10"
        print(f"         示例数: {len(EXAMPLES)}")
    test("示例数量 >= 10", test_examples_count)

    # ============================================================
    # 测试5：CLI模块导入和参数解析
    # ============================================================
    print()
    print("【测试组5：CLI模块】")

    def test_cli_import():
        import cicd.cli
        assert hasattr(cicd.cli, 'main')
        assert hasattr(cicd.cli, 'build_parser')
        assert hasattr(cicd.cli, 'CICDTool')
    test("CLI模块导入", test_cli_import)

    def test_cli_parser():
        from cicd.cli import build_parser
        parser = build_parser()
        # 测试解析scan命令
        args = parser.parse_args(['scan', '--target', 'https://example.com'])
        assert args.command == 'scan'
        assert args.target == 'https://example.com'
        assert args.type == 'comprehensive'  # 默认值

        # 测试check命令
        args2 = parser.parse_args(['check', '-t', 'https://test.com', '-th', 'critical'])
        assert args2.command == 'check'
        assert args2.threshold == 'critical'

        # 测试全局参数
        args3 = parser.parse_args(['--format', 'json', '--api-url', 'http://test:8000', 'scan', '-t', 'x.com'])
        assert args3.format == 'json'
        assert args3.api_url == 'http://test:8000'
    test("CLI参数解析", test_cli_parser)

    def test_cli_exit_codes():
        from cicd.cli import EXIT_SUCCESS, EXIT_VULN_FOUND, EXIT_SCAN_FAILED, EXIT_ARG_ERROR
        assert EXIT_SUCCESS == 0
        assert EXIT_VULN_FOUND == 1
        assert EXIT_SCAN_FAILED == 2
        assert EXIT_ARG_ERROR == 3
    test("CLI退出码常量", test_cli_exit_codes)

    # ============================================================
    # 测试6：文件存在性检查
    # ============================================================
    print()
    print("【测试组6：文件存在性】")

    required_files = [
        "sdk/python/ai_hacking_sdk.py",
        "sdk/python/examples.py",
        "sdk/python/__init__.py",
        "sdk/python/README.md",
        "sdk/python/requirements.txt",
        "cicd/__init__.py",
        "cicd/cli.py",
        "cicd/gitlab_ci.yml",
        "cicd/github_actions.yml",
        "cicd/jenkinsfile",
        "cicd/README.md",
    ]

    for f in required_files:
        path = os.path.join(PROJECT_ROOT, f)
        exists = os.path.exists(path)
        size = os.path.getsize(path) if exists else 0
        status = "PASS" if exists and size > 0 else "FAIL"
        results.append((f"文件存在: {f}", exists and size > 0, f"{size} bytes"))
        print(f"  [{status}] {f} ({size} bytes)")

    # ============================================================
    # 测试7：SDK内部方法存在性
    # ============================================================
    print()
    print("【测试组7：SDK内部方法】")

    def test_internal_methods():
        from sdk.python.ai_hacking_sdk import AIAgentClient
        c = AIAgentClient(base_url="http://localhost:9999", timeout=5)
        # 检查内部方法
        assert hasattr(c, '_request')
        assert hasattr(c, '_get')
        assert hasattr(c, '_post')
        assert hasattr(c, '_put')
        assert hasattr(c, '_delete')
        assert callable(c._request)
        assert callable(c._get)
        assert callable(c._post)
        c.close()
    test("SDK内部请求方法存在", test_internal_methods)

    # ============================================================
    # 汇总
    # ============================================================
    print()
    print("=" * 70)
    print("测试结果汇总")
    print("=" * 70)

    passed = sum(1 for _, ok, _ in results if ok)
    failed = sum(1 for _, ok, _ in results if not ok)
    total = len(results)

    print(f"总计: {total} 项")
    print(f"通过: {passed} 项")
    print(f"失败: {failed} 项")
    print()

    if failed > 0:
        print("失败的测试:")
        for name, ok, msg in results:
            if not ok:
                print(f"  - {name}: {msg}")
        print()
        print("❌ 部分测试未通过")
        sys.exit(1)
    else:
        print("✅ 全部测试通过！")
        sys.exit(0)


if __name__ == "__main__":
    main()
