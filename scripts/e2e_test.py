"""
e2e_test脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import sys
import json
import time
import requests
from typing import Dict, Any, List, Tuple


class E2ETester:
    """端到端测试器"""

    def __init__(self, base_url: str = "http://127.0.0.1:8000", api_key: str = ""):
        """初始化E2ETester实例。

        Args:
            self: 类实例。
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.results = []
        self.passed = 0
        self.failed = 0

    def _headers(self) -> Dict[str, str]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _request(self, method: str, endpoint: str, data: dict = None,
                 need_auth: bool = True) -> Tuple[int, Any]:
        """发送HTTP请求"""
        url = f"{self.base_url}{endpoint}"
        headers = self._headers() if need_auth else {"Content-Type": "application/json"}

        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, timeout=10)
            elif method == "POST":
                resp = requests.post(url, json=data, headers=headers, timeout=10)
            else:
                return 0, None

            return resp.status_code, resp.json() if resp.content else None
        except requests.exceptions.ConnectionError:
            return 0, "Connection refused"
        except Exception as e:
            return 0, str(e)

    def _record(self, name: str, passed: bool, detail: str = ""):
        """记录测试结果"""
        status = "✅ PASS" if passed else "❌ FAIL"
        self.results.append({"name": name, "passed": passed, "detail": detail})
        if passed:
            self.passed += 1
        else:
            self.failed += 1
        print(f"  {status}: {name}" + (f" - {detail}" if detail else ""))

    def test_health(self):
        """测试健康检查"""
        print("\n📋 系统管理测试")
        print("-" * 50)

        status, data = self._request("GET", "/health", need_auth=False)
        self._record("健康检查", status == 200, f"HTTP {status}")

        status, data = self._request("GET", "/api/v1/system/stats")
        self._record("系统统计", status == 200, f"HTTP {status}")

        status, data = self._request("GET", "/api/v1/system/config")
        self._record("系统配置", status == 200, f"HTTP {status}")

    def test_database(self):
        """测试数据库API"""
        print("\n🗄️ 数据库持久化测试")
        print("-" * 50)

        status, data = self._request("GET", "/api/v1/db/stats")
        self._record("数据库统计", status == 200,
                     f"用户: {data.get('total_users', 0) if data else 'N/A'}")

        status, data = self._request("GET", "/api/v1/db/tasks?limit=5")
        self._record("任务列表", status == 200, f"HTTP {status}")

        status, data = self._request("GET", "/api/v1/db/findings?limit=5")
        self._record("发现列表", status == 200, f"HTTP {status}")

    def test_user_management(self):
        """测试用户管理API"""
        print("\n👤 用户管理测试")
        print("-" * 50)

        # 用户登录
        login_data = {"username": "admin", "password": "admin123"}
        status, data = self._request("POST", "/api/v1/auth/login", data=login_data, need_auth=False)
        login_ok = status == 200 and data and data.get("success")
        self._record("用户登录", login_ok,
                     f"用户: {data.get('user', {}).get('username', 'N/A') if data else 'N/A'}")

        # 用户列表
        status, data = self._request("GET", "/api/v1/users?limit=5")
        self._record("用户列表", status == 200,
                     f"总数: {data.get('total', 0) if data else 'N/A'}")

        # 审计日志
        status, data = self._request("GET", "/api/v1/audit-logs?limit=5")
        self._record("审计日志", status == 200, f"HTTP {status}")

        # 用户注册（创建测试用户）
        test_user = f"testuser_{int(time.time())}"
        register_data = {
            "username": test_user,
            "password": "testpass123",
            "email": f"{test_user}@test.com",
            "role": "user"
        }
        status, data = self._request("POST", "/api/v1/auth/register", data=register_data, need_auth=False)
        register_ok = status == 200 and data and data.get("success")
        self._record("用户注册", register_ok,
                     f"用户: {data.get('username', 'N/A') if data else 'N/A'}")

    def test_plugin_system(self):
        """测试插件系统API"""
        print("\n🔌 插件系统测试")
        print("-" * 50)

        # 插件统计
        status, data = self._request("GET", "/api/v1/plugins/stats")
        self._record("插件统计", status == 200,
                     f"已注册: {data.get('total_registered', 0) if data else 'N/A'}")

        # 插件发现
        status, data = self._request("POST", "/api/v1/plugins/discover")
        discover_ok = status == 200 and data
        discovered = data.get("discovered", []) if data else []
        self._record("插件发现", discover_ok, f"发现: {len(discovered)}个")

        # 插件列表
        status, data = self._request("GET", "/api/v1/plugins")
        list_ok = status == 200 and data
        plugin_count = data.get("total", 0) if data else 0
        self._record("插件列表", list_ok, f"总数: {plugin_count}个")

        # 执行DNS查询插件
        if "dns_lookup" in discovered:
            execute_data = {
                "plugin_name": "dns_lookup",
                "parameters": {"domain": "example.com", "record_type": "A"}
            }
            status, data = self._request("POST", "/api/v1/plugins/execute", data=execute_data)
            exec_ok = status == 200 and data and data.get("success")
            record_count = data.get("result", {}).get("count", 0) if data else 0
            self._record("执行DNS查询插件", exec_ok, f"返回: {record_count}条记录")

            # 插件帮助
            status, data = self._request("GET", "/api/v1/plugins/dns_lookup/help")
            self._record("插件帮助信息", status == 200, f"HTTP {status}")

    def test_tools(self):
        """测试工具API"""
        print("\n🛠️ 工具调用测试")
        print("-" * 50)

        status, data = self._request("GET", "/api/v1/tools")
        self._record("工具列表", status == 200, f"HTTP {status}")

    def run_all(self) -> Dict[str, Any]:
        """运行所有测试"""
        print("=" * 60)
        print("  AI Hacking Agent - 端到端测试")
        print(f"  目标: {self.base_url}")
        print("=" * 60)

        start_time = time.time()

        self.test_health()
        self.test_database()
        self.test_user_management()
        self.test_plugin_system()
        self.test_tools()

        elapsed = time.time() - start_time

        print("\n" + "=" * 60)
        print("  测试结果汇总")
        print("=" * 60)
        print(f"  ✅ 通过: {self.passed}")
        print(f"  ❌ 失败: {self.failed}")
        print(f"  📊 总计: {self.passed + self.failed}")
        print(f"  ⏱️  耗时: {elapsed:.2f}秒")
        print(f"  📈 通过率: {self.passed / (self.passed + self.failed) * 100:.1f}%" if (self.passed + self.failed) > 0 else "")
        print("=" * 60)

        return {
            "passed": self.passed,
            "failed": self.failed,
            "total": self.passed + self.failed,
            "elapsed": elapsed,
            "results": self.results,
        }


def main():
    """主函数"""
    import argparse
    parser = argparse.ArgumentParser(description="AI Hacking Agent 端到端测试")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="API服务地址")
    parser.add_argument("--api-key", default=os.getenv("API_AUTH_KEY", ""), help="API密钥")
    args = parser.parse_args()

    tester = E2ETester(base_url=args.url, api_key=args.api_key)
    result = tester.run_all()

    sys.exit(0 if result["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
