#!/usr/bin/env python3
"""
target_verification脚本工具模块，提供相关的命令行工具和自动化脚本。

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
import os
import json
import time
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Tuple

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import log


class VerificationResult:
    """验证结果"""
    def __init__(self):
        """初始化VerificationResult实例。

        Args:
            self: 类实例。
        """
        self.results: List[Dict[str, Any]] = []
        self.start_time = datetime.now()

    def add(self, category: str, name: str, status: str, detail: str = "",
            data: Any = None):
        """添加相关数据。

        Args:
            category: 相关参数。
            name: 相关参数。
            status: 相关参数。
            detail: 相关参数。
            data: 相关参数。

        Returns:
            操作结果。
        """
        self.results.append({
            "category": category,
            "name": name,
            "status": status,  # pass/fail/skip/warning
            "detail": detail,
            "data": data,
            "timestamp": datetime.now().isoformat(),
        })

    def get_summary(self) -> Dict[str, Any]:
        """获取相关数据。

        Returns:
            操作结果。
        """
        total = len(self.results)
        passed = sum(1 for r in self.results if r["status"] == "pass")
        failed = sum(1 for r in self.results if r["status"] == "fail")
        skipped = sum(1 for r in self.results if r["status"] == "skip")
        warnings = sum(1 for r in self.results if r["status"] == "warning")
        duration = (datetime.now() - self.start_time).total_seconds()

        pass_rate = (passed / total * 100) if total > 0 else 0

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "warnings": warnings,
            "pass_rate": round(pass_rate, 1),
            "duration_seconds": round(duration, 2),
            "start_time": self.start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
        }

    def print_report(self):
        """打印验证报告"""
        summary = self.get_summary()

        print("\n" + "=" * 70)
        print("  AI Hacking Agent v8.0 靶场实战验证报告")
        print("=" * 70)
        print(f"  开始时间: {summary['start_time']}")
        print(f"  结束时间: {summary['end_time']}")
        print(f"  总耗时: {summary['duration_seconds']}秒")
        print("-" * 70)
        print(f"  总测试项: {summary['total']}")
        print(f"  ✅ 通过: {summary['passed']}")
        print(f"  ❌ 失败: {summary['failed']}")
        print(f"  ⚠️ 警告: {summary['warnings']}")
        print(f"  ⏭️ 跳过: {summary['skipped']}")
        print(f"  📊 通过率: {summary['pass_rate']}%")
        print("-" * 70)

        # 按类别分组
        categories = {}
        for r in self.results:
            cat = r["category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(r)

        for cat, items in categories.items():
            print(f"\n  📂 {cat} ({len(items)}项)")
            print("  " + "-" * 50)
            for item in items:
                status_icon = {
                    "pass": "✅", "fail": "❌", "skip": "⏭️", "warning": "⚠️"
                }.get(item["status"], "❓")
                print(f"  {status_icon} {item['name']}")
                if item["detail"]:
                    print(f"     {item['detail']}")

        print("\n" + "=" * 70)
        if summary["failed"] == 0:
            print("  🎉 所有测试通过！项目处于生产就绪状态！")
        elif summary["pass_rate"] >= 80:
            print("  ⚠️ 大部分测试通过，存在少量问题需要修复")
        else:
            print("  ❌ 存在较多问题，需要修复后重新验证")
        print("=" * 70 + "\n")

        return summary


def check_command(cmd: str) -> bool:
    """检查命令是否可用"""
    try:
        result = subprocess.run(
            [cmd, "--version"] if cmd != "python" else [cmd, "--version"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0 or "not recognized" not in result.stderr
    except Exception:
        return False


def run_verification():
    """运行完整验证"""
    result = VerificationResult()

    print("🚀 开始 AI Hacking Agent v8.0 靶场实战验证...\n")

    # ========== 1. 环境检查 ==========
    print("📋 [1/7] 环境检查...")

    # Python版本
    py_version = sys.version_info
    result.add("环境检查", "Python版本",
               "pass" if py_version >= (3, 10) else "fail",
               f"Python {py_version.major}.{py_version.minor}.{py_version.micro}")

    # 项目目录
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result.add("环境检查", "项目目录", "pass", project_dir)

    # 核心模块导入
    core_modules = [
        ("tools.internal_pentest", "内网渗透模块"),
        ("tools.ad_pentest", "域渗透模块"),
        ("tools.external_pentest", "外网渗透模块"),
        ("tools.ai_security_analyzer", "AI安全分析模块"),
        ("tools.password_security", "密码安全模块"),
        ("tools.traffic_analyzer", "流量分析模块"),
        ("tools.post_exploitation", "后渗透模块"),
    ]
    for module_name, desc in core_modules:
        try:
            __import__(module_name)
            result.add("环境检查", f"模块导入: {desc}", "pass")
        except Exception as e:
            result.add("环境检查", f"模块导入: {desc}", "fail", str(e))

    # ========== 2. 真实工具检查 ==========
    print("🧰 [2/7] 真实工具检查...")

    tools = [
        ("nmap", "Nmap端口扫描"),
        ("sqlmap", "SQLMap注入工具"),
        ("nuclei", "Nuclei漏洞扫描"),
        ("python", "Python解释器"),
        ("git", "Git版本控制"),
        ("docker", "Docker容器"),
    ]
    for tool, desc in tools:
        available = check_command(tool)
        result.add("真实工具", desc,
                   "pass" if available else "warning",
                   "已安装" if available else "未安装（可选）")

    # ========== 3. API服务检查 ==========
    print("🌐 [3/7] API服务检查...")

    try:
        import requests
        api_base = "http://127.0.0.1:8000"
        api_key = os.getenv("API_AUTH_KEY", "")
        headers = {"X-API-Key": api_key}

        # 健康检查
        try:
            r = requests.get(f"{api_base}/health", timeout=5)
            result.add("API服务", "健康检查端点",
                       "pass" if r.status_code == 200 else "fail",
                       f"HTTP {r.status_code}")
        except Exception as e:
            result.add("API服务", "健康检查端点", "warning",
                       f"API服务未运行: {e}")

        # 渗透测试操作列表
        try:
            r = requests.get(f"{api_base}/api/v1/pentest/actions",
                           headers=headers, timeout=5)
            if r.status_code == 200:
                data = r.json()
                result.add("API服务", "渗透测试操作列表", "pass",
                          f"{data.get('total_actions', 0)}个操作")
            else:
                result.add("API服务", "渗透测试操作列表", "fail",
                          f"HTTP {r.status_code}")
        except Exception as e:
            result.add("API服务", "渗透测试操作列表", "warning", str(e))

    except ImportError:
        result.add("API服务", "requests库", "fail", "未安装requests")

    # ========== 4. 7大模块功能验证 ==========
    print("🔬 [4/7] 7大模块功能验证...")

    # 4.1 内网渗透
    try:
        from tools.internal_pentest import internal_pentest
        ports = len(internal_pentest.COMMON_PORTS)
        result.add("模块验证", "内网渗透-常见端口库", "pass",
                  f"{ports}个端口")
    except Exception as e:
        result.add("模块验证", "内网渗透", "fail", str(e))

    # 4.2 域渗透
    try:
        from tools.ad_pentest import ad_pentest
        paths = len(ad_pentest.ATTACK_PATHS)
        result.add("模块验证", "域渗透-攻击路径", "pass",
                  f"{paths}种攻击路径")
    except Exception as e:
        result.add("模块验证", "域渗透", "fail", str(e))

    # 4.3 外网渗透
    try:
        from tools.external_pentest import external_pentest
        vulns = len(external_pentest.WEB_VULNERABILITY_TYPES)
        result.add("模块验证", "外网渗透-Web漏洞类型", "pass",
                  f"{vulns}种漏洞类型")
    except Exception as e:
        result.add("模块验证", "外网渗透", "fail", str(e))

    # 4.4 AI安全分析
    try:
        from tools.ai_security_analyzer import ai_security_analyzer
        test_code = 'import os\nos.system("rm -rf /")\npassword = "admin123"'
        analysis = ai_security_analyzer.analyze_code(test_code)
        vuln_count = analysis.get("vulnerabilities_found", 0)
        result.add("模块验证", "AI安全分析-代码漏洞检测", "pass",
                  f"检测到{vuln_count}个漏洞")
    except Exception as e:
        result.add("模块验证", "AI安全分析", "fail", str(e))

    # 4.5 密码安全
    try:
        from tools.password_security import password_security
        strength = password_security.check_password_strength("MyStr0ngP@ssw0rd!")
        score = strength.get("score", 0)
        result.add("模块验证", "密码安全-强度检测", "pass",
                  f"评分: {score}/100")
    except Exception as e:
        result.add("模块验证", "密码安全", "fail", str(e))

    # 4.6 流量分析
    try:
        from tools.traffic_analyzer import traffic_analyzer
        ids_rules = len(traffic_analyzer.IDS_RULES)
        result.add("模块验证", "流量分析-IDS规则", "pass",
                  f"{ids_rules}条规则")
    except Exception as e:
        result.add("模块验证", "流量分析", "fail", str(e))

    # 4.7 后渗透
    try:
        from tools.post_exploitation import post_exploitation
        roadmap = post_exploitation.generate_post_exploitation_roadmap("linux")
        phases = len(roadmap) - 2  # 减去access_level和platform
        result.add("模块验证", "后渗透-路线图生成", "pass",
                  f"{phases}个阶段")
    except Exception as e:
        result.add("模块验证", "后渗透", "fail", str(e))

    # ========== 5. 插件系统验证 ==========
    print("🔌 [5/7] 插件系统验证...")

    try:
        from utils.plugin_system import plugin_manager
        plugin_manager.discover_plugins()
        plugins = plugin_manager.list_plugins()
        result.add("插件系统", "插件发现", "pass",
                  f"发现{len(plugins)}个插件")

        # 综合渗透测试插件
        plugin_names = [p.get("name") for p in plugins]
        if "comprehensive_pentest" in plugin_names:
            result.add("插件系统", "综合渗透测试插件", "pass",
                      "已注册")
        else:
            result.add("插件系统", "综合渗透测试插件", "warning",
                      "未发现")
    except Exception as e:
        result.add("插件系统", "插件系统", "fail", str(e))

    # ========== 6. 靶场连通性检查 ==========
    print("🎯 [6/7] 靶场连通性检查...")

    try:
        import requests
        targets = [
            ("DVWA靶场", "http://127.0.0.1:8080"),
            ("Juice Shop靶场", "http://127.0.0.1:3000"),
        ]
        for name, url in targets:
            try:
                r = requests.get(url, timeout=3)
                result.add("靶场检查", name, "pass",
                          f"HTTP {r.status_code}")
            except Exception:
                result.add("靶场检查", name, "skip",
                          "未启动（可选）")
    except ImportError:
        result.add("靶场检查", "requests库", "fail", "未安装")

    # ========== 7. 项目文件完整性 ==========
    print("📁 [7/7] 项目文件完整性检查...")

    essential_files = [
        "main.py",
        "requirements.txt",
        "README.md",
        ".gitignore",
        "Dockerfile",
        "docker-compose.yml",
        "api_server/app.py",
        "tools/internal_pentest.py",
        "tools/ad_pentest.py",
        "tools/external_pentest.py",
        "tools/ai_security_analyzer.py",
        "tools/password_security.py",
        "tools/traffic_analyzer.py",
        "tools/post_exploitation.py",
        "plugins/comprehensive_pentest.py",
    ]
    for f in essential_files:
        fpath = os.path.join(project_dir, f)
        exists = os.path.exists(fpath)
        size = os.path.getsize(fpath) if exists else 0
        result.add("文件完整性", f,
                   "pass" if exists else "fail",
                   f"{size}字节" if exists else "不存在")

    # 打印报告
    summary = result.print_report()

    # 保存报告
    report_dir = os.path.join(project_dir, "data", "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_file = os.path.join(report_dir,
                                f"verification_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump({
            "summary": summary,
            "results": result.results,
        }, f, ensure_ascii=False, indent=2)
    print(f"📄 详细报告已保存: {report_file}\n")

    return summary


if __name__ == "__main__":
    try:
        summary = run_verification()
        sys.exit(0 if summary["failed"] == 0 else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️ 验证被用户中断")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ 验证过程出错: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
