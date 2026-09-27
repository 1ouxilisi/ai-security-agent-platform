#!/usr/bin/env python3
"""AI Hacking Agent 项目完整性验证脚本。

用法: python check_project.py
功能: 全面检查项目文件、模块、依赖、配置、前端页面等是否完整可用
"""
import os
import sys
import json
import importlib
from datetime import datetime

# 切换到脚本所在目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))

class ProjectChecker:
    """项目完整性检查器"""
    
    def __init__(self):
        self.results = []
        self.passed = 0
        self.failed = 0
        self.warnings = 0
    
    def check(self, name, condition, detail="", warning=False):
        """执行一项检查"""
        status = "PASS" if condition else ("WARN" if warning else "FAIL")
        if condition:
            self.passed += 1
        elif warning:
            self.warnings += 1
        else:
            self.failed += 1
        
        self.results.append({
            "name": name,
            "status": status,
            "detail": detail
        })
        
        icon = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️"}[status]
        print(f"  {icon} {name}" + (f" - {detail}" if detail else ""))
    
    def section(self, title):
        """打印检查章节标题"""
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
    
    def run_all_checks(self):
        """运行所有检查"""
        print("=" * 60)
        print("  AI Hacking Agent v10.0 - 项目完整性验证")
        print(f"  检查时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # 1. Python环境
        self.section("1. Python环境检查")
        py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        self.check("Python版本 >= 3.10", 
                   sys.version_info.major >= 3 and sys.version_info.minor >= 10,
                   f"当前版本: {py_version}")
        self.check("pip可用", self._check_module("pip"), "pip包管理器")
        
        # 2. 核心文件
        self.section("2. 核心文件检查")
        core_files = [
            ("main.py", "程序入口"),
            ("requirements.txt", "依赖清单"),
            ("README.md", "项目说明文档"),
            (".env.example", "环境变量模板"),
            ("start.bat", "Windows启动脚本"),
            ("start.sh", "Linux/Mac启动脚本"),
            ("Dockerfile", "Docker构建文件"),
            ("docker-compose.yml", "Docker Compose配置"),
            ("setup_wizard.py", "一键安装向导"),
            ("INSTALL.md", "安装指南"),
            ("USAGE.md", "使用指南"),
            ("QUICKSTART.md", "快速入门"),
            ("CHANGELOG.md", "更新日志"),
            ("ARCHITECTURE.md", "架构说明"),
        ]
        for filename, desc in core_files:
            self.check(f"{filename} ({desc})", os.path.exists(filename),
                      "存在" if os.path.exists(filename) else "缺失")
        
        # 3. 配置文件
        self.section("3. 配置文件检查")
        self.check(".env 配置文件", os.path.exists(".env"),
                  "存在" if os.path.exists(".env") else "缺失（可从.env.example复制）", warning=True)
        
        if os.path.exists(".env"):
            try:
                with open(".env", encoding="utf-8") as f:
                    env_content = f.read()
                has_api_key = "LLM_API_KEY" in env_content and "your_api_key" not in env_content
                self.check("LLM_API_KEY 已配置", has_api_key,
                          "大模型API密钥已配置" if has_api_key else "未配置大模型API密钥", warning=True)
            except Exception as e:
                self.check(".env 可读", False, str(e))
        
        # 4. 核心目录
        self.section("4. 核心目录检查")
        core_dirs = [
            "agent", "scanner", "exploit", "workflow", "knowledge",
            "api_server", "mcp_server", "config", "utils", "database",
            "security", "plugins", "reporting", "scheduler", "tests",
            "tools", "data", "logs", "reports"
        ]
        for dirname in core_dirs:
            self.check(f"目录 {dirname}/", os.path.isdir(dirname),
                      "存在" if os.path.isdir(dirname) else "缺失")
        
        # 5. 增强模块目录
        self.section("5. 增强模块目录检查")
        enhanced_dirs = [
            "mobile_security", "internal_pentest", "cloud_security",
            "api_security", "client_security", "code_audit", "wireless_security",
            "ai_security", "iot_security", "ics_security", "blockchain_security",
            "forensics", "threat_intelligence", "social_engineering",
            "vulnerability_management", "distributed"
        ]
        for dirname in enhanced_dirs:
            self.check(f"模块 {dirname}/", os.path.isdir(dirname),
                      "存在" if os.path.isdir(dirname) else "缺失")
        
        # 6. 核心模块导入
        self.section("6. 核心模块导入检查")
        core_modules = [
            "config.settings", "utils.logger", "api_server.app",
            "agent.base_agent", "scanner.advanced_vuln_scanner", "exploit.poc_library",
            "workflow.engine", "knowledge.cve", "mcp_server.server",
            "plugins.manager", "reporting.report_exporter", "scheduler.task_scheduler",
        ]
        for mod in core_modules:
            try:
                importlib.import_module(mod)
                self.check(f"模块 {mod}", True, "导入成功")
            except Exception as e:
                self.check(f"模块 {mod}", False, str(e)[:80])
        
        # 7. 增强模块导入
        self.section("7. 增强模块导入检查")
        enhanced_modules = [
            "tools.integration", "internal_pentest.enhanced",
            "cloud_security.enhanced", "utils.performance",
            "utils.multi_user", "distributed.core",
            "api_server.enhanced_routes",
        ]
        for mod in enhanced_modules:
            try:
                importlib.import_module(mod)
                self.check(f"模块 {mod}", True, "导入成功")
            except Exception as e:
                self.check(f"模块 {mod}", False, str(e)[:80])
        
        # 8. 前端页面
        self.section("8. 前端页面检查")
        html_pages = [
            ("api_server/index.html", "首页"),
            ("api_server/console_v7.html", "主控制台"),
            ("api_server/enhanced_console.html", "增强控制台"),
            ("api_server/extended_console.html", "扩展控制台"),
            ("api_server/advanced_console.html", "高级控制台"),
            ("api_server/dashboard.html", "仪表盘"),
            ("api_server/vuln_database.html", "漏洞库"),
            ("api_server/api_docs.html", "API文档"),
        ]
        for filepath, desc in html_pages:
            exists = os.path.exists(filepath)
            size = os.path.getsize(filepath) if exists else 0
            self.check(f"{desc} ({filepath})", exists and size > 1000,
                      f"{size} bytes" if exists else "缺失")
        
        # 9. API路由文件
        self.section("9. API路由文件检查")
        route_files = [
            "api_server/app.py", "api_server/enhanced_routes.py",
            "api_server/extended_routes.py", "api_server/advanced_routes.py",
            "api_server/auth_routes.py", "api_server/internal_routes.py",
            "api_server/exploit_routes.py", "api_server/tools_routes.py",
            "api_server/distributed_routes.py", "api_server/combat_routes.py",
        ]
        for filepath in route_files:
            self.check(f"路由 {filepath}", os.path.exists(filepath),
                      "存在" if os.path.exists(filepath) else "缺失")
        
        # 10. 测试文件
        self.section("10. 测试文件检查")
        test_files = [
            "tests/test_suite.py", "tests/test_unit.py",
            "tests/test_functionality.py", "tests/test_new_security_modules.py",
        ]
        for filepath in test_files:
            self.check(f"测试 {filepath}", os.path.exists(filepath),
                      "存在" if os.path.exists(filepath) else "缺失")
        
        # 11. 代码质量配置
        self.section("11. 代码质量与CI/CD检查")
        ci_files = [
            (".flake8", "flake8配置"),
            ("pyproject.toml", "项目配置"),
            (".github/workflows/ci-cd.yml", "CI/CD流水线"),
        ]
        for filepath, desc in ci_files:
            self.check(f"{desc} ({filepath})", os.path.exists(filepath),
                      "存在" if os.path.exists(filepath) else "缺失")
        
        # 12. 安全工具可用性（可选）
        self.section("12. 安全工具可用性检查（可选）")
        security_tools = ["nmap", "sqlmap", "nuclei", "masscan", "nikto"]
        for tool in security_tools:
            available = self._check_command(tool)
            self.check(f"工具 {tool}", available,
                      "已安装" if available else "未安装（可选，用于真实工具集成）", warning=True)
        
        # 打印总结
        self.print_summary()
    
    def _check_module(self, module_name):
        """检查模块是否可导入"""
        try:
            importlib.import_module(module_name)
            return True
        except Exception:
            return False
    
    def _check_command(self, command):
        """检查命令是否可用"""
        try:
            from shutil import which
            return which(command) is not None
        except Exception:
            return False
    
    def print_summary(self):
        """打印检查总结"""
        print(f"\n{'='*60}")
        print(f"  检查总结")
        print(f"{'='*60}")
        print(f"  ✅ 通过: {self.passed}")
        print(f"  ⚠️  警告: {self.warnings}")
        print(f"  ❌ 失败: {self.failed}")
        print(f"  📊 总计: {self.passed + self.warnings + self.failed}")
        print(f"{'='*60}")
        
        if self.failed == 0:
            print(f"\n  🎉 项目完整性验证通过！所有核心组件完整可用。")
            if self.warnings > 0:
                print(f"  ⚠️  有 {self.warnings} 个警告项（可选功能），不影响核心功能。")
            print(f"\n  启动方式:")
            print(f"    Windows: 双击 start.bat")
            print(f"    Linux/Mac: ./start.sh")
            print(f"    Python: python main.py api-server --host 127.0.0.1 --port 8000")
            print(f"\n  访问地址:")
            print(f"    增强控制台: http://127.0.0.1:8000/enhanced-console")
            print(f"    主控制台:   http://127.0.0.1:8000/console-v7")
            print(f"    API文档:    http://127.0.0.1:8000/docs")
        else:
            print(f"\n  ❌ 项目存在 {self.failed} 个问题，请检查上述失败项。")
            failed_items = [r for r in self.results if r["status"] == "FAIL"]
            for item in failed_items[:10]:
                print(f"    - {item['name']}: {item['detail']}")
        
        print(f"\n{'='*60}\n")
        
        # 保存检查报告
        report = {
            "check_time": datetime.now().isoformat(),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "summary": {
                "passed": self.passed,
                "warnings": self.warnings,
                "failed": self.failed,
                "total": self.passed + self.warnings + self.failed
            },
            "results": self.results
        }
        try:
            with open("project_check_report.json", "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"  📄 详细报告已保存: project_check_report.json")
        except Exception:
            pass
        
        return self.failed == 0


if __name__ == "__main__":
    checker = ProjectChecker()
    success = checker.run_all_checks()
    sys.exit(0 if success else 1)
