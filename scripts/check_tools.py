"""
check_tools脚本工具模块，提供相关的命令行工具和自动化脚本。

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
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

# 添加项目根目录
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.cli_engine import cli_engine
from utils.logger import log


def check_tool(tool_name: str, version_cmd: list, version_pattern: str = r"(\S+)") -> dict:
    """检查单个工具"""
    result = {
        "name": tool_name,
        "available": False,
        "version": None,
        "path": None,
        "error": None,
    }

    # 检查是否在PATH中
    tool_path = shutil.which(tool_name)
    if not tool_path:
        result["error"] = "未安装或不在PATH中"
        return result

    result["path"] = tool_path
    result["available"] = True

    # 获取版本
    try:
        proc = subprocess.run(
            version_cmd,
            capture_output=True,
            text=True,
            timeout=15
        )
        output = proc.stdout + proc.stderr
        import re
        match = re.search(version_pattern, output)
        if match:
            result["version"] = match.group(1)
    except subprocess.TimeoutExpired:
        result["error"] = "版本检查超时"
    except Exception as e:
        result["error"] = f"版本检查失败: {e}"

    return result


def verify_tool_functionality(tool_name: str) -> dict:
    """验证工具基本功能"""
    verification = {
        "name": tool_name,
        "functional": False,
        "test": None,
        "result": None,
        "error": None,
    }

    try:
        if tool_name == "nmap":
            verification["test"] = "扫描localhost端口80"
            proc = subprocess.run(
                ["nmap", "-p", "80", "127.0.0.1", "--host-timeout", "10s"],
                capture_output=True, text=True, timeout=30
            )
            verification["result"] = "扫描完成" if proc.returncode == 0 else f"返回码: {proc.returncode}"
            verification["functional"] = proc.returncode == 0

        elif tool_name == "sqlmap":
            verification["test"] = "显示版本和帮助"
            proc = subprocess.run(
                ["sqlmap", "--version"],
                capture_output=True, text=True, timeout=15
            )
            verification["result"] = "版本显示正常" if proc.returncode == 0 else f"返回码: {proc.returncode}"
            verification["functional"] = proc.returncode == 0

        elif tool_name == "nuclei":
            verification["test"] = "显示版本"
            proc = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True, text=True, timeout=15
            )
            verification["result"] = "版本显示正常" if proc.returncode == 0 else f"返回码: {proc.returncode}"
            verification["functional"] = proc.returncode == 0

        elif tool_name == "python":
            verification["test"] = "Python版本和依赖检查"
            proc = subprocess.run(
                [sys.executable, "--version"],
                capture_output=True, text=True, timeout=10
            )
            verification["result"] = proc.stdout.strip() if proc.returncode == 0 else f"返回码: {proc.returncode}"
            verification["functional"] = proc.returncode == 0

        else:
            verification["test"] = "基本命令执行"
            tool_path = shutil.which(tool_name)
            if tool_path:
                verification["result"] = f"工具路径: {tool_path}"
                verification["functional"] = True
            else:
                verification["error"] = "工具未找到"

    except Exception as e:
        verification["error"] = str(e)

    return verification


def main():
    """主函数"""
    print("=" * 60)
    print("  AI Hacking Agent - 工具检测和验证")
    print("=" * 60)
    print()

    # 工具配置
    tools_to_check = [
        {"name": "python", "version_cmd": [sys.executable, "--version"], "version_pattern": r"Python (\S+)"},
        {"name": "nmap", "version_cmd": ["nmap", "--version"], "version_pattern": r"Nmap version (\S+)"},
        {"name": "sqlmap", "version_cmd": ["sqlmap", "--version"], "version_pattern": r"sqlmap/(\S+)"},
        {"name": "nuclei", "version_cmd": ["nuclei", "-version"], "version_pattern": r"(\d+\.\d+\.\d+)"},
        {"name": "gobuster", "version_cmd": ["gobuster", "version"], "version_pattern": r"v(\S+)"},
        {"name": "ffuf", "version_cmd": ["ffuf", "-V"], "version_pattern": r"(\S+)"},
        {"name": "httpx", "version_cmd": ["httpx", "-version"], "version_pattern": r"(\S+)"},
        {"name": "whatweb", "version_cmd": ["whatweb", "--version"], "version_pattern": r"WhatWeb (\S+)"},
        {"name": "nikto", "version_cmd": ["nikto", "-Version"], "version_pattern": r"(\S+)"},
        {"name": "masscan", "version_cmd": ["masscan", "--version"], "version_pattern": r"(\S+)"},
        {"name": "amass", "version_cmd": ["amass", "-version"], "version_pattern": r"(\S+)"},
        {"name": "subfinder", "version_cmd": ["subfinder", "-version"], "version_pattern": r"(\S+)"},
    ]

    # 检查工具
    print("📋 工具安装状态检查")
    print("-" * 60)
    results = []
    available_count = 0

    for tool in tools_to_check:
        result = check_tool(tool["name"], tool["version_cmd"], tool["version_pattern"])
        results.append(result)
        status = "✅" if result["available"] else "❌"
        version = f"v{result['version']}" if result["version"] else "未知版本"
        error = f" ({result['error']})" if result["error"] else ""
        print(f"  {status} {tool['name']:<12} {version}{error}")
        if result["available"]:
            available_count += 1

    print()
    print(f"📊 统计: {available_count}/{len(tools_to_check)} 个工具可用")
    print()

    # 功能验证
    print("🔧 工具功能验证")
    print("-" * 60)
    verification_results = []

    for result in results:
        if result["available"] and result["name"] in ["nmap", "sqlmap", "nuclei", "python"]:
            print(f"  验证 {result['name']}...", end=" ", flush=True)
            verification = verify_tool_functionality(result["name"])
            verification_results.append(verification)
            status = "✅" if verification["functional"] else "❌"
            print(f"{status} {verification['result'] or verification['error']}")

    print()

    # 生成报告
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_tools": len(tools_to_check),
            "available_tools": available_count,
            "unavailable_tools": len(tools_to_check) - available_count,
        },
        "tools": results,
        "verifications": verification_results,
        "recommendations": [],
    }

    # 生成建议
    if available_count < len(tools_to_check):
        missing = [r["name"] for r in results if not r["available"]]
        report["recommendations"].append({
            "priority": "high",
            "message": f"以下工具未安装: {', '.join(missing)}",
            "action": "运行 install_tools.bat 或手动安装缺失的工具",
        })

    if not any(r["name"] == "nmap" and r["available"] for r in results):
        report["recommendations"].append({
            "priority": "critical",
            "message": "nmap未安装，端口扫描功能将使用模拟模式",
            "action": "从 https://nmap.org/download.html 下载安装nmap",
        })

    if not any(r["name"] == "nuclei" and r["available"] for r in results):
        report["recommendations"].append({
            "priority": "high",
            "message": "nuclei未安装，漏洞模板扫描功能不可用",
            "action": "从 https://github.com/projectdiscovery/nuclei/releases 下载安装",
        })

    # 保存报告
    report_path = Path(__file__).parent.parent / "data" / "tool_status_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"📄 工具状态报告已保存: {report_path}")
    print()

    # 显示建议
    if report["recommendations"]:
        print("💡 改进建议")
        print("-" * 60)
        for rec in report["recommendations"]:
            priority = rec["priority"].upper()
            print(f"  [{priority}] {rec['message']}")
            print(f"         操作: {rec['action']}")
            print()

    print("=" * 60)
    print("  检测完成！")
    print("=" * 60)

    return report


if __name__ == "__main__":
    main()
