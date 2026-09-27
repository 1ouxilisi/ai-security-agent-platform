#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_tools模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import json
import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    """工具状态"""
    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    ERROR = "error"


@dataclass
class ScanResult:
    """扫描结果"""
    tool: str
    target: str
    command: str
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    status: str = "success"
    raw_output: str = ""
    parsed_results: List[Dict] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class SecurityTools:
    """安全扫描工具集成"""

    def __init__(self, tools_path: str = "", output_dir: str = "./scan_output"):
        """初始化SecurityTools实例。

        Args:
            self: 类实例。
        """
        self.tools_path = tools_path
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._tool_cache: Dict[str, bool] = {}
        logger.info("安全扫描工具集成初始化完成")

    def _run_command(self, command: List[str], timeout: int = 300) -> Tuple[int, str, str]:
        """执行命令"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.output_dir,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "命令执行超时"
        except FileNotFoundError:
            return -1, "", "命令未找到"
        except Exception as e:
            return -1, "", str(e)

    def check_tool(self, tool_name: str) -> Dict:
        """检查工具是否安装"""
        if tool_name in self._tool_cache:
            return {"name": tool_name, "installed": self._tool_cache[tool_name]}

        commands = {
            "nmap": ["nmap", "--version"],
            "nuclei": ["nuclei", "-version"],
            "sqlmap": ["sqlmap", "--version"],
            "dirsearch": ["dirsearch", "--version"],
            "nikto": ["nikto", "-Version"],
            "masscan": ["masscan", "--version"],
            "whatweb": ["whatweb", "--version"],
            "wpscan": ["wpscan", "--version"],
            "gobuster": ["gobuster", "version"],
            "ffuf": ["ffuf", "-V"],
            "hydra": ["hydra", "-h"],
            "john": ["john", "--list=rules"],
            "hashcat": ["hashcat", "--version"],
            "metasploit": ["msfconsole", "--version"],
            "searchsploit": ["searchsploit", "--version"],
        }

        if tool_name not in commands:
            return {"name": tool_name, "installed": False, "error": "未知工具"}

        returncode, stdout, stderr = self._run_command(commands[tool_name], timeout=10)
        installed = returncode == 0
        self._tool_cache[tool_name] = installed

        result = {"name": tool_name, "installed": installed}
        if installed:
            version_match = re.search(r'(\d+\.\d+[\.\d]*)', stdout + stderr)
            if version_match:
                result["version"] = version_match.group(1)
        else:
            result["error"] = stderr or stdout

        return result

    def check_all_tools(self) -> List[Dict]:
        """检查所有工具"""
        tools = ["nmap", "nuclei", "sqlmap", "dirsearch", "nikto", "masscan",
                 "whatweb", "wpscan", "gobuster", "ffuf", "hydra", "john",
                 "hashcat", "metasploit", "searchsploit"]
        results = []
        for tool in tools:
            results.append(self.check_tool(tool))
        return results

    def nmap_scan(self, target: str, ports: str = "", scan_type: str = "default",
                   arguments: str = "", timeout: int = 300) -> ScanResult:
        """Nmap端口扫描"""
        result = ScanResult(tool="nmap", target=target)
        result.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 构建命令
        command = ["nmap"]

        # 扫描类型
        scan_types = {
            "default": ["-sV", "-sC"],
            "syn": ["-sS"],
            "udp": ["-sU"],
            "full": ["-sV", "-sC", "-A"],
            "intense": ["-T4", "-A", "-v"],
            "ping": ["-sn"],
        }
        command.extend(scan_types.get(scan_type, scan_types["default"]))

        # 端口
        if ports:
            command.extend(["-p", ports])

        # 输出格式
        output_file = os.path.join(self.output_dir, f"nmap_{target.replace('/', '_').replace(':', '_')}_{int(datetime.now().timestamp())}")
        command.extend(["-oX", f"{output_file}.xml"])

        # 额外参数
        if arguments:
            command.extend(arguments.split())

        command.append(target)
        result.command = " ".join(command)

        logger.info(f"执行Nmap扫描: {result.command}")

        # 执行
        returncode, stdout, stderr = self._run_command(command, timeout=timeout)
        result.raw_output = stdout + stderr
        result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 解析结果
        if returncode == 0 and os.path.exists(f"{output_file}.xml"):
            result.status = "success"
            result.parsed_results = self._parse_nmap_xml(f"{output_file}.xml")
        else:
            result.status = "failed"
            result.errors.append(stderr or "扫描失败")

        result.summary = {
            "open_ports": len([p for p in result.parsed_results if p.get("state") == "open"]),
            "filtered_ports": len([p for p in result.parsed_results if p.get("state") == "filtered"]),
            "total_ports": len(result.parsed_results),
            "hosts_up": 1,
        }

        return result

    def _parse_nmap_xml(self, xml_file: str) -> List[Dict]:
        """解析Nmap XML输出"""
        results = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host in root.findall(".//host"):
                address = host.find(".//address")
                ip = address.get("addr") if address is not None else "unknown"

                for port in host.findall(".//port"):
                    port_id = port.get("portid")
                    protocol = port.get("protocol")
                    state = port.find(".//state")
                    state_name = state.get("state") if state is not None else "unknown"

                    service = port.find(".//service")
                    service_name = service.get("name") if service is not None else "unknown"
                    service_version = service.get("version") if service is not None else ""
                    service_product = service.get("product") if service is not None else ""

                    results.append({
                        "ip": ip,
                        "port": int(port_id),
                        "protocol": protocol,
                        "state": state_name,
                        "service": service_name,
                        "version": service_version,
                        "product": service_product,
                    })
        except Exception as e:
            logger.error(f"解析Nmap XML失败: {e}")

        return results

    def nuclei_scan(self, target: str, templates: str = "", severity: str = "",
                    tags: str = "", timeout: int = 300) -> ScanResult:
        """Nuclei漏洞扫描"""
        result = ScanResult(tool="nuclei", target=target)
        result.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        command = ["nuclei", "-u", target, "-json"]

        if templates:
            command.extend(["-t", templates])
        if severity:
            command.extend(["-severity", severity])
        if tags:
            command.extend(["-tags", tags])

        output_file = os.path.join(self.output_dir, f"nuclei_{target.replace('/', '_').replace(':', '_')}_{int(datetime.now().timestamp())}.json")
        command.extend(["-o", output_file])

        result.command = " ".join(command)
        logger.info(f"执行Nuclei扫描: {result.command}")

        returncode, stdout, stderr = self._run_command(command, timeout=timeout)
        result.raw_output = stdout + stderr
        result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 解析JSON结果
        if os.path.exists(output_file):
            result.status = "success"
            with open(output_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            result.parsed_results.append({
                                "template": data.get("template-id", ""),
                                "name": data.get("info", {}).get("name", ""),
                                "severity": data.get("info", {}).get("severity", ""),
                                "description": data.get("info", {}).get("description", ""),
                                "matched_at": data.get("matched-at", ""),
                                "type": data.get("type", ""),
                                "tags": data.get("info", {}).get("tags", []),
                                "reference": data.get("info", {}).get("reference", []),
                            })
                        except:
                            pass
        else:
            result.status = "failed"
            result.errors.append(stderr or "扫描失败")

        result.summary = {
            "total_vulnerabilities": len(result.parsed_results),
            "critical": len([v for v in result.parsed_results if v.get("severity") == "critical"]),
            "high": len([v for v in result.parsed_results if v.get("severity") == "high"]),
            "medium": len([v for v in result.parsed_results if v.get("severity") == "medium"]),
            "low": len([v for v in result.parsed_results if v.get("severity") == "low"]),
        }

        return result

    def sqlmap_scan(self, url: str, data: str = "", cookie: str = "",
                     level: int = 1, risk: int = 1, timeout: int = 600) -> ScanResult:
        """SQLMap注入扫描"""
        result = ScanResult(tool="sqlmap", target=url)
        result.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        command = ["sqlmap", "-u", url, "--batch", "--json"]

        if data:
            command.extend(["--data", data])
        if cookie:
            command.extend(["--cookie", cookie])

        command.extend(["--level", str(level), "--risk", str(risk)])

        output_dir = os.path.join(self.output_dir, f"sqlmap_{int(datetime.now().timestamp())}")
        command.extend(["--output-dir", output_dir])

        result.command = " ".join(command)
        logger.info(f"执行SQLMap扫描: {result.command}")

        returncode, stdout, stderr = self._run_command(command, timeout=timeout)
        result.raw_output = stdout + stderr
        result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 解析结果
        if returncode == 0:
            result.status = "success"
            # 解析SQLMap输出
            if "sql injection" in stdout.lower() or "vulnerable" in stdout.lower():
                result.parsed_results.append({
                    "type": "sql_injection",
                    "url": url,
                    "vulnerable": True,
                    "details": "检测到SQL注入漏洞",
                })
        else:
            result.status = "failed"
            result.errors.append(stderr or "扫描失败")

        result.summary = {
            "vulnerable": len(result.parsed_results) > 0,
            "injection_points": len(result.parsed_results),
        }

        return result

    def dirsearch_scan(self, url: str, wordlist: str = "", extensions: str = "php,asp,aspx,jsp,html",
                       threads: int = 20, timeout: int = 300) -> ScanResult:
        """Dirsearch目录扫描"""
        result = ScanResult(tool="dirsearch", target=url)
        result.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        command = ["dirsearch", "-u", url, "-e", extensions, "-t", str(threads), "--format=json"]

        if wordlist:
            command.extend(["-w", wordlist])

        output_file = os.path.join(self.output_dir, f"dirsearch_{int(datetime.now().timestamp())}.json")
        command.extend(["-o", output_file])

        result.command = " ".join(command)
        logger.info(f"执行Dirsearch扫描: {result.command}")

        returncode, stdout, stderr = self._run_command(command, timeout=timeout)
        result.raw_output = stdout + stderr
        result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if os.path.exists(output_file):
            result.status = "success"
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        for path, info in data.get("results", {}).items():
                            result.parsed_results.append({
                                "path": path,
                                "status": info.get("status", 0),
                                "size": info.get("size", 0),
                                "redirect": info.get("redirect", ""),
                            })
            except Exception as e:
                result.errors.append(f"解析结果失败: {e}")
        else:
            result.status = "failed"
            result.errors.append(stderr or "扫描失败")

        result.summary = {
            "total_paths": len(result.parsed_results),
            "status_200": len([p for p in result.parsed_results if p.get("status") == 200]),
            "status_301": len([p for p in result.parsed_results if p.get("status") == 301]),
            "status_403": len([p for p in result.parsed_results if p.get("status") == 403]),
        }

        return result

    def nikto_scan(self, target: str, timeout: int = 300) -> ScanResult:
        """Nikto Web漏洞扫描"""
        result = ScanResult(tool="nikto", target=target)
        result.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        output_file = os.path.join(self.output_dir, f"nikto_{int(datetime.now().timestamp())}.xml")
        command = ["nikto", "-h", target, "-Format", "xml", "-output", output_file]

        result.command = " ".join(command)
        logger.info(f"执行Nikto扫描: {result.command}")

        returncode, stdout, stderr = self._run_command(command, timeout=timeout)
        result.raw_output = stdout + stderr
        result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if os.path.exists(output_file):
            result.status = "success"
            try:
                tree = ET.parse(output_file)
                root = tree.getroot()
                for item in root.findall(".//item"):
                    result.parsed_results.append({
                        "id": item.get("id", ""),
                        "description": item.findtext("description", ""),
                        "uri": item.findtext("uri", ""),
                        "method": item.findtext("method", ""),
                        "osvdb": item.findtext("osvdb", ""),
                    })
            except Exception as e:
                result.errors.append(f"解析结果失败: {e}")
        else:
            result.status = "failed"
            result.errors.append(stderr or "扫描失败")

        result.summary = {
            "total_vulnerabilities": len(result.parsed_results),
        }

        return result

    def full_scan(self, target: str, tools: List[str] = None, timeout: int = 600) -> Dict:
        """完整扫描（多工具组合）"""
        if tools is None:
            tools = ["nmap", "nuclei", "dirsearch"]

        results = {}
        all_vulnerabilities = []

        for tool in tools:
            try:
                if tool == "nmap":
                    result = self.nmap_scan(target, timeout=timeout)
                elif tool == "nuclei":
                    result = self.nuclei_scan(target, timeout=timeout)
                elif tool == "sqlmap":
                    result = self.sqlmap_scan(target, timeout=timeout)
                elif tool == "dirsearch":
                    result = self.dirsearch_scan(target, timeout=timeout)
                elif tool == "nikto":
                    result = self.nikto_scan(target, timeout=timeout)
                else:
                    continue

                results[tool] = {
                    "status": result.status,
                    "duration": result.duration,
                    "findings": len(result.parsed_results),
                    "summary": result.summary,
                }
                all_vulnerabilities.extend(result.parsed_results)

            except Exception as e:
                results[tool] = {"status": "error", "error": str(e)}

        return {
            "target": target,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tools_used": tools,
            "results": results,
            "total_vulnerabilities": len(all_vulnerabilities),
            "all_vulnerabilities": all_vulnerabilities,
        }

    def get_tool_help(self, tool_name: str) -> str:
        """获取工具帮助信息"""
        commands = {
            "nmap": ["nmap", "-h"],
            "nuclei": ["nuclei", "-h"],
            "sqlmap": ["sqlmap", "--help"],
            "dirsearch": ["dirsearch", "-h"],
            "nikto": ["nikto", "-H"],
        }
        if tool_name not in commands:
            return f"未知工具: {tool_name}"

        returncode, stdout, stderr = self._run_command(commands[tool_name], timeout=10)
        return stdout + stderr


def main():
    """演示用法"""
    print("=" * 60)
    print("  安全扫描工具集成")
    print("=" * 60)
    print()

    tools = SecurityTools()

    # 检查工具
    print("[1/3] 检查已安装的工具...")
    tool_status = tools.check_all_tools()
    installed = [t["name"] for t in tool_status if t["installed"]]
    not_installed = [t["name"] for t in tool_status if not t["installed"]]
    print(f"  已安装 ({len(installed)}): {', '.join(installed)}")
    print(f"  未安装 ({len(not_installed)}): {', '.join(not_installed)}")
    print()

    # 工具列表
    print("[2/3] 支持的扫描工具:")
    tool_list = [
        ("nmap", "端口扫描和服务识别", "nmap -sV -sC target"),
        ("nuclei", "基于模板的漏洞扫描", "nuclei -u target -t cves/"),
        ("sqlmap", "SQL注入检测和利用", "sqlmap -u 'http://target/page?id=1'"),
        ("dirsearch", "Web目录扫描", "dirsearch -u http://target -e php"),
        ("nikto", "Web服务器漏洞扫描", "nikto -h http://target"),
        ("masscan", "高速端口扫描", "masscan -p1-65535 target --rate=10000"),
        ("whatweb", "Web技术识别", "whatweb http://target"),
        ("wpscan", "WordPress漏洞扫描", "wpscan --url http://target"),
        ("gobuster", "目录/DNS爆破", "gobuster dir -u http://target -w wordlist.txt"),
        ("ffuf", "高速Web模糊测试", "ffuf -u http://target/FUZZ -w wordlist.txt"),
        ("hydra", "密码暴力破解", "hydra -l admin -P passwords.txt target ssh"),
        ("john", "密码哈希破解", "john --wordlist=passwords.txt hash.txt"),
        ("hashcat", "GPU密码破解", "hashcat -m 0 -a 0 hash.txt wordlist.txt"),
        ("metasploit", "漏洞利用框架", "msfconsole -q -x 'use exploit/...'"),
        ("searchsploit", "漏洞搜索", "searchsploit apache 2.4"),
    ]
    for name, desc, example in tool_list:
        status = "✅" if name in installed else "❌"
        print(f"  {status} {name:15s} - {desc}")
        print(f"           示例: {example}")
    print()

    # 扫描示例
    print("[3/3] 扫描示例:")
    print("  # Nmap端口扫描")
    print("  result = tools.nmap_scan('192.168.1.1', ports='1-1000', scan_type='full')")
    print()
    print("  # Nuclei漏洞扫描")
    print("  result = tools.nuclei_scan('http://example.com', severity='critical,high')")
    print()
    print("  # SQLMap注入扫描")
    print("  result = tools.sqlmap_scan('http://example.com/page?id=1', level=3)")
    print()
    print("  # Dirsearch目录扫描")
    print("  result = tools.dirsearch_scan('http://example.com', extensions='php,html')")
    print()
    print("  # 完整扫描（多工具组合）")
    print("  result = tools.full_scan('http://example.com', tools=['nmap','nuclei','dirsearch'])")
    print()

    print("=" * 60)
    print("  完成！")
    print("=" * 60)


if __name__ == "__main__":
    main()
