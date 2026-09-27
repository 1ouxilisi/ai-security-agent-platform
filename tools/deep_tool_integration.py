#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deep_tool_integration安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from loguru import logger


@dataclass
class ToolInfo:
    """工具信息"""
    name: str
    version: str = ""
    path: str = ""
    installed: bool = False
    description: str = ""
    category: str = ""  # scanner/exploit/cracking/forensics/recon
    supported_platforms: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)


@dataclass
class ToolResult:
    """工具执行结果"""
    tool_name: str
    command: str
    target: str
    success: bool = False
    output: str = ""
    parsed_results: List[Dict] = field(default_factory=list)
    execution_time: float = 0.0
    error: str = ""
    timestamp: str = ""


class DeepToolIntegration:
    """真实工具深度集成框架"""

    def __init__(self, config: Optional[Dict] = None):
        """初始化DeepToolIntegration实例。

        Args:
            self: 类实例。
        """
        self.config = config or {}
        self.timeout = self.config.get("timeout", 300)
        self.workspace = self.config.get("workspace", "./tool_workspace")
        self.tools = self._init_tools()
        self._ensure_workspace()
        logger.info("真实工具深度集成模块初始化完成")

    def _ensure_workspace(self):
        """确保工作目录存在"""
        os.makedirs(self.workspace, exist_ok=True)
        os.makedirs(f"{self.workspace}/nmap", exist_ok=True)
        os.makedirs(f"{self.workspace}/nuclei", exist_ok=True)
        os.makedirs(f"{self.workspace}/sqlmap", exist_ok=True)
        os.makedirs(f"{self.workspace}/metasploit", exist_ok=True)
        os.makedirs(f"{self.workspace}/hashcat", exist_ok=True)

    def _init_tools(self) -> Dict[str, ToolInfo]:
        """初始化工具库"""
        tools = {}

        # Nmap
        tools["nmap"] = ToolInfo(
            name="nmap",
            description="网络扫描和安全审计工具",
            category="scanner",
            supported_platforms=["windows", "linux", "macos"],
            capabilities=["端口扫描", "服务识别", "操作系统检测", "漏洞扫描", "脚本扫描"]
        )

        # Nuclei
        tools["nuclei"] = ToolInfo(
            name="nuclei",
            description="基于模板的漏洞扫描器",
            category="scanner",
            supported_platforms=["windows", "linux", "macos"],
            capabilities=["漏洞扫描", "POC验证", "模板扫描", "批量扫描"]
        )

        # SQLMap
        tools["sqlmap"] = ToolInfo(
            name="sqlmap",
            description="自动化SQL注入工具",
            category="exploit",
            supported_platforms=["windows", "linux", "macos"],
            capabilities=["SQL注入检测", "数据库枚举", "数据提取", "Shell获取", "提权"]
        )

        # Metasploit
        tools["metasploit"] = ToolInfo(
            name="metasploit",
            description="渗透测试框架",
            category="exploit",
            supported_platforms=["windows", "linux", "macos"],
            capabilities=["漏洞利用", "Payload生成", "后渗透", "凭证窃取", "横向移动"]
        )

        # Hashcat
        tools["hashcat"] = ToolInfo(
            name="hashcat",
            description="高级密码恢复工具",
            category="cracking",
            supported_platforms=["windows", "linux", "macos"],
            capabilities=["密码破解", "字典攻击", "掩码攻击", "规则攻击", "分布式破解"]
        )

        # Burp Suite
        tools["burp"] = ToolInfo(
            name="burp",
            description="Web应用安全测试平台",
            category="scanner",
            supported_platforms=["windows", "linux", "macos"],
            capabilities=["Web漏洞扫描", "代理拦截", "重放攻击", "Intruder爆破", "爬虫"]
        )

        # Masscan
        tools["masscan"] = ToolInfo(
            name="masscan",
            description="高速端口扫描器",
            category="scanner",
            supported_platforms=["linux", "macos"],
            capabilities=["高速端口扫描", "大范围扫描", "Banner抓取"]
        )

        # Dirb/Dirbuster
        tools["dirb"] = ToolInfo(
            name="dirb",
            description="目录爆破工具",
            category="recon",
            supported_platforms=["linux", "macos"],
            capabilities=["目录扫描", "文件枚举", "敏感路径发现"]
        )

        # Hydra
        tools["hydra"] = ToolInfo(
            name="hydra",
            description="网络登录破解工具",
            category="cracking",
            supported_platforms=["windows", "linux", "macos"],
            capabilities=["SSH破解", "FTP破解", "HTTP破解", "SMB破解", "RDP破解"]
        )

        # John the Ripper
        tools["john"] = ToolInfo(
            name="john",
            description="密码破解工具",
            category="cracking",
            supported_platforms=["windows", "linux", "macos"],
            capabilities=["密码破解", "哈希破解", "字典攻击", "规则攻击"]
        )

        # Volatility
        tools["volatility"] = ToolInfo(
            name="volatility",
            description="内存取证框架",
            category="forensics",
            supported_platforms=["windows", "linux", "macos"],
            capabilities=["内存分析", "进程分析", "网络连接分析", "凭证提取", "恶意软件检测"]
        )

        # Wireshark/Tshark
        tools["tshark"] = ToolInfo(
            name="tshark",
            description="网络协议分析器",
            category="forensics",
            supported_platforms=["windows", "linux", "macos"],
            capabilities=["流量分析", "协议解析", "数据包提取", "统计分析"]
        )

        return tools

    def check_tool_installed(self, tool_name: str) -> Tuple[bool, str]:
        """检查工具是否安装"""
        tool = self.tools.get(tool_name)
        if not tool:
            return False, f"未知工具: {tool_name}"

        try:
            # 特殊处理
            if tool_name == "metasploit":
                path = shutil.which("msfconsole") or shutil.which("msfvenom")
            elif tool_name == "burp":
                path = shutil.which("burpsuite") or shutil.which("burp")
            elif tool_name == "volatility":
                path = shutil.which("volatility") or shutil.which("vol")
            else:
                path = shutil.which(tool_name)

            if path:
                tool.path = path
                tool.installed = True
                # 获取版本
                version = self._get_tool_version(tool_name, path)
                tool.version = version
                return True, f"{tool_name} {version} 已安装: {path}"
            else:
                tool.installed = False
                return False, f"{tool_name} 未安装"
        except Exception as e:
            return False, f"检查失败: {e}"

    def _get_tool_version(self, tool_name: str, path: str) -> str:
        """获取工具版本"""
        version_flags = {
            "nmap": "--version",
            "nuclei": "-version",
            "sqlmap": "--version",
            "hashcat": "--version",
            "hydra": "-h",
            "john": "--list=format",
            "masscan": "--version",
            "tshark": "--version",
        }

        flag = version_flags.get(tool_name, "--version")
        try:
            result = subprocess.run(
                [path, flag],
                capture_output=True,
                text=True,
                timeout=10
            )
            output = result.stdout + result.stderr
            # 提取版本号
            version_match = re.search(r'(\d+\.\d+[\.\d]*)', output)
            if version_match:
                return version_match.group(1)
            return "unknown"
        except Exception:
            return "unknown"

    def list_all_tools(self) -> List[Dict]:
        """列出所有工具"""
        result = []
        for name, tool in self.tools.items():
            installed, _ = self.check_tool_installed(name)
            result.append({
                "name": tool.name,
                "description": tool.description,
                "category": tool.category,
                "installed": installed,
                "version": tool.version,
                "path": tool.path,
                "capabilities": tool.capabilities,
                "supported_platforms": tool.supported_platforms,
            })
        return result

    def list_installed_tools(self) -> List[Dict]:
        """列出已安装的工具"""
        return [t for t in self.list_all_tools() if t["installed"]]

    async def run_nmap_scan(
        self,
        target: str,
        scan_type: str = "default",
        ports: str = "",
        scripts: str = "",
        timing: int = 3,
        output_format: str = "json",
    ) -> ToolResult:
        """运行Nmap扫描"""
        start_time = time.time()
        result = ToolResult(
            tool_name="nmap",
            target=target,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        # 检查Nmap是否安装
        installed, msg = self.check_tool_installed("nmap")
        if not installed:
            result.success = False
            result.error = "Nmap未安装"
            return result

        # 构建命令
        cmd = [self.tools["nmap"].path]

        # 扫描类型
        scan_types = {
            "default": ["-sV", "-sC"],
            "syn": ["-sS"],
            "udp": ["-sU"],
            "service": ["-sV"],
            "os": ["-O"],
            "aggressive": ["-A"],
            "vuln": ["--script", "vuln"],
            "full": ["-sV", "-sC", "-O", "--script", "default,vuln,safe"],
        }

        if scan_type in scan_types:
            cmd.extend(scan_types[scan_type])

        # 端口
        if ports:
            cmd.extend(["-p", ports])

        # 脚本
        if scripts:
            cmd.extend(["--script", scripts])

        # 时序
        cmd.extend(["-T", str(timing)])

        # 输出
        output_file = f"{self.workspace}/nmap/{target.replace('/', '_')}_{int(time.time())}"
        if output_format == "json":
            cmd.extend(["-oJ", f"{output_file}.json"])
        elif output_format == "xml":
            cmd.extend(["-oX", f"{output_file}.xml"])
        elif output_format == "grepable":
            cmd.extend(["-oG", f"{output_file}.gnmap"])

        cmd.append(target)
        result.command = " ".join(cmd)

        try:
            logger.info(f"运行Nmap扫描: {result.command}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)

            result.output = stdout.decode("utf-8", errors="ignore")
            if process.returncode == 0:
                result.success = True
                # 解析结果
                result.parsed_results = self._parse_nmap_output(result.output)
            else:
                result.error = stderr.decode("utf-8", errors="ignore")

        except asyncio.TimeoutError:
            result.error = "扫描超时"
        except Exception as e:
            result.error = str(e)

        result.execution_time = time.time() - start_time
        return result

    def _parse_nmap_output(self, output: str) -> List[Dict]:
        """解析Nmap输出"""
        results = []
        try:
            # 解析端口
            port_pattern = r'(\d+)/(\w+)\s+(\w+)\s+(\S+)(?:\s+(.*))?'
            for match in re.finditer(port_pattern, output):
                port, protocol, state, service, version = match.groups()
                results.append({
                    "port": int(port),
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "version": version or "",
                })
        except Exception:
            pass
        return results

    async def run_nuclei_scan(
        self,
        target: str,
        templates: str = "",
        severity: str = "",
        tags: str = "",
        rate_limit: int = 150,
    ) -> ToolResult:
        """运行Nuclei扫描"""
        start_time = time.time()
        result = ToolResult(
            tool_name="nuclei",
            target=target,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        installed, msg = self.check_tool_installed("nuclei")
        if not installed:
            result.success = False
            result.error = "Nuclei未安装"
            return result

        cmd = [self.tools["nuclei"].path, "-u", target]

        if templates:
            cmd.extend(["-t", templates])
        if severity:
            cmd.extend(["-severity", severity])
        if tags:
            cmd.extend(["-tags", tags])

        cmd.extend(["-rate-limit", str(rate_limit)])
        cmd.extend(["-json", "-o", f"{self.workspace}/nuclei/{target.replace('/', '_')}_{int(time.time())}.json"])

        result.command = " ".join(cmd)

        try:
            logger.info(f"运行Nuclei扫描: {result.command}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)

            result.output = stdout.decode("utf-8", errors="ignore")
            if process.returncode == 0:
                result.success = True
                result.parsed_results = self._parse_nuclei_output(result.output)
            else:
                result.error = stderr.decode("utf-8", errors="ignore")

        except Exception as e:
            result.error = str(e)

        result.execution_time = time.time() - start_time
        return result

    def _parse_nuclei_output(self, output: str) -> List[Dict]:
        """解析Nuclei输出"""
        results = []
        for line in output.strip().split("\n"):
            try:
                if line.strip():
                    data = json.loads(line)
                    results.append({
                        "template": data.get("template-id", ""),
                        "name": data.get("info", {}).get("name", ""),
                        "severity": data.get("info", {}).get("severity", ""),
                        "url": data.get("matched-at", ""),
                        "description": data.get("info", {}).get("description", ""),
                    })
            except Exception:
                pass
        return results

    async def run_sqlmap(
        self,
        url: str,
        data: str = "",
        cookie: str = "",
        level: int = 1,
        risk: int = 1,
        batch: bool = True,
        dbs: bool = False,
        tables: bool = False,
        dump: bool = False,
        os_shell: bool = False,
    ) -> ToolResult:
        """运行SQLMap"""
        start_time = time.time()
        result = ToolResult(
            tool_name="sqlmap",
            target=url,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        installed, msg = self.check_tool_installed("sqlmap")
        if not installed:
            result.success = False
            result.error = "SQLMap未安装"
            return result

        cmd = [self.tools["sqlmap"].path, "-u", url]

        if data:
            cmd.extend(["--data", data])
        if cookie:
            cmd.extend(["--cookie", cookie])

        cmd.extend(["--level", str(level), "--risk", str(risk)])

        if batch:
            cmd.append("--batch")
        if dbs:
            cmd.append("--dbs")
        if tables:
            cmd.append("--tables")
        if dump:
            cmd.append("--dump")
        if os_shell:
            cmd.append("--os-shell")

        result.command = " ".join(cmd)

        try:
            logger.info(f"运行SQLMap: {result.command}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)

            result.output = stdout.decode("utf-8", errors="ignore")
            if process.returncode == 0:
                result.success = True
                result.parsed_results = self._parse_sqlmap_output(result.output)
            else:
                result.error = stderr.decode("utf-8", errors="ignore")

        except Exception as e:
            result.error = str(e)

        result.execution_time = time.time() - start_time
        return result

    def _parse_sqlmap_output(self, output: str) -> List[Dict]:
        """解析SQLMap输出"""
        results = []
        # 检测注入点
        if "is vulnerable" in output.lower() or "sql injection" in output.lower():
            results.append({"type": "sql_injection", "detected": True})
        # 提取数据库
        db_match = re.findall(r'\[(\w+)\]', output)
        if db_match:
            results.append({"type": "databases", "databases": list(set(db_match))})
        return results

    async def run_hashcat(
        self,
        hash_file: str,
        hash_type: int = 0,
        attack_mode: int = 0,
        dictionary: str = "",
        mask: str = "",
        rules: str = "",
        output_file: str = "",
    ) -> ToolResult:
        """运行Hashcat"""
        start_time = time.time()
        result = ToolResult(
            tool_name="hashcat",
            target=hash_file,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        installed, msg = self.check_tool_installed("hashcat")
        if not installed:
            result.success = False
            result.error = "Hashcat未安装"
            return result

        cmd = [self.tools["hashcat"].path, "-m", str(hash_type), "-a", str(attack_mode)]

        if attack_mode == 0 and dictionary:
            cmd.extend([hash_file, dictionary])
        elif attack_mode == 3 and mask:
            cmd.extend([hash_file, mask])
        else:
            cmd.append(hash_file)

        if rules:
            cmd.extend(["-r", rules])
        if output_file:
            cmd.extend(["-o", output_file])

        cmd.extend(["--workload-profile", "3", "--potfile-disable"])
        result.command = " ".join(cmd)

        try:
            logger.info(f"运行Hashcat: {result.command}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)

            result.output = stdout.decode("utf-8", errors="ignore")
            if process.returncode == 0:
                result.success = True
                result.parsed_results = self._parse_hashcat_output(result.output)
            else:
                result.error = stderr.decode("utf-8", errors="ignore")

        except Exception as e:
            result.error = str(e)

        result.execution_time = time.time() - start_time
        return result

    def _parse_hashcat_output(self, output: str) -> List[Dict]:
        """解析Hashcat输出"""
        results = []
        # 提取破解的密码
        cracked = re.findall(r'([a-fA-F0-9]+):(\S+)', output)
        for hash_val, password in cracked:
            results.append({"hash": hash_val, "password": password})
        # 提取速度
        speed_match = re.search(r'(\d+(?:\.\d+)?)\s*(MH/s|kH/s|H/s)', output)
        if speed_match:
            results.append({"speed": speed_match.group(0)})
        return results

    async def generate_metasploit_payload(
        self,
        payload_type: str = "windows/meterpreter/reverse_tcp",
        lhost: str = "127.0.0.1",
        lport: int = 4444,
        output_format: str = "exe",
        output_file: str = "",
    ) -> ToolResult:
        """生成Metasploit Payload"""
        start_time = time.time()
        result = ToolResult(
            tool_name="metasploit",
            target=payload_type,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        # 检查msfvenom
        msfvenom_path = shutil.which("msfvenom")
        if not msfvenom_path:
            result.success = False
            result.error = "msfvenom未安装"
            return result

        if not output_file:
            output_file = f"{self.workspace}/metasploit/payload_{int(time.time())}.{output_format}"

        cmd = [
            msfvenom_path,
            "-p", payload_type,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", output_format,
            "-o", output_file,
        ]

        result.command = " ".join(cmd)

        try:
            logger.info(f"生成Metasploit Payload: {result.command}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)

            result.output = stdout.decode("utf-8", errors="ignore")
            if process.returncode == 0 and os.path.exists(output_file):
                result.success = True
                result.parsed_results = [{
                    "payload_type": payload_type,
                    "lhost": lhost,
                    "lport": lport,
                    "output_file": output_file,
                    "file_size": os.path.getsize(output_file),
                }]
            else:
                result.error = stderr.decode("utf-8", errors="ignore")

        except Exception as e:
            result.error = str(e)

        result.execution_time = time.time() - start_time
        return result

    def get_tool_installation_guide(self, tool_name: str) -> str:
        """获取工具安装指南"""
        guides = {
            "nmap": "Windows: 下载 https://nmap.org/download.html\nLinux: sudo apt install nmap\nmacOS: brew install nmap",
            "nuclei": "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest\n或下载: https://github.com/projectdiscovery/nuclei/releases",
            "sqlmap": "git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git\n或下载: https://sqlmap.org/",
            "metasploit": "Windows: 下载 https://www.metasploit.com/download\nLinux: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall",
            "hashcat": "下载: https://hashcat.net/hashcat/\n或: git clone https://github.com/hashcat/hashcat.git",
            "burp": "下载: https://portswigger.net/burp/releases",
            "hydra": "Linux: sudo apt install hydra\nmacOS: brew install hydra",
            "john": "Linux: sudo apt install john\n或下载: https://www.openwall.com/john/",
            "volatility": "pip install volatility3\n或下载: https://www.volatilityfoundation.org/",
            "masscan": "Linux: sudo apt install masscan\n或: git clone https://github.com/robertdavidgraham/masscan",
            "tshark": "Windows: 安装Wireshark\nLinux: sudo apt install tshark\nmacOS: brew install wireshark",
        }
        return guides.get(tool_name, f"未找到 {tool_name} 的安装指南")

    def generate_tool_report(self, output_path: str) -> str:
        """生成工具集成报告"""
        all_tools = self.list_all_tools()
        installed = [t for t in all_tools if t["installed"]]
        not_installed = [t for t in all_tools if not t["installed"]]

        report = {
            "title": "真实工具深度集成报告",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_tools": len(all_tools),
                "installed": len(installed),
                "not_installed": len(not_installed),
                "installation_rate": f"{len(installed)/len(all_tools)*100:.1f}%",
            },
            "installed_tools": installed,
            "not_installed_tools": not_installed,
            "installation_guides": {
                t["name"]: self.get_tool_installation_guide(t["name"])
                for t in not_installed
            },
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        logger.info(f"工具集成报告已生成: {output_path}")
        return output_path


# 便捷函数
def check_all_tools() -> List[Dict]:
    """检查所有工具"""
    integration = DeepToolIntegration()
    return integration.list_all_tools()


def check_installed_tools() -> List[Dict]:
    """检查已安装工具"""
    integration = DeepToolIntegration()
    return integration.list_installed_tools()


async def scan_with_nmap(target: str, scan_type: str = "default") -> ToolResult:
    """Nmap扫描便捷函数"""
    integration = DeepToolIntegration()
    return await integration.run_nmap_scan(target, scan_type)


async def scan_with_nuclei(target: str, severity: str = "high,critical") -> ToolResult:
    """Nuclei扫描便捷函数"""
    integration = DeepToolIntegration()
    return await integration.run_nuclei_scan(target, severity=severity)


if __name__ == "__main__":
    # 测试
    print("=== 真实工具深度集成模块 ===")
    print()

    integration = DeepToolIntegration()

    # 列出所有工具
    all_tools = integration.list_all_tools()
    print(f"支持的工具总数: {len(all_tools)}")
    print()

    # 检查已安装的工具
    installed = integration.list_installed_tools()
    print(f"已安装的工具: {len(installed)}")
    for tool in installed:
        print(f"  - {tool['name']} {tool['version']}: {tool['description']}")
    print()

    # 未安装的工具
    not_installed = [t for t in all_tools if not t["installed"]]
    print(f"未安装的工具: {len(not_installed)}")
    for tool in not_installed:
        print(f"  - {tool['name']}: {tool['description']}")
