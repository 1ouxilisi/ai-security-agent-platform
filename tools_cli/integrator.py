"""
integrator安全工具集成模块，提供相关安全工具的封装和调用。

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
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
from utils.logger import log


@dataclass
class ToolResult:
    """工具执行结果"""
    tool: str
    command: str
    success: bool
    output: str = ""
    parsed_result: Any = None
    error: str = ""
    duration_ms: float = 0
    return_code: int = 0


class ToolIntegrator:
    """真实安全工具集成器"""

    def __init__(self, timeout: int = 300):
        """初始化ToolIntegrator实例。

        Args:
            self: 类实例。
        """
        self.timeout = timeout
        self._tool_cache: Dict[str, bool] = {}
        log.info("真实安全工具集成器初始化")

    def is_tool_available(self, tool_name: str) -> bool:
        """检测工具是否可用"""
        if tool_name in self._tool_cache:
            return self._tool_cache[tool_name]

        available = shutil.which(tool_name) is not None
        self._tool_cache[tool_name] = available
        log.debug(f"工具可用性检测: {tool_name} = {available}")
        return available

    async def _run_command(self, command: List[str], timeout: int = None) -> ToolResult:
        """运行命令（异步）"""
        tool_name = command[0]
        cmd_str = " ".join(command)
        start_time = asyncio.get_event_loop().time()

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout or self.timeout
            )
            duration = (asyncio.get_event_loop().time() - start_time) * 1000

            output = stdout.decode("utf-8", errors="ignore")
            error = stderr.decode("utf-8", errors="ignore")

            return ToolResult(
                tool=tool_name, command=cmd_str, success=proc.returncode == 0,
                output=output, error=error, duration_ms=round(duration, 2),
                return_code=proc.returncode or 0,
            )

        except asyncio.TimeoutError:
            duration = (asyncio.get_event_loop().time() - start_time) * 1000
            return ToolResult(
                tool=tool_name, command=cmd_str, success=False,
                error=f"命令超时 ({timeout or self.timeout}s)", duration_ms=round(duration, 2),
            )
        except FileNotFoundError:
            return ToolResult(
                tool=tool_name, command=cmd_str, success=False,
                error=f"工具未找到: {tool_name}", duration_ms=0,
            )
        except Exception as e:
            return ToolResult(
                tool=tool_name, command=cmd_str, success=False,
                error=str(e), duration_ms=0,
            )

    async def nmap_scan(self, target: str, ports: str = "1-1000",
                         arguments: str = "-sV -sC", output_xml: bool = True) -> ToolResult:
        """
        nmap端口扫描
        target: 目标IP/域名
        ports: 端口范围
        arguments: nmap参数
        """
        if not self.is_tool_available("nmap"):
            return ToolResult(tool="nmap", command="nmap", success=False,
                              error="nmap未安装，请安装: https://nmap.org/download.html")

        command = ["nmap", target, "-p", ports] + arguments.split()
        if output_xml:
            output_file = f"/tmp/nmap_{target.replace('/', '_')}.xml"
            command.extend(["-oX", output_file])

        result = await self._run_command(command)
        if result.success and output_xml:
            result.parsed_result = self._parse_nmap_xml(output_file)

        return result

    def _parse_nmap_xml(self, xml_file: str) -> Dict:
        """解析nmap XML输出"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            hosts = []

            for host in root.findall(".//host"):
                host_data = {"address": "", "status": "", "ports": []}
                addr = host.find("address")
                if addr is not None:
                    host_data["address"] = addr.get("addr", "")
                status = host.find("status")
                if status is not None:
                    host_data["status"] = status.get("state", "")
                for port in host.findall(".//port"):
                    port_data = {
                        "port": port.get("portid", ""),
                        "protocol": port.get("protocol", ""),
                        "state": port.find("state").get("state", "") if port.find("state") is not None else "",
                        "service": port.find("service").get("name", "") if port.find("service") is not None else "",
                        "version": port.find("service").get("version", "") if port.find("service") is not None else "",
                    }
                    host_data["ports"].append(port_data)
                hosts.append(host_data)

            return {"hosts": hosts, "total_open_ports": sum(len(h["ports"]) for h in hosts)}
        except Exception as e:
            log.error(f"解析nmap XML失败: {e}")
            return {"error": str(e)}

    async def sqlmap_scan(self, url: str, data: str = "",
                          level: int = 1, risk: int = 1,
                          batch: bool = True) -> ToolResult:
        """
        sqlmap SQL注入扫描
        url: 目标URL
        data: POST数据
        level: 测试级别 (1-5)
        risk: 风险级别 (1-3)
        """
        if not self.is_tool_available("sqlmap"):
            return ToolResult(tool="sqlmap", command="sqlmap", success=False,
                              error="sqlmap未安装，请安装: https://sqlmap.org/")

        command = ["sqlmap", "-u", url, "--level", str(level), "--risk", str(risk)]
        if data:
            command.extend(["--data", data])
        if batch:
            command.append("--batch")
        command.extend(["--batch", "--random-agent"])

        return await self._run_command(command, timeout=600)

    async def nuclei_scan(self, target: str, templates: str = "",
                          severity: str = "", tags: str = "",
                          output_json: bool = True) -> ToolResult:
        """
        nuclei CLI漏洞扫描
        target: 目标URL
        templates: 模板路径
        severity: 严重程度过滤
        tags: 标签过滤
        """
        if not self.is_tool_available("nuclei"):
            return ToolResult(tool="nuclei", command="nuclei", success=False,
                              error="nuclei未安装，请安装: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

        command = ["nuclei", "-u", target]
        if templates:
            command.extend(["-t", templates])
        if severity:
            command.extend(["-severity", severity])
        if tags:
            command.extend(["-tags", tags])
        if output_json:
            command.extend(["-jsonl", "-o", f"/tmp/nuclei_{target.replace('/', '_')}.json"])

        result = await self._run_command(command, timeout=600)
        if result.success and output_json:
            result.parsed_result = self._parse_nuclei_json(f"/tmp/nuclei_{target.replace('/', '_')}.json")

        return result

    def _parse_nuclei_json(self, json_file: str) -> Dict:
        """解析nuclei JSON输出"""
        findings = []
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            findings.append({
                                "template_id": data.get("template-id", ""),
                                "template_name": data.get("info", {}).get("name", ""),
                                "severity": data.get("info", {}).get("severity", ""),
                                "matched_at": data.get("matched-at", ""),
                                "type": data.get("type", ""),
                            })
                        except json.JSONDecodeError:
                            continue
            return {"findings": findings, "total": len(findings)}
        except Exception as e:
            return {"error": str(e), "findings": [], "total": 0}

    async def masscan_scan(self, target: str, ports: str = "0-65535",
                            rate: int = 1000) -> ToolResult:
        """
        masscan高速端口扫描
        target: 目标IP/网段
        ports: 端口范围
        rate: 发包速率
        """
        if not self.is_tool_available("masscan"):
            return ToolResult(tool="masscan", command="masscan", success=False,
                              error="masscan未安装，请安装: https://github.com/robertdavidgraham/masscan")

        command = ["masscan", target, "-p", ports, "--rate", str(rate)]
        return await self._run_command(command, timeout=300)

    def get_available_tools(self) -> Dict[str, bool]:
        """获取所有可用工具状态"""
        tools = ["nmap", "sqlmap", "nuclei", "masscan", "nikto", "gobuster",
                 "ffuf", "wfuzz", "dirb", "hydra", "john", "hashcat"]
        return {tool: self.is_tool_available(tool) for tool in tools}

    def get_installation_guide(self) -> Dict[str, str]:
        """获取工具安装指南"""
        return {
            "nmap": "Windows: https://nmap.org/download.html | Linux: sudo apt install nmap | Mac: brew install nmap",
            "sqlmap": "git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git",
            "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "masscan": "git clone https://github.com/robertdavidgraham/masscan && cd masscan && make",
            "nikto": "git clone https://github.com/sullo/nikto",
            "gobuster": "go install github.com/OJ/gobuster/v3@latest",
            "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
        }


# 全局工具集成器实例
tool_integrator = ToolIntegrator()
