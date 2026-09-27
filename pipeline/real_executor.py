#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真实工具执行器（Real Tool Executor）

负责检测系统中可用的安全工具，并提供统一调用接口。
工具不可用时自动回退到模拟模式，结果标记真实/模拟来源。

支持工具：
- nmap: 端口扫描、服务识别、操作系统检测
- nuclei: 漏洞模板扫描
- sqlmap: SQL注入检测与利用
- nikto: Web服务器扫描
- subfinder: 子域名枚举
- httpx: HTTP探测
- whatweb: 技术栈识别
"""

import subprocess
import shutil
import json
import re
import socket
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import platform
import os


class ToolStatus(Enum):
    """工具状态"""
    AVAILABLE = "available"
    NOT_FOUND = "not_found"
    ERROR = "error"


@dataclass
class ToolResult:
    """工具执行结果"""
    tool: str
    status: ToolStatus
    success: bool
    output: str = ""
    error: str = ""
    parsed: Any = None
    duration: float = 0
    is_real: bool = False  # 是否为真实执行结果


class ToolExecutor:
    """
    真实工具执行器

    统一管理所有安全工具的调用，自动检测可用性，
    不可用时返回模拟结果并标记is_real=False。
    """

    def __init__(self):
        self._tool_cache: Dict[str, ToolStatus] = {}
        self._detect_all_tools()

    def _detect_all_tools(self):
        """检测所有工具可用性"""
        tools = ["nmap", "nuclei", "sqlmap", "nikto", "subfinder", "httpx", "whatweb"]
        for tool in tools:
            self._tool_cache[tool] = self._detect_tool(tool)

    def _detect_tool(self, tool: str) -> ToolStatus:
        """检测单个工具是否可用"""
        try:
            path = shutil.which(tool)
            if path:
                return ToolStatus.AVAILABLE
            # Windows下可能需要.exe后缀
            if platform.system() == "Windows":
                path = shutil.which(f"{tool}.exe")
                if path:
                    return ToolStatus.AVAILABLE
            return ToolStatus.NOT_FOUND
        except Exception:
            return ToolStatus.ERROR

    def is_available(self, tool: str) -> bool:
        """检查工具是否可用"""
        return self._tool_cache.get(tool, ToolStatus.NOT_FOUND) == ToolStatus.AVAILABLE

    def get_available_tools(self) -> List[str]:
        """获取所有可用工具列表"""
        return [t for t, s in self._tool_cache.items() if s == ToolStatus.AVAILABLE]

    def get_tool_status(self) -> Dict[str, str]:
        """获取所有工具状态"""
        return {t: s.value for t, s in self._tool_cache.items()}

    def _run_command(self, cmd: List[str], timeout: int = 120) -> Tuple[str, str, int]:
        """执行系统命令"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "命令超时", -1
        except Exception as e:
            return "", str(e), -1

    # ========== Nmap ==========

    def nmap_scan(self, target: str, ports: str = "1-1000",
                  scan_type: str = "syn", timing: int = 3) -> ToolResult:
        """
        Nmap端口扫描

        Args:
            target: 目标IP或域名
            ports: 端口范围，如"1-1000"或"80,443,22"
            scan_type: 扫描类型 syn/connect/udp
            timing: 时序模板 0-5

        Returns:
            ToolResult with parsed open ports
        """
        if not self.is_available("nmap"):
            return self._simulate_nmap(target)

        scan_flag = "-sS" if scan_type == "syn" else "-sT" if scan_type == "connect" else "-sU"
        cmd = ["nmap", scan_flag, "-p", ports, f"-T{timing}",
               "--open", "-oX", "-", target]

        stdout, stderr, rc = self._run_command(cmd, timeout=180)

        if rc != 0 and not stdout:
            return ToolResult(
                tool="nmap", status=ToolStatus.ERROR,
                success=False, error=stderr or f"返回码{rc}",
                is_real=True
            )

        # 解析XML输出
        open_ports = self._parse_nmap_xml(stdout)

        return ToolResult(
            tool="nmap", status=ToolStatus.AVAILABLE,
            success=True, output=stdout[:2000],
            parsed={"open_ports": open_ports, "target": target},
            is_real=True
        )

    def _parse_nmap_xml(self, xml_output: str) -> List[Dict]:
        """解析Nmap XML输出"""
        ports = []
        # 简单正则解析
        port_pattern = re.compile(
            r'<port\s+protocol="(\w+)"\s+portid="(\d+)">.*?'
            r'<state\s+state="(\w+)".*?'
            r'(?:<service\s+name="([^"]*)"(?:\s+product="([^"]*)")?(?:\s+version="([^"]*)")?)?',
            re.DOTALL
        )
        for match in port_pattern.finditer(xml_output):
            proto, portid, state, name, product, version = match.groups()
            if state == "open":
                ports.append({
                    "port": int(portid),
                    "protocol": proto,
                    "service": name or "unknown",
                    "product": product or "",
                    "version": version or "",
                })
        return ports

    def _simulate_nmap(self, target: str) -> ToolResult:
        """模拟Nmap扫描结果"""
        return ToolResult(
            tool="nmap", status=ToolStatus.NOT_FOUND,
            success=True,
            parsed={
                "open_ports": [
                    {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.24"},
                    {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.24"},
                    {"port": 22, "protocol": "tcp", "service": "ssh", "product": "openssh", "version": "8.9"},
                ],
                "target": target,
                "note": "模拟结果（nmap未安装）"
            },
            is_real=False
        )

    # ========== Nuclei ==========

    def nuclei_scan(self, target: str, templates: str = "",
                    severity: str = "") -> ToolResult:
        """
        Nuclei漏洞模板扫描

        Args:
            target: 目标URL
            templates: 模板路径或标签
            severity: 严重级别过滤 critical,high,medium,low,info

        Returns:
            ToolResult with parsed vulnerabilities
        """
        if not self.is_available("nuclei"):
            return self._simulate_nuclei(target)

        cmd = ["nuclei", "-u", target, "-json", "-silent"]
        if templates:
            cmd.extend(["-t", templates])
        if severity:
            cmd.extend(["-severity", severity])

        stdout, stderr, rc = self._run_command(cmd, timeout=300)

        vulns = []
        for line in stdout.strip().split('\n'):
            if line.strip():
                try:
                    vuln = json.loads(line)
                    vulns.append({
                        "template": vuln.get("template-id", ""),
                        "name": vuln.get("info", {}).get("name", ""),
                        "severity": vuln.get("info", {}).get("severity", "info"),
                        "matched": vuln.get("matched-at", ""),
                        "description": vuln.get("info", {}).get("description", ""),
                    })
                except json.JSONDecodeError:
                    continue

        return ToolResult(
            tool="nuclei", status=ToolStatus.AVAILABLE,
            success=True, output=stdout[:2000],
            parsed={"vulnerabilities": vulns, "target": target, "count": len(vulns)},
            is_real=True
        )

    def _simulate_nuclei(self, target: str) -> ToolResult:
        """模拟Nuclei扫描结果"""
        return ToolResult(
            tool="nuclei", status=ToolStatus.NOT_FOUND,
            success=True,
            parsed={
                "vulnerabilities": [
                    {"template": "tech-detect", "name": "技术栈检测", "severity": "info",
                     "matched": f"https://{target}", "description": "检测到Nginx/Python技术栈"},
                    {"template": "git-config", "name": "Git配置暴露", "severity": "high",
                     "matched": f"https://{target}/.git/config", "description": ".git目录可访问"},
                ],
                "target": target,
                "count": 2,
                "note": "模拟结果（nuclei未安装）"
            },
            is_real=False
        )

    # ========== SQLMap ==========

    def sqlmap_scan(self, url: str, data: str = "",
                    level: int = 1, risk: int = 1) -> ToolResult:
        """
        SQLMap注入检测

        Args:
            url: 目标URL
            data: POST数据
            level: 测试级别 1-5
            risk: 风险级别 1-3

        Returns:
            ToolResult with parsed injection points
        """
        if not self.is_available("sqlmap"):
            return self._simulate_sqlmap(url)

        cmd = ["sqlmap", "-u", url, "--batch", "--level", str(level),
               "--risk", str(risk), "--json"]
        if data:
            cmd.extend(["--data", data])

        stdout, stderr, rc = self._run_command(cmd, timeout=300)

        return ToolResult(
            tool="sqlmap", status=ToolStatus.AVAILABLE,
            success=True, output=stdout[:2000],
            parsed={"url": url, "raw_output": stdout[:3000]},
            is_real=True
        )

    def _simulate_sqlmap(self, url: str) -> ToolResult:
        """模拟SQLMap结果"""
        return ToolResult(
            tool="sqlmap", status=ToolStatus.NOT_FOUND,
            success=True,
            parsed={
                "url": url,
                "injections": [
                    {"parameter": "id", "type": "boolean-based blind", "dbms": "MySQL"},
                    {"parameter": "username", "type": "time-based blind", "dbms": "MySQL"},
                ],
                "note": "模拟结果（sqlmap未安装）"
            },
            is_real=False
        )

    # ========== Nikto ==========

    def nikto_scan(self, target: str) -> ToolResult:
        """Nikto Web服务器扫描"""
        if not self.is_available("nikto"):
            return self._simulate_nikto(target)

        cmd = ["nikto", "-h", target, "-Format", "json"]
        stdout, stderr, rc = self._run_command(cmd, timeout=300)

        return ToolResult(
            tool="nikto", status=ToolStatus.AVAILABLE,
            success=True, output=stdout[:2000],
            parsed={"target": target, "raw": stdout[:3000]},
            is_real=True
        )

    def _simulate_nikto(self, target: str) -> ToolResult:
        """模拟Nikto结果"""
        return ToolResult(
            tool="nikto", status=ToolStatus.NOT_FOUND,
            success=True,
            parsed={
                "target": target,
                "findings": [
                    {"osvdb": "OSVDB-3092", "msg": "/admin/ 目录可访问"},
                    {"osvdb": "OSVDB-3268", "msg": "/backup/ 目录列表开启"},
                ],
                "note": "模拟结果（nikto未安装）"
            },
            is_real=False
        )

    # ========== Subfinder ==========

    def subfinder_enum(self, domain: str) -> ToolResult:
        """Subfinder子域名枚举"""
        if not self.is_available("subfinder"):
            return self._simulate_subfinder(domain)

        cmd = ["subfinder", "-d", domain, "-silent", "-json"]
        stdout, stderr, rc = self._run_command(cmd, timeout=120)

        subdomains = []
        for line in stdout.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    subdomains.append(data.get("host", line.strip()))
                except json.JSONDecodeError:
                    subdomains.append(line.strip())

        return ToolResult(
            tool="subfinder", status=ToolStatus.AVAILABLE,
            success=True, output=stdout[:2000],
            parsed={"domain": domain, "subdomains": subdomains, "count": len(subdomains)},
            is_real=True
        )

    def _simulate_subfinder(self, domain: str) -> ToolResult:
        """模拟子域名枚举"""
        return ToolResult(
            tool="subfinder", status=ToolStatus.NOT_FOUND,
            success=True,
            parsed={
                "domain": domain,
                "subdomains": [
                    f"www.{domain}", f"api.{domain}", f"admin.{domain}",
                    f"dev.{domain}", f"mail.{domain}",
                ],
                "count": 5,
                "note": "模拟结果（subfinder未安装）"
            },
            is_real=False
        )

    # ========== HTTPX ==========

    def httpx_probe(self, targets: List[str]) -> ToolResult:
        """HTTPX HTTP探测"""
        if not self.is_available("httpx"):
            return self._simulate_httpx(targets)

        input_text = '\n'.join(targets)
        cmd = ["httpx", "-silent", "-status-code", "-title", "-tech-detect", "-json"]
        stdout, stderr, rc = self._run_command(cmd, timeout=120)

        results = []
        for line in stdout.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    results.append({
                        "url": data.get("url", ""),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "tech": data.get("tech", []),
                    })
                except json.JSONDecodeError:
                    continue

        return ToolResult(
            tool="httpx", status=ToolStatus.AVAILABLE,
            success=True, output=stdout[:2000],
            parsed={"results": results, "count": len(results)},
            is_real=True
        )

    def _simulate_httpx(self, targets: List[str]) -> ToolResult:
        """模拟HTTP探测"""
        results = []
        for t in targets[:5]:
            results.append({
                "url": f"https://{t}",
                "status_code": 200,
                "title": "Welcome",
                "tech": ["Nginx", "Python", "FastAPI"],
            })
        return ToolResult(
            tool="httpx", status=ToolStatus.NOT_FOUND,
            success=True,
            parsed={"results": results, "count": len(results),
                    "note": "模拟结果（httpx未安装）"},
            is_real=False
        )

    # ========== DNS解析 ==========

    def dns_resolve(self, domain: str) -> ToolResult:
        """DNS解析（纯Python，无需外部工具）"""
        try:
            ip = socket.gethostbyname(domain)
            return ToolResult(
                tool="dns", status=ToolStatus.AVAILABLE,
                success=True, parsed={"domain": domain, "ip": ip},
                is_real=True
            )
        except socket.gaierror as e:
            return ToolResult(
                tool="dns", status=ToolStatus.ERROR,
                success=False, error=str(e),
                parsed={"domain": domain, "ip": "192.168.1.100"},
                is_real=False
            )

    # ========== HTTP请求 ==========

    def http_request(self, url: str, method: str = "GET") -> ToolResult:
        """发送HTTP请求（纯Python，用于基础探测）"""
        import urllib.request
        import urllib.error
        try:
            req = urllib.request.Request(url, method=method)
            req.add_header("User-Agent", "AI-Hacking-Agent/9.0")
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode('utf-8', errors='replace')[:2000]
                return ToolResult(
                    tool="http", status=ToolStatus.AVAILABLE,
                    success=True,
                    parsed={
                        "url": url,
                        "status_code": resp.status,
                        "headers": dict(resp.headers),
                        "body_length": len(body),
                        "body_preview": body[:500],
                    },
                    is_real=True
                )
        except urllib.error.HTTPError as e:
            return ToolResult(
                tool="http", status=ToolStatus.AVAILABLE,
                success=True,
                parsed={"url": url, "status_code": e.code, "error": str(e)},
                is_real=True
            )
        except Exception as e:
            return ToolResult(
                tool="http", status=ToolStatus.ERROR,
                success=False, error=str(e),
                parsed={"url": url, "status_code": 0},
                is_real=False
            )


# 全局单例
_executor: Optional[ToolExecutor] = None


def get_executor() -> ToolExecutor:
    """获取全局执行器单例"""
    global _executor
    if _executor is None:
        _executor = ToolExecutor()
    return _executor
