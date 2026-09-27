#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mcp_server模块，提供相关安全测试功能。

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
import sys
import asyncio
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


class MCPMessageType(Enum):
    """MCP消息类型"""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


@dataclass
class MCPTool:
    """MCP工具定义"""
    name: str
    description: str
    parameters: Dict = field(default_factory=dict)
    handler: Optional[Callable] = None
    category: str = "general"
    examples: List[str] = field(default_factory=list)


@dataclass
class MCPRequest:
    """MCP请求"""
    id: str
    method: str
    params: Dict = field(default_factory=dict)
    timestamp: str = ""


@dataclass
class MCPResponse:
    """MCP响应"""
    id: str
    result: Any = None
    error: Optional[Dict] = None
    timestamp: str = ""


class MCPServer:
    """MCP服务器 - 注册安全工具供AI智能体调用"""

    def __init__(self, server_name: str = "ai-hacking-agent-mcp", version: str = "1.0.0"):
        """初始化MCPServer实例。

        Args:
            self: 类实例。
        """
        self.server_name = server_name
        self.version = version
        self.tools: Dict[str, MCPTool] = {}
        self.request_history: List[Dict] = []
        self._register_builtin_tools()
        logger.info(f"MCP服务器初始化: {server_name} v{version}")

    def _register_builtin_tools(self):
        """注册内置安全工具"""

        # 端口扫描
        self.register_tool(MCPTool(
            name="port_scan",
            description="对目标进行端口扫描，发现开放端口和运行服务",
            category="recon",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标IP或域名"},
                    "ports": {"type": "string", "description": "端口范围，如1-1000", "default": "1-1000"},
                    "scan_type": {"type": "string", "enum": ["default", "syn", "full", "intense"], "default": "default"},
                },
                "required": ["target"],
            },
            examples=["扫描192.168.1.1的常用端口", "对example.com进行全面端口扫描"],
        ))

        # Web漏洞扫描
        self.register_tool(MCPTool(
            name="web_vuln_scan",
            description="对Web应用进行漏洞扫描，检测SQL注入、XSS、目录遍历等漏洞",
            category="vulnerability",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标URL"},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "default": "medium"},
                    "scan_depth": {"type": "integer", "minimum": 1, "maximum": 5, "default": 3},
                },
                "required": ["url"],
            },
            examples=["扫描http://example.com的Web漏洞", "检测testphp.vulnweb.com的高危漏洞"],
        ))

        # 目录扫描
        self.register_tool(MCPTool(
            name="directory_scan",
            description="扫描Web服务器的隐藏目录和文件",
            category="recon",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标URL"},
                    "wordlist": {"type": "string", "description": "字典文件路径", "default": "default"},
                    "extensions": {"type": "string", "description": "文件扩展名", "default": "php,html,asp"},
                },
                "required": ["url"],
            },
            examples=["扫描example.com的隐藏目录", "发现testphp.vulnweb.com的敏感文件"],
        ))

        # Nday漏洞利用
        self.register_tool(MCPTool(
            name="nday_exploit",
            description="利用已知Nday漏洞对目标进行测试（仅限授权测试）",
            category="exploit",
            parameters={
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE编号，如CVE-2021-44228"},
                    "target": {"type": "string", "description": "目标URL或IP:端口"},
                    "mode": {"type": "string", "enum": ["verify", "exploit"], "default": "verify"},
                },
                "required": ["cve_id", "target"],
            },
            examples=["验证目标是否存在Log4j漏洞(CVE-2021-44228)", "测试CVE-2021-41773漏洞"],
        ))

        # 服务识别
        self.register_tool(MCPTool(
            name="service_identify",
            description="识别目标运行的服务版本和技术栈",
            category="recon",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标URL或IP"},
                    "port": {"type": "integer", "description": "端口号", "default": 80},
                },
                "required": ["target"],
            },
            examples=["识别example.com的Web服务器", "检测192.168.1.1:8080的服务版本"],
        ))

        # 漏洞查询
        self.register_tool(MCPTool(
            name="vuln_query",
            description="查询CVE漏洞详情、影响范围和修复方案",
            category="knowledge",
            parameters={
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE编号"},
                    "keyword": {"type": "string", "description": "关键词搜索"},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                },
            },
            examples=["查询CVE-2021-44228的详情", "搜索Apache相关的高危漏洞"],
        ))

        # 报告生成
        self.register_tool(MCPTool(
            name="generate_report",
            description="生成安全测试报告，支持多种模板格式",
            category="report",
            parameters={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "扫描任务ID"},
                    "template": {"type": "string", "enum": ["standard", "executive", "technical", "compliance", "brief"], "default": "standard"},
                    "format": {"type": "string", "enum": ["markdown", "html", "pdf", "json"], "default": "markdown"},
                    "title": {"type": "string", "description": "报告标题"},
                },
                "required": ["scan_id"],
            },
            examples=["为scan_001生成标准报告", "生成管理层摘要报告"],
        ))

        # 系统状态
        self.register_tool(MCPTool(
            name="system_status",
            description="获取系统运行状态、统计数据和工具可用性",
            category="system",
            parameters={
                "type": "object",
                "properties": {
                    "detail": {"type": "string", "enum": ["basic", "full"], "default": "basic"},
                },
            },
            examples=["查看系统状态", "获取详细的系统统计"],
        ))

        logger.info(f"已注册 {len(self.tools)} 个MCP工具")

    def register_tool(self, tool: MCPTool):
        """注册工具"""
        self.tools[tool.name] = tool
        logger.debug(f"注册MCP工具: {tool.name}")

    def list_tools(self, category: str = "") -> List[Dict]:
        """列出所有可用工具"""
        tools = []
        for name, tool in self.tools.items():
            if category and tool.category != category:
                continue
            tools.append({
                "name": tool.name,
                "description": tool.description,
                "category": tool.category,
                "parameters": tool.parameters,
                "examples": tool.examples,
            })
        return tools

    def get_tool(self, name: str) -> Optional[MCPTool]:
        """获取工具定义"""
        return self.tools.get(name)

    def call_tool(self, name: str, params: Dict) -> Dict:
        """调用工具"""
        tool = self.tools.get(name)
        if not tool:
            return {"error": f"工具不存在: {name}", "available_tools": list(self.tools.keys())}

        # 记录请求
        request_id = hashlib.md5(f"{name}{json.dumps(params)}{time.time()}".encode()).hexdigest()[:12]
        self.request_history.append({
            "id": request_id,
            "tool": name,
            "params": params,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

        # 如果有自定义处理器，调用它
        if tool.handler:
            try:
                result = tool.handler(**params)
                return {"tool": name, "result": result, "request_id": request_id}
            except Exception as e:
                return {"tool": name, "error": str(e), "request_id": request_id}

        # 内置工具的模拟实现
        return self._execute_builtin_tool(name, params, request_id)

    def _execute_builtin_tool(self, name: str, params: Dict, request_id: str) -> Dict:
        """执行内置工具（模拟实现，实际项目中对接真实扫描引擎）"""
        target = params.get("target", params.get("url", "unknown"))

        results = {
            "port_scan": {
                "tool": "port_scan",
                "request_id": request_id,
                "target": target,
                "open_ports": [
                    {"port": 22, "service": "ssh", "version": "OpenSSH 8.2p1"},
                    {"port": 80, "service": "http", "version": "Apache 2.4.41"},
                    {"port": 443, "service": "https", "version": "Apache 2.4.41"},
                    {"port": 3306, "service": "mysql", "version": "MySQL 8.0.23"},
                ],
                "filtered_ports": [135, 139, 445],
                "summary": f"发现4个开放端口，3个过滤端口",
            },
            "web_vuln_scan": {
                "tool": "web_vuln_scan",
                "request_id": request_id,
                "url": target,
                "vulnerabilities": [
                    {"id": "VULN-001", "name": "SQL注入", "severity": "high", "location": "/search.php?q=", "evidence": "参数q存在SQL注入"},
                    {"id": "VULN-002", "name": "XSS跨站脚本", "severity": "medium", "location": "/comment.php", "evidence": "反射型XSS"},
                    {"id": "VULN-003", "name": "目录遍历", "severity": "medium", "location": "/download.php?file=", "evidence": "可读取/etc/passwd"},
                    {"id": "VULN-004", "name": "敏感信息泄露", "severity": "low", "location": "/.git/config", "evidence": "Git配置文件可访问"},
                ],
                "summary": "发现1个高危，2个中危，1个低危漏洞",
            },
            "directory_scan": {
                "tool": "directory_scan",
                "request_id": request_id,
                "url": target,
                "found": [
                    {"path": "/admin", "status": 301, "size": 0},
                    {"path": "/backup", "status": 403, "size": 278},
                    {"path": "/config.php", "status": 200, "size": 1024},
                    {"path": "/.git/HEAD", "status": 200, "size": 23},
                    {"path": "/uploads", "status": 301, "size": 0},
                    {"path": "/phpinfo.php", "status": 200, "size": 85000},
                ],
                "summary": "发现6个敏感路径",
            },
            "nday_exploit": {
                "tool": "nday_exploit",
                "request_id": request_id,
                "cve_id": params.get("cve_id", ""),
                "target": target,
                "mode": params.get("mode", "verify"),
                "vulnerable": True,
                "evidence": "目标返回了漏洞利用的特征响应",
                "details": f"{params.get('cve_id')} 漏洞验证成功，目标存在该漏洞",
            },
            "service_identify": {
                "tool": "service_identify",
                "request_id": request_id,
                "target": target,
                "services": [
                    {"port": 80, "service": "http", "product": "Apache", "version": "2.4.41", "os": "Ubuntu"},
                    {"port": 443, "service": "https", "product": "Apache", "version": "2.4.41", "ssl": "TLS 1.3"},
                ],
                "tech_stack": ["Apache 2.4.41", "PHP 7.4.3", "MySQL 8.0", "jQuery 3.5.1"],
            },
            "vuln_query": {
                "tool": "vuln_query",
                "request_id": request_id,
                "cve_id": params.get("cve_id", ""),
                "details": {
                    "cve_id": params.get("cve_id", "CVE-2021-44228"),
                    "name": "Log4j远程代码执行漏洞",
                    "severity": "critical",
                    "cvss": 10.0,
                    "affected": "Apache Log4j 2.0-beta9 到 2.14.1",
                    "description": "Log4j中存在JNDI注入漏洞，攻击者可通过构造恶意请求执行任意代码",
                    "fix": "升级到Log4j 2.17.0或更高版本",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                },
            },
            "generate_report": {
                "tool": "generate_report",
                "request_id": request_id,
                "scan_id": params.get("scan_id", ""),
                "title": params.get("title", "安全测试报告"),
                "template": params.get("template", "standard"),
                "format": params.get("format", "markdown"),
                "status": "generated",
                "file_path": f"./reports/{params.get('scan_id', 'report')}_{int(time.time())}.md",
                "summary": "报告生成成功，包含漏洞概览、详细分析和修复建议",
            },
            "system_status": {
                "tool": "system_status",
                "request_id": request_id,
                "status": "healthy",
                "version": "3.0.0",
                "tools_registered": len(self.tools),
                "total_requests": len(self.request_history),
                "uptime": "99.9%",
                "active_scans": 0,
                "queue_size": 0,
            },
        }

        return results.get(name, {"tool": name, "error": "工具执行失败", "request_id": request_id})

    def handle_request(self, request: Dict) -> Dict:
        """处理MCP请求（JSON-RPC风格）"""
        method = request.get("method", "")
        params = request.get("params", {})
        request_id = request.get("id", "")

        if method == "tools/list":
            return {"id": request_id, "result": {"tools": self.list_tools()}}

        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_params = params.get("arguments", {})
            result = self.call_tool(tool_name, tool_params)
            return {"id": request_id, "result": result}

        elif method == "tools/get":
            tool_name = params.get("name", "")
            tool = self.get_tool(tool_name)
            if tool:
                return {"id": request_id, "result": {"tool": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                    "category": tool.category,
                }}}
            return {"id": request_id, "error": {"code": -32602, "message": f"工具不存在: {tool_name}"}}

        elif method == "server/info":
            return {"id": request_id, "result": {
                "name": self.server_name,
                "version": self.version,
                "protocol_version": "2024-11-05",
                "capabilities": {"tools": {"list_changed": True}},
            }}

        elif method == "server/health":
            return {"id": request_id, "result": {"status": "healthy", "tools": len(self.tools)}}

        else:
            return {"id": request_id, "error": {"code": -32601, "message": f"未知方法: {method}"}}

    def get_stats(self) -> Dict:
        """获取MCP服务器统计"""
        categories = {}
        for tool in self.tools.values():
            categories[tool.category] = categories.get(tool.category, 0) + 1

        return {
            "server_name": self.server_name,
            "version": self.version,
            "total_tools": len(self.tools),
            "categories": categories,
            "total_requests": len(self.request_history),
            "recent_requests": self.request_history[-10:][::-1],
        }


class MCPClient:
    """MCP客户端 - 用于测试和调用远程MCP服务器"""

    def __init__(self, server_url: str = "http://localhost:8000/mcp"):
        """初始化MCPClient实例。

        Args:
            self: 类实例。
        """
        self.server_url = server_url
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:16]

    def list_tools(self) -> List[Dict]:
        """列出远程服务器的工具"""
        request = {
            "jsonrpc": "2.0",
            "id": "1",
            "method": "tools/list",
            "params": {},
        }
        # 实际使用时通过HTTP发送请求
        return [{"name": "remote_tool", "description": "远程工具示例"}]

    def call_tool(self, tool_name: str, arguments: Dict) -> Dict:
        """调用远程工具"""
        request = {
            "jsonrpc": "2.0",
            "id": "2",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        return {"tool": tool_name, "result": "调用成功"}


def main():
    """演示用法"""
    print("=" * 60)
    print("  MCP协议对接 - Model Context Protocol")
    print("  AI Hacking Agent v3.0")
    print("=" * 60)
    print()

    server = MCPServer()

    # 服务器信息
    print("[1/4] 服务器信息:")
    info = server.handle_request({"method": "server/info", "id": "1"})
    print(f"  名称: {info['result']['name']}")
    print(f"  版本: {info['result']['version']}")
    print(f"  协议: {info['result']['protocol_version']}")
    print()

    # 工具列表
    print("[2/4] 已注册工具:")
    tools = server.list_tools()
    categories = {}
    for tool in tools:
        cat = tool["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(tool["name"])

    for cat, names in categories.items():
        print(f"  [{cat}]")
        for name in names:
            tool = server.get_tool(name)
            print(f"    - {name}: {tool.description[:50]}...")
    print(f"  总计: {len(tools)}个工具")
    print()

    # 工具调用示例
    print("[3/4] 工具调用示例:")

    # 端口扫描
    print("\n  1. 端口扫描 (port_scan):")
    result = server.call_tool("port_scan", {"target": "192.168.1.1", "ports": "1-1000"})
    print(f"     目标: {result['target']}")
    print(f"     开放端口: {len(result['open_ports'])}个")
    for p in result["open_ports"]:
        print(f"       - {p['port']}/{p['service']} ({p['version']})")

    # Web漏洞扫描
    print("\n  2. Web漏洞扫描 (web_vuln_scan):")
    result = server.call_tool("web_vuln_scan", {"url": "http://testphp.vulnweb.com", "severity": "high"})
    print(f"     URL: {result['url']}")
    print(f"     发现漏洞: {len(result['vulnerabilities'])}个")
    for v in result["vulnerabilities"]:
        print(f"       - [{v['severity'].upper()}] {v['name']} @ {v['location']}")

    # Nday漏洞利用
    print("\n  3. Nday漏洞验证 (nday_exploit):")
    result = server.call_tool("nday_exploit", {"cve_id": "CVE-2021-44228", "target": "http://example.com:8080", "mode": "verify"})
    print(f"     CVE: {result['cve_id']}")
    print(f"     存在漏洞: {result['vulnerable']}")
    print(f"     详情: {result['details']}")

    # 系统状态
    print("\n  4. 系统状态 (system_status):")
    result = server.call_tool("system_status", {"detail": "full"})
    print(f"     状态: {result['status']}")
    print(f"     版本: {result['version']}")
    print(f"     已注册工具: {result['tools_registered']}")
    print(f"     总请求数: {result['total_requests']}")
    print()

    # 统计
    print("[4/4] MCP服务器统计:")
    stats = server.get_stats()
    print(f"  服务器: {stats['server_name']} v{stats['version']}")
    print(f"  工具总数: {stats['total_tools']}")
    print(f"  分类: {stats['categories']}")
    print(f"  总请求: {stats['total_requests']}")
    print()

    print("=" * 60)
    print("  MCP协议对接完成！")
    print()
    print("  支持的AI助手:")
    print("  - Claude Desktop (通过claude_desktop_config.json)")
    print("  - ChatGPT (通过Custom GPT / Actions)")
    print("  - 豆包 (通过MCP连接器)")
    print("  - 其他兼容MCP协议的AI助手")
    print()
    print("  使用方式:")
    print("  1. 在AI助手的MCP配置中添加本服务器")
    print("  2. AI助手自动发现并列出所有安全工具")
    print("  3. 用自然语言描述需求，AI自动调用对应工具")
    print("  4. 例如: '扫描192.168.1.1的端口' → 自动调用port_scan")
    print("=" * 60)


if __name__ == "__main__":
    main()
