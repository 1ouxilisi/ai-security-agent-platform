#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全工具统一管理器模块，支持57+安全工具的安装、配置、调用和状态管理。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import re
import shutil
import subprocess
import logging
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """工具信息"""
    name: str
    category: str  # recon, scanning, exploitation, post_exploitation, forensics, reporting
    description: str = ""
    version: str = ""
    installed: bool = False
    install_path: str = ""
    dependencies: List[str] = field(default_factory=list)
    python_module: str = ""
    command: str = ""
    last_used: str = ""
    usage_count: int = 0
    status: str = "unknown"  # ready, not_installed, error, disabled

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "version": self.version,
            "installed": self.installed,
            "install_path": self.install_path,
            "dependencies": self.dependencies,
            "python_module": self.python_module,
            "command": self.command,
            "last_used": self.last_used,
            "usage_count": self.usage_count,
            "status": self.status,
        }


class ToolManager:
    """工具管理器"""

    # 工具分类
    CATEGORIES = {
        'recon': '信息收集',
        'scanning': '扫描探测',
        'exploitation': '漏洞利用',
        'post_exploitation': '后渗透',
        'forensics': '取证分析',
        'reporting': '报告生成',
        'password': '密码攻击',
        'web': 'Web安全',
        'network': '网络安全',
        'wireless': '无线安全',
        'social': '社会工程',
    }

    def __init__(self):
        """初始化ToolManager实例。

        Args:
            self: 类实例。
        """
        self.tools: Dict[str, ToolInfo] = {}
        self._register_builtin_tools()

    def _register_builtin_tools(self):
        """注册内置工具"""
        builtin_tools = [
            # 信息收集
            ToolInfo(name="nmap", category="scanning", description="网络扫描和安全审计工具", command="nmap", python_module=""),
            ToolInfo(name="masscan", category="scanning", description="高速端口扫描器", command="masscan", python_module=""),
            ToolInfo(name="nikto", category="web", description="Web服务器漏洞扫描器", command="nikto", python_module=""),
            ToolInfo(name="whatweb", category="recon", description="Web指纹识别工具", command="whatweb", python_module=""),
            ToolInfo(name="wpscan", category="web", description="WordPress安全扫描器", command="wpscan", python_module=""),
            ToolInfo(name="gobuster", category="web", description="目录/文件/DNS爆破工具", command="gobuster", python_module=""),
            ToolInfo(name="ffuf", category="web", description="高速Web模糊测试工具", command="ffuf", python_module=""),
            ToolInfo(name="dirsearch", category="web", description="Web目录扫描工具", command="dirsearch", python_module=""),
            ToolInfo(name="wfuzz", category="web", description="Web应用模糊测试工具", command="wfuzz", python_module=""),
            ToolInfo(name="sublist3r", category="recon", description="子域名枚举工具", command="sublist3r", python_module=""),
            ToolInfo(name="amass", category="recon", description="攻击面测绘工具", command="amass", python_module=""),
            ToolInfo(name="theHarvester", category="recon", description="邮箱和子域名收集工具", command="theHarvester", python_module=""),
            ToolInfo(name="recon-ng", category="recon", description="Web侦察框架", command="recon-ng", python_module=""),
            ToolInfo(name="spiderfoot", category="recon", description="自动化侦察工具", command="spiderfoot", python_module=""),

            # 漏洞利用
            ToolInfo(name="metasploit", category="exploitation", description="渗透测试框架", command="msfconsole", python_module=""),
            ToolInfo(name="sqlmap", category="exploitation", description="SQL注入工具", command="sqlmap", python_module=""),
            ToolInfo(name="nuclei", category="exploitation", description="基于模板的漏洞扫描器", command="nuclei", python_module=""),
            ToolInfo(name="searchsploit", category="exploitation", description="Exploit-DB搜索工具", command="searchsploit", python_module=""),
            ToolInfo(name="commix", category="exploitation", description="命令注入工具", command="commix", python_module=""),
            ToolInfo(name="xsstrike", category="exploitation", description="XSS扫描和利用工具", command="xsstrike", python_module=""),
            ToolInfo(name="crackmapexec", category="exploitation", description="AD环境攻击工具", command="crackmapexec", python_module=""),
            ToolInfo(name="impacket", category="exploitation", description="网络协议攻击工具集", command="", python_module="impacket"),
            ToolInfo(name="bloodhound", category="exploitation", description="AD攻击路径分析工具", command="bloodhound", python_module=""),
            ToolInfo(name="responder", category="exploitation", description="LLMNR/NBT-NS/mDNS投毒工具", command="responder", python_module=""),
            ToolInfo(name="mitm6", category="exploitation", description="IPv6攻击工具", command="mitm6", python_module=""),
            ToolInfo(name="kerbrute", category="exploitation", description="Kerberos枚举工具", command="kerbrute", python_module=""),

            # 密码攻击
            ToolInfo(name="hydra", category="password", description="在线暴力破解工具", command="hydra", python_module=""),
            ToolInfo(name="john", category="password", description="离线密码破解工具", command="john", python_module=""),
            ToolInfo(name="hashcat", category="password", description="高速密码恢复工具", command="hashcat", python_module=""),
            ToolInfo(name="medusa", category="password", description="并行暴力破解工具", command="medusa", python_module=""),
            ToolInfo(name="cewl", category="password", description="自定义字典生成工具", command="cewl", python_module=""),
            ToolInfo(name="crunch", category="password", description="字典生成工具", command="crunch", python_module=""),
            ToolInfo(name="cupp", category="password", description="用户画像字典生成工具", command="cupp", python_module=""),

            # 后渗透
            ToolInfo(name="mimikatz", category="post_exploitation", description="Windows凭证提取工具", command="", python_module=""),
            ToolInfo(name="empire", category="post_exploitation", description="后渗透框架", command="empire", python_module=""),
            ToolInfo(name="covenant", category="post_exploitation", description=".NET后渗透框架", command="covenant", python_module=""),
            ToolInfo(name="powersploit", category="post_exploitation", description="PowerShell后渗透工具集", command="", python_module=""),
            ToolInfo(name="linpeas", category="post_exploitation", description="Linux权限提升枚举脚本", command="", python_module=""),
            ToolInfo(name="winpeas", category="post_exploitation", description="Windows权限提升枚举脚本", command="", python_module=""),
            ToolInfo(name="pspy", category="post_exploitation", description="无权限进程监控工具", command="pspy", python_module=""),
            ToolInfo(name="chisel", category="post_exploitation", description="HTTP隧道工具", command="chisel", python_module=""),
            ToolInfo(name="proxychains", category="post_exploitation", description="代理链工具", command="proxychains", python_module=""),

            # 取证分析
            ToolInfo(name="volatility", category="forensics", description="内存取证框架", command="volatility", python_module=""),
            ToolInfo(name="autopsy", category="forensics", description="数字取证平台", command="autopsy", python_module=""),
            ToolInfo(name="wireshark", category="forensics", description="网络协议分析器", command="wireshark", python_module=""),
            ToolInfo(name="tshark", category="forensics", description="命令行网络分析工具", command="tshark", python_module=""),
            ToolInfo(name="tcpdump", category="forensics", description="网络抓包工具", command="tcpdump", python_module=""),
            ToolInfo(name="binwalk", category="forensics", description="固件分析工具", command="binwalk", python_module=""),
            ToolInfo(name="foremost", category="forensics", description="文件恢复工具", command="foremost", python_module=""),
            ToolInfo(name="strings", category="forensics", description="字符串提取工具", command="strings", python_module=""),

            # 无线安全
            ToolInfo(name="aircrack-ng", category="wireless", description="WiFi安全审计工具集", command="aircrack-ng", python_module=""),
            ToolInfo(name="wifite", category="wireless", description="自动化WiFi攻击工具", command="wifite", python_module=""),
            ToolInfo(name="kismet", category="wireless", description="无线网络检测工具", command="kismet", python_module=""),
            ToolInfo(name="bettercap", category="wireless", description="网络攻击和监控框架", command="bettercap", python_module=""),

            # 报告生成
            ToolInfo(name="pwndoc", category="reporting", description="渗透测试报告生成工具", command="", python_module=""),
            ToolInfo(name="faraday", category="reporting", description="协作渗透测试平台", command="faraday", python_module=""),
            ToolInfo(name="dradis", category="reporting", description="安全测试协作框架", command="dradis", python_module=""),
        ]

        for tool in builtin_tools:
            self.tools[tool.name] = tool

    def register_tool(self, tool: ToolInfo) -> bool:
        """注册新工具"""
        if tool.name in self.tools:
            logger.warning(f"工具 {tool.name} 已存在，将被覆盖")
        self.tools[tool.name] = tool
        return True

    def unregister_tool(self, name: str) -> bool:
        """注销工具"""
        if name in self.tools:
            del self.tools[name]
            return True
        return False

    def check_installed(self, name: str) -> bool:
        """检查工具是否安装"""
        if name not in self.tools:
            return False

        tool = self.tools[name]

        # 检查命令是否存在
        if tool.command:
            tool.installed = shutil.which(tool.command) is not None
            if tool.installed:
                tool.install_path = shutil.which(tool.command)
                tool.status = "ready"
            else:
                tool.status = "not_installed"

        # 检查Python模块
        if tool.python_module:
            try:
                __import__(tool.python_module)
                tool.installed = True
                tool.status = "ready"
            except ImportError:
                tool.installed = False
                tool.status = "not_installed"

        return tool.installed

    def check_all_installed(self) -> Dict[str, bool]:
        """检查所有工具安装状态"""
        results = {}
        for name in self.tools:
            results[name] = self.check_installed(name)
        return results

    def get_tool(self, name: str) -> Optional[ToolInfo]:
        """获取工具信息"""
        return self.tools.get(name)

    def list_tools(self, category: str = "") -> List[ToolInfo]:
        """列出工具"""
        if category:
            return [t for t in self.tools.values() if t.category == category]
        return list(self.tools.values())

    def list_categories(self) -> Dict[str, int]:
        """列出工具分类及数量"""
        categories = {}
        for tool in self.tools.values():
            categories[tool.category] = categories.get(tool.category, 0) + 1
        return categories

    def get_installed_tools(self) -> List[ToolInfo]:
        """获取已安装工具"""
        return [t for t in self.tools.values() if t.installed]

    def get_not_installed_tools(self) -> List[ToolInfo]:
        """获取未安装工具"""
        return [t for t in self.tools.values() if not t.installed]

    def get_tools_by_category(self, category: str) -> List[ToolInfo]:
        """按分类获取工具"""
        return [t for t in self.tools.values() if t.category == category]

    def search_tools(self, keyword: str) -> List[ToolInfo]:
        """搜索工具"""
        keyword = keyword.lower()
        results = []
        for tool in self.tools.values():
            if (keyword in tool.name.lower() or
                keyword in tool.description.lower() or
                keyword in tool.category.lower()):
                results.append(tool)
        return results

    def update_usage(self, name: str):
        """更新工具使用记录"""
        if name in self.tools:
            tool = self.tools[name]
            tool.usage_count += 1
            tool.last_used = datetime.now().isoformat()

    def get_statistics(self) -> Dict[str, Any]:
        """获取工具统计"""
        total = len(self.tools)
        installed = sum(1 for t in self.tools.values() if t.installed)
        not_installed = total - installed
        categories = self.list_categories()

        # 按分类统计安装情况
        category_stats = {}
        for cat in categories:
            cat_tools = self.get_tools_by_category(cat)
            cat_installed = sum(1 for t in cat_tools if t.installed)
            category_stats[cat] = {
                "total": len(cat_tools),
                "installed": cat_installed,
                "not_installed": len(cat_tools) - cat_installed,
                "install_rate": f"{cat_installed/len(cat_tools)*100:.1f}%" if cat_tools else "0%",
            }

        # 最常用工具
        most_used = sorted(self.tools.values(), key=lambda t: t.usage_count, reverse=True)[:10]

        return {
            "total_tools": total,
            "installed": installed,
            "not_installed": not_installed,
            "install_rate": f"{installed/total*100:.1f}%" if total > 0 else "0%",
            "categories": category_stats,
            "most_used": [t.name for t in most_used if t.usage_count > 0],
        }

    def generate_install_script(self, tools: List[str] = None, os_type: str = "kali") -> str:
        """生成工具安装脚本"""
        if tools is None:
            tools = [t.name for t in self.get_not_installed_tools() if t.command]

        script_lines = [
            "#!/bin/bash",
            f"# 安全工具安装脚本 ({os_type})",
            f"# 生成时间: {datetime.now().isoformat()}",
            "",
            "echo '=== 开始安装安全工具 ==='",
            "",
            "sudo apt-get update",
            "",
        ]

        for tool_name in tools:
            tool = self.tools.get(tool_name)
            if tool and tool.command:
                script_lines.append(f"echo '安装 {tool_name}...'")
                script_lines.append(f"sudo apt-get install -y {tool_name}")
                script_lines.append("")

        script_lines.extend([
            "echo '=== 工具安装完成 ==='",
            "",
            "# 验证安装",
            "echo '验证安装...'",
        ])

        for tool_name in tools[:5]:  # 只验证前5个
            tool = self.tools.get(tool_name)
            if tool and tool.command:
                script_lines.append(f"which {tool.command} && echo '{tool_name} 安装成功' || echo '{tool_name} 安装失败'")

        return "\n".join(script_lines)

    def export_tool_list(self, format: str = "json") -> str:
        """导出工具列表"""
        if format == "json":
            import json
            return json.dumps([t.to_dict() for t in self.tools.values()], indent=2, ensure_ascii=False)
        elif format == "csv":
            lines = ["名称,分类,描述,版本,已安装,命令,状态"]
            for t in self.tools.values():
                lines.append(f"{t.name},{t.category},{t.description},{t.version},{t.installed},{t.command},{t.status}")
            return "\n".join(lines)
        elif format == "markdown":
            lines = ["| 名称 | 分类 | 描述 | 状态 |", "|------|------|------|------|"]
            for t in self.tools.values():
                lines.append(f"| {t.name} | {t.category} | {t.description} | {t.status} |")
            return "\n".join(lines)
        return ""


# 全局实例
tool_manager = ToolManager()
