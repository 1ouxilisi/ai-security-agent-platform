#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP服务器安全扫描器（MCP Security Scanner）

对标：
- GTIG/TeamPCP (UNC6780) 木马化MCP服务器事件
- tiktoken_mcp / azure-functions-mcp-extension 已知木马MCP
- OIDC token提取攻击
- SLSA构建产物签名滥用

核心能力：
- MCP服务器配置解析与审计
- 已知木马MCP特征检测
- MCP工具权限分析（文件/网络/命令执行）
- OIDC token提取检测
- 供应链安全评估
- 安全评分与修复建议
"""

import re
import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum


class MCPSeverity(Enum):
    """MCP安全问题严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MCPPermission(Enum):
    """MCP权限类型"""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    COMMAND_EXEC = "command_exec"
    NETWORK_ACCESS = "network_access"
    CREDENTIAL_ACCESS = "credential_access"
    ENV_ACCESS = "env_access"
    PROCESS_CONTROL = "process_control"
    CODE_EXECUTION = "code_execution"


@dataclass
class MCPServer:
    """MCP服务器"""
    name: str
    command: str = ""
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    url: str = ""
    tools: List[Dict] = field(default_factory=list)
    source: str = ""  # config_file/registry/url
    is_remote: bool = False


@dataclass
class MCPFinding:
    """MCP安全发现"""
    finding_id: str
    title: str
    severity: str
    description: str
    server_name: str
    evidence: str = ""
    category: str = ""  # trojan/permissions/oidc/supply_chain/tool
    recommendation: str = ""
    cwe: str = ""


@dataclass
class MCPScanResult:
    """MCP扫描结果"""
    server: MCPServer
    is_trojan: bool
    risk_score: float  # 0-100
    risk_level: str
    findings: List[MCPFinding] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    oidc_risk: bool = False
    supply_chain_risk: str = "unknown"
    scan_time: float = 0


class KnownTrojanDB:
    """
    已知木马MCP数据库

    基于公开披露的木马化MCP服务器事件。
    """

    TROJAN_MCPS = {
        "tiktoken_mcp": {
            "name": "tiktoken_mcp",
            "aliases": ["tiktoken-mcp", "tiktoken_mcp_server"],
            "threat_actor": "GTIG/UNC6780/TeamPCP",
            "description": "木马化MCP服务器，伪装成token计数工具，实际提取OIDC token",
            "indicators": [
                "tiktoken",
                "token.*count",
                "oidc.*token",
                "github.*actions.*token",
            ],
            "behavior": "提取GitHub Actions runner中的OIDC token，用于签名SLSA构建产物",
            "severity": "critical",
            "cve": "",
            "disclosed": "2026-09",
        },
        "azure-functions-mcp-extension": {
            "name": "azure-functions-mcp-extension",
            "aliases": ["azure-functions-mcp", "azure_functions_mcp"],
            "threat_actor": "GTIG/UNC6780/TeamPCP",
            "description": "木马化Azure Functions MCP扩展，窃取凭证",
            "indicators": [
                "azure.*functions.*mcp",
                "azure.*functions.*extension",
            ],
            "behavior": "窃取Azure凭证和OIDC token",
            "severity": "critical",
            "cve": "",
            "disclosed": "2026-09",
        },
    }

    # 可疑MCP行为模式
    SUSPICIOUS_PATTERNS = [
        {"pattern": r"oidc.*token|id_token|ACTIONS_ID_TOKEN", "desc": "OIDC token访问", "severity": "critical"},
        {"pattern": r"GITHUB_TOKEN|GH_TOKEN|PERSONAL_ACCESS_TOKEN", "desc": "GitHub token访问", "severity": "critical"},
        {"pattern": r"aws.*(secret|key)|AWS_SECRET|AWS_ACCESS", "desc": "AWS凭证访问", "severity": "high"},
        {"pattern": r"slsa.*sign|sigstore|cosign", "desc": "SLSA签名操作", "severity": "high"},
        {"pattern": r"base64.*(encode|decode).*(token|key|secret)", "desc": "凭证编码处理", "severity": "high"},
        {"pattern": r"(curl|wget|requests).*(http|https).*\?(token|key|secret|data)=", "desc": "数据渗出", "severity": "critical"},
        {"pattern": r"eval\(|exec\(|subprocess|os\.system", "desc": "代码/命令执行", "severity": "high"},
        {"pattern": r"open\(.*['\"](/etc|\.ssh|\.aws|\.kube)", "desc": "敏感文件读取", "severity": "high"},
        {"pattern": r"chmod.*777|chown.*root", "desc": "权限修改", "severity": "medium"},
        {"pattern": r"rm\s+-rf|shutil\.rmtree", "desc": "递归删除", "severity": "high"},
        {"pattern": r"socket\.connect|websocket|reverse.*shell", "desc": "网络连接/C2", "severity": "critical"},
        {"pattern": r"keylogger|keystroke|hook.*keyboard", "desc": "键盘记录", "severity": "critical"},
        {"pattern": r"screenshot|screen.*capture|pil.*imagegrab", "desc": "屏幕截图", "severity": "medium"},
        {"pattern": r"camera|webcam|cv2\.VideoCapture", "desc": "摄像头访问", "severity": "high"},
        {"pattern": r"microphone|pyaudio|sounddevice", "desc": "麦克风访问", "severity": "high"},
        {"pattern": r"clipboard|pyperclip|xclip", "desc": "剪贴板访问", "severity": "medium"},
        {"pattern": r"persistence|startup|registry.*run|crontab", "desc": "持久化机制", "severity": "high"},
        {"pattern": r"obfuscate|encrypt|xor|base64.*exec", "desc": "代码混淆", "severity": "medium"},
    ]


class MCPToolAnalyzer:
    """
    MCP工具安全分析器

    分析MCP服务器暴露的工具，评估其安全风险。
    """

    # 危险工具模式
    DANGEROUS_TOOLS = [
        {"pattern": r"(exec|run|execute).*(command|shell|cmd)", "permission": "command_exec", "severity": "critical"},
        {"pattern": r"(write|create|save|upload).*(file|document)", "permission": "file_write", "severity": "high"},
        {"pattern": r"(delete|remove|rm).*(file|document)", "permission": "file_delete", "severity": "high"},
        {"pattern": r"(read|get|open|load).*(file|document|secret|credential)", "permission": "file_read", "severity": "medium"},
        {"pattern": r"(http|request|fetch|api|curl).*(call|send|get|post)", "permission": "network_access", "severity": "medium"},
        {"pattern": r"(env|environment|variable|getenv)", "permission": "env_access", "severity": "medium"},
        {"pattern": r"(process|kill|start|stop).*(service|app)", "permission": "process_control", "severity": "high"},
        {"pattern": r"(eval|evaluate|run).*(code|script|python|js)", "permission": "code_execution", "severity": "critical"},
        {"pattern": r"(token|key|secret|password|credential).*(get|extract|read)", "permission": "credential_access", "severity": "critical"},
    ]

    def analyze_tools(self, tools: List[Dict]) -> Dict:
        """分析工具列表的安全风险"""
        permissions = set()
        findings = []

        for tool in tools:
            tool_name = tool.get("name", "").lower()
            tool_desc = tool.get("description", "").lower()
            combined = f"{tool_name} {tool_desc}"

            for danger in self.DANGEROUS_TOOLS:
                if re.search(danger["pattern"], combined, re.IGNORECASE):
                    permissions.add(danger["permission"])
                    findings.append({
                        "tool": tool.get("name"),
                        "permission": danger["permission"],
                        "severity": danger["severity"],
                        "description": f"工具 '{tool.get('name')}' 可能具有 {danger['permission']} 权限",
                    })

        return {
            "permissions": sorted(permissions),
            "findings": findings,
            "risk_level": self._permissions_to_risk(permissions),
        }

    def _permissions_to_risk(self, permissions: set) -> str:
        """根据权限集评估风险等级"""
        critical_perms = {"command_exec", "code_execution", "credential_access"}
        high_perms = {"file_write", "file_delete", "process_control", "network_access"}

        if permissions & critical_perms:
            return "critical"
        elif permissions & high_perms:
            return "high"
        elif permissions:
            return "medium"
        else:
            return "low"


class MCPScanner:
    """
    MCP服务器安全扫描器（主类）

    整合木马检测 + 工具分析 + 权限审计 + OIDC检测 + 供应链评估。
    """

    def __init__(self):
        self.trojan_db = KnownTrojanDB()
        self.tool_analyzer = MCPToolAnalyzer()
        self.scan_history: List[MCPScanResult] = []

    def scan_server(self, server: MCPServer, code_content: str = "") -> MCPScanResult:
        """
        扫描单个MCP服务器

        Args:
            server: MCP服务器配置
            code_content: 服务器代码内容（可选，用于深度分析）
        """
        start_time = time.time()
        findings = []
        is_trojan = False
        oidc_risk = False

        # 1. 已知木马MCP检测
        trojan_findings = self._check_known_trojans(server)
        findings.extend(trojan_findings)
        if any(f.severity == "critical" for f in trojan_findings):
            is_trojan = True

        # 2. 代码内容深度分析
        if code_content:
            code_findings = self._analyze_code(code_content, server.name)
            findings.extend(code_findings)
            if any("oidc" in f.description.lower() or "token" in f.description.lower()
                   for f in code_findings if f.severity in ["critical", "high"]):
                oidc_risk = True

        # 3. 工具权限分析
        tool_result = self.tool_analyzer.analyze_tools(server.tools)
        for f in tool_result["findings"]:
            findings.append(MCPFinding(
                finding_id=hashlib.md5(f"{f['tool']}{time.time()}".encode()).hexdigest()[:10],
                title=f"危险工具权限: {f['permission']}",
                severity=f["severity"],
                description=f["description"],
                server_name=server.name,
                category="tool",
                recommendation=f"审查工具 '{f['tool']}' 的必要性，限制其权限范围",
            ))

        # 4. 配置安全审计
        config_findings = self._audit_config(server)
        findings.extend(config_findings)

        # 5. 供应链评估
        supply_chain_risk = self._assess_supply_chain(server)

        # 6. 计算风险评分
        risk_score = self._calculate_risk_score(findings, is_trojan, oidc_risk)
        risk_level = self._score_to_level(risk_score)

        result = MCPScanResult(
            server=server,
            is_trojan=is_trojan,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
            permissions=tool_result["permissions"],
            oidc_risk=oidc_risk,
            supply_chain_risk=supply_chain_risk,
            scan_time=time.time() - start_time,
        )

        self.scan_history.append(result)
        return result

    def scan_config(self, config: Dict, code_content: str = "") -> MCPScanResult:
        """
        从配置字典扫描MCP服务器

        支持Claude Desktop / Cursor / VS Code的MCP配置格式。
        """
        servers = self._parse_config(config)
        if not servers:
            server = MCPServer(name="unknown", source="config_parse_failed")
            return MCPScanResult(server=server, is_trojan=False, risk_score=0,
                                 risk_level="unknown", scan_time=0)

        # 扫描第一个服务器（或合并）
        all_findings = []
        combined_server = servers[0]
        for s in servers:
            result = self.scan_server(s, code_content)
            all_findings.extend(result.findings)

        combined_result = self.scan_server(combined_server, code_content)
        combined_result.findings = all_findings
        combined_result.risk_score = max(combined_result.risk_score,
                                          self._calculate_risk_score(all_findings, False, False))
        combined_result.risk_level = self._score_to_level(combined_result.risk_score)
        return combined_result

    def generate_remediation(self, result: MCPScanResult) -> Dict:
        """生成修复建议"""
        recommendations = []

        if result.is_trojan:
            recommendations.append({
                "priority": "P0",
                "action": "立即移除木马MCP服务器",
                "detail": f"服务器 '{result.server.name}' 被检测为已知木马MCP，立即从配置中移除",
            })
            recommendations.append({
                "priority": "P0",
                "action": "轮换所有相关凭证",
                "detail": "OIDC token、GitHub token、云凭证等全部轮换",
            })
            recommendations.append({
                "priority": "P1",
                "action": "审计CI/CD管道",
                "detail": "检查是否有未授权的构建签名或制品修改",
            })

        if result.oidc_risk:
            recommendations.append({
                "priority": "P0",
                "action": "审查OIDC token使用",
                "detail": "检查MCP服务器是否异常访问OIDC token，限制token受众",
            })

        critical_perms = [p for p in result.permissions
                          if p in ["command_exec", "code_execution", "credential_access"]]
        if critical_perms:
            recommendations.append({
                "priority": "P1",
                "action": "限制危险权限",
                "detail": f"服务器具有危险权限: {', '.join(critical_perms)}，评估是否必要",
            })

        if not recommendations:
            recommendations.append({
                "priority": "P3",
                "action": "持续监控",
                "detail": "未发现严重问题，建议定期扫描MCP配置",
            })

        return {
            "server": result.server.name,
            "risk_level": result.risk_level,
            "risk_score": result.risk_score,
            "recommendations": recommendations,
        }

    def get_stats(self) -> Dict:
        """获取扫描统计"""
        return {
            "total_scans": len(self.scan_history),
            "trojans_detected": sum(1 for r in self.scan_history if r.is_trojan),
            "known_trojans": len(self.trojan_db.TROJAN_MCPS),
            "suspicious_patterns": len(self.trojan_db.SUSPICIOUS_PATTERNS),
            "by_risk": dict(Counter(r.risk_level for r in self.scan_history)),
        }

    def _check_known_trojans(self, server: MCPServer) -> List[MCPFinding]:
        """检查已知木马MCP"""
        findings = []
        name_lower = server.name.lower()
        command_lower = server.command.lower()

        for trojan_id, trojan in self.trojan_db.TROJAN_MCPS.items():
            # 检查名称和别名
            if any(alias.lower() in name_lower or alias.lower() in command_lower
                   for alias in [trojan["name"]] + trojan["aliases"]):
                findings.append(MCPFinding(
                    finding_id=hashlib.md5(f"{trojan_id}{time.time()}".encode()).hexdigest()[:10],
                    title=f"已知木马MCP: {trojan['name']}",
                    severity=trojan["severity"],
                    description=f"检测到已知木马MCP服务器。威胁组织: {trojan['threat_actor']}。行为: {trojan['behavior']}",
                    server_name=server.name,
                    category="trojan",
                    evidence=f"匹配特征: {trojan['name']}",
                    recommendation="立即移除此MCP服务器，轮换所有凭证，审计CI/CD管道",
                ))

        return findings

    def _analyze_code(self, code: str, server_name: str) -> List[MCPFinding]:
        """分析MCP服务器代码"""
        findings = []
        code_lower = code.lower()

        for pattern in self.trojan_db.SUSPICIOUS_PATTERNS:
            if re.search(pattern["pattern"], code, re.IGNORECASE):
                findings.append(MCPFinding(
                    finding_id=hashlib.md5(f"{pattern['pattern']}{time.time()}".encode()).hexdigest()[:10],
                    title=f"可疑行为: {pattern['desc']}",
                    severity=pattern["severity"],
                    description=f"代码中检测到可疑模式: {pattern['desc']}",
                    server_name=server_name,
                    category="code",
                    evidence=f"匹配正则: {pattern['pattern']}",
                    recommendation=f"审查相关代码，确认 {pattern['desc']} 是否为预期行为",
                ))

        return findings

    def _audit_config(self, server: MCPServer) -> List[MCPFinding]:
        """审计MCP配置安全"""
        findings = []

        # 检查环境变量中的敏感信息
        for key, value in server.env.items():
            if any(kw in key.upper() for kw in ["TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL"]):
                if value and len(value) > 8:
                    findings.append(MCPFinding(
                        finding_id=hashlib.md5(f"env_{key}{time.time()}".encode()).hexdigest()[:10],
                        title=f"环境变量中的敏感信息: {key}",
                        severity="high",
                        description=f"MCP配置中直接设置了敏感环境变量 {key}",
                        server_name=server.name,
                        category="config",
                        recommendation="使用安全的凭证管理方式，不要在配置中硬编码凭证",
                    ))

        # 检查远程MCP（HTTP传输）
        if server.url and server.url.startswith("http://"):
            findings.append(MCPFinding(
                finding_id=hashlib.md5(f"http_{server.url}".encode()).hexdigest()[:10],
                title="不安全的MCP传输",
                severity="high",
                description=f"远程MCP使用HTTP明文传输: {server.url}",
                server_name=server.name,
                category="config",
                recommendation="改用HTTPS加密传输",
            ))

        # 检查命令执行型MCP
        if any(kw in server.command.lower() for kw in ["bash", "sh", "cmd", "powershell", "python", "node"]):
            # 这是正常的，但需要注意
            pass

        return findings

    def _assess_supply_chain(self, server: MCPServer) -> str:
        """评估供应链风险"""
        risk_factors = 0

        # 未知来源
        if not server.source:
            risk_factors += 2

        # 命令包含下载执行
        if any(kw in server.command.lower() for kw in ["curl", "wget", "pip install", "npm install"]):
            risk_factors += 2

        # 远程MCP
        if server.is_remote:
            risk_factors += 1

        # 无版本锁定
        if not any(kw in server.command for kw in ["==", "@", "#"]):
            risk_factors += 1

        if risk_factors >= 4:
            return "high"
        elif risk_factors >= 2:
            return "medium"
        else:
            return "low"

    def _calculate_risk_score(self, findings: List[MCPFinding],
                              is_trojan: bool, oidc_risk: bool) -> float:
        """计算风险评分"""
        score = 0
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}

        for f in findings:
            score += weights.get(f.severity, 5)

        if is_trojan:
            score += 40
        if oidc_risk:
            score += 20

        return min(100, score)

    def _score_to_level(self, score: float) -> str:
        if score >= 70:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        elif score >= 10:
            return "low"
        else:
            return "safe"

    def _parse_config(self, config: Dict) -> List[MCPServer]:
        """解析MCP配置"""
        servers = []

        # Claude Desktop格式: {"mcpServers": {"name": {"command": "...", "args": [...]}}}
        if "mcpServers" in config:
            for name, cfg in config["mcpServers"].items():
                servers.append(MCPServer(
                    name=name,
                    command=cfg.get("command", ""),
                    args=cfg.get("args", []),
                    env=cfg.get("env", {}),
                    url=cfg.get("url", ""),
                    source="claude_config",
                    is_remote=bool(cfg.get("url")),
                ))

        # Cursor格式: {"mcp": {"servers": [...]}}
        elif "mcp" in config and "servers" in config["mcp"]:
            for s in config["mcp"]["servers"]:
                servers.append(MCPServer(
                    name=s.get("name", "unknown"),
                    command=s.get("command", ""),
                    args=s.get("args", []),
                    env=s.get("env", {}),
                    url=s.get("url", ""),
                    source="cursor_config",
                    is_remote=bool(s.get("url")),
                ))

        return servers


from collections import Counter

# 单例模式
_scanner_instance: Optional[MCPScanner] = None

def get_mcp_scanner() -> MCPScanner:
    """获取全局MCP扫描器实例"""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = MCPScanner()
    return _scanner_instance
