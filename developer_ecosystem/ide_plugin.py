# -*- coding: utf-8 -*-
"""
ide_plugin.py — VS Code / IDE 插件（第24轮升级方向4 / 模块3）。

包含：
  - 插件核心：命令注册 / 菜单注册 / 快捷键 / 设置项 / 输出面板 / 状态栏 / 侧边栏 / Webview
  - 代码安全扫描：实时扫描 / 漏洞检测 / 依赖漏洞 / 硬编码密钥 / 不安全API / 代码质量 / 安全建议
  - 渗透测试辅助：Payload生成 / 编解码 / 加解密 / Hash计算 / 正则测试 / HTTP请求构造 / 响应分析
  - 安全知识库：CVE查询 / CWE查询 / OWASP查询 / ATT&CK查询 / 漏洞详情 / 修复建议 / 最佳实践
  - 集成功能：平台API集成 / 扫描任务管理 / 报告查看 / 资产同步 / 通知推送
  - 插件市场：列表 / 详情 / 安装 / 更新 / 卸载 / 评分 / 评论

全部内存字典模拟。
"""

from __future__ import annotations

import hashlib
import base64
import json
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


# ==================== 插件核心 ====================

class IDECommand:
    """IDE 命令定义"""
    def __init__(self, id: str, title: str, handler: str, shortcut: str = ""):
        self.id = id
        self.title = title
        self.handler = handler
        self.shortcut = shortcut

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "title": self.title, "handler": self.handler, "shortcut": self.shortcut}


class IDESetting:
    """IDE 设置项"""
    def __init__(self, key: str, default: Any, description: str, value_type: str = "string"):
        self.key = key
        self.default = default
        self.description = description
        self.type = value_type
        self.value = default

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "default": self.default, "value": self.value,
                "description": self.description, "type": self.type}


class IDEPluginCore:
    """IDE 插件核心框架"""

    def __init__(self, plugin_id: str = "aha-security"):
        self.plugin_id = plugin_id
        self.version = "1.4.0"
        self.commands: List[IDECommand] = []
        self.menus: List[Dict[str, str]] = []
        self.settings: Dict[str, IDESetting] = {}
        self.output_panels: Dict[str, List[str]] = {}
        self.status_bar_items: Dict[str, Dict[str, Any]] = {}
        self.sidebar_views: List[Dict[str, Any]] = []
        self.webview_panels: Dict[str, Dict[str, Any]] = {}
        self._register_builtin()

    def _register_builtin(self):
        # 命令
        builtin_cmds = [
            IDECommand("aha.scanFile", "安全扫描当前文件", "scan_file", "Ctrl+Shift+A"),
            IDECommand("aha.scanWorkspace", "安全扫描整个工作区", "scan_workspace", "Ctrl+Shift+W"),
            IDECommand("aha.generatePayload", "生成 Payload", "gen_payload", "Ctrl+Shift+P"),
            IDECommand("aha.encodeDecode", "编码/解码工具", "encode_decode"),
            IDECommand("aha.queryCVE", "查询 CVE", "query_cve", "Ctrl+Shift+C"),
            IDECommand("aha.showReport", "查看安全报告", "show_report"),
            IDECommand("aha.syncAssets", "同步资产", "sync_assets"),
            IDECommand("aha.openSettings", "插件设置", "open_settings"),
        ]
        self.commands.extend(builtin_cmds)

        # 菜单
        self.menus = [
            {"id": "editor/context", "when": "editorTextFocus", "command": "aha.scanFile", "group": "navigation@1"},
            {"id": "explorer/context", "when": "explorerResourceIsFolder", "command": "aha.scanWorkspace", "group": "navigation@1"},
        ]

        # 设置项
        builtin_settings = [
            IDESetting("aha.apiEndpoint", "http://127.0.0.1:8000", "安全平台 API 地址", "string"),
            IDESetting("aha.apiKey", "", "API 密钥", "string"),
            IDESetting("aha.realTimeScan", True, "实时安全扫描", "boolean"),
            IDESetting("aha.scanOnSave", True, "保存时自动扫描", "boolean"),
            IDESetting("aha.severityThreshold", "medium", "报告最低严重级别", "string"),
            IDESetting("aha.customRules", "", "自定义规则文件路径", "string"),
        ]
        for s in builtin_settings:
            self.settings[s.key] = s

        # 状态栏
        self.status_bar_items = {
            "scan_status": {"id": "aha.scanStatus", "text": "$(shield) 就绪", "tooltip": "安全扫描状态", "alignment": "right"},
            "vuln_count": {"id": "aha.vulnCount", "text": "$(warning) 0", "tooltip": "漏洞数量", "alignment": "right"},
        }

        # 侧边栏
        self.sidebar_views = [
            {"id": "aha-explorer", "name": "安全扫描", "icon": "shield", "view": "tree"},
            {"id": "aha-reports", "name": "安全报告", "icon": "report", "view": "list"},
            {"id": "aha-knowledge", "name": "知识库", "icon": "book", "view": "list"},
        ]

    def register_command(self, cmd: IDECommand):
        self.commands.append(cmd)

    def get_manifest(self) -> Dict[str, Any]:
        """生成 package.json 插件清单"""
        return {
            "name": self.plugin_id,
            "displayName": "AI Hacking Agent Security",
            "version": self.version,
            "engines": {"vscode": "^1.80.0"},
            "categories": ["Programming Languages", "Linters", "Snippets"],
            "activationEvents": ["onLanguage:python", "onLanguage:javascript", "onCommand:aha.scanFile"],
            "contributes": {
                "commands": [c.to_dict() for c in self.commands],
                "keybindings": [{"command": c.id, "key": c.shortcut} for c in self.commands if c.shortcut],
                "configuration": {
                    "title": "AI Hacking Agent",
                    "properties": {s.key: {"type": s.type, "default": s.default, "description": s.description}
                                  for s in self.settings.values()},
                },
            },
        }


# ==================== 代码安全扫描 ====================

class CodeSecurityScanner:
    """代码安全扫描引擎"""

    # 硬编码密钥正则
    SECRET_PATTERNS: List[Dict[str, Any]] = [
        {"name": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "critical"},
        {"name": "AWS Secret Key", "pattern": r"(?i)aws_secret_access_key\s*=\s*['\"][^'\"]{20,}", "severity": "critical"},
        {"name": "Private Key", "pattern": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "severity": "critical"},
        {"name": "API Key Generic", "pattern": r"(?i)(api[_-]?key|apikey|secret)\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]", "severity": "high"},
        {"name": "JWT Token", "pattern": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "severity": "high"},
        {"name": "DB Connection String", "pattern": r"(?i)(mysql|postgresql|mongodb)://[^\s:@]+:[^\s:@]+@", "severity": "critical"},
    ]

    # 不安全 API 调用
    UNSAFE_APIS: List[Dict[str, str]] = [
        {"name": "eval()", "pattern": r"\beval\s*\(", "severity": "critical", "fix": "避免使用 eval，改用 ast.literal_eval"},
        {"name": "exec()", "pattern": r"\bexec\s*\(", "severity": "high", "fix": "避免动态执行代码"},
        {"name": "pickle.loads", "pattern": r"pickle\.loads?\s*\(", "severity": "high", "fix": "使用 JSON 替代 pickle"},
        {"name": "subprocess shell=True", "pattern": r"shell\s*=\s*True", "severity": "high", "fix": "使用列表参数避免 shell 注入"},
        {"name": "os.system", "pattern": r"os\.system\s*\(", "severity": "high", "fix": "使用 subprocess.run"},
        {"name": "SQL 字符串拼接", "pattern": r"(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*request\.", "severity": "critical", "fix": "使用参数化查询"},
        {"name": "random 模块", "pattern": r"\bimport random\b", "severity": "low", "fix": "安全场景使用 secrets 模块"},
    ]

    def scan_content(self, code: str, filename: str = "untitled") -> Dict[str, Any]:
        """扫描代码内容"""
        findings: List[Dict[str, Any]] = []

        # 硬编码密钥检测
        for pat in self.SECRET_PATTERNS:
            for m in re.finditer(pat["pattern"], code):
                line_no = code[:m.start()].count("\n") + 1
                findings.append({
                    "rule": pat["name"], "severity": pat["severity"],
                    "line": line_no, "column": m.start() - code.rfind("\n", 0, m.start()),
                    "snippet": m.group()[:60],
                    "message": f"检测到疑似{pat['name']}",
                })

        # 不安全 API 检测
        for api in self.UNSAFE_APIS:
            for m in re.finditer(api["pattern"], code):
                line_no = code[:m.start()].count("\n") + 1
                findings.append({
                    "rule": api["name"], "severity": api["severity"],
                    "line": line_no, "column": 0,
                    "snippet": m.group()[:60],
                    "message": f"不安全 API 调用: {api['name']}",
                    "fix": api.get("fix", ""),
                })

        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f["severity"]
            if sev in summary:
                summary[sev] += 1

        return {
            "file": filename,
            "findings": findings,
            "total": len(findings),
            "summary": summary,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }

    def scan_dependencies(self, package_content: str, pkg_format: str = "requirements") -> Dict[str, Any]:
        """依赖漏洞扫描"""
        vulns = [
            {"package": "requests", "installed": "2.25.0", "fixed": "2.31.0", "cve": "CVE-2023-32681", "severity": "high"},
            {"package": "django", "installed": "3.2.0", "fixed": "3.2.24", "cve": "CVE-2024-2046", "severity": "critical"},
            {"package": "pyyaml", "installed": "5.1", "fixed": "5.4", "cve": "CVE-2020-1747", "severity": "high"},
        ]
        return {"format": pkg_format, "vulnerabilities": vulns, "total": len(vulns), "outdated": 3}

    def code_quality(self, code: str, language: str = "python") -> Dict[str, Any]:
        """代码质量分析"""
        lines = code.split("\n")
        return {
            "language": language,
            "total_lines": len(lines),
            "blank_lines": sum(1 for l in lines if not l.strip()),
            "comment_lines": sum(1 for l in lines if l.strip().startswith("#") or l.strip().startswith("//")),
            "complexity_score": 7.2,
            "duplication_pct": 3.5,
            "suggestions": [
                "建议添加类型注解",
                "函数长度超过 50 行，建议拆分",
                "缺少模块级文档字符串",
            ],
        }


# ==================== 渗透测试辅助 ====================

class PentestHelper:
    """渗透测试辅助工具集"""

    # ---- Payload 生成 ----
    PAYLOAD_TEMPLATES: Dict[str, List[str]] = {
        "xss": [
            "<script>alert('XSS')</script>",
            "\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
        ],
        "sqli": [
            "' OR '1'='1",
            "' UNION SELECT NULL,NULL--",
            "1' AND SLEEP(5)--",
            "' OR 1=1#",
        ],
        "rce": [
            ";cat /etc/passwd",
            "$(whoami)",
            "|id",
            "&&whoami",
        ],
        "ssrf": [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:8080/admin",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
        ],
    }

    @classmethod
    def generate_payload(cls, category: str = "xss", count: int = 4) -> List[str]:
        templates = cls.PAYLOAD_TEMPLATES.get(category.lower(), [])
        return templates[:count] if templates else []

    # ---- 编码解码 ----
    @staticmethod
    def encode(data: str, enc: str = "base64") -> str:
        if enc == "base64":
            return base64.b64encode(data.encode()).decode()
        if enc == "url":
            from urllib.parse import quote
            return quote(data)
        if enc == "hex":
            return data.encode().hex()
        if enc == "html":
            return data.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        return data

    @staticmethod
    def decode(data: str, enc: str = "base64") -> str:
        try:
            if enc == "base64":
                return base64.b64decode(data).decode(errors="replace")
            if enc == "url":
                from urllib.parse import unquote
                return unquote(data)
            if enc == "hex":
                return bytes.fromhex(data).decode(errors="replace")
            if enc == "html":
                return data.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
        except Exception:
            return "(解码失败)"
        return data

    # ---- Hash 计算 ----
    @staticmethod
    def hash_value(data: str, algo: str = "sha256") -> str:
        h = hashlib.new(algo)
        h.update(data.encode())
        return h.hexdigest()

    # ---- 加密解密 ----
    @staticmethod
    def encrypt_simple(data: str, key: str = "key", algo: str = "xor") -> str:
        if algo == "xor":
            result = []
            for i, ch in enumerate(data):
                result.append(chr(ord(ch) ^ ord(key[i % len(key)])))
            return base64.b64encode("".join(result).encode()).decode()
        return data

    # ---- 正则测试 ----
    @staticmethod
    def regex_test(pattern: str, text: str, flags: str = "") -> Dict[str, Any]:
        fl = 0
        if "i" in flags:
            fl |= re.IGNORECASE
        if "m" in flags:
            fl |= re.MULTILINE
        try:
            matches = list(re.finditer(pattern, text, fl))
            return {
                "pattern": pattern, "matches": len(matches),
                "groups": [m.groups() for m in matches[:10]],
                "positions": [m.span() for m in matches[:10]],
            }
        except re.error as e:
            return {"pattern": pattern, "error": str(e), "matches": 0}

    # ---- HTTP 请求构造 ----
    @staticmethod
    def build_request(method: str, url: str, headers: Optional[Dict[str, str]] = None,
                      body: str = "") -> Dict[str, Any]:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return {
            "method": method.upper(),
            "url": url,
            "host": parsed.hostname,
            "path": parsed.path or "/",
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "scheme": parsed.scheme,
            "headers": headers or {"User-Agent": "aha-ide/1.4", "Accept": "*/*"},
            "body": body,
            "raw": f"{method.upper()} {parsed.path or '/'} HTTP/1.1\r\nHost: {parsed.hostname}\r\n\r\n{body}",
        }


# ==================== 安全知识库 ====================

class SecurityKnowledgeBase:
    """安全知识库查询"""

    CVE_DB: Dict[str, Dict[str, Any]] = {
        "CVE-2024-23334": {"product": "aiohttp", "cvss": 7.5, "severity": "high", "description": "路径遍历漏洞", "references": ["https://example.com/cve-2024-23334"]},
        "CVE-2023-46805": {"product": "nginx", "cvss": 5.3, "severity": "medium", "description": "信息泄露", "references": []},
        "CVE-2024-2046": {"product": "django", "cvss": 9.8, "severity": "critical", "description": "SQL注入", "references": []},
    }

    CWE_DB: Dict[str, Dict[str, str]] = {
        "CWE-79": {"name": "跨站脚本 (XSS)", "category": "注入"},
        "CWE-89": {"name": "SQL注入", "category": "注入"},
        "CWE-78": {"name": "OS命令注入", "category": "注入"},
        "CWE-22": {"name": "路径遍历", "category": "文件操作"},
        "CWE-312": {"name": "明文存储敏感信息", "category": "加密"},
        "CWE-862": {"name": "缺少授权", "category": "访问控制"},
    }

    OWASP_TOP10: Dict[str, str] = {
        "A01": "失效的访问控制",
        "A02": "加密机制失效",
        "A03": "注入",
        "A04": "不安全设计",
        "A05": "安全配置错误",
        "A06": "脆弱和过时的组件",
        "A07": "身份识别和身份验证错误",
        "A08": "软件和数据完整性故障",
        "A09": "安全日志和监控失败",
        "A10": "服务器端请求伪造 (SSRF)",
    }

    ATTACK_TECHNIQUES: Dict[str, Dict[str, str]] = {
        "T1190": {"name": "利用公开-facing应用", "tactic": "initial-access"},
        "T1078": {"name": "有效账户", "tactic": "initial-access"},
        "T1059": {"name": "命令和脚本解释器", "tactic": "execution"},
        "T1027": {"name": "混淆文件或信息", "tactic": "defense-evasion"},
        "T1003": {"name": "操作系统凭证转储", "tactic": "credential-access"},
    }

    @classmethod
    def query_cve(cls, cve_id: str) -> Dict[str, Any]:
        cve_id = cve_id.upper().strip()
        return cls.CVE_DB.get(cve_id, {"error": "未找到该 CVE", "id": cve_id})

    @classmethod
    def query_cwe(cls, cwe_id: str) -> Dict[str, Any]:
        cwe_id = cwe_id.upper().strip()
        return cls.CWE_DB.get(cwe_id, {"error": "未找到该 CWE", "id": cwe_id})

    @classmethod
    def query_owasp(cls, category: str = "") -> Dict[str, Any]:
        if category:
            return {category: cls.OWASP_TOP10.get(category.upper(), "未找到")}
        return cls.OWASP_TOP10

    @classmethod
    def query_attack(cls, technique_id: str = "") -> Dict[str, Any]:
        if technique_id:
            return cls.ATTACK_TECHNIQUES.get(technique_id.upper(), {"error": "未找到"})
        return cls.ATTACK_TECHNIQUES

    @classmethod
    def best_practices(cls, topic: str = "") -> List[Dict[str, str]]:
        practices = [
            {"topic": "认证", "title": "使用多因素认证", "detail": "强制所有用户启用 MFA"},
            {"topic": "密码", "title": "密码策略", "detail": "最小长度12位，包含大小写数字符号"},
            {"topic": "加密", "title": "传输加密", "detail": "全站启用 HTTPS，禁用弱加密套件"},
            {"topic": "输入", "title": "输入验证", "detail": "所有用户输入必须服务端验证"},
            {"topic": "日志", "title": "审计日志", "detail": "记录所有敏感操作，保留180天"},
        ]
        if topic:
            return [p for p in practices if topic.lower() in p["topic"].lower()]
        return practices


# ==================== 集成功能 ====================

class PluginIntegration:
    """与安全平台集成"""

    def __init__(self):
        self.api_endpoint: str = "http://127.0.0.1:8000"
        self.api_key: str = ""
        self.sync_enabled: bool = False
        self.tasks: List[Dict[str, Any]] = []
        self.reports: List[Dict[str, Any]] = []
        self.assets: List[Dict[str, Any]] = []

    def connect(self, endpoint: str, api_key: str) -> Dict[str, Any]:
        self.api_endpoint = endpoint
        self.api_key = api_key
        return {"connected": True, "endpoint": endpoint, "authenticated": bool(api_key)}

    def list_remote_tasks(self) -> List[Dict[str, Any]]:
        return self.tasks or [
            {"id": "t1", "type": "port_scan", "status": "completed", "target": "10.0.0.1"},
            {"id": "t2", "type": "web_scan", "status": "running", "target": "https://demo.test"},
        ]

    def list_remote_reports(self) -> List[Dict[str, Any]]:
        return self.reports or [
            {"id": "r1", "title": "9月安全报告", "date": "2026-09-01", "vulns": 12},
        ]

    def sync_assets(self) -> Dict[str, Any]:
        return {"synced": True, "assets_synced": 42, "last_sync": datetime.now().isoformat(timespec="seconds")}

    def push_notification(self, title: str, body: str) -> Dict[str, Any]:
        return {"pushed": True, "title": title, "body": body}


# ==================== 插件市场 ====================

class PluginMarketplace:
    """IDE 插件市场"""

    def __init__(self):
        self.plugins: Dict[str, Dict[str, Any]] = {
            "aha-security-scan": {
                "id": "aha-security-scan", "name": "AHA Security Scanner",
                "publisher": "AHA Team", "version": "1.4.0",
                "description": "实时代码安全扫描与漏洞检测",
                "category": "Security", "rating": 4.8, "downloads": 15234,
                "price": "Free", "installs": 12000, "verified": True,
            },
            "aha-pentest-toolkit": {
                "id": "aha-pentest-toolkit", "name": "AHA Pentest Toolkit",
                "publisher": "AHA Team", "version": "2.1.0",
                "description": "渗透测试辅助工具集",
                "category": "Security", "rating": 4.6, "downloads": 8934,
                "price": "Free", "installs": 7200, "verified": True,
            },
            "aha-threat-intel": {
                "id": "aha-threat-intel", "name": "AHA Threat Intelligence",
                "publisher": "AHA Team", "version": "1.0.5",
                "description": "威胁情报实时推送",
                "category": "Security", "rating": 4.3, "downloads": 3200,
                "price": "$5/月", "installs": 2100, "verified": True,
            },
        }
        self.installed: List[str] = ["aha-security-scan"]

    def list(self, category: str = "", search: str = "") -> List[Dict[str, Any]]:
        items = list(self.plugins.values())
        if category:
            items = [p for p in items if p["category"] == category]
        if search:
            s = search.lower()
            items = [p for p in items if s in p["name"].lower() or s in p["description"].lower()]
        return items

    def detail(self, plugin_id: str) -> Dict[str, Any]:
        return self.plugins.get(plugin_id, {"error": "插件不存在"})

    def install(self, plugin_id: str) -> Dict[str, Any]:
        if plugin_id in self.plugins and plugin_id not in self.installed:
            self.installed.append(plugin_id)
            return {"installed": True, "plugin_id": plugin_id, "version": self.plugins[plugin_id]["version"]}
        return {"installed": False, "reason": "已安装或不存在"}

    def uninstall(self, plugin_id: str) -> Dict[str, Any]:
        if plugin_id in self.installed:
            self.installed.remove(plugin_id)
        return {"uninstalled": True, "plugin_id": plugin_id}

    def update(self, plugin_id: str) -> Dict[str, Any]:
        return {"updated": True, "plugin_id": plugin_id, "old_version": "1.3.0", "new_version": "1.4.0"}

    def rate(self, plugin_id: str, score: int, comment: str = "") -> Dict[str, Any]:
        return {"rated": True, "plugin_id": plugin_id, "score": score, "comment": comment}


# ==================== 单例 ====================

ide_plugin_core = IDEPluginCore()
code_scanner = CodeSecurityScanner()
pentest_helper = PentestHelper()
knowledge_base = SecurityKnowledgeBase()
plugin_integration = PluginIntegration()
plugin_marketplace = PluginMarketplace()

__all__ = [
    "IDECommand", "IDESetting", "IDEPluginCore",
    "CodeSecurityScanner", "PentestHelper", "SecurityKnowledgeBase",
    "PluginIntegration", "PluginMarketplace",
    "ide_plugin_core", "code_scanner", "pentest_helper",
    "knowledge_base", "plugin_integration", "plugin_marketplace",
]
