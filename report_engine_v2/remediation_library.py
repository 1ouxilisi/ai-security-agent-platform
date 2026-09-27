#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复建议库
提供各类漏洞的详细修复方案、代码示例、最佳实践
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class Remediation:
    """修复方案"""
    vulnerability_type: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    code_examples: Dict[str, str] = field(default_factory=dict)
    best_practices: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cwe_id: str = ""
    owasp_category: str = ""


class RemediationLibrary:
    """修复建议库"""

    def __init__(self):
        self._library: Dict[str, Remediation] = {}
        self._init_library()

    def _init_library(self):
        """初始化修复库"""
        self._library = {
            "sql_injection": self._sql_injection_remediation(),
            "sqli": self._sql_injection_remediation(),
            "xss": self._xss_remediation(),
            "rce": self._rce_remediation(),
            "ssrf": self._ssrf_remediation(),
            "lfi": self._lfi_remediation(),
            "path_traversal": self._path_traversal_remediation(),
            "command_injection": self._command_injection_remediation(),
            "open_redirect": self._open_redirect_remediation(),
            "information_disclosure": self._info_disclosure_remediation(),
            "authentication_bypass": self._auth_bypass_remediation(),
            "privilege_escalation": self._privesc_remediation(),
            "csrf": self._csrf_remediation(),
            "deserialization": self._deserialization_remediation(),
            "xxe": self._xxe_remediation(),
            "insecure_deserialization": self._deserialization_remediation(),
            "file_upload": self._file_upload_remediation(),
            "weak_password": self._weak_password_remediation(),
            "hardcoded_credentials": self._hardcoded_creds_remediation(),
            "ssl_tls": self._ssl_tls_remediation(),
            "misconfiguration": self._misconfig_remediation(),
            "default_credentials": self._default_creds_remediation(),
            "exposed_panel": self._exposed_panel_remediation(),
            "outdated_component": self._outdated_component_remediation(),
        }

    def _sql_injection_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="sql_injection",
            severity="critical",
            title="SQL注入漏洞修复方案",
            description="SQL注入是由于未对用户输入进行正确过滤和转义，导致攻击者可以篡改SQL查询语句。",
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
            remediation_steps=[
                "使用参数化查询/预编译语句（Prepared Statements）",
                "对用户输入进行严格的白名单验证",
                "使用ORM框架（如SQLAlchemy、Hibernate）",
                "最小化数据库账户权限",
                "实施Web应用防火墙（WAF）作为防御层",
                "对数据库错误信息进行脱敏处理",
            ],
            code_examples={
                "python_secure": """# 安全：使用参数化查询
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# 使用SQLAlchemy ORM
user = session.query(User).filter(User.username == username).first()""",
                "python_insecure": """# 不安全：字符串拼接
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)""",
                "java_secure": """// 安全：使用PreparedStatement
String sql = "SELECT * FROM users WHERE username = ?";
PreparedStatement stmt = conn.prepareStatement(sql);
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();""",
                "php_secure": """// 安全：使用PDO预处理
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = :username');
$stmt->execute(['username' => $username]);""",
            },
            best_practices=[
                "永远不要信任用户输入",
                "使用最小权限原则配置数据库账户",
                "定期进行SQL注入安全测试",
                "实施输入验证和输出编码",
                "使用数据库连接池和参数绑定",
            ],
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
        )

    def _xss_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="xss",
            severity="high",
            title="跨站脚本(XSS)漏洞修复方案",
            description="XSS漏洞允许攻击者在受害者浏览器中执行恶意脚本，可能导致会话劫持、钓鱼攻击等。",
            cwe_id="CWE-79",
            owasp_category="A03:2021 - Injection",
            remediation_steps=[
                "对所有输出进行HTML实体编码",
                "使用上下文相关的输出编码（HTML/JS/URL/CSS）",
                "实施内容安全策略（CSP）",
                "使用HttpOnly和Secure标记的Cookie",
                "对用户输入进行白名单验证",
                "使用现代前端框架（React/Vue）的自动转义",
            ],
            code_examples={
                "python_flask": """# Flask/Jinja2默认自动转义
# 安全：使用模板自动转义
render_template('user.html', username=username)

# 不安全：使用Markup关闭转义
from markupsafe import Markup
render_template_string(Markup("<h1>" + username + "</h1>"))""",
                "javascript_secure": """// 安全：使用textContent
element.textContent = userInput;

// 不安全：使用innerHTML
element.innerHTML = userInput;""",
                "csp_header": """# 内容安全策略响应头
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-abc123'; style-src 'self'; img-src 'self' data:;""",
            },
            best_practices=[
                "实施CSP策略，限制脚本来源",
                "对所有用户输入进行验证和编码",
                "使用HttpOnly Cookie防止会话劫持",
                "定期进行XSS安全测试",
                "避免使用eval()和innerHTML",
            ],
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
        )

    def _rce_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="rce",
            severity="critical",
            title="远程代码执行(RCE)漏洞修复方案",
            description="远程代码执行漏洞允许攻击者在目标服务器上执行任意命令，是最严重的安全漏洞之一。",
            cwe_id="CWE-94",
            owasp_category="A03:2021 - Injection",
            remediation_steps=[
                "避免使用eval()、exec()等动态执行函数",
                "对用户输入进行严格的白名单验证",
                "使用沙箱环境执行不可信代码",
                "及时更新第三方组件和依赖",
                "实施Web应用防火墙（WAF）",
                "最小化应用程序运行权限",
                "禁用不必要的功能和服务",
            ],
            code_examples={
                "python_secure": """# 安全：使用白名单验证
ALLOWED_COMMANDS = {'list', 'status', 'help'}

def execute_command(cmd):
    if cmd not in ALLOWED_COMMANDS:
        raise ValueError("Invalid command")
    return run_allowed_command(cmd)""",
                "python_insecure": """# 不安全：直接执行用户输入
eval(user_input)
exec(user_input)
os.system(user_input)""",
            },
            best_practices=[
                "永远不要执行用户提供的代码",
                "使用最小权限原则运行应用",
                "及时修补已知漏洞",
                "实施入侵检测系统（IDS）",
                "定期进行渗透测试",
            ],
            references=[
                "https://owasp.org/www-community/attacks/Code_Injection",
                "https://cwe.mitre.org/data/definitions/94.html",
            ],
        )

    def _ssrf_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="ssrf",
            severity="high",
            title="服务器端请求伪造(SSRF)修复方案",
            description="SSRF漏洞允许攻击者诱导服务器向内部或外部资源发起请求，可能导致内网探测、云元数据泄露等。",
            cwe_id="CWE-918",
            owasp_category="A10:2021 - Server-Side Request Forgery",
            remediation_steps=[
                "对目标URL进行白名单验证",
                "禁止访问内网IP地址段（10.x, 172.16-31.x, 192.168.x, 127.x）",
                "禁止访问云元数据服务（169.254.169.254）",
                "禁用不必要的URL协议（file://, gopher://, dict://）",
                "实施网络分段和防火墙规则",
                "对响应内容进行验证和过滤",
            ],
            code_examples={
                "python_secure": """import ipaddress
from urllib.parse import urlparse

def is_safe_url(url):
    try:
        parsed = urlparse(url)
        # 只允许http和https
        if parsed.scheme not in ('http', 'https'):
            return False
        # 检查是否为内网IP
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
        return True
    except:
        return False""",
            },
            best_practices=[
                "实施URL白名单验证",
                "网络层面限制出站访问",
                "禁用危险的URL协议",
                "定期进行SSRF安全测试",
                "监控异常的服务器请求",
            ],
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cwe.mitre.org/data/definitions/918.html",
            ],
        )

    def _lfi_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="lfi",
            severity="high",
            title="本地文件包含(LFI)漏洞修复方案",
            description="LFI漏洞允许攻击者读取服务器上的任意文件，可能导致敏感信息泄露、代码执行等。",
            cwe_id="CWE-98",
            owasp_category="A03:2021 - Injection",
            remediation_steps=[
                "对文件路径进行白名单验证",
                "使用basename()去除路径中的目录部分",
                "禁止使用用户输入直接作为文件路径",
                "将包含文件限制在特定目录",
                "关闭allow_url_include（PHP）",
                "实施文件系统权限最小化",
            ],
            code_examples={
                "python_secure": """import os

ALLOWED_DIR = "/var/www/templates"

def load_template(name):
    # 使用basename去除路径遍历
    safe_name = os.path.basename(name)
    path = os.path.join(ALLOWED_DIR, safe_name)
    # 验证路径在允许目录内
    if not path.startswith(ALLOWED_DIR):
        raise ValueError("Invalid path")
    with open(path) as f:
        return f.read()""",
            },
            best_practices=[
                "永远不要信任用户提供的文件路径",
                "使用白名单验证文件名",
                "实施文件系统权限控制",
                "定期进行LFI安全测试",
            ],
            references=[
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cwe.mitre.org/data/definitions/98.html",
            ],
        )

    def _path_traversal_remediation(self) -> Remediation:
        r = self._lfi_remediation()
        r.vulnerability_type = "path_traversal"
        r.title = "路径遍历漏洞修复方案"
        r.cwe_id = "CWE-22"
        return r

    def _command_injection_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="command_injection",
            severity="critical",
            title="命令注入漏洞修复方案",
            description="命令注入漏洞允许攻击者在服务器上执行任意系统命令，可能导致完全的系统沦陷。",
            cwe_id="CWE-78",
            owasp_category="A03:2021 - Injection",
            remediation_steps=[
                "避免使用system()、exec()等执行系统命令的函数",
                "使用参数化的API而非shell命令",
                "对用户输入进行严格的白名单验证",
                "使用安全的库函数（如subprocess.run with shell=False）",
                "最小化应用程序运行权限",
                "实施Web应用防火墙（WAF）",
            ],
            code_examples={
                "python_secure": """import subprocess

# 安全：使用参数列表，shell=False
subprocess.run(["ping", "-c", "1", host], shell=False)

# 安全：白名单验证
ALLOWED_HOSTS = {'example.com', 'test.com'}
def ping_host(host):
    if host not in ALLOWED_HOSTS:
        raise ValueError("Invalid host")
    subprocess.run(["ping", "-c", "1", host])""",
                "python_insecure": """# 不安全：shell=True + 字符串拼接
os.system("ping " + user_input)
subprocess.run("ping " + user_input, shell=True)""",
            },
            best_practices=[
                "避免使用shell执行命令",
                "使用参数化的API调用",
                "实施输入白名单验证",
                "最小权限原则运行应用",
                "定期进行命令注入测试",
            ],
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cwe.mitre.org/data/definitions/78.html",
            ],
        )

    def _open_redirect_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="open_redirect",
            severity="medium",
            title="开放重定向漏洞修复方案",
            description="开放重定向漏洞允许攻击者将用户重定向到恶意网站，常用于钓鱼攻击。",
            cwe_id="CWE-601",
            owasp_category="A01:2021 - Broken Access Control",
            remediation_steps=[
                "对重定向URL进行白名单验证",
                "使用相对路径而非绝对URL",
                "避免直接使用用户输入作为重定向目标",
                "实施重定向确认页面",
            ],
            code_examples={
                "python_secure": """from urllib.parse import urlparse

ALLOWED_DOMAINS = {'example.com', 'www.example.com'}

def safe_redirect(url):
    parsed = urlparse(url)
    if parsed.netloc not in ALLOWED_DOMAINS:
        return "/"  # 重定向到首页
    return url""",
            },
            best_practices=[
                "实施URL白名单验证",
                "使用相对路径重定向",
                "避免在URL参数中传递重定向目标",
                "定期进行安全测试",
            ],
            references=[
                "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
                "https://cwe.mitre.org/data/definitions/601.html",
            ],
        )

    def _info_disclosure_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="information_disclosure",
            severity="medium",
            title="信息泄露漏洞修复方案",
            description="信息泄露漏洞可能暴露敏感信息，如配置文件、源代码、用户数据等。",
            cwe_id="CWE-200",
            owasp_category="A05:2021 - Security Misconfiguration",
            remediation_steps=[
                "移除或限制访问敏感文件（.git, .env, backup等）",
                "关闭目录列表功能",
                "对错误信息进行脱敏处理",
                "移除HTTP响应头中的版本信息",
                "实施访问控制和身份验证",
                "定期检查敏感文件暴露",
            ],
            code_examples={
                "nginx_config": """# Nginx配置：禁止访问敏感文件
location ~ /\\.(git|env|svn|hg) {
    deny all;
    return 404;
}

# 关闭目录列表
autoindex off;

# 隐藏版本信息
server_tokens off;""",
                "apache_config": """# Apache配置
<FilesMatch "\\.(git|env|bak|old|sql)$">
    Require all denied
</FilesMatch>""",
            },
            best_practices=[
                "定期扫描敏感文件暴露",
                "实施适当的访问控制",
                "错误信息脱敏处理",
                "隐藏服务器版本信息",
                "定期进行安全配置审计",
            ],
            references=[
                "https://owasp.org/www-community/attacks/Information_Leakage",
                "https://cwe.mitre.org/data/definitions/200.html",
            ],
        )

    def _auth_bypass_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="authentication_bypass",
            severity="critical",
            title="认证绕过漏洞修复方案",
            description="认证绕过漏洞允许攻击者在没有有效凭据的情况下访问受保护的资源。",
            cwe_id="CWE-287",
            owasp_category="A07:2021 - Identification and Authentication Failures",
            remediation_steps=[
                "在服务器端实施严格的身份验证",
                "使用安全的会话管理机制",
                "实施多因素认证（MFA）",
                "对所有受保护资源进行访问控制检查",
                "使用安全的密码哈希算法（bcrypt, Argon2）",
                "实施账户锁定和暴力破解防护",
            ],
            best_practices=[
                "永远不要信任客户端的认证状态",
                "使用安全的会话管理",
                "实施多因素认证",
                "定期进行认证安全测试",
                "使用安全的密码存储方式",
            ],
            references=[
                "https://owasp.org/www-community/attacks/Authentication_Bypass",
                "https://cwe.mitre.org/data/definitions/287.html",
            ],
        )

    def _privesc_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="privilege_escalation",
            severity="high",
            title="权限提升漏洞修复方案",
            description="权限提升漏洞允许低权限用户获得更高的系统权限。",
            cwe_id="CWE-269",
            owasp_category="A01:2021 - Broken Access Control",
            remediation_steps=[
                "实施最小权限原则",
                "定期审查用户权限和角色",
                "及时修补操作系统和应用程序漏洞",
                "实施严格的访问控制检查",
                "使用sudo等工具限制特权操作",
                "监控异常的权限变更",
            ],
            best_practices=[
                "实施最小权限原则",
                "定期权限审计",
                "及时修补已知漏洞",
                "实施特权操作监控",
            ],
            references=[
                "https://owasp.org/www-community/attacks/Privilege_Escalation",
                "https://cwe.mitre.org/data/definitions/269.html",
            ],
        )

    def _csrf_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="csrf",
            severity="medium",
            title="跨站请求伪造(CSRF)修复方案",
            description="CSRF漏洞允许攻击者诱导已登录用户执行非预期的操作。",
            cwe_id="CWE-352",
            owasp_category="A01:2021 - Broken Access Control",
            remediation_steps=[
                "实施CSRF Token验证",
                "使用SameSite Cookie属性",
                "验证Referer/Origin头",
                "对敏感操作要求重新认证",
                "使用自定义请求头（如X-Requested-With）",
            ],
            code_examples={
                "python_flask": """# Flask-WTF CSRF保护
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# 表单中包含CSRF token
<form method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
</form>""",
                "cookie_samesite": """# 设置SameSite Cookie
Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly""",
            },
            best_practices=[
                "实施CSRF Token保护",
                "使用SameSite Cookie属性",
                "对敏感操作要求重新认证",
                "定期进行CSRF安全测试",
            ],
            references=[
                "https://owasp.org/www-community/attacks/csrf",
                "https://cwe.mitre.org/data/definitions/352.html",
            ],
        )

    def _deserialization_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="deserialization",
            severity="critical",
            title="不安全反序列化漏洞修复方案",
            description="不安全反序列化漏洞允许攻击者通过构造恶意序列化数据执行任意代码。",
            cwe_id="CWE-502",
            owasp_category="A08:2021 - Software and Data Integrity Failures",
            remediation_steps=[
                "避免反序列化不可信数据",
                "使用安全的数据格式（JSON）",
                "实施类型白名单验证",
                "对序列化数据进行签名验证",
                "及时更新存在反序列化漏洞的库",
                "使用沙箱环境处理不可信数据",
            ],
            code_examples={
                "python_secure": """# 安全：使用JSON
import json
data = json.loads(user_input)

# 不安全：使用pickle
import pickle
data = pickle.loads(user_input)  # 危险！""",
            },
            best_practices=[
                "避免反序列化不可信数据",
                "使用JSON等安全格式",
                "实施数据签名验证",
                "及时更新存在漏洞的库",
                "定期进行反序列化测试",
            ],
            references=[
                "https://owasp.org/www-community/attacks/Deserialization_of_untrusted_data",
                "https://cwe.mitre.org/data/definitions/502.html",
            ],
        )

    def _xxe_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="xxe",
            severity="high",
            title="XML外部实体(XXE)注入修复方案",
            description="XXE漏洞允许攻击者通过构造恶意XML读取本地文件或发起SSRF攻击。",
            cwe_id="CWE-611",
            owasp_category="A05:2021 - Security Misconfiguration",
            remediation_steps=[
                "禁用XML解析器中的外部实体",
                "使用JSON等更安全的数据格式",
                "禁用DTD处理",
                "实施输入验证和过滤",
                "及时更新XML解析库",
            ],
            code_examples={
                "python_secure": """# 安全：禁用外部实体
import xml.etree.ElementTree as ET
# defusedxml更安全
from defusedxml import ElementTree as DET
tree = DET.parse(xml_data)""",
                "java_secure": """// 安全：禁用外部实体
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);""",
            },
            best_practices=[
                "禁用XML外部实体",
                "使用JSON替代XML",
                "及时更新XML解析库",
                "定期进行XXE安全测试",
            ],
            references=[
                "https://owasp.org/www-community/attacks/xxe",
                "https://cwe.mitre.org/data/definitions/611.html",
            ],
        )

    def _file_upload_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="file_upload",
            severity="high",
            title="不安全文件上传修复方案",
            description="不安全文件上传可能导致恶意文件执行、WebShell上传等严重后果。",
            cwe_id="CWE-434",
            owasp_category="A04:2021 - Insecure Design",
            remediation_steps=[
                "实施文件类型白名单验证",
                "验证文件内容而非仅扩展名",
                "重命名上传文件",
                "将上传文件存储在Web根目录之外",
                "设置上传目录的执行权限为不可执行",
                "实施文件大小限制",
                "使用病毒扫描",
            ],
            best_practices=[
                "实施文件类型白名单",
                "验证文件内容",
                "存储在非Web可访问目录",
                "禁用上传目录的脚本执行",
                "定期进行文件上传安全测试",
            ],
            references=[
                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                "https://cwe.mitre.org/data/definitions/434.html",
            ],
        )

    def _weak_password_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="weak_password",
            severity="medium",
            title="弱密码策略修复方案",
            description="弱密码策略可能导致账户被暴力破解。",
            cwe_id="CWE-521",
            owasp_category="A07:2021 - Identification and Authentication Failures",
            remediation_steps=[
                "实施强密码策略（最小长度、复杂度要求）",
                "使用安全的密码哈希算法（bcrypt, Argon2, scrypt）",
                "实施账户锁定机制",
                "鼓励使用密码管理器",
                "实施多因素认证（MFA）",
                "定期要求密码更新",
            ],
            best_practices=[
                "使用bcrypt/Argon2哈希密码",
                "实施强密码策略",
                "启用多因素认证",
                "实施账户锁定机制",
            ],
            references=[
                "https://owasp.org/www-community/controls/Password_Storage_Cheat_Sheet",
                "https://cwe.mitre.org/data/definitions/521.html",
            ],
        )

    def _hardcoded_creds_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="hardcoded_credentials",
            severity="high",
            title="硬编码凭据修复方案",
            description="硬编码凭据可能导致源代码泄露后账户被直接访问。",
            cwe_id="CWE-798",
            owasp_category="A07:2021 - Identification and Authentication Failures",
            remediation_steps=[
                "从代码中移除所有硬编码凭据",
                "使用环境变量存储敏感配置",
                "使用密钥管理服务（如AWS KMS, HashiCorp Vault）",
                "使用配置文件并加入.gitignore",
                "实施密钥轮换机制",
                "定期扫描代码中的硬编码密钥",
            ],
            code_examples={
                "python_secure": """# 安全：使用环境变量
import os
db_password = os.environ.get("DB_PASSWORD")
api_key = os.environ.get("API_KEY")

# 使用python-dotenv
from dotenv import load_dotenv
load_dotenv()  # 从.env文件加载""",
                "python_insecure": """# 不安全：硬编码凭据
DB_PASSWORD = "supersecret123"
API_KEY = "sk-1234567890abcdef" """,
            },
            best_practices=[
                "使用环境变量和密钥管理服务",
                "将配置文件加入.gitignore",
                "实施密钥轮换机制",
                "定期扫描代码中的硬编码密钥",
            ],
            references=[
                "https://owasp.org/www-community/controls/Key_Management_Cheat_Sheet",
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
        )

    def _ssl_tls_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="ssl_tls",
            severity="medium",
            title="SSL/TLS配置修复方案",
            description="不安全的SSL/TLS配置可能导致数据被窃听或篡改。",
            cwe_id="CWE-327",
            owasp_category="A02:2021 - Cryptographic Failures",
            remediation_steps=[
                "禁用SSLv3、TLS 1.0、TLS 1.1",
                "使用TLS 1.2或更高版本",
                "禁用弱密码套件",
                "实施HSTS（HTTP Strict Transport Security）",
                "使用强加密算法（AES-256, ChaCha20）",
                "定期更新SSL证书",
                "实施证书透明度监控",
            ],
            code_examples={
                "nginx_config": """# Nginx TLS配置
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;
add_header Strict-Transport-Security "max-age=63072000" always;""",
            },
            best_practices=[
                "使用TLS 1.2+",
                "禁用弱密码套件",
                "实施HSTS",
                "定期更新证书",
                "使用SSL Labs测试配置",
            ],
            references=[
                "https://owasp.org/www-community/controls/Transport_Layer_Protection_Cheat_Sheet",
                "https://cwe.mitre.org/data/definitions/327.html",
            ],
        )

    def _misconfig_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="misconfiguration",
            severity="medium",
            title="安全配置错误修复方案",
            description="安全配置错误是最常见的漏洞之一，包括默认配置、不必要的功能、错误信息泄露等。",
            cwe_id="CWE-16",
            owasp_category="A05:2021 - Security Misconfiguration",
            remediation_steps=[
                "移除默认账户和默认密码",
                "关闭不必要的服务和功能",
                "实施安全的错误处理（不泄露内部信息）",
                "实施安全响应头（CSP, X-Frame-Options, X-Content-Type-Options）",
                "定期进行安全配置审计",
                "使用自动化配置管理工具",
                "实施最小权限原则",
            ],
            best_practices=[
                "实施安全基线配置",
                "定期配置审计",
                "关闭不必要的功能",
                "使用自动化配置管理",
            ],
            references=[
                "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
                "https://cwe.mitre.org/data/definitions/16.html",
            ],
        )

    def _default_creds_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="default_credentials",
            severity="high",
            title="默认凭据修复方案",
            description="默认账户和密码是最常见的安全风险之一。",
            cwe_id="CWE-798",
            owasp_category="A07:2021 - Identification and Authentication Failures",
            remediation_steps=[
                "修改所有默认账户密码",
                "禁用或删除不必要的默认账户",
                "实施首次登录强制修改密码",
                "使用强密码策略",
                "实施多因素认证",
                "定期扫描默认凭据",
            ],
            best_practices=[
                "修改所有默认密码",
                "禁用不必要的默认账户",
                "实施首次登录密码修改",
                "定期扫描默认凭据",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
        )

    def _exposed_panel_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="exposed_panel",
            severity="medium",
            title="管理面板暴露修复方案",
            description="管理面板直接暴露在公网可能导致未授权访问。",
            cwe_id="CWE-284",
            owasp_category="A01:2021 - Broken Access Control",
            remediation_steps=[
                "将管理面板放在内网或VPN后",
                "实施IP白名单限制",
                "实施强身份验证和多因素认证",
                "修改默认管理路径",
                "实施访问日志和监控",
                "使用Web应用防火墙保护",
            ],
            best_practices=[
                "管理面板不直接暴露公网",
                "实施IP白名单",
                "强身份验证+MFA",
                "访问日志监控",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/284.html",
            ],
        )

    def _outdated_component_remediation(self) -> Remediation:
        return Remediation(
            vulnerability_type="outdated_component",
            severity="high",
            title="使用含已知漏洞的组件修复方案",
            description="使用过时的、含已知漏洞的组件可能导致安全风险。",
            cwe_id="CWE-1104",
            owasp_category="A06:2021 - Vulnerable and Outdated Components",
            remediation_steps=[
                "建立软件物料清单（SBOM）",
                "定期扫描依赖漏洞（npm audit, pip-audit, OWASP Dependency-Check）",
                "及时更新存在漏洞的组件",
                "移除未使用的依赖",
                "使用依赖锁定文件确保版本一致性",
                "实施自动化依赖更新工具（Dependabot, Renovate）",
                "监控安全公告和CVE数据库",
            ],
            best_practices=[
                "定期依赖漏洞扫描",
                "及时更新有漏洞的组件",
                "移除未使用的依赖",
                "使用自动化依赖更新",
                "监控CVE公告",
            ],
            references=[
                "https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components",
                "https://cwe.mitre.org/data/definitions/1104.html",
            ],
        )

    # ==================== 公共方法 ====================

    def get_remediation(self, vulnerability_type: str) -> Optional[Remediation]:
        """获取修复方案"""
        return self._library.get(vulnerability_type.lower())

    def search_remediation(self, keyword: str) -> List[Remediation]:
        """搜索修复方案"""
        keyword = keyword.lower()
        results = []
        for r in self._library.values():
            if (keyword in r.vulnerability_type.lower() or
                keyword in r.title.lower() or
                keyword in r.description.lower() or
                keyword in r.cwe_id.lower()):
                results.append(r)
        return results

    def get_all_types(self) -> List[str]:
        """获取所有支持的漏洞类型"""
        return list(self._library.keys())

    def get_stats(self) -> Dict:
        """获取统计信息"""
        by_severity = {}
        for r in self._library.values():
            by_severity[r.severity] = by_severity.get(r.severity, 0) + 1
        return {
            "total": len(self._library),
            "by_severity": by_severity,
        }

    def to_dict(self, remediation: Remediation) -> Dict:
        """转换为字典"""
        return {
            "vulnerability_type": remediation.vulnerability_type,
            "severity": remediation.severity,
            "title": remediation.title,
            "description": remediation.description,
            "remediation_steps": remediation.remediation_steps,
            "code_examples": remediation.code_examples,
            "best_practices": remediation.best_practices,
            "references": remediation.references,
            "cwe_id": remediation.cwe_id,
            "owasp_category": remediation.owasp_category,
        }
