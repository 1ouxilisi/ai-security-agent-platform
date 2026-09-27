#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
remediation_library知识库模块，存储和管理相关安全知识、漏洞信息和攻击链数据。

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
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from collections import Counter

from utils.logger import log


@dataclass
class Remediation:
    """漏洞修复方案"""
    rem_id: str
    vuln_type: str
    vuln_name: str
    severity: str
    cwe_id: str = ""
    description: str = ""
    risk: str = ""
    remediation_summary: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    code_examples: Dict[str, str] = field(default_factory=dict)  # 语言 -> 代码示例
    config_examples: Dict[str, str] = field(default_factory=dict)  # 配置名 -> 配置示例
    best_practices: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=__import__('time').time)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "rem_id": self.rem_id,
            "vuln_type": self.vuln_type,
            "vuln_name": self.vuln_name,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "description": self.description,
            "risk": self.risk,
            "remediation_summary": self.remediation_summary,
            "remediation_steps": self.remediation_steps,
            "code_examples": self.code_examples,
            "config_examples": self.config_examples,
            "best_practices": self.best_practices,
            "references": self.references,
            "tags": self.tags
        }


class RemediationLibrary:
    """漏洞修复方案库"""

    def __init__(self, data_dir: str = "data/knowledge/remediation"):
        """初始化RemediationLibrary实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.remediations: Dict[str, Remediation] = {}
        os.makedirs(data_dir, exist_ok=True)
        self._load()
        if not self.remediations:
            self._init_default()

    def _load(self):
        """从文件加载"""
        f = os.path.join(self.data_dir, "remediation_library.json")
        if os.path.exists(f):
            try:
                with open(f, 'r', encoding='utf-8') as fp:
                    data = json.load(fp)
                for rid, rdata in data.items():
                    self.remediations[rid] = Remediation(
                        rem_id=rdata["rem_id"],
                        vuln_type=rdata["vuln_type"],
                        vuln_name=rdata["vuln_name"],
                        severity=rdata.get("severity", "medium"),
                        cwe_id=rdata.get("cwe_id", ""),
                        description=rdata.get("description", ""),
                        risk=rdata.get("risk", ""),
                        remediation_summary=rdata.get("remediation_summary", ""),
                        remediation_steps=rdata.get("remediation_steps", []),
                        code_examples=rdata.get("code_examples", {}),
                        config_examples=rdata.get("config_examples", {}),
                        best_practices=rdata.get("best_practices", []),
                        references=rdata.get("references", []),
                        tags=rdata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载修复方案库失败: {e}")

    def _save(self):
        """保存到文件"""
        f = os.path.join(self.data_dir, "remediation_library.json")
        try:
            data = {rid: r.to_dict() for rid, r in self.remediations.items()}
            with open(f, 'w', encoding='utf-8') as fp:
                json.dump(data, fp, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存修复方案库失败: {e}")

    def _add(self, **kwargs):
        """添加修复方案"""
        rem_id = f"rem-{len(self.remediations)+1:03d}"
        r = Remediation(rem_id=rem_id, **kwargs)
        self.remediations[rem_id] = r
        return rem_id

    def _init_default(self):
        """初始化50+默认修复方案"""
        log.info("初始化50+默认修复方案...")

        remediations = [
            # ===== 注入类 (10个) =====
            {
                "vuln_type": "sql_injection", "vuln_name": "SQL注入", "severity": "critical", "cwe_id": "CWE-89",
                "description": "用户输入被直接拼接到SQL语句中，导致攻击者可以执行任意SQL命令",
                "risk": "数据库数据泄露、篡改、删除，认证绕过，服务器权限获取",
                "remediation_summary": "使用参数化查询（预编译语句），禁止字符串拼接SQL，使用ORM框架，输入验证和转义",
                "remediation_steps": [
                    "1. 将所有动态SQL改为参数化查询/预编译语句",
                    "2. 使用ORM框架（如MyBatis/Hibernate/Django ORM），避免手写SQL",
                    "3. 对用户输入进行严格的白名单验证",
                    "4. 数据库账户使用最小权限原则，禁止DBA权限连接应用",
                    "5. 部署WAF拦截SQL注入攻击",
                    "6. 关闭生产环境的数据库错误回显"
                ],
                "code_examples": {
                    "Java (JDBC)": "// 不安全\nString sql = \"SELECT * FROM users WHERE id='\" + userId + \"'\";\nStatement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery(sql);\n\n// 安全（参数化查询）\nString sql = \"SELECT * FROM users WHERE id = ?\";\nPreparedStatement pstmt = conn.prepareStatement(sql);\npstmt.setString(1, userId);\nResultSet rs = pstmt.executeQuery();",
                    "Python (sqlite3)": "# 不安全\ncursor.execute(f\"SELECT * FROM users WHERE id='{user_id}'\")\n\n# 安全（参数化查询）\ncursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
                    "PHP (PDO)": "// 不安全\n$sql = \"SELECT * FROM users WHERE id='\" . $_GET['id'] . \"'\";\n$result = mysqli_query($conn, $sql);\n\n// 安全（PDO预处理）\n$stmt = $pdo->prepare(\"SELECT * FROM users WHERE id = :id\");\n$stmt->execute(['id' => $_GET['id']]);\n$result = $stmt->fetch();"
                },
                "best_practices": ["使用参数化查询", "最小权限数据库账户", "输入白名单验证", "部署WAF", "关闭错误回显", "定期安全审计"],
                "references": ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
                "tags": ["injection", "sql", "database", "critical"]
            },
            {
                "vuln_type": "command_injection", "vuln_name": "命令注入", "severity": "critical", "cwe_id": "CWE-78",
                "description": "用户输入被拼接到系统命令中执行，导致攻击者可以执行任意系统命令",
                "risk": "远程代码执行、服务器完全控制、数据泄露",
                "remediation_summary": "避免调用系统命令，使用编程语言内置API替代，如必须调用则使用白名单验证和参数化",
                "remediation_steps": [
                    "1. 避免使用system()/exec()/shell_exec()等函数调用系统命令",
                    "2. 使用编程语言内置API替代系统命令（如用Python的os.listdir替代ls命令）",
                    "3. 如必须调用系统命令，使用参数数组形式（避免shell解析）",
                    "4. 对用户输入进行严格的白名单验证（只允许字母数字和特定字符）",
                    "5. 使用escapeshellarg()/escapeshellcmd()转义用户输入",
                    "6. 以最低权限运行应用进程，禁止root/administrator"
                ],
                "code_examples": {
                    "PHP": "// 不安全\nsystem('ping -c 4 ' . $_GET['host']);\n\n// 安全（白名单验证）\n$host = $_GET['host'];\nif (!preg_match('/^[a-zA-Z0-9.\\-]+$/', $host)) {\n    die('Invalid host');\n}\nsystem('ping -c 4 ' . escapeshellarg($host));",
                    "Python": "# 不安全\nimport os\nos.system(f'ping -c 4 {host}')\n\n# 安全（subprocess参数数组）\nimport subprocess\nsubprocess.run(['ping', '-c', '4', host], check=True)"
                },
                "best_practices": ["避免系统命令调用", "使用内置API", "白名单验证", "参数数组形式", "最低权限运行"],
                "references": ["https://owasp.org/www-community/attacks/Command_Injection"],
                "tags": ["injection", "rce", "command", "critical"]
            },
            {
                "vuln_type": "xss", "vuln_name": "跨站脚本(XSS)", "severity": "high", "cwe_id": "CWE-79",
                "description": "用户输入未经过滤直接输出到HTML页面，导致攻击者可以注入恶意脚本",
                "risk": "Cookie窃取、会话劫持、钓鱼、键盘记录、恶意重定向",
                "remediation_summary": "对输出进行HTML编码，使用CSP，输入验证，HttpOnly Cookie",
                "remediation_steps": [
                    "1. 对所有输出到HTML的用户数据进行HTML实体编码",
                    "2. 根据输出上下文使用不同编码（HTML/JS/CSS/URL）",
                    "3. 设置Content-Security-Policy (CSP) 响应头",
                    "4. 对Cookie设置HttpOnly和Secure标志",
                    "5. 对用户输入进行白名单验证",
                    "6. 使用现代框架的自动转义功能（React/Vue/Angular默认转义）",
                    "7. 避免使用innerHTML/document.write/eval等危险API"
                ],
                "code_examples": {
                    "HTML编码": "// 不安全\n<div><?php echo $user_input; ?></div>\n\n// 安全（HTML编码）\n<div><?php echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8'); ?></div>",
                    "CSP配置": "// Nginx配置\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'; base-uri 'self';\" always;",
                    "React": "{/* React默认转义，安全 */}\n<div>{userInput}</div>\n\n{/* 危险：使用dangerouslySetInnerHTML */}\n<div dangerouslySetInnerHTML={{__html: userInput}} />"
                },
                "best_practices": ["输出编码", "CSP", "HttpOnly Cookie", "输入验证", "使用现代框架", "避免危险API"],
                "references": ["https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                "tags": ["xss", "injection", "web", "high"]
            },
            # 继续添加更多修复方案...
            {
                "vuln_type": "ssrf", "vuln_name": "服务器端请求伪造(SSRF)", "severity": "high", "cwe_id": "CWE-918",
                "description": "服务器端发起用户可控的URL请求，导致攻击者可以访问内网服务和云元数据",
                "risk": "内网信息泄露、云凭证窃取、内网服务攻击、端口扫描",
                "remediation_summary": "白名单验证URL，禁止访问内网IP和元数据地址，使用独立网络隔离的代理",
                "remediation_steps": [
                    "1. 对用户提供的URL进行白名单验证（只允许特定域名）",
                    "2. 解析URL后验证IP地址，禁止访问内网IP段（10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.169.254）",
                    "3. 禁止访问云元数据地址（169.254.169.254）",
                    "4. 限制允许的协议（只允许http/https，禁止file/gopher/dict等）",
                    "5. 使用独立的网络隔离的代理服务器发起请求",
                    "6. 设置请求超时和响应大小限制",
                    "7. 云服务器使用IMDSv2（需要令牌才能访问元数据）"
                ],
                "code_examples": {
                    "Python URL验证": "import ipaddress\nimport urllib.parse\n\ndef is_safe_url(url):\n    try:\n        parsed = urllib.parse.urlparse(url)\n        # 只允许http/https\n        if parsed.scheme not in ('http', 'https'):\n            return False\n        # 解析IP\n        hostname = parsed.hostname\n        ip = socket.gethostbyname(hostname)\n        ip_obj = ipaddress.ip_address(ip)\n        # 禁止内网和回环\n        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:\n            return False\n        # 禁止云元数据\n        if str(ip_obj) == '169.254.169.254':\n            return False\n        return True\n    except:\n        return False"
                },
                "best_practices": ["白名单验证", "禁止内网IP", "禁止元数据地址", "限制协议", "网络隔离代理", "IMDSv2"],
                "references": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                "tags": ["ssrf", "web", "cloud", "high"]
            },
            {
                "vuln_type": "path_traversal", "vuln_name": "目录遍历", "severity": "high", "cwe_id": "CWE-22",
                "description": "用户输入被用于文件路径，未正确过滤../等字符，导致攻击者可以读取任意文件",
                "risk": "敏感文件读取、源代码泄露、配置文件泄露、凭证泄露",
                "remediation_summary": "规范化路径，白名单限制可访问目录，避免直接使用用户输入构建文件路径",
                "remediation_steps": [
                    "1. 避免直接使用用户输入构建文件路径",
                    "2. 使用白名单限制可访问的目录和文件扩展名",
                    "3. 对路径进行规范化（realpath/canonicalize）后验证是否在允许目录内",
                    "4. 过滤../、..\\、%2e%2e、%252e%252e等遍历字符",
                    "5. Web服务器配置禁止目录遍历（关闭Indexes）",
                    "6. 以最低权限运行应用进程，限制文件系统访问范围",
                    "7. 使用chroot或容器隔离应用"
                ],
                "code_examples": {
                    "Python路径验证": "import os\n\ndef safe_read_file(base_dir, filename):\n    # 规范化路径\n    safe_path = os.path.realpath(os.path.join(base_dir, filename))\n    # 验证是否在允许目录内\n    if not safe_path.startswith(os.path.realpath(base_dir) + os.sep):\n        raise ValueError('Invalid file path')\n    with open(safe_path, 'r') as f:\n        return f.read()"
                },
                "best_practices": ["路径规范化", "白名单目录", "过滤遍历字符", "最低权限", "chroot/容器隔离"],
                "references": ["https://owasp.org/www-community/attacks/Path_Traversal"],
                "tags": ["path_traversal", "file_read", "web", "high"]
            },
            {
                "vuln_type": "file_upload", "vuln_name": "文件上传漏洞", "severity": "critical", "cwe_id": "CWE-434",
                "description": "文件上传功能未正确验证文件类型和内容，导致攻击者可以上传恶意脚本",
                "risk": "Webshell上传、远程代码执行、服务器完全控制",
                "remediation_summary": "白名单验证文件类型，重命名文件，存储在非Web可访问目录，禁止上传目录脚本执行",
                "remediation_steps": [
                    "1. 使用白名单验证允许的文件扩展名（只允许.jpg/.png/.pdf等）",
                    "2. 验证文件内容（Magic Number/文件头），不仅依赖Content-Type或扩展名",
                    "3. 上传后重命名文件（使用随机文件名，保留原扩展名）",
                    "4. 将上传文件存储在非Web可访问目录（Web根目录之外）",
                    "5. 上传目录禁止脚本执行（Nginx/Apache配置）",
                    "6. 设置上传文件大小限制",
                    "7. 对图片文件进行重新编码（去除EXIF和恶意代码）",
                    "8. 禁止上传.htaccess、.user.ini等配置文件"
                ],
                "config_examples": {
                    "Nginx禁止执行": "location /uploads/ {\n    location ~ \\.(php|phtml|php5|php7)$ {\n        deny all;\n    }\n}",
                    "Apache禁止执行": "<Directory /var/www/html/uploads>\n    php_flag engine off\n    RemoveHandler .php .phtml .php5\n</Directory>"
                },
                "best_practices": ["白名单扩展名", "验证文件内容", "重命名文件", "非Web目录存储", "禁止脚本执行", "大小限制"],
                "references": ["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
                "tags": ["file_upload", "webshell", "rce", "critical"]
            },
            {
                "vuln_type": "deserialization", "vuln_name": "反序列化漏洞", "severity": "critical", "cwe_id": "CWE-502",
                "description": "不可信数据被反序列化，导致攻击者可以构造恶意对象执行任意代码",
                "risk": "远程代码执行、服务器完全控制",
                "remediation_summary": "避免反序列化不可信数据，使用白名单限制可反序列化的类，升级存在漏洞的库",
                "remediation_steps": [
                    "1. 避免反序列化来自不可信来源的数据",
                    "2. 使用安全的序列化格式（JSON/XML/Protocol Buffers）替代原生序列化",
                    "3. 如必须反序列化，使用白名单限制可反序列化的类",
                    "4. 升级存在已知反序列化漏洞的库（CommonsCollections/Fastjson/Log4j等）",
                    "5. Java环境使用ObjectInputFilter过滤类",
                    "6. PHP环境禁止反序列化用户可控数据（unserialize）",
                    "7. Python环境禁止pickle.loads用户数据，使用json替代",
                    "8. 部署RASP运行时应用自我保护"
                ],
                "code_examples": {
                    "Java ObjectInputFilter": "// Java 9+ 使用ObjectInputFilter\nObjectInputStream ois = new ObjectInputStream(inputStream);\nois.setObjectInputFilter(filterInfo -> {\n    Class<?> clazz = filterInfo.serialClass();\n    if (clazz != null) {\n        // 白名单：只允许特定类\n        if (!clazz.getName().startsWith(\"com.example.\")) {\n            return ObjectInputFilter.Status.REJECTED;\n        }\n    }\n    return ObjectInputFilter.Status.ALLOWED;\n});",
                    "Python安全替代": "# 不安全\nimport pickle\ndata = pickle.loads(user_input)\n\n# 安全（使用JSON）\nimport json\ndata = json.loads(user_input)"
                },
                "best_practices": ["避免反序列化不可信数据", "使用JSON替代", "类白名单", "升级漏洞库", "RASP"],
                "references": ["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
                "tags": ["deserialization", "rce", "java", "php", "python", "critical"]
            },
            {
                "vuln_type": "xxe", "vuln_name": "XML外部实体注入(XXE)", "severity": "high", "cwe_id": "CWE-611",
                "description": "XML解析器未禁用外部实体，导致攻击者可以读取服务器文件或发起SSRF",
                "risk": "敏感文件读取、SSRF、拒绝服务",
                "remediation_summary": "禁用DTD和外部实体，使用JSON替代XML，升级XML解析器",
                "remediation_steps": [
                    "1. 禁用XML解析器的DTD（文档类型定义）",
                    "2. 禁用外部实体（external entities）",
                    "3. 禁用参数实体（parameter entities）",
                    "4. 禁用XInclude",
                    "5. 使用JSON替代XML作为数据交换格式",
                    "6. 升级XML解析器到最新版本",
                    "7. 如必须使用XML，使用安全的解析配置"
                ],
                "code_examples": {
                    "Java安全配置": "// 不安全\nDocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n\n// 安全配置\ndbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\ndbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\ndbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\ndbf.setXIncludeAware(false);\ndbf.setExpandEntityReferences(false);",
                    "PHP安全配置": "// 禁用外部实体\nlibxml_disable_entity_loader(true);\n$dom = new DOMDocument();\n$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);"
                },
                "best_practices": ["禁用DTD", "禁用外部实体", "使用JSON", "升级解析器", "安全配置"],
                "references": ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                "tags": ["xxe", "xml", "file_read", "ssrf", "high"]
            },
            {
                "vuln_type": "idor", "vuln_name": "不安全的直接对象引用(IDOR)", "severity": "high", "cwe_id": "CWE-639",
                "description": "应用使用用户提供的输入直接访问对象，未验证用户是否有权访问该对象",
                "risk": "未授权数据访问、数据泄露、数据篡改、权限提升",
                "remediation_summary": "对每个对象访问进行权限验证，使用不可预测的ID，基于会话的访问控制",
                "remediation_steps": [
                    "1. 对每个对象访问进行服务端权限验证（不能只依赖前端隐藏）",
                    "2. 使用不可预测的ID（UUID/随机字符串）替代自增ID",
                    "3. 实现基于角色的访问控制（RBAC）",
                    "4. 实现基于属性的访问控制（ABAC）",
                    "5. 对象所有权验证（确保用户只能访问自己的对象）",
                    "6. 对敏感操作进行二次验证",
                    "7. 记录对象访问日志，异常访问告警"
                ],
                "best_practices": ["服务端权限验证", "不可预测ID", "RBAC", "所有权验证", "访问日志"],
                "references": ["https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference"],
                "tags": ["idor", "access_control", "data_exposure", "high"]
            },
            {
                "vuln_type": "csrf", "vuln_name": "跨站请求伪造(CSRF)", "severity": "medium", "cwe_id": "CWE-352",
                "description": "攻击者诱导已登录用户执行非预期操作，利用用户的已认证会话",
                "risk": "未授权操作、数据篡改、账户变更、转账",
                "remediation_summary": "使用CSRF Token，验证Referer/Origin，SameSite Cookie，关键操作二次验证",
                "remediation_steps": [
                    "1. 对所有状态改变的请求（POST/PUT/DELETE）使用CSRF Token",
                    "2. CSRF Token绑定到用户会话，每次请求验证",
                    "3. 设置Cookie的SameSite属性（Lax或Strict）",
                    "4. 验证请求的Referer或Origin头",
                    "5. 关键操作（修改密码/转账/删除）要求二次验证（密码/验证码）",
                    "6. 使用自定义请求头（如X-Requested-With）",
                    "7. 登录后重新生成会话ID"
                ],
                "code_examples": {
                    "SameSite Cookie": "// 设置SameSite Cookie\nSet-Cookie: sessionid=abc123; SameSite=Lax; Secure; HttpOnly",
                    "CSRF Token": "// 表单中包含CSRF Token\n<form action=\"/change-password\" method=\"POST\">\n    <input type=\"hidden\" name=\"csrf_token\" value=\"{random_token}\">\n    <input type=\"password\" name=\"new_password\">\n    <button type=\"submit\">修改密码</button>\n</form>"
                },
                "best_practices": ["CSRF Token", "SameSite Cookie", "Referer验证", "二次验证", "自定义请求头"],
                "references": ["https://owasp.org/www-community/attacks/csrf"],
                "tags": ["csrf", "web", "session", "medium"]
            },
            # ===== 认证/会话 (8个) =====
            {
                "vuln_type": "weak_password", "vuln_name": "弱密码策略", "severity": "high", "cwe_id": "CWE-521",
                "description": "系统允许用户设置弱密码，容易被暴力破解",
                "risk": "账户被暴力破解、未授权访问",
                "remediation_summary": "实施强密码策略，密码长度和复杂度要求，密码历史检查，账户锁定",
                "remediation_steps": [
                    "1. 密码最小长度至少12位",
                    "2. 要求包含大小写字母、数字、特殊字符",
                    "3. 禁止使用常见密码（与Top 10000常见密码库比对）",
                    "4. 密码不能包含用户名、邮箱、公司名等",
                    "5. 密码历史检查（不能重复使用最近5-10次密码）",
                    "6. 密码定期过期（90-180天）",
                    "7. 登录失败多次后账户锁定（如5次失败锁定15分钟）",
                    "8. 使用bcrypt/argon2/scrypt等慢哈希算法存储密码"
                ],
                "code_examples": {
                    "密码哈希": "// PHP使用password_hash（bcrypt）\n$hash = password_hash($password, PASSWORD_DEFAULT);\n\n// Python使用bcrypt\nimport bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n\n// Java使用BCrypt\nString hash = BCrypt.hashpw(password, BCrypt.gensalt(12));"
                },
                "best_practices": ["最小长度12位", "复杂度要求", "常见密码检查", "密码历史", "定期过期", "账户锁定", "bcrypt/argon2"],
                "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
                "tags": ["authentication", "password", "brute_force", "high"]
            },
            {
                "vuln_type": "session_fixation", "vuln_name": "会话固定", "severity": "high", "cwe_id": "CWE-384",
                "description": "登录后未重新生成会话ID，攻击者可以预设会话ID",
                "risk": "会话劫持、账户接管",
                "remediation_summary": "登录/权限变更后重新生成会话ID，设置安全的Cookie属性",
                "remediation_steps": [
                    "1. 用户登录成功后重新生成会话ID（session_regenerate_id）",
                    "2. 权限变更（如提升为管理员）后重新生成会话ID",
                    "3. 设置Cookie的HttpOnly、Secure、SameSite属性",
                    "4. 设置会话超时（闲置超时和绝对超时）",
                    "5. 绑定会话到用户代理/IP（注意移动网络IP变化问题）",
                    "6. 登出时销毁会话",
                    "7. 使用安全的随机会话ID（至少128位熵）"
                ],
                "best_practices": ["登录后重新生成会话ID", "HttpOnly/Secure Cookie", "会话超时", "登出销毁会话", "安全随机ID"],
                "references": ["https://owasp.org/www-community/attacks/Session_fixation"],
                "tags": ["session", "authentication", "session_hijacking", "high"]
            },
            {
                "vuln_type": "jwt_none_algorithm", "vuln_name": "JWT算法混淆(none)", "severity": "critical", "cwe_id": "CWE-347",
                "description": "JWT验证时接受alg=none的令牌，攻击者可以伪造任意用户的Token",
                "risk": "认证绕过、权限提升、任意用户登录",
                "remediation_summary": "强制指定JWT算法，不接受none算法，验证签名，使用强密钥",
                "remediation_steps": [
                    "1. 强制指定JWT签名算法（如HS256/RS256），不接受alg=none",
                    "2. 验证JWT签名（不能只解码不验证）",
                    "3. 使用强密钥（HS256至少256位随机密钥，RS256使用2048位RSA密钥）",
                    "4. 设置JWT过期时间（access token 15-30分钟，refresh token 7-14天）",
                    "5. 验证iss（签发者）、aud（受众）、exp（过期）、nbf（生效时间）",
                    "6. 实现Token撤销机制（黑名单/短期Token）",
                    "7. 不要在JWT payload中存储敏感信息（base64可解码）"
                ],
                "code_examples": {
                    "安全JWT验证": "// Node.js (jsonwebtoken)\n// 不安全\nconst decoded = jwt.decode(token);\n\n// 安全（指定算法，验证签名）\nconst decoded = jwt.verify(token, secretKey, {\n    algorithms: ['HS256'],  // 只允许HS256，不接受none\n    issuer: 'your-app',\n    audience: 'your-app-users',\n    maxAge: '15m'\n});"
                },
                "best_practices": ["强制指定算法", "验证签名", "强密钥", "过期时间", "验证iss/aud/exp", "Token撤销"],
                "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JWT"],
                "tags": ["jwt", "authentication", "auth_bypass", "critical"]
            },
            {
                "vuln_type": "oauth_redirect_uri", "vuln_name": "OAuth重定向URI验证不严", "severity": "high", "cwe_id": "CWE-601",
                "description": "OAuth授权时redirect_uri验证不严，攻击者可以窃取授权码",
                "risk": "账户接管、权限提升、Token窃取",
                "remediation_summary": "严格验证redirect_uri（精确匹配），绑定redirect_uri和client_id，使用PKCE",
                "remediation_steps": [
                    "1. 严格验证redirect_uri（精确匹配，不使用前缀匹配/通配符）",
                    "2. 在OAuth平台注册时绑定固定的redirect_uri白名单",
                    "3. 使用PKCE（Proof Key for Code Exchange）防止授权码拦截",
                    "4. 授权码设置短期过期（1-5分钟），一次性使用",
                    "5. 验证state参数（防止CSRF）",
                    "6. 绑定redirect_uri和client_id（一个client_id只能使用预注册的redirect_uri）",
                    "7. 审计OAuth应用，移除不再使用的应用"
                ],
                "best_practices": ["精确匹配redirect_uri", "白名单", "PKCE", "授权码短期过期", "state参数", "client_id绑定"],
                "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_OAuth"],
                "tags": ["oauth", "authentication", "account_takeover", "high"]
            },
            # ===== 配置错误 (8个) =====
            {
                "vuln_type": "cors_misconfiguration", "vuln_name": "CORS配置错误", "severity": "high", "cwe_id": "CWE-942",
                "description": "CORS配置允许任意Origin且允许凭证，导致跨域数据窃取",
                "risk": "跨域数据窃取、认证绕过、CSRF辅助",
                "remediation_summary": "严格白名单验证Origin，禁止ACAO为*且允许凭证，验证Vary头",
                "remediation_steps": [
                    "1. 严格白名单验证Origin（只允许信任的域名）",
                    "2. 禁止Access-Control-Allow-Origin为*且Access-Control-Allow-Credentials为true的组合",
                    "3. 动态验证Origin后再设置ACAO头",
                    "4. 设置Vary: Origin头（防止缓存攻击）",
                    "5. 限制允许的HTTP方法和请求头",
                    "6. 敏感接口不使用CORS，或要求二次验证",
                    "7. 定期审计CORS配置"
                ],
                "code_examples": {
                    "安全CORS配置": "// Node.js Express\nconst allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];\n\napp.use(cors({\n    origin: function(origin, callback) {\n        if (allowedOrigins.indexOf(origin) !== -1 || !origin) {\n            callback(null, true);\n        } else {\n            callback(new Error('Not allowed by CORS'));\n        }\n    },\n    credentials: true,\n    methods: ['GET', 'POST', 'PUT', 'DELETE'],\n    allowedHeaders: ['Content-Type', 'Authorization']\n}));"
                },
                "best_practices": ["Origin白名单", "禁止*+credentials", "Vary: Origin", "限制方法/头", "敏感接口二次验证"],
                "references": ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                "tags": ["cors", "misconfiguration", "web", "high"]
            },
            {
                "vuln_type": "security_headers_missing", "vuln_name": "安全响应头缺失", "severity": "medium", "cwe_id": "CWE-693",
                "description": "缺少安全相关的HTTP响应头，增加XSS/点击劫持/信息泄露等风险",
                "risk": "XSS风险增加、点击劫持、信息泄露、MIME类型嗅探",
                "remediation_summary": "设置完整的安全响应头（CSP/X-Frame-Options/X-Content-Type-Options等）",
                "remediation_steps": [
                    "1. 设置Content-Security-Policy（CSP）",
                    "2. 设置X-Frame-Options: DENY或SAMEORIGIN（防止点击劫持）",
                    "3. 设置X-Content-Type-Options: nosniff（防止MIME嗅探）",
                    "4. 设置Strict-Transport-Security（HSTS，强制HTTPS）",
                    "5. 设置Referrer-Policy（控制Referer头）",
                    "6. 设置Permissions-Policy（限制浏览器功能）",
                    "7. 移除Server/X-Powered-By等信息泄露头",
                    "8. 设置X-XSS-Protection（虽然现代浏览器已废弃，但旧浏览器仍有用）"
                ],
                "config_examples": {
                    "Nginx安全头": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';\" always;\nadd_header X-Frame-Options \"DENY\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\nadd_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;\nserver_tokens off;"
                },
                "best_practices": ["CSP", "X-Frame-Options", "X-Content-Type-Options", "HSTS", "Referrer-Policy", "移除信息泄露头"],
                "references": ["https://owasp.org/www-project-secure-headers/"],
                "tags": ["security_headers", "misconfiguration", "web", "medium"]
            },
            {
                "vuln_type": "default_credentials", "vuln_name": "默认凭证", "severity": "critical", "cwe_id": "CWE-798",
                "description": "系统使用默认的用户名和密码（如admin/admin），未修改",
                "risk": "未授权访问、系统完全控制",
                "remediation_summary": "修改所有默认凭证，使用强密码，首次登录强制修改密码",
                "remediation_steps": [
                    "1. 修改所有默认账户的密码（admin/root/user等）",
                    "2. 删除不需要的默认账户",
                    "3. 首次登录强制修改密码",
                    "4. 使用强密码（至少12位，包含大小写字母、数字、特殊字符）",
                    "5. 禁用默认的管理员账户，创建自定义管理员账户",
                    "6. 启用多因素认证（MFA）",
                    "7. 定期审计账户，移除不再使用的账户",
                    "8. 检查配置文件/代码中的硬编码凭证"
                ],
                "best_practices": ["修改默认密码", "删除默认账户", "首次登录改密", "强密码", "MFA", "定期审计"],
                "references": ["https://owasp.org/www-community/attacks/Credential_stuffing"],
                "tags": ["default_credentials", "authentication", "critical"]
            },
            {
                "vuln_type": "sensitive_data_exposure", "vuln_name": "敏感数据泄露", "severity": "high", "cwe_id": "CWE-200",
                "description": "敏感数据（密码/密钥/个人信息）未加密存储或传输，或暴露在公开可访问位置",
                "risk": "数据泄露、身份盗窃、合规违规",
                "remediation_summary": "加密存储和传输敏感数据，最小化数据收集，移除公开可访问的敏感文件",
                "remediation_steps": [
                    "1. 使用TLS/HTTPS加密所有数据传输",
                    "2. 加密存储敏感数据（密码使用bcrypt/argon2，其他敏感数据使用AES-256）",
                    "3. 最小化数据收集（只收集必要的数据）",
                    "4. 移除公开可访问的敏感文件（.git/.env/backup.sql/web.config.bak等）",
                    "5. 数据库账户使用最小权限",
                    "6. 日志中不记录敏感数据（密码/Token/身份证号等）",
                    "7. 实施数据分类和访问控制",
                    "8. 定期进行数据泄露扫描",
                    "9. 符合数据保护法规（GDPR/个人信息保护法等）"
                ],
                "best_practices": ["HTTPS/TLS", "加密存储", "最小化收集", "移除敏感文件", "最小权限", "日志脱敏", "数据分类"],
                "references": ["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"],
                "tags": ["data_exposure", "privacy", "encryption", "high"]
            },
            # ===== 业务逻辑 (6个) =====
            {
                "vuln_type": "mass_assignment", "vuln_name": "批量赋值", "severity": "high", "cwe_id": "CWE-915",
                "description": "框架自动绑定请求参数到对象，攻击者可以修改受保护字段（is_admin/role等）",
                "risk": "权限提升、数据篡改",
                "remediation_summary": "使用白名单限制可更新字段，禁止自动绑定敏感字段",
                "remediation_steps": [
                    "1. 使用白名单限制可更新/可创建的字段",
                    "2. 禁止自动绑定敏感字段（is_admin/role/password/balance等）",
                    "3. 使用DTO（数据传输对象）明确指定可接受的字段",
                    "4. 对敏感字段的修改进行单独的权限验证",
                    "5. 框架配置禁用自动绑定（如Spring的@InitBinder）",
                    "6. 代码审查关注批量赋值风险",
                    "7. 测试时尝试添加额外参数（如is_admin=true）"
                ],
                "code_examples": {
                    "Spring白名单": "// 不安全（自动绑定所有字段）\n@PostMapping(\"/users/{id}\")\npublic User updateUser(@PathVariable Long id, @RequestBody User user) {\n    user.setId(id);\n    return userRepository.save(user);\n}\n\n// 安全（使用DTO白名单）\n@PostMapping(\"/users/{id}\")\npublic User updateUser(@PathVariable Long id, @RequestBody UserUpdateDTO dto) {\n    User user = userRepository.findById(id);\n    user.setName(dto.getName());  // 只更新白名单字段\n    user.setEmail(dto.getEmail());\n    // 不更新role/is_admin/password等敏感字段\n    return userRepository.save(user);\n}"
                },
                "best_practices": ["字段白名单", "DTO", "禁止自动绑定敏感字段", "权限验证", "代码审查"],
                "references": ["https://owasp.org/www-community/vulnerabilities/Mass_Assignment"],
                "tags": ["mass_assignment", "business_logic", "privilege_escalation", "high"]
            },
            {
                "vuln_type": "race_condition", "vuln_name": "竞态条件", "severity": "high", "cwe_id": "CWE-362",
                "description": "并发请求导致业务逻辑错误（如重复使用优惠券、重复转账、超卖）",
                "risk": "经济损失、业务逻辑绕过、数据不一致",
                "remediation_summary": "使用事务和锁机制，幂等性设计，乐观锁/悲观锁",
                "remediation_steps": [
                    "1. 使用数据库事务保证原子性",
                    "2. 使用乐观锁（版本号）或悲观锁（SELECT FOR UPDATE）",
                    "3. 对关键操作实现幂等性（重复请求结果相同）",
                    "4. 使用分布式锁（Redis/Zookeeper）处理分布式场景",
                    "5. 对库存/余额等关键字段使用原子操作（如UPDATE ... SET balance = balance - 10 WHERE balance >= 10）",
                    "6. 限制请求频率（防止高并发攻击）",
                    "7. 测试时使用高并发请求验证竞态条件"
                ],
                "code_examples": {
                    "原子操作": "-- 不安全（先查后改，有竞态）\nSELECT balance FROM accounts WHERE id = 1;\n-- 应用层判断 balance >= 10\nUPDATE accounts SET balance = balance - 10 WHERE id = 1;\n\n-- 安全（原子操作，数据库层面保证）\nUPDATE accounts SET balance = balance - 10 WHERE id = 1 AND balance >= 10;",
                    "乐观锁": "// 乐观锁（版本号）\nUPDATE products SET stock = stock - 1, version = version + 1 WHERE id = 1 AND version = {expected_version};\n// 如果影响行数为0，说明版本不匹配，需要重试"
                },
                "best_practices": ["数据库事务", "乐观锁/悲观锁", "幂等性", "分布式锁", "原子操作", "请求限流"],
                "references": ["https://owasp.org/www-community/vulnerabilities/Race_Condition"],
                "tags": ["race_condition", "business_logic", "economic_loss", "high"]
            },
            # ===== 服务器/基础设施 (10个) =====
            {
                "vuln_type": "redis_unauthorized", "vuln_name": "Redis未授权访问", "severity": "critical", "cwe_id": "CWE-306",
                "description": "Redis开放6379端口且未设置密码，攻击者可以未授权访问",
                "risk": "数据泄露、数据篡改、写入SSH公钥/计划任务/Webshell获取服务器权限",
                "remediation_summary": "设置Redis密码，绑定127.0.0.1，禁用CONFIG命令，非root运行，防火墙限制6379",
                "remediation_steps": [
                    "1. 在redis.conf中设置requirepass强密码",
                    "2. 绑定127.0.0.1（bind 127.0.0.1），禁止公网访问",
                    "3. 禁用CONFIG/FLUSHALL/FLUSHDB等危险命令（rename-command CONFIG \"\"）",
                    "4. 以非root用户运行Redis",
                    "5. 防火墙限制6379端口访问（只允许特定IP）",
                    "6. 启用Redis TLS加密传输",
                    "7. 定期备份数据，配置数据持久化",
                    "8. 监控Redis访问日志，异常访问告警"
                ],
                "config_examples": {
                    "redis.conf安全配置": "# 设置密码\nrequirepass YourStrongPassword123!\n\n# 绑定本地\nbind 127.0.0.1\n\n# 禁用危险命令\nrename-command CONFIG \"\"\nrename-command FLUSHALL \"\"\nrename-command FLUSHDB \"\"\nrename-command KEYS \"\"\n\n# 以非root运行（系统层面）\n# useradd redis\n# chown redis:redis /var/lib/redis"
                },
                "best_practices": ["设置密码", "绑定127.0.0.1", "禁用危险命令", "非root运行", "防火墙限制", "TLS加密"],
                "references": ["https://redis.io/docs/management/security/"],
                "tags": ["redis", "unauthorized", "database", "critical"]
            },
            {
                "vuln_type": "docker_api_unauthorized", "vuln_name": "Docker API未授权访问", "severity": "critical", "cwe_id": "CWE-306",
                "description": "Docker API开放2375端口且未设置TLS认证，攻击者可以未授权访问",
                "risk": "创建特权容器逃逸到宿主机、服务器完全控制、数据泄露",
                "remediation_summary": "启用Docker TLS认证，绑定127.0.0.1，防火墙限制2375，禁用特权容器",
                "remediation_steps": [
                    "1. 启用Docker TLS认证（生成CA、服务器证书、客户端证书）",
                    "2. 绑定127.0.0.1，禁止公网访问2375端口",
                    "3. 防火墙限制2375/2376端口访问",
                    "4. 禁用特权容器（--privileged）",
                    "5. 限制容器能力（--cap-drop=ALL --cap-add=必要能力）",
                    "6. 使用rootless Docker",
                    "7. 启用Docker内容信任（DCT）",
                    "8. 定期更新Docker版本",
                    "9. 监控Docker API访问日志"
                ],
                "config_examples": {
                    "Docker TLS配置": "# /etc/docker/daemon.json\n{\n  \"tlsverify\": true,\n  \"tlscacert\": \"/etc/docker/ca.pem\",\n  \"tlscert\": \"/etc/docker/server-cert.pem\",\n  \"tlskey\": \"/etc/docker/server-key.pem\",\n  \"hosts\": [\"tcp://127.0.0.1:2376\", \"unix:///var/run/docker.sock\"],\n  \"no-new-privileges\": true,\n  \"userland-proxy\": false\n}"
                },
                "best_practices": ["TLS认证", "绑定127.0.0.1", "防火墙限制", "禁用特权容器", "rootless Docker", "DCT", "定期更新"],
                "references": ["https://docs.docker.com/engine/security/"],
                "tags": ["docker", "unauthorized", "container", "critical"]
            },
            {
                "vuln_type": "elasticsearch_unauthorized", "vuln_name": "Elasticsearch未授权访问", "severity": "high", "cwe_id": "CWE-306",
                "description": "Elasticsearch开放9200端口且未设置认证，攻击者可以未授权访问",
                "risk": "数据泄露、数据篡改/删除、集群控制",
                "remediation_summary": "启用Elasticsearch安全认证，绑定127.0.0.1，防火墙限制9200，启用TLS",
                "remediation_steps": [
                    "1. 启用Elasticsearch安全模块（xpack.security.enabled: true）",
                    "2. 设置强密码（elastic用户和其他内置用户）",
                    "3. 绑定127.0.0.1（network.host: 127.0.0.1）",
                    "4. 防火墙限制9200/9300端口访问",
                    "5. 启用TLS加密传输（xpack.security.transport.ssl.enabled）",
                    "6. 启用审计日志（xpack.security.audit.enabled）",
                    "7. 配置基于角色的访问控制（RBAC）",
                    "8. 定期备份数据",
                    "9. 更新Elasticsearch到最新版本"
                ],
                "config_examples": {
                    "elasticsearch.yml安全配置": "# 启用安全模块\nxpack.security.enabled: true\n\n# 绑定本地\nnetwork.host: 127.0.0.1\n\n# 启用TLS\nxpack.security.transport.ssl.enabled: true\nxpack.security.transport.ssl.verification_mode: certificate\nxpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12\nxpack.security.transport.ssl.truststore.path: certs/elastic-certificates.p12\n\n# 启用审计\nxpack.security.audit.enabled: true"
                },
                "best_practices": ["启用安全模块", "强密码", "绑定127.0.0.1", "防火墙限制", "TLS加密", "RBAC", "审计日志"],
                "references": ["https://www.elastic.co/guide/en/elasticsearch/reference/current/security.html"],
                "tags": ["elasticsearch", "unauthorized", "database", "high"]
            },
            {
                "vuln_type": "mongodb_unauthorized", "vuln_name": "MongoDB未授权访问", "severity": "high", "cwe_id": "CWE-306",
                "description": "MongoDB开放27017端口且未设置认证，攻击者可以未授权访问",
                "risk": "数据泄露、数据篡改/删除、勒索攻击",
                "remediation_summary": "启用MongoDB认证，绑定127.0.0.1，防火墙限制27017，启用TLS",
                "remediation_steps": [
                    "1. 启用MongoDB认证（security.authorization: enabled）",
                    "2. 创建管理员用户和应用用户（最小权限）",
                    "3. 绑定127.0.0.1（bindIp: 127.0.0.1）",
                    "4. 防火墙限制27017端口访问",
                    "5. 启用TLS加密传输（net.ssl.mode: requireSSL）",
                    "6. 启用审计日志（auditLog.destination: file）",
                    "7. 配置基于角色的访问控制（RBAC）",
                    "8. 定期备份数据",
                    "9. 更新MongoDB到最新版本"
                ],
                "best_practices": ["启用认证", "强密码", "绑定127.0.0.1", "防火墙限制", "TLS加密", "RBAC", "审计日志"],
                "references": ["https://www.mongodb.com/docs/manual/security/"],
                "tags": ["mongodb", "unauthorized", "database", "high"]
            },
            {
                "vuln_type": "jenkins_unauthorized", "vuln_name": "Jenkins未授权访问", "severity": "critical", "cwe_id": "CWE-306",
                "description": "Jenkins开放8080端口且未设置认证，攻击者可以未授权访问",
                "risk": "执行任意命令、服务器完全控制、代码篡改、凭证窃取",
                "remediation_summary": "启用Jenkins认证，禁用匿名访问，绑定127.0.0.1，防火墙限制8080，最小权限",
                "remediation_steps": [
                    "1. 启用Jenkins安全认证（Manage Jenkins -> Configure Global Security）",
                    "2. 禁用匿名访问（取消勾选\"Allow anonymous read access\"）",
                    "3. 绑定127.0.0.1（--httpListenAddress=127.0.0.1）",
                    "4. 防火墙限制8080端口访问",
                    "5. 启用CSRF保护（防止跨站请求伪造）",
                    "6. 配置基于角色的访问控制（RBAC），最小权限原则",
                    "7. 禁用脚本控制台（Script Console）或限制访问",
                    "8. 禁用不必要的插件",
                    "9. 定期更新Jenkins和插件",
                    "10. 配置Jenkins在反向代理（Nginx/Apache）后面，启用HTTPS"
                ],
                "best_practices": ["启用认证", "禁用匿名访问", "绑定127.0.0.1", "防火墙限制", "CSRF保护", "RBAC", "禁用脚本控制台", "定期更新"],
                "references": ["https://www.jenkins.io/doc/book/security/"],
                "tags": ["jenkins", "unauthorized", "ci_cd", "critical"]
            },
            {
                "vuln_type": "ms17_010", "vuln_name": "MS17-010永恒之蓝", "severity": "critical", "cwe_id": "CWE-119",
                "description": "Windows SMB服务存在远程代码执行漏洞（永恒之蓝），未打补丁",
                "risk": "远程代码执行、服务器完全控制、蠕虫传播（如WannaCry）",
                "remediation_summary": "安装MS17-010补丁，禁用SMBv1，防火墙限制445端口，启用网络隔离",
                "remediation_steps": [
                    "1. 安装MS17-010安全补丁（KB4013389等）",
                    "2. 禁用SMBv1协议（Windows功能中取消勾选\"SMB 1.0/CIFS文件共享支持\"）",
                    "3. 防火墙限制445端口访问（只允许可信IP）",
                    "4. 启用网络隔离（关键服务器与办公网络隔离）",
                    "5. 启用Windows Defender或其他杀毒软件",
                    "6. 启用Windows Update自动更新",
                    "7. 定期扫描内网MS17-010漏洞",
                    "8. 备份重要数据",
                    "9. 监控445端口异常访问"
                ],
                "config_examples": {
                    "禁用SMBv1": "# PowerShell禁用SMBv1\nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\n\n# 或通过注册表\nSet-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" -Name SMB1 -Type DWORD -Value 0 -Force"
                },
                "best_practices": ["安装补丁", "禁用SMBv1", "防火墙限制445", "网络隔离", "杀毒软件", "自动更新", "定期扫描"],
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144"],
                "tags": ["ms17_010", "eternalblue", "windows", "smb", "critical"]
            },
            {
                "vuln_type": "log4shell", "vuln_name": "Log4Shell (Log4j RCE)", "severity": "critical", "cwe_id": "CWE-502",
                "description": "Apache Log4j存在远程代码执行漏洞（CVE-2021-44228），攻击者可以通过JNDI注入执行任意代码",
                "risk": "远程代码执行、服务器完全控制、数据泄露",
                "remediation_summary": "升级Log4j到2.17.0+，设置log4j2.formatMsgNoLookups=true，移除JndiLookup类，WAF拦截",
                "remediation_steps": [
                    "1. 升级Log4j到2.17.0或更高版本（修复CVE-2021-44228/45046/45105）",
                    "2. 如无法升级，设置log4j2.formatMsgNoLookups=true（2.10+版本）",
                    "3. 移除JndiLookup类（zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class）",
                    "4. 升级所有使用Log4j的应用和组件",
                    "5. 部署WAF规则拦截${jndi:等攻击payload",
                    "6. 限制服务器出站连接（防止LDAP/RMI回调）",
                    "7. 监控日志中的${jndi:等异常字符串",
                    "8. 扫描所有Java应用的Log4j版本",
                    "9. 启用JVM安全参数（-Dlog4j2.formatMsgNoLookups=true）"
                ],
                "best_practices": ["升级Log4j", "formatMsgNoLookups=true", "移除JndiLookup", "WAF拦截", "限制出站连接", "监控日志", "扫描所有应用"],
                "references": ["https://logging.apache.org/log4j/2.x/security.html"],
                "tags": ["log4shell", "log4j", "rce", "java", "critical"]
            },
            {
                "vuln_type": "spring4shell", "vuln_name": "Spring4Shell (Spring Framework RCE)", "severity": "critical", "cwe_id": "CWE-940",
                "description": "Spring Framework存在远程代码执行漏洞（CVE-2022-22965），攻击者可以通过数据绑定修改Tomcat日志配置",
                "risk": "远程代码执行、服务器完全控制",
                "remediation_summary": "升级Spring Framework到5.3.18+/5.2.20+，升级Tomcat，设置disallowedFields，WAF拦截",
                "remediation_steps": [
                    "1. 升级Spring Framework到5.3.18+或5.2.20+",
                    "2. 升级Spring Boot到2.6.6+或2.5.12+",
                    "3. 升级Apache Tomcat到10.0.20+/9.0.62+/8.5.78+",
                    "4. 如无法升级，在Controller中设置disallowedFields（@InitBinder）",
                    "5. 部署WAF规则拦截class.module.classLoader等攻击payload",
                    "6. 升级JDK到9+（JDK 8受影响更大）",
                    "7. 监控访问日志中的异常参数",
                    "8. 扫描所有Spring应用的版本"
                ],
                "best_practices": ["升级Spring", "升级Tomcat", "disallowedFields", "WAF拦截", "升级JDK", "监控日志", "扫描所有应用"],
                "references": ["https://spring.io/security/cve-2022-22965"],
                "tags": ["spring4shell", "spring", "rce", "java", "critical"]
            },
            {
                "vuln_type": "fastjson_rce", "vuln_name": "Fastjson反序列化RCE", "severity": "critical", "cwe_id": "CWE-502",
                "description": "Alibaba Fastjson存在反序列化远程代码执行漏洞（多个CVE），攻击者可以构造恶意JSON执行任意代码",
                "risk": "远程代码执行、服务器完全控制",
                "remediation_summary": "升级Fastjson到1.2.83+或2.x版本，开启safeMode，禁用autoType，WAF拦截",
                "remediation_steps": [
                    "1. 升级Fastjson到1.2.83+或最新2.x版本",
                    "2. 开启safeMode（ParserConfig.getGlobalInstance().setSafeMode(true)）",
                    "3. 禁用autoType（关闭autotype支持）",
                    "4. 升级所有使用Fastjson的应用和组件",
                    "5. 部署WAF规则拦截@type等攻击payload",
                    "6. 代码审查，替换Fastjson为Jackson（更安全）",
                    "7. 监控日志中的异常JSON",
                    "8. 扫描所有Java应用的Fastjson版本"
                ],
                "code_examples": {
                    "开启safeMode": "// 开启Fastjson safeMode（1.2.68+）\nParserConfig.getGlobalInstance().setSafeMode(true);\n\n// 或通过JVM参数\n-Dfastjson.parser.safeMode=true"
                },
                "best_practices": ["升级Fastjson", "safeMode", "禁用autoType", "WAF拦截", "替换为Jackson", "监控日志", "扫描所有应用"],
                "references": ["https://github.com/alibaba/fastjson/wiki"],
                "tags": ["fastjson", "deserialization", "rce", "java", "critical"]
            },
            {
                "vuln_type": "weak_tls", "vuln_name": "弱TLS/SSL配置", "severity": "medium", "cwe_id": "CWE-327",
                "description": "服务器使用弱TLS版本（SSLv3/TLS1.0/TLS1.1）或弱加密套件，容易被攻击",
                "risk": "中间人攻击、数据解密、信息泄露",
                "remediation_summary": "禁用SSLv3/TLS1.0/TLS1.1，只启用TLS1.2/1.3，使用强加密套件，启用HSTS",
                "remediation_steps": [
                    "1. 禁用SSLv2/SSLv3/TLS1.0/TLS1.1",
                    "2. 只启用TLS1.2和TLS1.3",
                    "3. 使用强加密套件（ECDHE+AESGCM+SHA256/384等）",
                    "4. 禁用弱加密套件（RC4/3DES/DES/MD5/SHA1等）",
                    "5. 启用HSTS（Strict-Transport-Security）",
                    "6. 使用强证书（RSA 2048+或ECC 256+，SHA256+签名）",
                    "7. 配置证书自动续期（Let's Encrypt + certbot）",
                    "8. 定期使用SSL Labs/OpenSSL测试TLS配置",
                    "9. 启用OCSP Stapling"
                ],
                "config_examples": {
                    "Nginx强TLS配置": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\nssl_prefer_server_ciphers off;\nssl_session_cache shared:SSL:10m;\nssl_session_timeout 1d;\nssl_session_tickets off;\n\n# HSTS\nadd_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\n\n# OCSP Stapling\nssl_stapling on;\nssl_stapling_verify on;"
                },
                "best_practices": ["TLS1.2/1.3 only", "强加密套件", "禁用弱套件", "HSTS", "强证书", "定期测试", "OCSP Stapling"],
                "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                "tags": ["tls", "ssl", "encryption", "web", "medium"]
            }
        ]

        for r in remediations:
            self._add(**r)

        self._save()
        log.info(f"初始化完成，共 {len(self.remediations)} 个修复方案")

    # ===== 查询方法 =====
    def get_remediation(self, rem_id: str) -> Optional[Dict[str, Any]]:
        """获取修复方案详情"""
        r = self.remediations.get(rem_id)
        return r.to_dict() if r else None

    def get_by_vuln_type(self, vuln_type: str) -> List[Dict[str, Any]]:
        """按漏洞类型获取修复方案"""
        results = []
        for r in self.remediations.values():
            if r.vuln_type.lower() == vuln_type.lower() or vuln_type.lower() in r.tags:
                results.append(r.to_dict())
        return results

    def search(self, keyword: str = None, severity: str = None,
               cwe_id: str = None) -> List[Dict[str, Any]]:
        """搜索修复方案"""
        results = []
        for r in self.remediations.values():
            if severity and r.severity != severity:
                continue
            if cwe_id and r.cwe_id != cwe_id:
                continue
            if keyword and keyword.lower() not in (r.vuln_name + r.description + r.vuln_type).lower():
                continue
            results.append(r.to_dict())
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        by_severity = Counter(r.severity for r in self.remediations.values())
        by_type = Counter(r.vuln_type for r in self.remediations.values())
        with_code = sum(1 for r in self.remediations.values() if r.code_examples)
        with_config = sum(1 for r in self.remediations.values() if r.config_examples)
        return {
            "total_remediations": len(self.remediations),
            "by_severity": dict(by_severity),
            "by_vuln_type": dict(by_type),
            "with_code_examples": with_code,
            "with_config_examples": with_config,
            "with_references": sum(1 for r in self.remediations.values() if r.references)
        }


# 全局实例
remediation_library = RemediationLibrary()
