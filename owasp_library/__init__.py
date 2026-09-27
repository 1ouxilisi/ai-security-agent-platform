#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OWASP 测试用例库
覆盖 OWASP Top 10 (2021) 共120+测试用例
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class OWASPTestCase:
    """OWASP测试用例"""
    case_id: str = ""  # OTG-xxx
    category: str = ""  # A01-A10
    category_name: str = ""
    name: str = ""
    description: str = ""
    severity: str = "medium"  # critical/high/medium/low/info
    test_method: str = ""  # manual/automated/semi-automated
    prerequisites: List[str] = field(default_factory=list)
    test_steps: List[str] = field(default_factory=list)
    expected_result: str = ""
    tools: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cwe: str = ""
    automated: bool = False


class OWASPCaseLibrary:
    """OWASP测试用例库"""

    def __init__(self):
        self.cases: Dict[str, OWASPTestCase] = {}
        self._init_cases()

    def _init_cases(self):
        """初始化所有测试用例"""
        cases = []

        # ==================== A01: 失效的访问控制 (20个用例) ====================
        a01_cases = [
            ("OTG-A01-001", "水平越权测试", "测试用户A能否访问用户B的资源", "high",
             ["登录两个不同权限的账户"],
             ["1. 以用户A登录，获取资源ID", "2. 修改资源ID为用户B的资源", "3. 观察是否能访问"],
             "用户A无法访问用户B的资源",
             ["burp", "curl"], ["?user_id=2", "/api/users/2/profile"], "CWE-639"),
            ("OTG-A01-002", "垂直越权测试", "测试普通用户能否访问管理员功能", "critical",
             ["普通用户账户"],
             ["1. 以普通用户登录", "2. 直接访问管理员URL", "3. 观察是否被拒绝"],
             "普通用户无法访问管理员功能",
             ["burp", "curl"], ["/admin", "/api/admin/users"], "CWE-269"),
            ("OTG-A01-003", "IDOR测试", "不安全的直接对象引用", "high",
             ["可访问的资源ID"],
             ["1. 记录正常资源请求", "2. 修改ID参数", "3. 观察是否返回其他用户数据"],
             "修改ID后无法访问其他资源",
             ["burp"], ["?id=1", "?id=2", "?id=999"], "CWE-639"),
            ("OTG-A01-004", "路径遍历访问控制", "测试能否通过路径遍历访问受保护资源", "high",
             ["Web应用URL"],
             ["1. 尝试../序列", "2. 尝试编码绕过", "3. 观察响应"],
             "无法通过路径遍历访问受保护资源",
             ["burp", "curl"], ["../admin", "..%2fadmin", "%2e%2e/admin"], "CWE-22"),
            ("OTG-A01-005", "API端点权限测试", "测试API端点是否正确实施权限控制", "high",
             ["API文档或发现的端点"],
             ["1. 列出所有API端点", "2. 以低权限用户访问每个端点", "3. 检查响应状态码"],
             "所有端点正确实施权限控制",
             ["postman", "curl"], [], "CWE-285"),
            ("OTG-A01-006", "功能级访问控制", "测试特定功能是否需要特定权限", "high",
             ["功能列表"],
             ["1. 识别需要特殊权限的功能", "2. 以普通用户尝试访问", "3. 验证拒绝"],
             "需要特殊权限的功能对普通用户不可用",
             ["burp"], [], "CWE-285"),
            ("OTG-A01-007", "URL访问控制绕过", "测试能否通过URL操作绕过访问控制", "medium",
             ["受保护的URL"],
             ["1. 尝试添加参数绕过", "2. 尝试HTTP方法切换", "3. 尝试路径编码"],
             "无法通过URL操作绕过访问控制",
             ["burp"], ["?debug=true", "POST→GET", "/admin/."], "CWE-288"),
            ("OTG-A01-008", "Referer头绕过测试", "测试能否通过修改Referer头绕过访问控制", "medium",
             ["受保护的页面"],
             ["1. 拦截请求", "2. 修改Referer头", "3. 观察是否绕过"],
             "Referer头不能用于访问控制",
             ["burp"], ["Referer: https://target.com/admin"], "CWE-290"),
            ("OTG-A01-009", "X-Forwarded-For绕过", "测试能否通过XFF头绕过IP限制", "medium",
             ["有IP限制的功能"],
             ["1. 添加X-Forwarded-For头", "2. 设置为允许的IP", "3. 观察是否绕过"],
             "XFF头不能用于访问控制决策",
             ["burp"], ["X-Forwarded-For: 127.0.0.1"], "CWE-290"),
            ("OTG-A01-010", "参数污染绕过", "测试HTTP参数污染能否绕过访问控制", "medium",
             ["有访问控制的参数"],
             ["1. 复制参数", "2. 第二个参数设置为越权值", "3. 观察应用使用哪个"],
             "参数污染不能绕过访问控制",
             ["burp"], ["?id=1&id=2", "?role=user&role=admin"], "CWE-235"),
            ("OTG-A01-011", "文件上传权限测试", "测试未授权用户能否上传文件", "high",
             ["文件上传功能"],
             ["1. 以未授权用户访问上传端点", "2. 尝试上传文件", "3. 验证拒绝"],
             "未授权用户无法上传文件",
             ["curl", "burp"], [], "CWE-434"),
            ("OTG-A01-012", "下载权限测试", "测试能否下载其他用户的文件", "high",
             ["文件下载功能"],
             ["1. 获取文件ID", "2. 修改为其他用户的文件ID", "3. 尝试下载"],
             "无法下载其他用户的文件",
             ["curl"], ["/download?file_id=2"], "CWE-639"),
            ("OTG-A01-013", "搜索功能权限测试", "测试搜索能否返回未授权数据", "medium",
             ["搜索功能"],
             ["1. 以普通用户搜索", "2. 搜索管理员或其他用户数据", "3. 检查结果"],
             "搜索结果只包含授权数据",
             ["burp"], ["?q=admin", "?q=password"], "CWE-200"),
            ("OTG-A01-014", "批量操作权限测试", "测试批量操作能否越权", "medium",
             ["批量操作功能"],
             ["1. 构造批量请求", "2. 包含其他用户的ID", "3. 观察是否执行"],
             "批量操作正确检查每个对象的权限",
             ["burp"], ["ids=1,2,3", "{\"ids\":[1,2,3]}"], "CWE-639"),
            ("OTG-A01-015", "GraphQL权限测试", "测试GraphQL查询的权限控制", "high",
             ["GraphQL端点"],
             ["1. 枚举所有查询和变更", "2. 以低权限用户尝试每个", "3. 验证拒绝"],
             "GraphQL操作正确实施权限控制",
             ["graphql-cli", "burp"], ["{ admin { users } }"], "CWE-285"),
            ("OTG-A01-016", "WebSocket权限测试", "测试WebSocket消息的权限控制", "medium",
             ["WebSocket端点"],
             ["1. 建立WebSocket连接", "2. 发送需要高权限的消息", "3. 观察响应"],
             "WebSocket消息正确检查权限",
             ["wscat"], [], "CWE-285"),
            ("OTG-A01-017", "缓存键权限测试", "测试缓存是否导致权限绕过", "medium",
             ["有缓存的页面"],
             ["1. 以用户A访问页面", "2. 以用户B访问同一URL", "3. 检查是否看到A的数据"],
             "缓存键包含用户身份信息",
             ["curl"], [], "CWE-524"),
            ("OTG-A01-018", "API版本控制权限", "测试旧版API是否有更宽松的权限", "medium",
             ["多版本API"],
             ["1. 找到旧版API端点", "2. 尝试访问需要权限的操作", "3. 验证拒绝"],
             "所有版本API实施相同的权限控制",
             ["curl"], ["/v1/admin", "/api/v1/users"], "CWE-285"),
            ("OTG-A01-019", "子域权限测试", "测试子域是否共享认证状态", "medium",
             ["多个子域"],
             ["1. 在主域登录", "2. 访问其他子域", "3. 检查是否自动登录"],
             "子域间正确隔离会话",
             ["curl", "browser"], [], "CWE-668"),
            ("OTG-A01-020", "CORS配置测试", "测试CORS配置是否允许未授权访问", "high",
             ["API端点"],
             ["1. 发送Origin头", "2. 检查ACAO响应头", "3. 测试凭证请求"],
             "CORS配置严格限制允许的源",
             ["curl", "burp"], ["Origin: https://evil.com"], "CWE-942"),
        ]

        for c in a01_cases:
            cases.append(OWASPTestCase(
                case_id=c[0], category="A01", category_name="失效的访问控制",
                name=c[1], description=c[2], severity=c[3],
                prerequisites=c[4], test_steps=c[5], expected_result=c[6],
                tools=c[7], payloads=c[8], cwe=c[9], automated=True,
                test_method="semi-automated",
            ))

        # ==================== A02: 加密机制失效 (12个用例) ====================
        a02_cases = [
            ("OTG-A02-001", "弱加密算法测试", "检测使用弱加密算法", "high",
             ["源代码或配置文件"],
             ["1. 搜索加密相关代码", "2. 检查算法名称", "3. 验证是否为弱算法"],
             "不使用MD5/SHA1/DES/3DES等弱算法",
             ["grep", "semgrep"], ["MD5", "SHA1", "DES", "RC4"], "CWE-327"),
            ("OTG-A02-002", "硬编码密钥测试", "检测代码中的硬编码密钥", "critical",
             ["源代码"],
             ["1. 搜索密钥模式", "2. 检查配置文件", "3. 验证密钥管理"],
             "密钥不硬编码在代码中",
             ["gitleaks", "trufflehog"], ["API_KEY", "SECRET", "PRIVATE_KEY"], "CWE-798"),
            ("OTG-A02-003", "密码哈希强度测试", "检测弱密码哈希", "high",
             ["用户数据库或注册功能"],
             ["1. 注册测试账户", "2. 获取密码哈希", "3. 分析哈希算法和参数"],
             "使用bcrypt/Argon2/scrypt，参数足够强",
             ["hashid", "john"], [], "CWE-916"),
            ("OTG-A02-004", "TLS配置测试", "测试TLS配置安全性", "high",
             ["HTTPS服务"],
             ["1. 扫描支持的协议版本", "2. 检查密码套件", "3. 检查证书配置"],
             "仅支持TLS 1.2+，使用强密码套件",
             ["testssl.sh", "sslyze", "nmap"], [], "CWE-326"),
            ("OTG-A02-005", "敏感数据明文传输", "检测敏感数据是否明文传输", "critical",
             ["登录/支付等功能"],
             ["1. 拦截请求", "2. 检查是否使用HTTPS", "3. 检查敏感字段是否加密"],
             "所有敏感数据通过HTTPS传输",
             ["burp", "wireshark"], [], "CWE-319"),
            ("OTG-A02-006", "随机数生成测试", "检测弱随机数生成", "high",
             ["使用随机数的功能"],
             ["1. 识别随机数使用点", "2. 检查生成器", "3. 测试可预测性"],
             "使用密码学安全的随机数生成器",
             ["代码审查"], ["Math.random", "rand()", "Random"], "CWE-338"),
            ("OTG-A02-007", "IV重用测试", "检测加密中IV重用", "medium",
             ["使用CBC模式加密的功能"],
             ["1. 加密相同明文两次", "2. 比较密文", "3. 检查IV是否相同"],
             "每次加密使用唯一IV",
             ["自定义脚本"], [], "CWE-329"),
            ("OTG-A02-008", "填充Oracle测试", "测试是否存在填充Oracle攻击", "high",
             ["使用CBC模式的加密功能"],
             ["1. 修改密文填充", "2. 观察错误信息", "3. 测试是否可解密"],
             "不泄露填充错误信息",
             ["padbuster"], [], "CWE-649"),
            ("OTG-A02-009", "证书验证测试", "测试客户端是否正确验证证书", "high",
             ["移动应用或客户端"],
             ["1. 设置代理", "2. 使用自签名证书", "3. 观察是否接受"],
             "客户端正确验证服务器证书",
             ["burp", "mitmproxy"], [], "CWE-295"),
            ("OTG-A02-010", "HSTS配置测试", "测试HSTS头配置", "medium",
             ["HTTPS网站"],
             ["1. 检查响应头", "2. 验证max-age", "3. 测试includeSubDomains"],
             "配置HSTS，max-age≥31536000",
             ["curl", "nikto"], ["Strict-Transport-Security"], "CWE-319"),
            ("OTG-A02-011", "密钥长度测试", "检测密钥长度是否足够", "medium",
             ["加密配置"],
             ["1. 识别加密算法", "2. 检查密钥长度", "3. 验证是否符合标准"],
             "RSA≥2048，ECC≥256，AES≥128",
             ["sslscan", "代码审查"], [], "CWE-326"),
            ("OTG-A02-012", "敏感数据存储测试", "检测敏感数据是否明文存储", "high",
             ["数据库/日志/缓存"],
             ["1. 检查数据库字段", "2. 检查日志文件", "3. 检查本地存储"],
             "敏感数据加密存储，日志脱敏",
             ["数据库查询", "grep"], [], "CWE-312"),
        ]

        for c in a02_cases:
            cases.append(OWASPTestCase(
                case_id=c[0], category="A02", category_name="加密机制失效",
                name=c[1], description=c[2], severity=c[3],
                prerequisites=c[4], test_steps=c[5], expected_result=c[6],
                tools=c[7], payloads=c[8], cwe=c[9], automated=True,
                test_method="semi-automated",
            ))

        # ==================== A03: 注入 (15个用例) ====================
        a03_cases = [
            ("OTG-A03-001", "SQL注入测试", "测试SQL注入漏洞", "critical",
             ["所有输入点"],
             ["1. 识别所有输入参数", "2. 注入单引号", "3. 观察错误", "4. 使用sqlmap验证"],
             "所有输入使用参数化查询",
             ["sqlmap", "burp"], ["'", "1' OR '1'='1", "1; DROP TABLE--"], "CWE-89"),
            ("OTG-A03-002", "NoSQL注入测试", "测试NoSQL注入漏洞", "high",
             ["使用NoSQL数据库的应用"],
             ["1. 识别NoSQL查询点", "2. 注入操作符", "3. 观察响应变化"],
             "输入经过验证，不直接用于NoSQL查询",
             ["burp", "nosqlmap"], ["{$gt: ''}", "{$ne: null}", "$where"], "CWE-943"),
            ("OTG-A03-003", "命令注入测试", "测试操作系统命令注入", "critical",
             ["执行系统命令的功能"],
             ["1. 识别命令执行点", "2. 注入命令分隔符", "3. 观察命令执行结果"],
             "不使用shell执行，使用参数化API",
             ["burp", "commix"], ["; id;", "| whoami", "&& ls", "$(id)"], "CWE-78"),
            ("OTG-A03-004", "XSS测试", "测试跨站脚本漏洞", "high",
             ["所有输出点"],
             ["1. 识别所有输入", "2. 注入XSS payload", "3. 检查是否在响应中执行"],
             "所有输出进行上下文相关编码",
             ["burp", "xssstrike"], ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"], "CWE-79"),
            ("OTG-A03-005", "LDAP注入测试", "测试LDAP注入漏洞", "high",
             ["使用LDAP的功能"],
             ["1. 识别LDAP查询点", "2. 注入LDAP元字符", "3. 观察响应"],
             "使用参数化LDAP查询",
             ["burp"], ["*)(uid=*))(|(uid=*", "admin)(&)"], "CWE-90"),
            ("OTG-A03-006", "XPath注入测试", "测试XPath注入漏洞", "high",
             ["使用XML/XPath的功能"],
             ["1. 识别XPath查询点", "2. 注入XPath语法", "3. 观察响应"],
             "使用参数化XPath查询",
             ["burp"], ["' or '1'='1", "'] | //user | ['a"], "CWE-643"),
            ("OTG-A03-007", "XXE测试", "测试XML外部实体注入", "high",
             ["解析XML的功能"],
             ["1. 识别XML输入点", "2. 注入DOCTYPE实体", "3. 观察是否读取文件"],
             "禁用外部实体和DTD",
             ["burp"], ["<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"], "CWE-611"),
            ("OTG-A03-008", "SSRF测试", "测试服务器端请求伪造", "high",
             ["发起服务器端请求的功能"],
             ["1. 识别URL输入点", "2. 注入内网地址", "3. 观察响应差异"],
             "URL白名单验证，禁止内网访问",
             ["burp", "ssrfmap"], ["http://127.0.0.1", "http://169.254.169.254/"], "CWE-918"),
            ("OTG-A03-009", "模板注入测试", "测试SSTI服务器端模板注入", "high",
             ["使用模板引擎的功能"],
             ["1. 识别模板输入点", "2. 注入模板表达式", "3. 观察是否执行"],
             "不允许用户输入直接作为模板",
             ["burp", "tplmap"], ["{{7*7}}", "${7*7}", "<%= 7*7 %>"], "CWE-1336"),
            ("OTG-A03-010", "邮件头注入测试", "测试邮件头注入", "medium",
             ["发送邮件的功能"],
             ["1. 识别邮件参数", "2. 注入CRLF", "3. 观察是否添加额外头"],
             "过滤CRLF字符",
             ["burp"], ["%0aBcc: victim@evil.com", "%0d%0aCc: test@test.com"], "CWE-77"),
            ("OTG-A03-011", "CRLF注入测试", "测试HTTP响应拆分", "medium",
             ["设置响应头的功能"],
             ["1. 识别头注入点", "2. 注入CRLF", "3. 观察响应是否拆分"],
             "过滤CRLF字符",
             ["burp"], ["%0d%0aSet-Cookie: injected=1"], "CWE-113"),
            ("OTG-A03-012", "表达式语言注入", "测试EL/OGNL注入", "high",
             ["Java应用"],
             ["1. 识别EL表达式点", "2. 注入表达式", "3. 观察执行结果"],
             "不允许用户输入作为EL表达式",
             ["burp"], ["${Runtime.getRuntime().exec('id')}"], "CWE-917"),
            ("OTG-A03-013", "反序列化测试", "测试不安全反序列化", "critical",
             ["反序列化数据的功能"],
             ["1. 识别序列化数据", "2. 替换为恶意payload", "3. 观察是否执行"],
             "使用白名单类验证，不反序列化不可信数据",
             ["ysoserial", "burp"], ["rO0AB...（恶意序列化数据）"], "CWE-502"),
            ("OTG-A03-014", "GraphQL注入测试", "测试GraphQL注入", "high",
             ["GraphQL端点"],
             ["1. 分析GraphQL schema", "2. 测试参数注入", "3. 测试批量查询攻击"],
             "GraphQL参数正确验证，限制查询复杂度",
             ["graphql-cli", "burp"], ["{ user(id: \"1' OR '1'='1\") { name } }"], "CWE-89"),
            ("OTG-A03-015", "日志注入测试", "测试日志注入/伪造", "low",
             ["日志记录功能"],
             ["1. 识别日志输入点", "2. 注入换行和假日志", "3. 检查日志文件"],
             "日志输入进行净化",
             ["burp"], ["%0a[INFO] Fake log entry"], "CWE-117"),
        ]

        for c in a03_cases:
            cases.append(OWASPTestCase(
                case_id=c[0], category="A03", category_name="注入",
                name=c[1], description=c[2], severity=c[3],
                prerequisites=c[4], test_steps=c[5], expected_result=c[6],
                tools=c[7], payloads=c[8], cwe=c[9], automated=True,
                test_method="automated",
            ))

        # 由于篇幅，我会创建完整的120+用例，这里先展示结构
        # 剩余类别用更紧凑的方式添加

        # ==================== A04: 不安全设计 (10个用例) ====================
        a04_names = [
            ("业务逻辑漏洞测试", "测试业务逻辑缺陷", "high", ["CWE-840"]),
            ("竞争条件测试", "测试竞态条件漏洞", "high", ["CWE-362"]),
            ("工作流绕过测试", "测试能否绕过业务流程", "high", ["CWE-840"]),
            ("信任边界测试", "测试信任边界是否清晰", "medium", ["CWE-501"]),
            ("输入验证设计测试", "测试输入验证策略", "medium", ["CWE-20"]),
            ("错误处理设计测试", "测试错误处理策略", "medium", ["CWE-755"]),
            ("安全功能设计测试", "测试安全功能的设计", "high", ["CWE-693"]),
            ("数据完整性设计测试", "测试数据完整性保护", "medium", ["CWE-353"]),
            ("会话管理设计测试", "测试会话管理设计", "high", ["CWE-384"]),
            ("加密设计测试", "测试加密方案设计", "high", ["CWE-327"]),
        ]
        for i, (name, desc, sev, cwe) in enumerate(a04_names, 1):
            cases.append(OWASPTestCase(
                case_id=f"OTG-A04-{i:03d}", category="A04", category_name="不安全设计",
                name=name, description=desc, severity=sev, cwe=cwe[0],
                test_method="manual", automated=False,
                test_steps=["1. 分析业务流程设计", "2. 识别设计缺陷", "3. 验证安全控制"],
                expected_result="设计层面无安全缺陷",
            ))

        # ==================== A05: 安全配置错误 (15个用例) ====================
        a05_names = [
            ("默认凭据测试", "检测默认账户和密码", "critical", "CWE-798"),
            ("目录列表测试", "检测目录列表是否开启", "medium", "CWE-548"),
            ("错误信息泄露测试", "检测详细错误信息", "medium", "CWE-209"),
            ("安全响应头测试", "检测安全响应头配置", "medium", "CWE-693"),
            ("CORS配置测试", "检测CORS配置", "high", "CWE-942"),
            ("HTTP方法测试", "检测危险HTTP方法", "medium", "CWE-650"),
            ("管理面板暴露测试", "检测管理面板是否暴露", "high", "CWE-284"),
            ("备份文件测试", "检测备份文件泄露", "medium", "CWE-530"),
            ("源码泄露测试", "检测源码泄露", "high", "CWE-540"),
            ("版本信息泄露测试", "检测服务器版本信息", "low", "CWE-200"),
            ("TRACE方法测试", "检测TRACE方法", "low", "CWE-693"),
            ("SSL配置测试", "检测SSL/TLS配置", "high", "CWE-326"),
            ("Cookie安全属性测试", "检测Cookie安全属性", "medium", "CWE-614"),
            ("缓存控制测试", "检测缓存控制头", "low", "CWE-525"),
            ("云存储配置测试", "检测云存储权限", "high", "CWE-284"),
        ]
        for i, (name, desc, sev, cwe) in enumerate(a05_names, 1):
            cases.append(OWASPTestCase(
                case_id=f"OTG-A05-{i:03d}", category="A05", category_name="安全配置错误",
                name=name, description=desc, severity=sev, cwe=cwe,
                test_method="automated", automated=True,
                tools=["nmap", "nikto", "nuclei", "curl"],
                test_steps=["1. 扫描目标配置", "2. 对比安全基线", "3. 记录发现"],
                expected_result="符合安全配置基线",
            ))

        # ==================== A06: 易受攻击和过时的组件 (10个用例) ====================
        a06_names = [
            ("已知漏洞组件扫描", "扫描含已知漏洞的组件", "high", "CWE-1104"),
            ("依赖版本检查", "检查依赖版本是否过时", "medium", "CWE-1104"),
            ("未使用依赖检查", "识别未使用的依赖", "low", "CWE-1104"),
            ("组件配置测试", "检查组件安全配置", "medium", "CWE-16"),
            ("CVE匹配测试", "匹配组件版本与CVE", "high", "CWE-1104"),
            ("开发框架测试", "测试开发框架安全性", "medium", "CWE-1104"),
            ("客户端库测试", "测试客户端库安全性", "medium", "CWE-1104"),
            ("容器镜像扫描", "扫描容器镜像漏洞", "high", "CWE-1104"),
            ("CDN依赖测试", "测试CDN依赖安全性", "medium", "CWE-829"),
            ("软件物料清单", "生成SBOM并分析", "medium", "CWE-1104"),
        ]
        for i, (name, desc, sev, cwe) in enumerate(a06_names, 1):
            cases.append(OWASPTestCase(
                case_id=f"OTG-A06-{i:03d}", category="A06", category_name="易受攻击和过时的组件",
                name=name, description=desc, severity=sev, cwe=cwe,
                test_method="automated", automated=True,
                tools=["npm audit", "pip-audit", "owasp-dep-check", "trivy"],
                test_steps=["1. 识别所有依赖", "2. 检查版本和已知漏洞", "3. 生成报告"],
                expected_result="无已知高危漏洞的组件",
            ))

        # ==================== A07: 身份识别和认证失败 (12个用例) ====================
        a07_names = [
            ("暴力破解测试", "测试登录暴力破解防护", "high", "CWE-307"),
            ("弱密码策略测试", "测试密码强度要求", "high", "CWE-521"),
            ("会话固定测试", "测试会话固定攻击", "high", "CWE-384"),
            ("会话超时测试", "测试会话超时配置", "medium", "CWE-613"),
            ("密码找回测试", "测试密码找回功能", "high", "CWE-640"),
            ("MFA测试", "测试多因素认证", "high", "CWE-308"),
            ("注册功能测试", "测试注册功能安全", "medium", "CWE-306"),
            ("账户锁定测试", "测试账户锁定机制", "medium", "CWE-307"),
            ("凭据填充测试", "测试凭据填充防护", "high", "CWE-307"),
            ("OAuth测试", "测试OAuth实现安全", "high", "CWE-384"),
            ("JWT测试", "测试JWT实现安全", "high", "CWE-347"),
            ("API认证测试", "测试API认证机制", "high", "CWE-306"),
        ]
        for i, (name, desc, sev, cwe) in enumerate(a07_names, 1):
            cases.append(OWASPTestCase(
                case_id=f"OTG-A07-{i:03d}", category="A07", category_name="身份识别和认证失败",
                name=name, description=desc, severity=sev, cwe=cwe,
                test_method="semi-automated", automated=False,
                tools=["burp", "hydra", "jwt_tool"],
                test_steps=["1. 识别认证机制", "2. 测试各种攻击向量", "3. 验证防护措施"],
                expected_result="认证机制安全可靠",
            ))

        # ==================== A08: 软件和数据完整性失败 (8个用例) ====================
        a08_names = [
            ("不安全反序列化测试", "测试反序列化漏洞", "critical", "CWE-502"),
            ("CI/CD管道测试", "测试CI/CD管道安全", "high", "CWE-494"),
            ("软件更新测试", "测试软件更新机制", "high", "CWE-494"),
            ("数据完整性测试", "测试数据完整性保护", "medium", "CWE-353"),
            ("供应链攻击测试", "测试供应链安全", "high", "CWE-1104"),
            ("插件安全测试", "测试插件/扩展安全", "medium", "CWE-494"),
            ("配置完整性测试", "测试配置文件完整性", "medium", "CWE-353"),
            ("签名验证测试", "测试数字签名验证", "high", "CWE-347"),
        ]
        for i, (name, desc, sev, cwe) in enumerate(a08_names, 1):
            cases.append(OWASPTestCase(
                case_id=f"OTG-A08-{i:03d}", category="A08", category_name="软件和数据完整性失败",
                name=name, description=desc, severity=sev, cwe=cwe,
                test_method="manual", automated=False,
                test_steps=["1. 分析完整性保护机制", "2. 测试各种绕过方法", "3. 验证保护效果"],
                expected_result="软件和数据完整性得到保护",
            ))

        # ==================== A09: 安全日志和监控失败 (10个用例) ====================
        a09_names = [
            ("登录日志测试", "测试登录事件日志", "medium", "CWE-778"),
            ("敏感操作日志测试", "测试敏感操作日志", "medium", "CWE-778"),
            ("日志完整性测试", "测试日志防篡改", "high", "CWE-353"),
            ("告警机制测试", "测试安全告警机制", "medium", "CWE-778"),
            ("日志保留测试", "测试日志保留策略", "low", "CWE-778"),
            ("实时监控测试", "测试实时监控能力", "medium", "CWE-778"),
            ("事件响应测试", "测试事件响应流程", "medium", "CWE-778"),
            ("审计追踪测试", "测试审计追踪能力", "medium", "CWE-778"),
            ("日志注入测试", "测试日志注入防护", "low", "CWE-117"),
            ("敏感信息日志测试", "测试日志中敏感信息", "high", "CWE-532"),
        ]
        for i, (name, desc, sev, cwe) in enumerate(a09_names, 1):
            cases.append(OWASPTestCase(
                case_id=f"OTG-A09-{i:03d}", category="A09", category_name="安全日志和监控失败",
                name=name, description=desc, severity=sev, cwe=cwe,
                test_method="manual", automated=False,
                test_steps=["1. 检查日志配置", "2. 触发安全事件", "3. 验证日志记录和告警"],
                expected_result="安全事件被正确记录和告警",
            ))

        # ==================== A10: SSRF (8个用例) ====================
        a10_names = [
            ("基础SSRF测试", "测试基础SSRF漏洞", "high", "CWE-918"),
            ("内网探测测试", "通过SSRF探测内网", "high", "CWE-918"),
            ("云元数据测试", "测试云元数据访问", "critical", "CWE-918"),
            ("协议绕过测试", "测试协议限制绕过", "medium", "CWE-918"),
            ("DNS重绑定测试", "测试DNS重绑定防护", "medium", "CWE-918"),
            ("URL解析差异测试", "测试URL解析差异", "medium", "CWE-918"),
            ("盲SSRF测试", "测试盲SSRF漏洞", "medium", "CWE-918"),
            ("时间延迟SSRF测试", "测试基于时间的SSRF", "low", "CWE-918"),
        ]
        for i, (name, desc, sev, cwe) in enumerate(a10_names, 1):
            cases.append(OWASPTestCase(
                case_id=f"OTG-A10-{i:03d}", category="A10", category_name="服务器端请求伪造",
                name=name, description=desc, severity=sev, cwe=cwe,
                test_method="semi-automated", automated=True,
                tools=["burp", "ssrfmap"],
                payloads=["http://127.0.0.1", "http://169.254.169.254/", "file:///etc/passwd", "gopher://127.0.0.1:6379"],
                test_steps=["1. 识别URL输入点", "2. 注入各种内网地址", "3. 观察响应差异"],
                expected_result="无法通过SSRF访问内网资源",
            ))

        # 注册所有用例
        for case in cases:
            self.cases[case.case_id] = case

    def get_case(self, case_id: str) -> Optional[OWASPTestCase]:
        """获取测试用例"""
        return self.cases.get(case_id)

    def get_by_category(self, category: str) -> List[OWASPTestCase]:
        """按类别获取用例"""
        return [c for c in self.cases.values() if c.category == category]

    def get_by_severity(self, severity: str) -> List[OWASPTestCase]:
        """按严重级别获取用例"""
        return [c for c in self.cases.values() if c.severity == severity]

    def get_automated_cases(self) -> List[OWASPTestCase]:
        """获取可自动化的用例"""
        return [c for c in self.cases.values() if c.automated]

    def search_cases(self, keyword: str) -> List[OWASPTestCase]:
        """搜索用例"""
        keyword = keyword.lower()
        return [
            c for c in self.cases.values()
            if keyword in c.name.lower()
            or keyword in c.description.lower()
            or keyword in c.category_name.lower()
        ]

    def get_all_categories(self) -> List[Dict]:
        """获取所有类别统计"""
        categories = {}
        for c in self.cases.values():
            if c.category not in categories:
                categories[c.category] = {
                    "category": c.category,
                    "name": c.category_name,
                    "count": 0,
                    "by_severity": {},
                }
            categories[c.category]["count"] += 1
            sev = c.severity
            categories[c.category]["by_severity"][sev] = categories[c.category]["by_severity"].get(sev, 0) + 1

        return sorted(categories.values(), key=lambda x: x["category"])

    def get_stats(self) -> Dict:
        """获取统计信息"""
        by_severity = {}
        by_category = {}
        automated = 0

        for c in self.cases.values():
            by_severity[c.severity] = by_severity.get(c.severity, 0) + 1
            by_category[c.category] = by_category.get(c.category, 0) + 1
            if c.automated:
                automated += 1

        return {
            "total": len(self.cases),
            "by_severity": by_severity,
            "by_category": by_category,
            "automated": automated,
            "manual": len(self.cases) - automated,
        }

    def generate_test_plan(self, target: str = "",
                           categories: List[str] = None,
                           severity_filter: List[str] = None) -> List[OWASPTestCase]:
        """
        生成测试计划

        Args:
            target: 测试目标
            categories: 要包含的类别（None表示全部）
            severity_filter: 严重级别过滤（None表示全部）

        Returns:
            测试用例列表
        """
        plan = list(self.cases.values())

        if categories:
            plan = [c for c in plan if c.category in categories]

        if severity_filter:
            plan = [c for c in plan if c.severity in severity_filter]

        # 按类别和严重级别排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        plan.sort(key=lambda c: (c.category, severity_order.get(c.severity, 99)))

        return plan
