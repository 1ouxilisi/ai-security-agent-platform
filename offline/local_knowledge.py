#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本地知识库 - 内置漏洞/工具/最佳实践知识，离线可用

三类知识库:
1. vulnerabilities  漏洞知识库（20条）
2. tools            工具知识库（15条）
3. best_practices   最佳实践库（10条）
"""
from typing import Any, Dict, List, Optional


# ==================== 漏洞知识库（20条） ====================
_VULNERABILITIES: Dict[str, Dict[str, Any]] = {
    "sql_injection": {"vuln_id": "sql_injection", "name": "SQL注入", "category": "注入",
        "description": "攻击者将恶意SQL语句拼接到应用程序的查询中，可读取/篡改/删除数据库数据，甚至执行系统命令。",
        "detection_method": "输入单引号、布尔型(AND 1=1/1=2)、时间盲注(SLEEP)，观察响应差异与错误信息。",
        "remediation": "使用参数化查询/预编译语句；最小权限数据库账户；输入校验；ORM。",
        "severity": "critical", "references": ["OWASP A03", "CWE-89"]},
    "xss": {"vuln_id": "xss", "name": "跨站脚本XSS", "category": "注入",
        "description": "攻击者在网页中注入恶意脚本，在受害者浏览器执行，可窃取Cookie/会话。",
        "detection_method": "插入<script>、事件处理器、SVG payload，观察是否反射/存储到页面。",
        "remediation": "输出编码；CSP内容安全策略；HttpOnly Cookie；输入校验。",
        "severity": "high", "references": ["OWASP A03", "CWE-79"]},
    "csrf": {"vuln_id": "csrf", "name": "跨站请求伪造CSRF", "category": "身份认证",
        "description": "诱导已登录用户在不知情下发送恶意请求，执行非预期操作。",
        "detection_method": "检查状态变更请求是否携带不可预测的CSRF Token/Origin/Referer。",
        "remediation": "CSRF Token；SameSite Cookie；校验Origin/Referer；二次确认。",
        "severity": "medium", "references": ["OWASP A01", "CWE-352"]},
    "command_injection": {"vuln_id": "command_injection", "name": "命令注入", "category": "注入",
        "description": "应用将用户输入直接传入系统命令，攻击者可执行任意操作系统命令。",
        "detection_method": "插入 ; | && `id` $(whoami)，观察命令执行结果(uid=)。",
        "remediation": "避免调用shell；使用参数化API；白名单校验；最小权限运行。",
        "severity": "critical", "references": ["OWASP A03", "CWE-78"]},
    "path_traversal": {"vuln_id": "path_traversal", "name": "路径穿越", "category": "访问控制",
        "description": "通过../或绝对路径读取Web根目录外的任意文件。",
        "detection_method": "请求../../etc/passwd、boot.ini，观察文件内容是否泄露。",
        "remediation": "规范化路径并限制在根目录；白名单；禁止用户输入拼路径。",
        "severity": "high", "references": ["OWASP A01", "CWE-22"]},
    "ssrf": {"vuln_id": "ssrf", "name": "服务端请求伪造SSRF", "category": "注入",
        "description": "诱导服务器发起攻击者控制的请求，访问内网或云元数据服务。",
        "detection_method": "让服务端请求http://169.254.169.254/、内网IP，观察响应。",
        "remediation": "URL白名单；禁用不必要协议；内网网络隔离；禁用重定向跟随。",
        "severity": "high", "references": ["OWASP A10", "CWE-918"]},
    "xxe": {"vuln_id": "xxe", "name": "XML外部实体XXE", "category": "注入",
        "description": "XML解析器处理恶意DOCTYPE，读取本地文件或发起SSRF。",
        "detection_method": "提交含外部实体的XML，观察是否回显文件内容或XML解析错误。",
        "remediation": "禁用DTD/外部实体；使用JSON；升级XML库。",
        "severity": "high", "references": ["OWASP A05", "CWE-611"]},
    "deserialization": {"vuln_id": "deserialization", "name": "不安全反序列化", "category": "不安全设计",
        "description": "对不可信数据反序列化导致任意代码执行，如Java原生序列化、PHP unserialize。",
        "detection_method": "发送恶意序列化payload，观察反序列化异常/RCE回显。",
        "remediation": "避免反序列化不可信数据；使用JSON；白名单类；完整性签名。",
        "severity": "critical", "references": ["OWASP A08", "CWE-502"]},
    "file_upload": {"vuln_id": "file_upload", "name": "任意文件上传", "category": "访问控制",
        "description": "允许上传可执行文件(webshell)并访问执行，获取服务器控制权。",
        "detection_method": "上传.php/.jsp/.html，检查是否可访问执行，绕过前端校验。",
        "remediation": "白名单后缀；重命名；存储于非Web目录；内容检测；独立域名。",
        "severity": "critical", "references": ["OWASP A04", "CWE-434"]},
    "auth_bypass": {"vuln_id": "auth_bypass", "name": "认证绕过", "category": "身份认证",
        "description": "通过篡改请求、默认凭据、逻辑缺陷绕过登录认证。",
        "detection_method": "测试空密码、SQL万能钥匙、JWT算法替换、路径绕过。",
        "remediation": "服务端统一鉴权；强密码策略；安全会话；JWT强算法。",
        "severity": "critical", "references": ["OWASP A07", "CWE-287"]},
    "session_fixation": {"vuln_id": "session_fixation", "name": "会话固定", "category": "身份认证",
        "description": "登录后未更换SessionID，攻击者可预设会话劫持用户。",
        "detection_method": "登录前后对比SessionID是否变化；检查Cookie属性。",
        "remediation": "登录后重新生成SessionID；登出销毁；HttpOnly/Secure。",
        "severity": "medium", "references": ["OWASP A07", "CWE-384"]},
    "privilege_escalation": {"vuln_id": "privilege_escalation", "name": "越权访问", "category": "访问控制",
        "description": "水平/垂直越权，普通用户访问他人数据或管理员功能。",
        "detection_method": "水平：改ID访问他人资源；垂直：直接请求管理接口。",
        "remediation": "服务端对象级鉴权ABAC；默认拒绝；统一权限校验。",
        "severity": "high", "references": ["OWASP A01", "CWE-639"]},
    "idor": {"vuln_id": "idor", "name": "不安全直接对象引用IDOR", "category": "访问控制",
        "description": "通过修改URL参数/ID直接访问未授权对象，是越权的典型形式。",
        "detection_method": "遍历ID、UUID替换，检查是否返回他人数据。",
        "remediation": "对象级访问控制；不可预测ID；会话绑定校验。",
        "severity": "high", "references": ["OWASP A01", "CWE-639"]},
    "open_redirect": {"vuln_id": "open_redirect", "name": "开放重定向", "category": "访问控制",
        "description": "跳转参数可控到外部域名，常用于钓鱼。",
        "detection_method": "修改redirect/url参数为外部域名，检查是否302跳转。",
        "remediation": "跳转白名单；相对路径；提示确认。",
        "severity": "low", "references": ["OWASP A01", "CWE-601"]},
    "info_leak": {"vuln_id": "info_leak", "name": "敏感信息泄露", "category": "配置错误",
        "description": "响应中泄露堆栈、路径、版本、密钥等敏感信息。",
        "detection_method": "触发错误页，检查Server头、错误详情、调试接口。",
        "remediation": "关闭调试模式；统一错误页；隐藏版本号；日志脱敏。",
        "severity": "medium", "references": ["OWASP A09", "CWE-200"]},
    "directory_traversal": {"vuln_id": "directory_traversal", "name": "目录遍历", "category": "配置错误",
        "description": "Web服务器开启目录浏览，列出敏感文件。",
        "detection_method": "请求常见目录，检查'Index of /'特征。",
        "remediation": "关闭Indexes；禁止列目录；目录默认文档。",
        "severity": "low", "references": ["CWE-548"]},
    "weak_crypto": {"vuln_id": "weak_crypto", "name": "不安全加密", "category": "加密失败",
        "description": "使用MD5/SHA1/DES/硬编码密钥，加密强度不足。",
        "detection_method": "检查证书链、TLS版本、算法套件、密码哈希方式。",
        "remediation": "TLS1.2+；bcrypt/Argon2；AES-256；HMAC；密钥管理。",
        "severity": "medium", "references": ["OWASP A02", "CWE-327"]},
    "log4j": {"vuln_id": "log4j", "name": "CVE-2021-44228 Log4Shell", "category": "已知CVE",
        "description": "Apache Log4j2 JNDI注入，攻击者通过日志内容触发远程代码执行。",
        "detection_method": "发送${jndi:ldap://...} payload到各HTTP头，观察DNS/LDAP外连。",
        "remediation": "升级Log4j到2.17.1+；移除JndiLookup；WAF规则。",
        "severity": "critical", "references": ["CVE-2021-44228"]},
    "struts2": {"vuln_id": "struts2", "name": "CVE-2017-5638 Struts2 S2-045", "category": "已知CVE",
        "description": "Apache Struts2 Jakarta Multipart解析OGNL注入导致RCE。",
        "detection_method": "在Content-Type头注入OGNL表达式，观察回显。",
        "remediation": "升级Struts2到2.3.32/2.5.10.1+；WAF拦截。",
        "severity": "critical", "references": ["CVE-2017-5638"]},
    "heartbleed": {"vuln_id": "heartbleed", "name": "CVE-2014-0160 Heartbleed", "category": "已知CVE",
        "description": "OpenSSL TLS心跳处理越界读取，泄露内存中的私钥/数据。",
        "detection_method": "使用sslscan/testssl发送恶意heartbeat，检查返回长度。",
        "remediation": "升级OpenSSL到1.0.1g+；吊销并更换泄露证书密钥。",
        "severity": "high", "references": ["CVE-2014-0160"]},
}


# ==================== 工具知识库（15条） ====================
_TOOLS: Dict[str, Dict[str, Any]] = {
    "nmap": {"tool_id": "nmap", "name": "Nmap", "category": "网络扫描",
        "description": "端口扫描与服务指纹识别工具。",
        "usage_examples": ["nmap -sV -sC target", "nmap -p- --open target", "nmap -O target"],
        "common_params": {"-sV": "服务版本探测", "-sC": "默认脚本", "-p-": "全端口", "-A": "综合探测"},
        "tips": "先快速扫描再深扫；避免对生产网造成影响。"},
    "nikto": {"tool_id": "nikto", "name": "Nikto", "category": "Web扫描",
        "description": "Web服务器漏洞与配置扫描。",
        "usage_examples": ["nikto -h http://target", "nikto -h target -p 80,443"],
        "common_params": {"-h": "目标", "-p": "端口", "-Tuning": "扫描类型"},
        "tips": "误报较多，结果需人工验证。"},
    "sqlmap": {"tool_id": "sqlmap", "name": "sqlmap", "category": "注入检测",
        "description": "自动化SQL注入检测与利用。",
        "usage_examples": ["sqlmap -u 'http://target/?id=1'", "sqlmap -r req.txt --dbs"],
        "common_params": {"-u": "目标URL", "-r": "请求文件", "--dbs": "枚举数据库", "--os-shell": "系统shell"},
        "tips": "仅在授权目标使用；--batch 减少交互。"},
    "burp": {"tool_id": "burp", "name": "Burp Suite", "category": "Web代理",
        "description": "Web应用渗透测试代理与手动分析平台。",
        "usage_examples": ["代理拦截HTTP请求", "Repeater重放", "Intruder模糊测试"],
        "common_params": {"Proxy": "流量拦截", "Repeater": "手动重放", "Intruder": "批量fuzz"},
        "tips": "配置浏览器代理与CA证书。"},
    "metasploit": {"tool_id": "metasploit", "name": "Metasploit", "category": "利用框架",
        "description": "渗透测试利用框架（仅介绍，勿用于未授权目标）。",
        "usage_examples": ["msfconsole", "search log4j", "use exploit/...; run"],
        "common_params": {"search": "搜索模块", "use": "选择模块", "set": "设置参数", "run": "执行"},
        "tips": "严格遵守授权；注意痕迹清理。"},
    "wireshark": {"tool_id": "wireshark", "name": "Wireshark", "category": "流量分析",
        "description": "网络协议抓包与分析。",
        "usage_examples": ["http filter: http.request", "tcp.port==443", "Follow TCP Stream"],
        "common_params": {"捕获过滤器": "BPF语法", "显示过滤器": "协议字段过滤"},
        "tips": "抓包需网卡权限；保存pcap留证。"},
    "john": {"tool_id": "john", "name": "John the Ripper", "category": "密码破解",
        "description": "离线密码哈希破解。",
        "usage_examples": ["john --wordlist=rockyou.txt hash.txt"],
        "common_params": {"--wordlist": "字典", "--format": "哈希类型"},
        "tips": "仅对授权获取的哈希破解。"},
    "hashcat": {"tool_id": "hashcat", "name": "Hashcat", "category": "密码破解",
        "description": "GPU加速密码破解。",
        "usage_examples": ["hashcat -m 0 hash.txt rockyou.txt"],
        "common_params": {"-m": "哈希模式", "-a": "攻击模式"},
        "tips": "选择正确哈希模式；利用GPU。"},
    "dirb": {"tool_id": "dirb", "name": "Dirb", "category": "目录扫描",
        "description": "Web目录与文件爆破。",
        "usage_examples": ["dirb http://target /usr/share/wordlist.txt"],
        "common_params": {"": "URL 字典"},
        "tips": "控制线程避免压垮目标。"},
    "gobuster": {"tool_id": "gobuster", "name": "Gobuster", "category": "目录扫描",
        "description": "高速目录/DNS/vhost爆破。",
        "usage_examples": ["gobuster dir -u http://target -w words.txt"],
        "common_params": {"dir": "目录模式", "-u": "URL", "-w": "字典", "-x": "扩展名"},
        "tips": "配合常见扩展名 -x php,html,bak。"},
    "wfuzz": {"tool_id": "wfuzz", "name": "Wfuzz", "category": "模糊测试",
        "description": "Web参数/路径模糊测试。",
        "usage_examples": ["wfuzz -w words.txt -u http://target/FUZZ"],
        "common_params": {"-w": "字典", "-u": "URL(FUZZ占位)", "--hc": "隐藏码"},
        "tips": "用--hc过滤404噪声。"},
    "sslyze": {"tool_id": "sslyze", "name": "SSLyze", "category": "TLS审计",
        "description": "TLS/SSL配置与证书审计。",
        "usage_examples": ["sslyze --regular target:443"],
        "common_params": {"--regular": "常规检查", "--certinfo": "证书信息"},
        "tips": "检测弱协议与弱套件。"},
    "zap": {"tool_id": "zap", "name": "OWASP ZAP", "category": "Web扫描",
        "description": "开源Web应用代理与主动扫描。",
        "usage_examples": ["zap-cli quick-scan http://target"],
        "common_params": {"quick-scan": "快速扫描", "ajax-spider": "爬虫"},
        "tips": "可CI集成；开源免费。"},
    "nessus": {"tool_id": "nessus", "name": "Nessus", "category": "漏洞扫描",
        "description": "商业漏洞扫描器（家庭版免费）。",
        "usage_examples": ["新建扫描policy", "输入目标启动扫描", "查看漏洞报告"],
        "common_params": {"Policy": "扫描策略", "Target": "目标范围"},
        "tips": "补丁库需及时更新。"},
    "openvas": {"tool_id": "openvas", "name": "OpenVAS", "category": "漏洞扫描",
        "description": "开源漏洞管理与扫描框架(Greenbone)。",
        "usage_examples": ["新建Task", "配置目标", "启动并查看Report"],
        "common_params": {"Task": "扫描任务", "Report": "报告"},
        "tips": "资源占用高；适合内网定期扫描。"},
}


# ==================== 最佳实践库（10条） ====================
_PRACTICES: Dict[str, Dict[str, Any]] = {
    "web_checklist": {"practice_id": "web_checklist", "name": "Web应用安全检查清单", "category": "检查清单",
        "description": "Web渗透测试标准检查项。",
        "checklist": ["身份认证与会话", "访问控制越权", "注入(XSS/SQLi/命令)", "文件上传", "错误处理信息泄露", "安全响应头", "CSRF", "加密传输"],
        "references": ["OWASP WSTG"]},
    "api_checklist": {"practice_id": "api_checklist", "name": "API安全检查清单", "category": "检查清单",
        "description": "REST/GraphQL API安全测试。",
        "checklist": ["认证与Token", "对象级授权IDOR", "速率限制", "输入校验", "BOLA", "批量赋值", "错误信息", "GraphQL内省"],
        "references": ["OWASP API Security Top10"]},
    "mobile_checklist": {"practice_id": "mobile_checklist", "name": "移动应用安全检查清单", "category": "检查清单",
        "description": "Android/iOS应用测试项。",
        "checklist": ["反编译与硬编码密钥", "本地存储加密", "通信TLS校验", "组件导出", "日志泄露", "证书锁定"],
        "references": ["OWASP MASVS"]},
    "pentest_methodology": {"practice_id": "pentest_methodology", "name": "网络渗透测试方法论", "category": "方法论",
        "description": "标准渗透测试流程。",
        "checklist": ["情报收集", "枚举与扫描", "漏洞识别", "漏洞验证利用", "权限提升", "后渗透", "痕迹清理", "报告"],
        "references": ["PTES", "OSSTMM"]},
    "vuln_verify": {"practice_id": "vuln_verify", "name": "漏洞验证流程", "category": "流程规范",
        "description": "区分扫描器告警与真实可利用漏洞。",
        "checklist": ["复现步骤", "影响版本确认", "非破坏性验证", "误报排除", "证据截图", "严重等级标定"],
        "references": ["CVSS"]},
    "report_writing": {"practice_id": "report_writing", "name": "报告编写规范", "category": "流程规范",
        "description": "渗透测试报告标准结构。",
        "checklist": ["封面与授权", "执行摘要", "范围与方法", "漏洞详情", "风险评级", "修复建议", "附录"],
        "references": []},
    "authorization_flow": {"practice_id": "authorization_flow", "name": "授权测试流程", "category": "合规",
        "description": "合法测试前的授权确认。",
        "checklist": ["书面授权书", "范围界定", "时间窗口", "紧急联系人", "免责条款", "禁止破坏性操作"],
        "references": []},
    "evidence_collect": {"practice_id": "evidence_collect", "name": "证据收集规范", "category": "流程规范",
        "description": "漏洞证据的留存与保全。",
        "checklist": ["完整请求/响应", "时间戳", "截图录屏", "避免篡改数据", "证据链记录", "脱敏存储"],
        "references": []},
    "risk_rating": {"practice_id": "risk_rating", "name": "风险评级标准", "category": "标准",
        "description": "按CVSS评定漏洞严重程度。",
        "checklist": ["攻击向量", "复杂度", "权限要求", "用户交互", "影响范围", "CVSS分值映射等级"],
        "references": ["CVSS v3.1"]},
    "remediation_verify": {"practice_id": "remediation_verify", "name": "修复验证流程", "category": "流程规范",
        "description": "修复后回归验证。",
        "checklist": ["复测原漏洞", "确认修复生效", "检查引入新问题", "回归报告", "关闭工单"],
        "references": []},
}


class LocalKnowledge:
    """本地知识库（离线静态数据）"""

    def __init__(self):
        self.vulnerabilities = _VULNERABILITIES
        self.tools = _TOOLS
        self.best_practices = _PRACTICES

    def _score(self, text: str, query_terms: List[str]) -> int:
        text_lower = text.lower()
        return sum(1 for q in query_terms if q in text_lower)

    def search(self, query: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """基于关键词搜索，按相关度排序"""
        try:
            terms = [t for t in query.lower().split() if t] or [query.lower()]
            results = []

            pools = {"vulnerabilities": self.vulnerabilities,
                     "tools": self.tools,
                     "best_practices": self.best_practices}
            for pool_name, pool in pools.items():
                if category and category not in (pool_name, "all"):
                    continue
                for item in pool.values():
                    blob = " ".join(str(v) for v in item.values())
                    score = self._score(blob, terms)
                    if score > 0:
                        entry = dict(item)
                        entry["_pool"] = pool_name
                        entry["_score"] = score
                        results.append(entry)
            results.sort(key=lambda x: x["_score"], reverse=True)
            return results[:20]
        except Exception:
            return []

    def get_vulnerability(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        return self.vulnerabilities.get(vuln_id)

    def get_tool(self, tool_id: str) -> Optional[Dict[str, Any]]:
        return self.tools.get(tool_id)

    def get_practice(self, practice_id: str) -> Optional[Dict[str, Any]]:
        return self.best_practices.get(practice_id)

    def list_categories(self) -> Dict[str, List[str]]:
        return {
            "vulnerabilities": list(self.vulnerabilities.keys()),
            "tools": list(self.tools.keys()),
            "best_practices": list(self.best_practices.keys()),
        }

    def get_stats(self) -> Dict[str, Any]:
        return {
            "vulnerabilities": len(self.vulnerabilities),
            "tools": len(self.tools),
            "best_practices": len(self.best_practices),
            "total": len(self.vulnerabilities) + len(self.tools) + len(self.best_practices),
        }
