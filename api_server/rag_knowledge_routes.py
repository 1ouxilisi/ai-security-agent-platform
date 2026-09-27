# -*- coding: utf-8 -*-
"""RAG知识库检索 - 漏洞知识检索增强（对标CyberStrikeAI RAG知识库）"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List
import json, os

router = APIRouter(prefix="/api/v1/rag", tags=["RAG知识库"])

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
CVE_DB_PATH = os.path.join(DATA_DIR, "vuln_database.json")

# 安全知识库（内置常见漏洞类型知识）
KNOWLEDGE_BASE = {
    "sql_injection": {
        "title": "SQL注入",
        "category": "Web漏洞",
        "severity": "critical",
        "description": "攻击者通过在输入中插入恶意SQL代码，操纵后端数据库查询，导致数据泄露、篡改或权限提升。",
        "types": ["联合查询注入", "报错注入", "布尔盲注", "时间盲注", "堆叠查询", "二阶注入"],
        "detection": ["使用单引号测试异常", "AND/OR布尔逻辑测试", "UNION SELECT探测列数", "SLEEP/BENCHMARK时间延迟", "sqlmap自动化检测"],
        "prevention": ["使用参数化查询/预编译语句", "输入验证和白名单过滤", "最小权限数据库账户", "使用ORM框架", "WAF规则拦截", "定期安全审计"],
        "remediation": ["修复所有用户输入拼接SQL的位置", "改用参数化查询", "审查并收紧数据库权限", "部署WAF作为防御层"],
        "tools": ["sqlmap", "NoSQLMap", "Havij", "Burp Suite"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection"
    },
    "xss": {
        "title": "跨站脚本(XSS)",
        "category": "Web漏洞",
        "severity": "high",
        "description": "攻击者在网页中注入恶意脚本，当其他用户访问时脚本在浏览器中执行，导致Cookie窃取、会话劫持、钓鱼攻击。",
        "types": ["存储型XSS", "反射型XSS", "DOM型XSS", "Self-XSS", "Mutation XSS"],
        "detection": ["输入<script>alert(1)</script>测试", "检查输出编码", "Burp Suite主动扫描", "XSS Hunter盲打平台"],
        "prevention": ["输出编码（HTML/JS/URL/Attribute）", "Content Security Policy", "HttpOnly Cookie", "输入验证", "使用安全模板引擎"],
        "remediation": ["对所有用户输入进行上下文感知的输出编码", "部署CSP策略", "设置Cookie HttpOnly和Secure标志"],
        "tools": ["XSS Hunter", "BeEF", "Burp Suite", "OWASP ZAP"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection"
    },
    "rce": {
        "title": "远程代码执行(RCE)",
        "category": "严重漏洞",
        "severity": "critical",
        "description": "攻击者能够在远程服务器上执行任意系统命令或代码，通常由反序列化、命令注入、文件上传、模板注入等漏洞导致。",
        "types": ["命令注入", "代码注入", "反序列化RCE", "模板注入(SSTI)", "文件上传RCE", "内存破坏RCE"],
        "detection": ["命令分隔符测试(;|&&|`)", "反序列化Payload测试", "SSTI模板表达式测试", "文件上传绕过测试"],
        "prevention": ["禁止直接执行用户输入", "使用安全的反序列化白名单", "沙箱隔离执行环境", "文件上传严格验证", "禁用危险函数"],
        "remediation": ["立即修补RCE漏洞", "排查是否已被入侵", "重置所有凭证", "检查后门和持久化"],
        "tools": ["Metasploit", "Commix", "ysoserial", "Burp Suite"],
        "cwe": "CWE-94/CWE-78",
        "owasp": "A03:2021 - Injection"
    },
    "ssrf": {
        "title": "服务端请求伪造(SSRF)",
        "category": "Web漏洞",
        "severity": "high",
        "description": "攻击者诱导服务器向任意URL发起请求，可用于探测内网、访问云元数据、端口扫描、读取本地文件。",
        "types": ["基本SSRF", "盲SSRF", "重定向SSRF", "DNS重绑定SSRF"],
        "detection": ["http://127.0.0.1测试", "http://169.254.169.254云元数据测试", "file:///etc/passwd测试", "内网IP扫描"],
        "prevention": ["URL白名单验证", "禁用重定向跟随", "禁止访问内网IP段", "使用独立网络隔离的代理", "DNS解析后验证IP"],
        "remediation": ["实施URL白名单", "阻止访问内网和元数据地址", "限制出站请求协议"],
        "tools": ["SSRFmap", "Gopherus", "Burp Suite"],
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery"
    },
    "path_traversal": {
        "title": "路径穿越",
        "category": "Web漏洞",
        "severity": "high",
        "description": "攻击者通过在文件路径中插入../等序列，访问Web根目录之外的文件，导致敏感文件泄露。",
        "types": ["../穿越", "绝对路径", "URL编码绕过", "双写绕过", "UNC路径"],
        "detection": ["../../../../etc/passwd测试", "..\\..\\windows\\win.ini测试", "URL编码%2e%2e测试"],
        "prevention": ["规范化路径后验证", "使用白名单文件名", "chroot隔离", "禁止文件路径参数"],
        "remediation": ["规范化并验证所有文件路径", "使用安全的文件访问API"],
        "tools": ["Dotdotpwn", "Burp Suite"],
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control"
    },
    "weak_password": {
        "title": "弱口令/默认凭证",
        "category": "配置漏洞",
        "severity": "high",
        "description": "系统使用弱密码、默认密码或空密码，攻击者可通过暴力破解或直接登录获取访问权限。",
        "types": ["默认凭证", "弱密码", "空密码", "密码复用", "硬编码密码"],
        "detection": ["常见默认密码尝试", "Hydra暴力破解", "Medusa暴力破解", "源代码中硬编码密码搜索"],
        "prevention": ["强制强密码策略", "首次登录强制修改默认密码", "多因素认证", "密码管理器", "定期密码轮换"],
        "remediation": ["立即修改所有弱密码和默认密码", "实施强密码策略", "启用MFA", "排查是否有未授权访问"],
        "tools": ["Hydra", "Medusa", "Ncrack", "Burp Intruder"],
        "cwe": "CWE-521/CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures"
    },
    "misconfiguration": {
        "title": "安全配置错误",
        "category": "配置漏洞",
        "severity": "medium",
        "description": "系统、应用或服务器配置不当导致安全漏洞，如目录列表、默认页面、调试模式开启、CORS配置过宽、TLS配置弱。",
        "types": ["目录列表", "调试模式", "默认页面", "CORS配置错误", "TLS弱配置", "HTTP方法不安全", "敏感信息泄露"],
        "detection": ["Nikto扫描", "Nmap脚本扫描", "手动检查HTTP响应头", "SSL Labs测试"],
        "prevention": ["安全基线配置", "禁用目录列表", "关闭调试模式", "严格CORS配置", "强TLS配置", "定期配置审计"],
        "remediation": ["按照安全基线重新配置", "关闭不必要的功能和端口", "修复CORS和TLS配置"],
        "tools": ["Nikto", "Nmap NSE", "OpenVAS", "Lynis"],
        "cwe": "CWE-16",
        "owasp": "A05:2021 - Security Misconfiguration"
    },
    "sensitive_data_exposure": {
        "title": "敏感数据泄露",
        "category": "数据安全",
        "severity": "high",
        "description": "敏感数据（密码、信用卡、个人信息、API密钥）未加密或加密不足，在传输或存储过程中被窃取。",
        "types": ["明文传输", "明文存储", "弱加密", "密钥管理不当", "备份泄露", "日志泄露"],
        "detection": ["检查HTTPS配置", "搜索数据库明文密码", "检查日志中的敏感信息", "检查备份文件"],
        "prevention": ["强制HTTPS/TLS", "敏感数据加密存储", "使用强加密算法", "密钥安全管理", "数据脱敏", "安全日志审计"],
        "remediation": ["加密所有敏感数据", "强制HTTPS", "轮换泄露的密钥和凭证", "排查数据是否已泄露"],
        "tools": ["sslscan", "testssl.sh", "Burp Suite", "Nmap NSE"],
        "cwe": "CWE-319/CWE-312",
        "owasp": "A02:2021 - Cryptographic Failures"
    },
}

class RAGQueryReq(BaseModel):
    query: str
    top_k: int = 5
    category: Optional[str] = None

@router.post("/search")
def search_knowledge(req: RAGQueryReq):
    """RAG知识库检索（关键词匹配+相关性排序）"""
    query = req.query.lower()
    results = []
    for key, kb in KNOWLEDGE_BASE.items():
        if req.category and kb.get("category") != req.category:
            continue
        # 相关性评分
        score = 0
        search_text = (kb["title"] + " " + kb["description"] + " " + " ".join(kb.get("types",[])) + " " + kb.get("cwe","") + " " + " ".join(kb.get("tools",[]))).lower()
        for word in query.split():
            if word in search_text:
                score += 2
            if word in kb["title"].lower():
                score += 3
        if score > 0:
            results.append({"key": key, "score": score, "knowledge": kb})
    results.sort(key=lambda x: x["score"], reverse=True)
    return {"success": True, "data": {"query": req.query, "results": results[:req.top_k], "total": len(results)}}

@router.get("/knowledge/{key}")
def get_knowledge(key: str):
    """获取指定漏洞类型的完整知识"""
    if key in KNOWLEDGE_BASE:
        return {"success": True, "data": KNOWLEDGE_BASE[key]}
    return {"success": False, "error": "知识不存在", "available_keys": list(KNOWLEDGE_BASE.keys())}

@router.get("/categories")
def list_categories():
    """知识库分类统计"""
    cats = {}
    for key, kb in KNOWLEDGE_BASE.items():
        cat = kb.get("category", "其他")
        cats[cat] = cats.get(cat, 0) + 1
    return {"success": True, "data": {"categories": cats, "total_knowledge": len(KNOWLEDGE_BASE)}}

@router.post("/cve/search")
def search_cve(query: str, limit: int = 10):
    """CVE漏洞库检索"""
    if not os.path.exists(CVE_DB_PATH):
        return {"success": False, "error": "CVE数据库不存在"}
    try:
        with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
            cve_db = json.load(f)
        if isinstance(cve_db, dict):
            cve_list = cve_db.get("vulnerabilities", cve_db.get("cves", []))
        else:
            cve_list = cve_db
        query_lower = query.lower()
        results = []
        for cve in cve_list:
            cve_id = cve.get("cve_id", cve.get("id", "")).lower()
            desc = cve.get("description", "").lower()
            if query_lower in cve_id or query_lower in desc:
                results.append(cve)
                if len(results) >= limit:
                    break
        return {"success": True, "data": {"query": query, "results": results, "total": len(results)}}
    except Exception as e:
        return {"success": False, "error": str(e)}
