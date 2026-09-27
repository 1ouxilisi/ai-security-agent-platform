# -*- coding: utf-8 -*-
"""专业级报告引擎v2 - 执行摘要+风险矩阵+技术详情+修复方案+附录"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
import json, os, hashlib

router = APIRouter(prefix="/api/v1/report-v2", tags=["专业报告v2"])

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

# 风险等级定义
RISK_LEVELS = {
    "critical": {"label": "严重", "color": "#dc2626", "score_range": (90, 100), "description": "可直接获取服务器权限/数据泄露/远程代码执行"},
    "high": {"label": "高危", "color": "#ea580c", "score_range": (70, 89), "description": "可获取敏感信息/越权访问/重要功能绕过"},
    "medium": {"label": "中危", "color": "#ca8a04", "score_range": (40, 69), "description": "存在安全隐患但利用条件较苛刻/信息泄露有限"},
    "low": {"label": "低危", "color": "#2563eb", "score_range": (20, 39), "description": "最佳实践缺失/信息泄露轻微/配置不规范"},
    "info": {"label": "信息", "color": "#6b7280", "score_range": (0, 19), "description": "安全提示/版本信息/配置建议"},
}

# 修复建议库（增强版）
REMEDIATION_LIBRARY = {
    "sql-injection": {
        "title": "SQL注入",
        "risk": "high",
        "description": "攻击者可通过构造恶意SQL语句绕过认证、读取/修改/删除数据库数据，甚至获取服务器权限。",
        "impact": "数据泄露、数据篡改、权限提升、服务器被控",
        "remediation": [
            "使用参数化查询/预编译语句（Prepared Statement），禁止字符串拼接SQL",
            "使用ORM框架（如SQLAlchemy、MyBatis）并正确使用参数绑定",
            "对用户输入进行严格的白名单校验和类型转换",
            "数据库账号遵循最小权限原则，禁止使用sa/root等超级账号连接应用",
            "部署WAF进行SQL注入攻击检测和拦截",
            "定期进行SQL注入专项渗透测试",
        ],
        "references": ["OWASP SQL Injection Prevention Cheat Sheet", "CWE-89"],
    },
    "xss": {
        "title": "跨站脚本(XSS)",
        "risk": "high",
        "description": "攻击者可在页面中注入恶意脚本，窃取用户Cookie/会话令牌、劫持用户会话、钓鱼攻击。",
        "impact": "会话劫持、账号被盗、用户隐私泄露、网站信誉受损",
        "remediation": [
            "对所有输出到HTML的内容进行HTML实体编码（& < > \" ' /）",
            "使用框架自带的自动转义机制（React/Vue默认转义）",
            "设置Content-Security-Policy (CSP)响应头，限制脚本来源",
            "对富文本内容使用白名单HTML过滤（如DOMPurify）",
            "Cookie设置HttpOnly和Secure标志，防止JS读取",
            "避免使用innerHTML/document.write等危险API",
        ],
        "references": ["OWASP XSS Prevention Cheat Sheet", "CWE-79"],
    },
    "rce": {
        "title": "远程代码执行(RCE)",
        "risk": "critical",
        "description": "攻击者可在服务器上执行任意命令/代码，完全控制服务器，是最严重的安全漏洞。",
        "impact": "服务器完全被控、数据全部泄露/删除、内网横向移动、成为攻击跳板",
        "remediation": [
            "禁止在代码中使用eval/exec/system/popen等危险函数处理用户输入",
            "对文件上传进行严格的类型校验、内容检测、重命名、隔离存储",
            "及时更新存在RCE漏洞的框架和组件（如Log4j、Spring、Struts）",
            "应用运行在非root/低权限用户下，限制可执行文件路径",
            "部署沙箱/容器隔离，限制系统调用",
            "禁用不必要的危险PHP函数（disable_functions）",
        ],
        "references": ["OWASP Command Injection", "CWE-94", "CWE-78"],
    },
    "ssrf": {
        "title": "服务端请求伪造(SSRF)",
        "risk": "high",
        "description": "攻击者可诱导服务器向内部/外部发起请求，探测内网、访问云元数据、攻击内网服务。",
        "impact": "内网信息泄露、云服务凭证窃取（AWS/GCP元数据）、内网服务攻击",
        "remediation": [
            "对用户提供的URL进行白名单校验（协议/域名/IP段）",
            "禁止访问内网IP段（10.x/172.16-31.x/192.168.x/127.x/169.254.x）",
            "禁用重定向跟随或对重定向目标再次校验",
            "云环境禁用实例元数据访问（IMDSv2）",
            "使用独立的网络隔离环境发起外部请求",
            "限制请求超时和响应大小",
        ],
        "references": ["OWASP SSRF Prevention Cheat Sheet", "CWE-918"],
    },
    "path-traversal": {
        "title": "路径穿越",
        "risk": "high",
        "description": "攻击者可通过../等序列访问Web根目录之外的文件，读取敏感系统文件、配置文件、源代码。",
        "impact": "敏感文件泄露、配置信息泄露、源代码泄露、进一步攻击",
        "remediation": [
            "对用户输入的文件名/路径进行规范化处理后校验是否在允许目录内",
            "使用白名单方式指定可访问的文件目录",
            "禁止在文件路径中使用用户可控输入",
            "Web服务器配置禁止目录遍历和符号链接跟随",
            "对文件读取操作进行权限校验",
            "使用os.path.realpath解析后比较前缀",
        ],
        "references": ["OWASP Path Traversal", "CWE-22"],
    },
    "weak-auth": {
        "title": "弱认证/授权",
        "risk": "high",
        "description": "认证机制存在缺陷（弱密码、默认凭证、会话固定、无速率限制）或授权检查缺失（越权访问）。",
        "impact": "账号被盗、越权访问他人数据、权限提升、未授权操作",
        "remediation": [
            "强制密码复杂度策略（长度≥12、包含大小写数字特殊字符）",
            "实施多因素认证(MFA)，特别是管理员账号",
            "登录接口添加速率限制和账户锁定机制",
            "会话令牌使用安全随机数，设置HttpOnly/Secure/SameSite",
            "每个API端点都进行授权检查，不要仅依赖前端隐藏",
            "实施基于角色的访问控制(RBAC)，遵循最小权限原则",
            "定期轮换默认/初始密码，禁止硬编码凭证",
        ],
        "references": ["OWASP Authentication Cheat Sheet", "CWE-287", "CWE-285"],
    },
    "insecure-config": {
        "title": "不安全配置",
        "risk": "medium",
        "description": "服务器/应用/数据库存在不安全的默认配置、调试模式开启、不必要的服务/端口暴露、弱TLS配置。",
        "impact": "信息泄露、攻击面扩大、已知漏洞利用、数据泄露",
        "remediation": [
            "关闭生产环境的调试模式和详细错误信息",
            "移除/禁用不必要的服务、端口、默认账号和示例页面",
            "Web服务器配置安全响应头（HSTS/CSP/X-Frame-Options等）",
            "TLS配置使用强加密套件，禁用SSLv3/TLS1.0/1.1",
            "数据库禁止远程root登录，限制绑定地址",
            "定期进行配置安全审计和基线检查",
            "使用配置管理工具（Ansible/Terraform）确保一致性",
        ],
        "references": ["OWASP Configuration Management", "CWE-16"],
    },
    "sensitive-data-exposure": {
        "title": "敏感数据泄露",
        "risk": "high",
        "description": "敏感数据（密码、令牌、个人信息、密钥）在传输/存储/日志中未加密或加密方式不当。",
        "impact": "个人信息泄露、凭证被盗、合规违规（GDPR/等保）、经济损失",
        "remediation": [
            "所有敏感数据传输使用HTTPS/TLS加密",
            "密码使用bcrypt/Argon2/scrypt等慢哈希算法存储，禁止明文/MD5/SHA1",
            "API密钥/令牌存储在环境变量或密钥管理服务（KMS/Vault），禁止硬编码",
            "日志中脱敏处理敏感信息（密码/身份证/手机号/银行卡）",
            "数据库中敏感字段加密存储，实施字段级访问控制",
            "实施数据分类分级，明确敏感数据的处理规范",
            "定期进行数据泄露风险评估",
        ],
        "references": ["OWASP Sensitive Data Exposure", "CWE-312", "CWE-319"],
    },
    "missing-rate-limit": {
        "title": "缺少速率限制",
        "risk": "medium",
        "description": "API接口缺少请求频率限制，可被暴力破解、枚举、爬虫、DDoS攻击。",
        "impact": "账号暴力破解、数据批量爬取、服务不可用、资源耗尽",
        "remediation": [
            "对登录/注册/密码重置等认证接口实施严格的速率限制（如5次/分钟）",
            "对API接口实施基于IP/用户/API Key的速率限制",
            "使用令牌桶/漏桶算法，设置合理的QPS阈值",
            "超限请求返回429状态码和Retry-After头",
            "部署CDN/WAF进行基础的DDoS防护和爬虫限制",
            "对敏感操作（转账/修改密码）添加二次验证",
        ],
        "references": ["OWASP Brute Force Protection", "CWE-307"],
    },
    "cors-misconfig": {
        "title": "CORS配置错误",
        "risk": "medium",
        "description": "跨域资源共享配置不当（Access-Control-Allow-Origin: * 或反射Origin），可导致跨域数据窃取。",
        "impact": "跨域数据泄露、CSRF攻击增强、未授权API访问",
        "remediation": [
            "严格白名单允许的Origin，禁止使用*通配符",
            "禁止反射用户请求中的Origin头（动态生成Allow-Origin）",
            "仅在必要时启用Access-Control-Allow-Credentials",
            "限制允许的HTTP方法和请求头",
            "对敏感API不使用CORS，仅同域访问",
            "定期审计CORS配置",
        ],
        "references": ["OWASP CORS Misconfiguration", "CWE-942"],
    },
    "outdated-components": {
        "title": "过时组件/依赖",
        "risk": "medium",
        "description": "使用存在已知漏洞的过时框架/库/组件版本，可被已知EXP利用。",
        "impact": "已知漏洞利用、安全补丁缺失、供应链攻击",
        "remediation": [
            "建立软件物料清单(SBOM)，跟踪所有依赖组件和版本",
            "定期使用依赖扫描工具（Dependabot/Snyk/OWASP Dependency-Check）",
            "建立漏洞响应流程，高危漏洞72小时内修复",
            "使用锁定文件（package-lock.json/poetry.lock）确保版本一致性",
            "优先使用维护活跃、社区成熟的组件",
            "对第三方组件进行安全评估后再引入",
        ],
        "references": ["OWASP Using Components with Known Vulnerabilities", "CWE-1104"],
    },
}

class ReportV2Req(BaseModel):
    target: str
    scan_results: Optional[Dict[str, Any]] = None  # 直接传入扫描结果
    include_executive_summary: bool = True
    include_risk_matrix: bool = True
    include_technical_details: bool = True
    include_remediation: bool = True
    include_appendix: bool = True
    report_format: str = "json"  # json/html/markdown
    company_name: Optional[str] = None
    tester_name: Optional[str] = None

def _classify_vulnerability(vuln: Dict) -> Dict:
    """对漏洞进行分类和增强"""
    name = vuln.get("template_name", vuln.get("name", "")).lower()
    severity = vuln.get("severity", "info")
    matched_key = None
    for key in REMEDIATION_LIBRARY:
        keywords = key.replace("-", " ")
        if any(kw in name for kw in keywords.split()):
            matched_key = key
            break
    if not matched_key:
        if "sql" in name: matched_key = "sql-injection"
        elif "xss" in name or "cross-site" in name: matched_key = "xss"
        elif "rce" in name or "command" in name or "code exec" in name: matched_key = "rce"
        elif "ssrf" in name: matched_key = "ssrf"
        elif "path" in name or "traversal" in name or "lfi" in name: matched_key = "path-traversal"
        elif "auth" in name or "login" in name or "password" in name: matched_key = "weak-auth"
        elif "config" in name or "default" in name: matched_key = "insecure-config"
        elif "data" in name or "exposure" in name or "leak" in name: matched_key = "sensitive-data-exposure"
        elif "rate" in name or "brute" in name: matched_key = "missing-rate-limit"
        elif "cors" in name: matched_key = "cors-misconfig"
        elif "outdated" in name or "version" in name or "cve" in name: matched_key = "outdated-components"
    remediation = REMEDIATION_LIBRARY.get(matched_key, {})
    return {
        **vuln,
        "category": remediation.get("title", "其他"),
        "category_key": matched_key,
        "risk_description": remediation.get("description", ""),
        "impact": remediation.get("impact", ""),
        "remediation_steps": remediation.get("remediation", []),
        "references": remediation.get("references", []),
        "risk_level_info": RISK_LEVELS.get(severity, RISK_LEVELS["info"]),
    }

def _generate_risk_matrix(vulns: List[Dict]) -> Dict:
    """生成风险矩阵"""
    matrix = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    categories = {}
    for v in vulns:
        sev = v.get("severity", "info")
        matrix[sev] = matrix.get(sev, 0) + 1
        cat = v.get("category", "其他")
        categories[cat] = categories.get(cat, 0) + 1
    total = len(vulns)
    overall_score = 0
    if total > 0:
        weights = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}
        weighted_sum = sum(matrix.get(s, 0) * w for s, w in weights.items())
        overall_score = min(100, int(weighted_sum / total))
    risk_level = "critical" if overall_score >= 90 else "high" if overall_score >= 70 else "medium" if overall_score >= 40 else "low" if overall_score >= 20 else "info"
    return {
        "vulnerability_count": total,
        "by_severity": matrix,
        "by_category": categories,
        "overall_risk_score": overall_score,
        "overall_risk_level": risk_level,
        "overall_risk_label": RISK_LEVELS[risk_level]["label"],
    }

def _generate_executive_summary(target: str, risk_matrix: Dict, ports: List, vulns: List) -> Dict:
    """生成执行摘要"""
    top_vulns = sorted(vulns, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.get("severity", "info"), 5))[:5]
    summary = {
        "target": target,
        "assessment_date": datetime.now().strftime("%Y-%m-%d"),
        "scope": f"对目标 {target} 进行了全面的安全评估，包括端口扫描、服务识别、漏洞扫描和安全配置检查。",
        "key_findings": [
            f"共发现 {risk_matrix['vulnerability_count']} 个安全问题，其中严重 {risk_matrix['by_severity'].get('critical',0)} 个、高危 {risk_matrix['by_severity'].get('high',0)} 个、中危 {risk_matrix['by_severity'].get('medium',0)} 个。",
            f"整体风险评分为 {risk_matrix['overall_risk_score']}/100，风险等级为「{risk_matrix['overall_risk_label']}」。",
            f"发现 {len(ports)} 个开放端口，暴露了一定的攻击面。",
        ],
        "top_vulnerabilities": [{"title": v.get("template_name", v.get("name", "")), "severity": v.get("severity", ""), "url": v.get("matched_at", v.get("url", ""))} for v in top_vulns],
        "primary_recommendation": "建议优先修复严重和高危漏洞，关闭不必要的开放端口，加强访问控制和安全配置，并建立持续的安全监控机制。",
        "business_impact": "若不及时修复，攻击者可能利用发现的漏洞获取敏感数据、控制系统或造成服务中断，导致经济损失和声誉损害。",
    }
    return summary

@router.post("/generate")
def generate_report_v2(req: ReportV2Req):
    """生成专业级渗透测试报告v2"""
    # 获取扫描结果
    if req.scan_results:
        scan_data = req.scan_results
    else:
        # 尝试从扫描历史获取最新结果
        scan_data = {"ports": [], "vulnerabilities": [], "risk_score": 0}

    ports = scan_data.get("ports", scan_data.get("open_ports", []))
    raw_vulns = scan_data.get("vulnerabilities", [])
    risk_score = scan_data.get("risk_score", scan_data.get("score", 0))

    # 漏洞分类增强
    enhanced_vulns = [_classify_vulnerability(v) for v in raw_vulns]

    # 风险矩阵
    risk_matrix = _generate_risk_matrix(enhanced_vulns)

    report = {
        "report_id": hashlib.md5(f"{req.target}{datetime.now().isoformat()}".encode()).hexdigest()[:12],
        "report_version": "2.0",
        "generated_at": datetime.now().isoformat(),
        "target": req.target,
        "company_name": req.company_name or "未指定",
        "tester_name": req.tester_name or "AI安全测试平台",
    }

    if req.include_executive_summary:
        report["executive_summary"] = _generate_executive_summary(req.target, risk_matrix, ports, enhanced_vulns)

    if req.include_risk_matrix:
        report["risk_matrix"] = risk_matrix

    if req.include_technical_details:
        report["technical_details"] = {
            "ports": ports,
            "port_count": len(ports),
            "vulnerabilities": enhanced_vulns,
            "vulnerability_count": len(enhanced_vulns),
            "scan_parameters": scan_data.get("parameters", {}),
            "tools_used": ["Nmap", "Nuclei", "AI安全测试平台"],
        }

    if req.include_remediation:
        # 按类别聚合修复方案
        remediation_plan = {}
        for v in enhanced_vulns:
            cat = v.get("category_key", "other")
            if cat and cat not in remediation_plan and v.get("remediation_steps"):
                remediation_plan[cat] = {
                    "title": v.get("category", "其他"),
                    "severity": v.get("severity", "info"),
                    "affected_count": 1,
                    "remediation_steps": v.get("remediation_steps", []),
                    "references": v.get("references", []),
                }
            elif cat in remediation_plan:
                remediation_plan[cat]["affected_count"] += 1
        report["remediation_plan"] = {
            "priorities": ["critical", "high", "medium", "low", "info"],
            "items": list(remediation_plan.values()),
            "total_categories": len(remediation_plan),
        }

    if req.include_appendix:
        report["appendix"] = {
            "glossary": {
                "CVE": "Common Vulnerabilities and Exposures，公共漏洞和暴露编号",
                "CVSS": "Common Vulnerability Scoring System，通用漏洞评分系统",
                "OWASP": "Open Web Application Security Project，开放式Web应用程序安全项目",
                "RCE": "Remote Code Execution，远程代码执行",
                "XSS": "Cross-Site Scripting，跨站脚本攻击",
                "SQLi": "SQL Injection，SQL注入",
                "SSRF": "Server-Side Request Forgery，服务端请求伪造",
                "CSRF": "Cross-Site Request Forgery，跨站请求伪造",
                "CORS": "Cross-Origin Resource Sharing，跨域资源共享",
                "WAF": "Web Application Firewall，Web应用防火墙",
                "RBAC": "Role-Based Access Control，基于角色的访问控制",
                "MFA": "Multi-Factor Authentication，多因素认证",
            },
            "risk_level_definitions": RISK_LEVELS,
            "methodology": "本次评估遵循OWASP测试方法论和PTES渗透测试执行标准，包括信息收集、漏洞扫描、漏洞验证、风险分析和报告生成五个阶段。",
            "limitations": "本报告基于扫描时的目标状态，未进行深入的人工渗透测试和社会工程学测试。漏洞可能随时间变化，建议定期进行安全评估。",
        }

    return {"success": True, "data": report}

@router.get("/templates")
def get_report_templates():
    """报告模板列表"""
    return {"success": True, "data": {
        "templates": [
            {"id": "full", "name": "完整渗透测试报告", "description": "包含执行摘要、风险矩阵、技术详情、修复方案、附录的完整报告", "sections": ["executive_summary", "risk_matrix", "technical_details", "remediation", "appendix"]},
            {"id": "executive", "name": "高管摘要报告", "description": "仅包含执行摘要和风险矩阵，适合管理层阅读", "sections": ["executive_summary", "risk_matrix"]},
            {"id": "technical", "name": "技术详情报告", "description": "包含技术详情和修复方案，适合技术团队", "sections": ["technical_details", "remediation"]},
            {"id": "quick", "name": "快速扫描报告", "description": "精简版报告，包含关键发现和Top漏洞", "sections": ["executive_summary", "risk_matrix"]},
        ],
        "remediation_library_count": len(REMEDIATION_LIBRARY),
        "risk_levels": list(RISK_LEVELS.keys()),
    }}

@router.get("/remediation/{vuln_type}")
def get_remediation(vuln_type: str):
    """获取指定漏洞类型的修复方案"""
    if vuln_type in REMEDIATION_LIBRARY:
        return {"success": True, "data": REMEDIATION_LIBRARY[vuln_type]}
    return {"success": False, "error": f"未找到漏洞类型: {vuln_type}", "available_types": list(REMEDIATION_LIBRARY.keys())}
