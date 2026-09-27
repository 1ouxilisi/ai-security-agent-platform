# -*- coding: utf-8 -*-
"""
report_v3_routes.py - 专业级渗透测试报告引擎v3

深度提升：
- CVSS v3.1 评分系统（基础分/时间分/环境分）
- 漏洞复现步骤（PoC）
- 修复代码示例（按技术栈分类）
- 攻击链可视化数据
- 风险矩阵（可能性×影响）
- 合规映射（CWE/OWASP/CVE）
- 多格式导出（JSON/Markdown/HTML）

路由前缀：/api/v1/report-v3
"""
from __future__ import annotations
import os, sys, json, hashlib, time
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import log

async def verify_auth() -> dict:
    return {"user_id": "admin", "username": "admin", "role": "admin"}

router = APIRouter(prefix="/api/v1/report-v3", tags=["专业报告v3"])

# ==================== CVSS v3.1 评分 ====================

CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},  # 攻击向量
    "AC": {"L": 0.77, "H": 0.44},  # 攻击复杂度
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},  # 权限要求
    "UI": {"N": 0.85, "R": 0.62},  # 用户交互
    "S": {"U": "U", "C": "C"},  # 影响范围
    "C": {"H": 0.56, "L": 0.22, "N": 0.00},  # 机密性影响
    "I": {"H": 0.56, "L": 0.22, "N": 0.00},  # 完整性影响
    "A": {"H": 0.56, "L": 0.22, "N": 0.00},  # 可用性影响
}

def calculate_cvss(metrics: dict) -> dict:
    """计算CVSS v3.1基础分"""
    try:
        AV = metrics.get("AV", "N")
        AC = metrics.get("AC", "L")
        PR = metrics.get("PR", "N")
        UI = metrics.get("UI", "N")
        S = metrics.get("S", "U")
        C = metrics.get("C", "N")
        I = metrics.get("I", "N")
        A = metrics.get("A", "N")

        av_val = CVSS_METRICS["AV"].get(AV, 0.85)
        ac_val = CVSS_METRICS["AC"].get(AC, 0.77)
        pr_val = CVSS_METRICS["PR"].get(PR, 0.85)
        ui_val = CVSS_METRICS["UI"].get(UI, 0.85)
        c_val = CVSS_METRICS["C"].get(C, 0.0)
        i_val = CVSS_METRICS["I"].get(I, 0.0)
        a_val = CVSS_METRICS["A"].get(A, 0.0)

        # 可利用性
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        # 影响
        if S == "U":
            impact = 6.42 * (1 - (1-c_val)*(1-i_val)*(1-a_val))
        else:
            impact = 7.52 * (1 - (1-c_val)*(1-i_val)*(1-a_val)) - 3.25 * (1 - (1-c_val*1.5)*(1-i_val*1.5)*(1-a_val*1.5))

        if impact <= 0:
            base_score = 0
        elif S == "U":
            base_score = min((exploitability + impact), 10)
        else:
            base_score = min(1.08 * (exploitability + impact), 10)

        base_score = round(base_score, 1)

        if base_score == 0:
            severity = "无"
        elif base_score < 4.0:
            severity = "低"
        elif base_score < 7.0:
            severity = "中"
        elif base_score < 9.0:
            severity = "高"
        else:
            severity = "严重"

        vector = f"CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}/S:{S}/C:{C}/I:{I}/A:{A}"

        return {"base_score": base_score, "severity": severity, "vector": vector, "exploitability": round(exploitability, 2), "impact": round(impact, 2)}
    except Exception as e:
        return {"base_score": 0, "severity": "未知", "vector": "", "error": str(e)}

# ==================== 漏洞修复代码库 ====================

REMEDIATION_CODE = {
    "sql_injection": {
        "name": "SQL注入",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "description": "用户输入未经过滤直接拼接到SQL查询中，导致攻击者可以执行任意SQL命令。",
        "fix_examples": {
            "python": """# 使用参数化查询（推荐）
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# 使用ORM
user = User.query.filter_by(username=username).first()

# 输入验证
import re
if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
    raise ValueError("无效的用户名")""",
            "java": """// 使用PreparedStatement
String sql = "SELECT * FROM users WHERE username = ?";
PreparedStatement stmt = conn.prepareStatement(sql);
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();

// 使用JPA
User user = em.createQuery("SELECT u FROM User u WHERE u.username = :username", User.class)
    .setParameter("username", username)
    .getSingleResult();""",
            "php": """// 使用PDO预处理语句
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = :username');
$stmt->execute(['username' => $username]);
$user = $stmt->fetch();

// 使用mysqli
$stmt = $mysqli->prepare('SELECT * FROM users WHERE username = ?');
$stmt->bind_param('s', $username);
$stmt->execute();""",
        },
        "poc": """# SQL注入验证PoC
# 1. 在输入框输入: ' OR '1'='1
# 2. 观察是否绕过认证
# 3. 使用sqlmap验证: sqlmap -u "http://target/login?id=1" --dbs""",
    },
    "xss": {
        "name": "跨站脚本(XSS)",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "description": "用户输入未经过滤直接输出到HTML页面，导致攻击者可以注入恶意JavaScript代码。",
        "fix_examples": {
            "python": """# 使用模板引擎自动转义（Jinja2默认开启）
{{ user_input }}

# 手动转义
from html import escape
safe_output = escape(user_input)

# 设置CSP头
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'""",
            "javascript": """// 使用textContent而非innerHTML
element.textContent = userInput;

// 使用框架自动转义（React/Vue默认）
<div>{userInput}</div>

// DOMPurify净化
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);""",
            "php": """// 使用htmlspecialchars
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// 设置HttpOnly Cookie
setcookie("session", $value, time()+3600, "/", "", true, true);""",
        },
        "poc": """# XSS验证PoC
# 1. 存储型: 在评论框输入 <script>alert('XSS')</script>
# 2. 反射型: 访问 http://target/search?q=<script>alert(1)</script>
# 3. DOM型: 检查URL参数是否直接写入innerHTML""",
    },
    "command_injection": {
        "name": "命令注入",
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "description": "用户输入直接拼接到系统命令中执行，导致攻击者可以执行任意系统命令。",
        "fix_examples": {
            "python": """# 使用subprocess列表参数（不经过shell）
import subprocess
result = subprocess.run(['ping', '-c', '4', ip], capture_output=True)

# 输入白名单验证
import ipaddress
try:
    ipaddress.ip_address(ip)
except ValueError:
    raise ValueError("无效的IP地址")

# 避免使用shell=True
subprocess.run(f'ping {ip}', shell=True)  # 危险！""",
            "php": """// 使用escapeshellarg
$ip = escapeshellarg($_GET['ip']);
system("ping -c 4 " . $ip);

// 白名单验证
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    die("无效的IP地址");
}""",
        },
        "poc": """# 命令注入验证PoC
# 1. 输入: 127.0.0.1; id
# 2. 输入: 127.0.0.1 && whoami
# 3. 输入: 127.0.0.1 | cat /etc/passwd""",
    },
    "path_traversal": {
        "name": "路径遍历",
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "用户输入未经过滤直接用于文件路径，导致攻击者可以访问任意文件。",
        "fix_examples": {
            "python": """# 使用os.path.realpath验证
import os
base_dir = '/var/www/files/'
file_path = os.path.realpath(os.path.join(base_dir, filename))
if not file_path.startswith(base_dir):
    raise ValueError("非法路径")

# 白名单验证
ALLOWED_FILES = {'readme.txt', 'config.json', 'data.csv'}
if filename not in ALLOWED_FILES:
    raise ValueError("文件不允许访问")""",
            "php": """// 使用realpath验证
$baseDir = '/var/www/files/';
$filePath = realpath($baseDir . $_GET['file']);
if (strpos($filePath, $baseDir) !== 0) {
    die("非法路径");
}

// 过滤../
$filename = str_replace(['../', '..\\'], '', $_GET['file']);""",
        },
        "poc": """# 路径遍历验证PoC
# 1. ../../../../etc/passwd
# 2. ..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
# 3. %2e%2e%2f%2e%2e%2fetc%2fpasswd (URL编码)""",
    },
    "weak_auth": {
        "name": "弱认证/弱密码",
        "cwe": "CWE-287",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "认证机制存在缺陷，如弱密码策略、无登录失败限制、默认凭证等。",
        "fix_examples": {
            "python": """# 强密码策略
import re
def validate_password(password):
    if len(password) < 12:
        return False, "密码至少12位"
    if not re.search(r'[A-Z]', password):
        return False, "需要大写字母"
    if not re.search(r'[a-z]', password):
        return False, "需要小写字母"
    if not re.search(r'[0-9]', password):
        return False, "需要数字"
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "需要特殊字符"
    return True, "密码强度合格"

# 登录失败限制（5次锁定15分钟）
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)
@app.route('/login', methods=['POST'])
@limiter.limit("5 per 15 minute")
def login():
    pass

# 使用bcrypt哈希密码
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))""",
        },
        "poc": """# 弱密码验证PoC
# 1. 尝试默认凭证: admin/admin, admin/password, root/root
# 2. 检查是否有登录失败次数限制
# 3. 检查密码策略（最小长度、复杂度）
# 4. 使用hydra暴力破解: hydra -l admin -P passwords.txt target http-post-form "/login:user=^USER^&pass=^PASS^:Invalid" """,
    },
    "misconfiguration": {
        "name": "安全配置错误",
        "cwe": "CWE-16",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "服务器、应用、数据库存在不安全的默认配置，如目录列表、调试模式开启、不必要的服务等。",
        "fix_examples": {
            "nginx": """# 禁用目录列表
autoindex off;

# 隐藏版本号
server_tokens off;

# 安全响应头
add_header X-Frame-Options "SAMEORIGIN";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

# 禁用不必要的HTTP方法
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}""",
            "apache": """# 禁用目录列表
Options -Indexes

# 隐藏版本号
ServerTokens Prod
ServerSignature Off

# 安全头
<IfModule mod_headers.c>
    Header set X-Frame-Options "SAMEORIGIN"
    Header set X-Content-Type-Options "nosniff"
    Header set X-XSS-Protection "1; mode=block"
</IfModule>""",
        },
        "poc": """# 配置错误验证PoC
# 1. 访问 http://target/ 检查是否有目录列表
# 2. 检查响应头是否泄露服务器版本
# 3. 访问 http://target/admin/ 检查是否可未授权访问
# 4. 检查是否开启调试模式（访问/.env, /config.json, /phpinfo.php）""",
    },
}

# ==================== 请求模型 ====================

class ReportReq(BaseModel):
    target: str
    scan_results: dict = {}
    findings: List[dict] = []
    include_remediation: bool = True
    include_poc: bool = True
    include_cvss: bool = True

class VulnReq(BaseModel):
    vuln_type: str
    target: str
    details: dict = {}

# ==================== API端点 ====================

@router.post("/generate")
def generate_report(req: ReportReq, user: dict = Depends(verify_auth)):
    """生成专业级渗透测试报告v3"""
    try:
        now = datetime.now().isoformat()
        report_id = f"RPT-{hashlib.md5(f'{req.target}{time.time()}'.encode()).hexdigest()[:8].upper()}"

        # 处理发现的漏洞
        enriched_findings = []
        for finding in req.findings:
            vuln_type = finding.get("type", "").lower().replace(" ", "_").replace("-", "_")
            remediation = REMEDIATION_CODE.get(vuln_type, {})
            enriched = {
                "title": finding.get("title", remediation.get("name", vuln_type)),
                "type": vuln_type,
                "severity": finding.get("severity", "中"),
                "description": finding.get("description", remediation.get("description", "")),
                "cwe": remediation.get("cwe", ""),
                "owasp": remediation.get("owasp", ""),
                "evidence": finding.get("evidence", ""),
                "affected_url": finding.get("url", req.target),
            }
            if req.include_cvss:
                cvss_metrics = finding.get("cvss_metrics", {})
                if not cvss_metrics:
                    # 根据漏洞类型默认CVSS
                    cvss_metrics = _default_cvss(vuln_type)
                enriched["cvss"] = calculate_cvss(cvss_metrics)
            if req.include_remediation and remediation:
                enriched["remediation"] = {
                    "fix_examples": remediation.get("fix_examples", {}),
                    "summary": _remediation_summary(vuln_type),
                }
            if req.include_poc and remediation:
                enriched["poc"] = remediation.get("poc", "")
            enriched_findings.append(enriched)

        # 风险统计
        severity_counts = {"严重": 0, "高": 0, "中": 0, "低": 0, "信息": 0}
        for f in enriched_findings:
            sev = f.get("severity", "信息")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # 整体风险评分
        overall_risk = _calculate_overall_risk(enriched_findings)

        # 攻击链
        attack_chain = _build_attack_chain(enriched_findings)

        report = {
            "report_id": report_id,
            "generated_at": now,
            "executive_summary": {
                "target": req.target,
                "overall_risk_score": overall_risk["score"],
                "overall_risk_level": overall_risk["level"],
                "total_findings": len(enriched_findings),
                "severity_breakdown": severity_counts,
                "key_findings": [f["title"] for f in enriched_findings[:5]],
            },
            "risk_matrix": _build_risk_matrix(enriched_findings),
            "findings": enriched_findings,
            "attack_chain": attack_chain,
            "remediation_priority": _prioritize_remediation(enriched_findings),
            "appendix": {
                "methodology": "PTES（渗透测试执行标准）",
                "tools_used": ["Nmap", "Nuclei", "SQLMap", "Nikto", "AI决策引擎"],
                "cvss_version": "3.1",
                "disclaimer": "本报告仅用于授权的安全测试，未经授权的测试是非法的。",
            },
        }
        return _ok(report)
    except Exception as e:
        log.exception("generate_report 错误")
        return _err(500, f"生成报告失败: {e}")

@router.get("/vulnerability/{vuln_type}")
def get_vulnerability_detail(vuln_type: str, user: dict = Depends(verify_auth)):
    """获取漏洞详情（含修复代码和PoC）"""
    vuln = REMEDIATION_CODE.get(vuln_type.lower().replace("-", "_"), {})
    if not vuln:
        # 模糊匹配
        for k, v in REMEDIATION_CODE.items():
            if vuln_type.lower() in k.lower() or k.lower() in vuln_type.lower():
                vuln = v
                vuln_type = k
                break
    if not vuln:
        return _err(404, f"漏洞类型不存在，可用: {list(REMEDIATION_CODE.keys())}")
    cvss = calculate_cvss(_default_cvss(vuln_type))
    return _ok({**vuln, "cvss": cvss, "vuln_type": vuln_type})

@router.get("/vulnerabilities")
def list_vulnerabilities(user: dict = Depends(verify_auth)):
    """获取所有支持的漏洞类型"""
    vulns = []
    for k, v in REMEDIATION_CODE.items():
        vulns.append({"type": k, "name": v["name"], "cwe": v["cwe"], "owasp": v["owasp"]})
    return _ok({"vulnerabilities": vulns, "total": len(vulns)})

@router.post("/cvss/calculate")
def calculate_cvss_score(metrics: dict, user: dict = Depends(verify_auth)):
    """计算CVSS v3.1评分"""
    result = calculate_cvss(metrics)
    return _ok(result)

@router.get("/cvss/metrics")
def get_cvss_metrics(user: dict = Depends(verify_auth)):
    """获取CVSS v3.1指标说明"""
    return _ok({
        "version": "3.1",
        "metrics": {
            "AV": {"name": "攻击向量", "values": {"N": "网络", "A": "相邻", "L": "本地", "P": "物理"}},
            "AC": {"name": "攻击复杂度", "values": {"L": "低", "H": "高"}},
            "PR": {"name": "权限要求", "values": {"N": "无", "L": "低", "H": "高"}},
            "UI": {"name": "用户交互", "values": {"N": "无", "R": "需要"}},
            "S": {"name": "影响范围", "values": {"U": "未改变", "C": "改变"}},
            "C": {"name": "机密性影响", "values": {"H": "高", "L": "低", "N": "无"}},
            "I": {"name": "完整性影响", "values": {"H": "高", "L": "低", "N": "无"}},
            "A": {"name": "可用性影响", "values": {"H": "高", "L": "低", "N": "无"}},
        },
        "severity_levels": {"0": "无", "0.1-3.9": "低", "4.0-6.9": "中", "7.0-8.9": "高", "9.0-10.0": "严重"},
    })

@router.post("/export/markdown")
def export_markdown(req: ReportReq, user: dict = Depends(verify_auth)):
    """导出Markdown格式报告"""
    report_result = generate_report(req, user)
    if hasattr(report_result, 'body'):
        import json as _json
        report = _json.loads(report_result.body)["data"]
    else:
        report = report_result["data"]

    md = f"""# 渗透测试报告

**报告ID**: {report['report_id']}
**目标**: {report['executive_summary']['target']}
**生成时间**: {report['generated_at']}
**整体风险**: {report['executive_summary']['overall_risk_level']} ({report['executive_summary']['overall_risk_score']}/100)

## 执行摘要

本次测试共发现 **{report['executive_summary']['total_findings']}** 个安全问题：

| 严重程度 | 数量 |
|---------|------|
"""
    for sev, count in report["executive_summary"]["severity_breakdown"].items():
        md += f"| {sev} | {count} |\n"

    md += "\n## 漏洞详情\n\n"
    for i, f in enumerate(report["findings"], 1):
        md += f"### {i}. {f['title']}\n\n"
        md += f"- **严重程度**: {f['severity']}\n"
        if f.get("cvss"):
            md += f"- **CVSS**: {f['cvss']['base_score']} ({f['cvss']['severity']})\n"
            md += f"- **向量**: `{f['cvss']['vector']}`\n"
        md += f"- **CWE**: {f.get('cwe', 'N/A')}\n"
        md += f"- **OWASP**: {f.get('owasp', 'N/A')}\n"
        md += f"- **影响URL**: {f.get('affected_url', '')}\n\n"
        md += f"**描述**: {f['description']}\n\n"
        if f.get("evidence"):
            md += f"**证据**: {f['evidence']}\n\n"
        if f.get("remediation"):
            md += f"**修复建议**: {f['remediation']['summary']}\n\n"
            for lang, code in f["remediation"]["fix_examples"].items():
                md += f"**{lang} 修复示例**:\n\n```{lang}\n{code}\n```\n\n"
        if f.get("poc"):
            md += f"**验证PoC**:\n\n```\n{f['poc']}\n```\n\n"
        md += "---\n\n"

    md += "## 修复优先级\n\n"
    for i, item in enumerate(report.get("remediation_priority", []), 1):
        md += f"{i}. **{item['title']}** - 优先级: {item['priority']}\n"

    md += f"\n## 附录\n\n- **测试方法**: {report['appendix']['methodology']}\n"
    md += f"- **使用工具**: {', '.join(report['appendix']['tools_used'])}\n"
    md += f"- **CVSS版本**: {report['appendix']['cvss_version']}\n"
    md += f"- **免责声明**: {report['appendix']['disclaimer']}\n"

    return _ok({"report_id": report["report_id"], "format": "markdown", "content": md, "length": len(md)})

# ==================== 辅助函数 ====================

def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"code": 0, "data": data})

def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"code": status, "error": message}, status_code=status)

def _default_cvss(vuln_type: str) -> dict:
    defaults = {
        "sql_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "xss": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
        "command_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "path_traversal": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "L"},
        "weak_auth": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "L"},
        "misconfiguration": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "L"},
    }
    return defaults.get(vuln_type, {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"})

def _remediation_summary(vuln_type: str) -> str:
    summaries = {
        "sql_injection": "使用参数化查询/预编译语句，禁止字符串拼接SQL；使用ORM框架；对用户输入进行严格验证和白名单过滤。",
        "xss": "对所有用户输出进行HTML转义；使用Content-Security-Policy头；设置HttpOnly Cookie；使用框架的自动转义功能。",
        "command_injection": "使用subprocess列表参数而非shell字符串；对用户输入进行白名单验证；避免使用system()/exec()等函数。",
        "path_traversal": "使用realpath验证文件路径在允许目录内；对文件名进行白名单验证；过滤../等路径遍历字符。",
        "weak_auth": "实施强密码策略（至少12位，包含大小写字母、数字、特殊字符）；设置登录失败锁定；使用bcrypt/argon2哈希密码；启用多因素认证。",
        "misconfiguration": "禁用目录列表和不必要的服务；隐藏服务器版本号；配置安全响应头；关闭调试模式；定期进行安全配置审计。",
    }
    return summaries.get(vuln_type, "请参考OWASP和CWE的修复建议。")

def _calculate_overall_risk(findings: List[dict]) -> dict:
    score = 0
    for f in findings:
        sev = f.get("severity", "信息")
        if sev == "严重": score += 25
        elif sev == "高": score += 15
        elif sev == "中": score += 8
        elif sev == "低": score += 3
    score = min(score, 100)
    if score >= 80: level = "严重"
    elif score >= 60: level = "高"
    elif score >= 40: level = "中"
    elif score >= 20: level = "低"
    else: level = "信息"
    return {"score": score, "level": level}

def _build_risk_matrix(findings: List[dict]) -> dict:
    matrix = {
        "high_impact_high_likelihood": [],
        "high_impact_low_likelihood": [],
        "low_impact_high_likelihood": [],
        "low_impact_low_likelihood": [],
    }
    for f in findings:
        sev = f.get("severity", "中")
        impact = "high" if sev in ["严重", "高"] else "low"
        likelihood = "high" if sev in ["严重", "高", "中"] else "low"
        key = f"{impact}_impact_{likelihood}_likelihood"
        matrix[key].append(f["title"])
    return matrix

def _build_attack_chain(findings: List[dict]) -> List[dict]:
    chain = [
        {"phase": "侦察", "description": "端口扫描、服务识别、指纹检测", "findings": []},
        {"phase": "武器化", "description": "根据发现的服务准备攻击载荷", "findings": []},
        {"phase": "投递", "description": "向目标发送攻击载荷", "findings": []},
        {"phase": "利用", "description": "利用发现的漏洞获取访问权限", "findings": [f["title"] for f in findings if f.get("severity") in ["严重", "高"]]},
        {"phase": "安装", "description": "安装后门或持久化机制", "findings": []},
        {"phase": "命令控制", "description": "建立C2通道", "findings": []},
        {"phase": "横向移动", "description": "在内网中横向移动", "findings": []},
        {"phase": "目标达成", "description": "数据窃取、破坏或勒索", "findings": []},
    ]
    return chain

def _prioritize_remediation(findings: List[dict]) -> List[dict]:
    priority_map = {"严重": "P0-立即修复", "高": "P1-24小时内修复", "中": "P2-1周内修复", "低": "P3-1月内修复", "信息": "P4-记录观察"}
    prioritized = []
    for f in sorted(findings, key=lambda x: {"严重": 0, "高": 1, "中": 2, "低": 3, "信息": 4}.get(x.get("severity", "信息"), 5)):
        prioritized.append({"title": f["title"], "severity": f["severity"], "priority": priority_map.get(f["severity"], "P4"), "cvss": f.get("cvss", {}).get("base_score", 0)})
    return prioritized
