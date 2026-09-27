# -*- coding: utf-8 -*-
"""武器手册知识库 - 渗透测试方法论+工具用法+攻击技术
参考Blitz Strike的317份武器手册设计，提供结构化的安全知识
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

router = APIRouter(prefix="/api/v1/weapon-manual", tags=["武器手册知识库"])

# ============== 武器手册数据库 ==============
WEAPON_MANUALS = [
    # ===== 信息收集阶段 =====
    {
        "id": "WM-001",
        "name": "Nmap端口扫描手册",
        "category": "信息收集",
        "phase": "侦察",
        "tool": "nmap",
        "description": "Nmap全功能端口扫描指南，覆盖TCP/UDP扫描、服务识别、操作系统探测、脚本引擎",
        "commands": [
            {"cmd": "nmap -sS -p- target", "desc": "全端口SYN扫描（需root）"},
            {"cmd": "nmap -sV -sC target", "desc": "服务版本识别+默认脚本扫描"},
            {"cmd": "nmap -O target", "desc": "操作系统指纹识别"},
            {"cmd": "nmap -sU -p 53,161 target", "desc": "UDP端口扫描"},
            {"cmd": "nmap --script vuln target", "desc": "漏洞脚本扫描"},
            {"cmd": "nmap -T4 -A -v target", "desc": "激进扫描（服务+OS+脚本+traceroute）"}
        ],
        "tips": ["-sS比-sT更隐蔽更快", "-p-扫描所有65535端口较慢，建议先扫Top1000", "--script=vuln可能触发WAF/IDS"],
        "risk_level": "低"
    },
    {
        "id": "WM-002",
        "name": "子域名枚举手册",
        "category": "信息收集",
        "phase": "侦察",
        "tool": "subfinder",
        "description": "子域名发现与资产扩展，被动数据源+主动爆破",
        "commands": [
            {"cmd": "subfinder -d target.com -all", "desc": "全数据源被动枚举"},
            {"cmd": "subfinder -d target.com -o subs.txt", "desc": "输出到文件"},
            {"cmd": "subfinder -dL domains.txt", "desc": "批量域名枚举"},
            {"cmd": "subfinder -d target.com -silent | httpx -title", "desc": "枚举+存活探测+标题"}
        ],
        "tips": ["配合httpx验证存活", "被动枚举不会触发目标告警", "可配合amass做更全面的枚举"],
        "risk_level": "极低"
    },
    {
        "id": "WM-003",
        "name": "Web指纹识别手册",
        "category": "信息收集",
        "phase": "侦察",
        "tool": "whatweb/httpx",
        "description": "Web服务器、框架、CMS、技术栈识别",
        "commands": [
            {"cmd": "whatweb -a 3 target.com", "desc": "激进指纹识别"},
            {"cmd": "httpx -title -tech-detect -status-code -u target.com", "desc": "技术栈+标题+状态码"},
            {"cmd": "httpx -l urls.txt -title -tech-detect -o results.txt", "desc": "批量指纹识别"}
        ],
        "tips": ["Wappalyzer浏览器插件可辅助识别", "指纹库需定期更新", "CDN可能隐藏真实服务器"],
        "risk_level": "极低"
    },
    {
        "id": "WM-004",
        "name": "目录路径枚举手册",
        "category": "信息收集",
        "phase": "侦察",
        "tool": "gobuster/ffuf/dirsearch",
        "description": "Web隐藏目录、文件、备份发现",
        "commands": [
            {"cmd": "gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt", "desc": "目录爆破"},
            {"cmd": "ffuf -u http://target/FUZZ -w wordlist.txt -mc 200,204,301,302,403", "desc": "快速模糊测试"},
            {"cmd": "dirsearch -u http://target -e php,asp,aspx,jsp", "desc": "指定扩展名扫描"}
        ],
        "tips": ["大字典扫描慢，先用小字典快速过", "403状态码的目录值得关注", "备份文件(.bak/.old/.swp)可能泄露源码"],
        "risk_level": "低"
    },
    # ===== 漏洞扫描阶段 =====
    {
        "id": "WM-005",
        "name": "Nuclei漏洞扫描手册",
        "category": "漏洞扫描",
        "phase": "扫描",
        "tool": "nuclei",
        "description": "基于YAML模板的漏洞扫描器，支持自定义模板",
        "commands": [
            {"cmd": "nuclei -u http://target -t cves/", "desc": "CVE漏洞扫描"},
            {"cmd": "nuclei -u http://target -severity critical,high", "desc": "仅高危/严重漏洞"},
            {"cmd": "nuclei -l urls.txt -t exposures/ -o results.txt", "desc": "批量信息泄露扫描"},
            {"cmd": "nuclei -u http://target -tags tech,panel", "desc": "按标签扫描"},
            {"cmd": "nuclei -update-templates", "desc": "更新模板库"},
            {"cmd": "nuclei -tl", "desc": "列出所有可用模板"}
        ],
        "tips": ["模板库定期更新（nuclei -update-templates）", "-stats可实时查看进度", "可编写自定义YAML模板"],
        "risk_level": "低"
    },
    {
        "id": "WM-006",
        "name": "SQL注入检测手册",
        "category": "漏洞扫描",
        "phase": "扫描",
        "tool": "sqlmap",
        "description": "自动化SQL注入检测与利用工具",
        "commands": [
            {"cmd": "sqlmap -u 'http://target/page?id=1' --batch", "desc": "自动检测注入点"},
            {"cmd": "sqlmap -u 'http://target/page?id=1' --dbs", "desc": "枚举数据库"},
            {"cmd": "sqlmap -u 'http://target/page?id=1' -D dbname --tables", "desc": "枚举表"},
            {"cmd": "sqlmap -u 'http://target/page?id=1' -D db -T users --dump", "desc": "导出数据"},
            {"cmd": "sqlmap -r request.txt --batch", "desc": "从请求文件检测"},
            {"cmd": "sqlmap -u 'http://target/login' --data='user=admin&pass=123' --batch", "desc": "POST参数检测"}
        ],
        "tips": ["--batch自动确认所有提示", "--level=5 --risk=3更全面但更慢", "WAF可能拦截，需用--tamper绕过脚本"],
        "risk_level": "中"
    },
    {
        "id": "WM-007",
        "name": "SSL/TLS安全检测手册",
        "category": "漏洞扫描",
        "phase": "扫描",
        "tool": "testssl/sslyze",
        "description": "SSL/TLS配置安全评估",
        "commands": [
            {"cmd": "testssl.sh target.com:443", "desc": "全面SSL检测"},
            {"cmd": "sslyze --regular target.com", "desc": "常规SSL扫描"},
            {"cmd": "testssl.sh --heartbleed target.com", "desc": "Heartbleed检测"},
            {"cmd": "testssl.sh --protocols target.com", "desc": "协议版本检测"}
        ],
        "tips": ["关注TLS 1.0/1.1禁用情况", "检查证书有效期和链完整性", "弱加密套件(如RC4/3DES)应禁用"],
        "risk_level": "极低"
    },
    # ===== Web漏洞利用 =====
    {
        "id": "WM-008",
        "name": "XSS跨站脚本手册",
        "category": "Web漏洞",
        "phase": "利用",
        "tool": "manual",
        "description": "XSS漏洞检测与利用，反射型/存储型/DOM型",
        "payloads": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>"
        ],
        "bypass": ["大小写混淆<ScRiPt>", "HTML实体编码", "Unicode编码", "事件处理器onerror/onload", "SVG/IMG标签绕过script过滤"],
        "tips": ["先找输入点再测输出位置", "DOM型XSS需查看JS源码", "存储型XSS危害最大，可能窃取管理员Cookie"],
        "risk_level": "中"
    },
    {
        "id": "WM-009",
        "name": "文件上传漏洞手册",
        "category": "Web漏洞",
        "phase": "利用",
        "tool": "manual",
        "description": "文件上传漏洞检测与Webshell上传",
        "techniques": [
            "扩展名绕过: .php3/.php5/.phtml/.phar",
            "MIME类型伪造: Content-Type: image/jpeg",
            "双扩展名: shell.php.jpg",
            "大小写: shell.PHP",
            "空字节: shell.php%00.jpg",
            ".htaccess上传: AddType application/x-httpd-php .jpg",
            "图片马: 图片文件末尾追加PHP代码"
        ],
        "tips": ["上传后需找到文件访问路径", "GIF89a文件头可绕过图片检测", "竞争条件上传(先传后删)"],
        "risk_level": "高"
    },
    {
        "id": "WM-010",
        "name": "SSRF服务端请求伪造手册",
        "category": "Web漏洞",
        "phase": "利用",
        "tool": "manual",
        "description": "SSRF漏洞检测与内网探测",
        "payloads": [
            "http://127.0.0.1:80",
            "http://localhost/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:80",
            "http://0.0.0.0:22",
            "dict://127.0.0.1:6379/info",
            "gopher://127.0.0.1:6379/_INFO",
            "file:///etc/passwd"
        ],
        "tips": ["云环境重点打169.254.169.254元数据", "Redis未授权可通过dict/gopher利用", "DNS重绑定可绕过IP白名单"],
        "risk_level": "高"
    },
    # ===== 内网渗透 =====
    {
        "id": "WM-011",
        "name": "SMB信息收集手册",
        "category": "内网渗透",
        "phase": "内网",
        "tool": "smbclient/enum4linux",
        "description": "SMB服务枚举与共享发现",
        "commands": [
            {"cmd": "smbclient -L //target -N", "desc": "列出共享（空会话）"},
            {"cmd": "enum4linux -a target", "desc": "全面枚举（用户/组/共享/OS）"},
            {"cmd": "rpcclient -U '' target -c 'enumdomusers'", "desc": "枚举域用户"},
            {"cmd": "crackmapexec smb target -u '' -p '' --shares", "desc": "空会话共享枚举"}
        ],
        "tips": ["空会话在旧系统上可能成功", "SYSVOL/NETLOGON共享值得关注", "SMB签名未启用可进行中继攻击"],
        "risk_level": "低"
    },
    {
        "id": "WM-012",
        "name": "哈希传递攻击手册",
        "category": "内网渗透",
        "phase": "内网",
        "tool": "impacket/crackmapexec",
        "description": "Pass-the-Hash横向移动",
        "commands": [
            {"cmd": "psexec.py domain/user:password@target", "desc": "PsExec远程执行"},
            {"cmd": "wmiexec.py domain/user:password@target", "desc": "WMI远程执行"},
            {"cmd": "smbexec.py domain/user:password@target", "desc": "SMB远程执行"},
            {"cmd": "crackmapexec smb 192.168.1.0/24 -u user -H hash", "desc": "哈希传递批量验证"},
            {"cmd": "secretsdump.py domain/user:password@dc", "desc": "域控哈希转储"}
        ],
        "tips": ["需先获取NTLM哈希", "域管理员哈希可控制整个域", "AES密钥也可用于Kerberos认证"],
        "risk_level": "高"
    },
    # ===== 报告阶段 =====
    {
        "id": "WM-013",
        "name": "渗透测试报告编写手册",
        "category": "报告",
        "phase": "报告",
        "tool": "manual",
        "description": "专业渗透测试报告结构与编写规范",
        "structure": [
            "1. 执行摘要（管理层视角，1-2页）",
            "2. 测试范围与方法（授权范围、测试时间、工具）",
            "3. 漏洞总览（数量统计、严重度分布、风险评级）",
            "4. 漏洞详情（每个漏洞：描述/影响/复现步骤/修复建议/CVSS评分）",
            "5. 攻击路径推演（从初始访问到目标达成的完整路径）",
            "6. 附录（工具列表、原始数据、参考资料）"
        ],
        "tips": ["执行摘要要让非技术人员看懂", "每个漏洞必须有可复现步骤", "修复建议要具体可操作", "用CVSS 3.1评分标准"],
        "risk_level": "无"
    },
    {
        "id": "WM-014",
        "name": "OWASP Top 10映射手册",
        "category": "报告",
        "phase": "报告",
        "tool": "manual",
        "description": "漏洞到OWASP Top 10 (2021)分类映射",
        "mapping": {
            "A01": "Broken Access Control - 访问控制失效",
            "A02": "Cryptographic Failures - 加密机制失效",
            "A03": "Injection - 注入（SQL/XSS/命令注入）",
            "A04": "Insecure Design - 不安全设计",
            "A05": "Security Misconfiguration - 安全配置错误",
            "A06": "Vulnerable and Outdated Components - 脆弱和过时组件",
            "A07": "Identification and Authentication Failures - 身份识别和认证失效",
            "A08": "Software and Data Integrity Failures - 软件和数据完整性失效",
            "A09": "Security Logging and Monitoring Failures - 安全日志和监控失效",
            "A10": "Server-Side Request Forgery - 服务端请求伪造"
        },
        "tips": ["每个漏洞都应映射到OWASP分类", "报告中按OWASP分类统计漏洞分布", "A01访问控制失效连续多年排名第一"],
        "risk_level": "无"
    },
    # ===== 方法论 =====
    {
        "id": "WM-015",
        "name": "渗透测试标准流程手册",
        "category": "方法论",
        "phase": "全流程",
        "tool": "methodology",
        "description": "PTES渗透测试执行标准七阶段",
        "phases": [
            "1. 前期交互（Pre-engagement）：合同、授权、范围确认、规则约定",
            "2. 情报收集（Intelligence Gathering）：OSINT、被动扫描、主动探测",
            "3. 威胁建模（Threat Modeling）：资产识别、威胁代理、攻击路径",
            "4. 漏洞分析（Vulnerability Analysis）：漏洞扫描、验证、误报排除",
            "5. 漏洞利用（Exploitation）：精准利用、权限获取、边界突破",
            "6. 后渗透（Post-Exploitation）：权限提升、横向移动、数据收集、持久化",
            "7. 报告（Reporting）：漏洞报告、修复建议、风险评级、执行摘要"
        ],
        "tips": ["授权是第一原则，没有授权不碰", "每个阶段都要记录证据", "漏洞利用前需确认在授权范围内"],
        "risk_level": "无"
    },
    {
        "id": "WM-016",
        "name": "护网行动攻防手册",
        "category": "方法论",
        "phase": "全流程",
        "tool": "methodology",
        "description": "HW护网行动攻击方战术与防守方要点",
        "attacker_tactics": [
            "初始访问：钓鱼邮件、VPN漏洞、Web应用漏洞、供应链",
            "侦察：子域名枚举、端口扫描、指纹识别、信息泄露",
            "武器化：Webshell、内存马、免杀木马、C2通道",
            "横向移动：哈希传递、Kerberos攻击、内网代理、隧道",
            "目标达成：数据窃取、页面篡改、服务中断、权限维持"
        ],
        "defender_points": [
            "边界防护：WAF、IDS/IPS、零信任访问控制",
            "监控：SIEM日志分析、异常行为检测、流量分析",
            "应急：漏洞快速修复、隔离受感染主机、溯源分析",
            "加固：最小权限、补丁管理、强密码策略、MFA"
        ],
        "tips": ["护网期间攻击方重点打0day和Nday", "防守方重点是监控和应急响应", "蓝队需关注异常登录和横向移动"],
        "risk_level": "无"
    }
]


@router.get("/list")
def list_manuals(category: Optional[str] = None, phase: Optional[str] = None):
    """列出武器手册，可按类别/阶段筛选"""
    manuals = WEAPON_MANUALS
    if category:
        manuals = [m for m in manuals if m["category"] == category]
    if phase:
        manuals = [m for m in manuals if m["phase"] == phase]
    return {
        "success": True,
        "data": {
            "manuals": [{"id": m["id"], "name": m["name"], "category": m["category"], "phase": m["phase"], "tool": m["tool"], "risk_level": m["risk_level"]} for m in manuals],
            "total": len(manuals),
            "categories": list(set(m["category"] for m in WEAPON_MANUALS)),
            "phases": list(set(m["phase"] for m in WEAPON_MANUALS))
        }
    }


@router.get("/{manual_id}")
def get_manual(manual_id: str):
    """获取武器手册详情"""
    manual = next((m for m in WEAPON_MANUALS if m["id"] == manual_id), None)
    if not manual:
        raise HTTPException(404, f"手册不存在: {manual_id}")
    return {"success": True, "data": manual}


@router.get("/search/{keyword}")
def search_manuals(keyword: str):
    """搜索武器手册"""
    keyword_lower = keyword.lower()
    results = []
    for m in WEAPON_MANUALS:
        if (keyword_lower in m["name"].lower() or
            keyword_lower in m["description"].lower() or
            keyword_lower in m["tool"].lower() or
            keyword_lower in m["category"].lower()):
            results.append({"id": m["id"], "name": m["name"], "category": m["category"], "phase": m["phase"]})
    return {"success": True, "data": {"results": results, "total": len(results)}}


@router.get("/by-tool/{tool_name}")
def get_by_tool(tool_name: str):
    """按工具名获取手册"""
    results = [m for m in WEAPON_MANUALS if tool_name.lower() in m["tool"].lower()]
    return {"success": True, "data": {"manuals": results, "total": len(results)}}
