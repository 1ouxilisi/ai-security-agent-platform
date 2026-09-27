# -*- coding: utf-8 -*-
"""增强版报告引擎 - 真实数据引用+风险详情+修复建议+攻击路径"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
import json, os

router = APIRouter(prefix="/api/v1/report", tags=["报告引擎"])

# 漏洞修复建议库
REMEDIATION_DB = {
    "sql-injection": {"risk": "攻击者可直接读取/修改/删除数据库数据", "fix": "1.使用参数化查询/预编译语句 2.输入验证和过滤 3.最小权限数据库账号 4.WAF规则拦截"},
    "xss": {"risk": "攻击者可注入恶意脚本窃取Cookie/会话/钓鱼", "fix": "1.输出编码转义 2.Content-Security-Policy 3.HttpOnly Cookie 4.输入过滤"},
    "csrf": {"risk": "攻击者可诱导用户执行未授权操作", "fix": "1.CSRF Token验证 2.SameSite Cookie 3.关键操作二次确认"},
    "lfi": {"risk": "攻击者可读取服务器任意文件", "fix": "1.白名单文件校验 2.禁止路径穿越字符 3.chroot隔离"},
    "rce": {"risk": "攻击者可远程执行任意命令完全控制服务器", "fix": "1.禁用危险函数 2.输入严格过滤 3.沙箱隔离 4.立即下线受影响服务"},
    "ssrf": {"risk": "攻击者可利用服务器发起内网请求", "fix": "1.URL白名单 2.禁止内网IP 3.DNS重绑定防护"},
    "xxe": {"risk": "攻击者可读取文件/SSRF/DoS", "fix": "1.禁用外部实体解析 2.禁用DTD 3.使用JSON替代XML"},
    "open-redirect": {"risk": "攻击者可构造钓鱼链接", "fix": "1.跳转URL白名单 2.跳转前提示确认"},
    "weak-crypto": {"risk": "加密可被破解导致数据泄露", "fix": "1.升级到AES-256/RSA-2048 2.使用TLS1.2+ 3.禁用弱密码套件"},
    "misconfig": {"risk": "错误配置可能导致信息泄露/未授权访问", "fix": "1.关闭调试模式 2.移除默认账号 3.最小权限原则 4.安全头配置"},
    "exposure": {"risk": "敏感信息泄露可能被攻击者利用", "fix": "1.移除敏感文件 2.目录列表关闭 3.错误信息脱敏"},
}

def _get_remediation(vuln_name):
    """根据漏洞名匹配修复建议"""
    name = (vuln_name or "").lower()
    for key, val in REMEDIATION_DB.items():
        if key in name or key.replace("-", "") in name.replace("-", ""):
            return val
    return {"risk": "需进一步人工确认具体风险", "fix": "1.参考CVE/OWASP对应漏洞修复指南 2.升级到最新版本 3.部署WAF临时防护"}

def _attack_paths(ports, vulns):
    """推演攻击路径"""
    paths = []
    web_ports = [p for p in ports if p.get("service","") in ("http","https","http-alt","https-alt") or p["port"] in (80,443,8000,8080,8443,3000)]
    if web_ports and vulns:
        high = [v for v in vulns if v.get("severity","") in ("critical","high")]
        if high:
            paths.append({"name": "Web服务高危漏洞利用链", "probability": "高", "impact": "严重",
                "steps": [f"访问Web服务端口{web_ports[0]['port']}", f"利用{high[0].get('template_id','高危漏洞')}", "获取服务器权限", "横向移动/数据窃取"]})
        else:
            paths.append({"name": "Web服务漏洞组合利用", "probability": "中", "impact": "中",
                "steps": [f"访问Web服务端口{web_ports[0]['port']}", "组合利用多个中危漏洞", "获取敏感信息", "进一步攻击"]})
    if any(p["port"] == 22 for p in ports):
        paths.append({"name": "SSH暴力破解路径", "probability": "中", "impact": "高",
            "steps": ["端口22 SSH开放", "字典暴力破解", "获取Shell", "提权/横向移动"]})
    if any(p["port"] in (445,139) for p in ports):
        paths.append({"name": "SMB漏洞利用路径", "probability": "中", "impact": "高",
            "steps": ["SMB端口开放", "探测SMB版本/漏洞", "利用永恒之蓝等漏洞", "获取系统权限"]})
    if not paths:
        paths.append({"name": "信息收集→进一步攻击", "probability": "低", "impact": "待评估",
            "steps": ["端口/服务指纹收集", "查找对应CVE漏洞", "验证漏洞可利用性", "制定攻击方案"]})
    return paths

class ReportReq(BaseModel):
    target: str
    depth: str = "standard"
    include_remediation: bool = True
    include_attack_paths: bool = True

@router.post("/generate")
def generate_enhanced_report(req: ReportReq):
    """生成增强版完整报告"""
    from asm.real_tools import NmapRunner, NucleiRunner
    t0 = datetime.now()
    # 1. Nmap扫描
    nmap = NmapRunner(req.target, timeout=30).quick_scan()
    ports = nmap.get("open_ports", [])
    # 2. Nuclei扫描（仅对实际开放的HTTP端口，避免扫描不存在的端口超时）
    is_local = req.target in ("127.0.0.1","localhost","::1") or req.target.startswith("192.168.") or req.target.startswith("10.")
    http_ports = [p for p in ports if p.get("service","") in ("http","https","http-alt","https-alt") or p["port"] in (80,443,8000,8080,8443,3000,8001)]
    vulns = []
    if http_ports and not is_local:
        hp = http_ports[0]["port"]
        scheme = "https" if hp in (443,8443) else "http"
        http_target = "%s://%s:%d" % (scheme, req.target, hp) if hp not in (80,443) else "%s://%s" % (scheme, req.target)
        nuclei = NucleiRunner(http_target, timeout=15).scan("critical,high,medium")
        vulns = nuclei.get("vulnerabilities", [])
    # 3. 风险评分
    from api_server.recon_workflow_routes import _risk_score
    risk = _risk_score(ports, vulns, [])
    # 4. 攻击路径
    attack_paths = _attack_paths(ports, vulns) if req.include_attack_paths else []
    # 5. 漏洞详情+修复建议
    vuln_details = []
    for v in vulns[:30]:
        rem = _get_remediation(v.get("template_id","") + " " + v.get("template_name","")) if req.include_remediation else {}
        vuln_details.append({
            "id": v.get("template_id",""),
            "name": v.get("template_name",""),
            "severity": v.get("severity","info"),
            "url": v.get("matched_at", v.get("url","")),
            "description": v.get("description", v.get("info","")),
            "cve": v.get("cve", v.get("reference","")),
            "risk": rem.get("risk",""),
            "fix": rem.get("fix","")
        })
    # 6. 端口服务详情
    port_details = [{"port": p["port"], "protocol": p["protocol"], "service": p.get("service","unknown"),
        "product": p.get("product",""), "version": p.get("version","")} for p in ports]
    elapsed = (datetime.now() - t0).total_seconds()
    # 7. 组装报告
    report = {
        "meta": {"target": req.target, "generated_at": datetime.now().isoformat(),
            "tool": "AI Hacking Agent v9.0", "elapsed_seconds": round(elapsed,1),
            "depth": req.depth},
        "summary": {"open_ports": len(ports), "vulnerabilities": len(vulns),
            "critical": sum(1 for v in vulns if v.get("severity")=="critical"),
            "high": sum(1 for v in vulns if v.get("severity")=="high"),
            "medium": sum(1 for v in vulns if v.get("severity")=="medium"),
            "low": sum(1 for v in vulns if v.get("severity")=="low")},
        "risk_assessment": risk,
        "ports": port_details,
        "vulnerabilities": vuln_details,
        "attack_paths": attack_paths,
        "recommendations": [
            "立即修复critical/high级别漏洞",
            "关闭不必要的开放端口",
            "部署WAF作为临时防护",
            "建立定期漏洞扫描机制",
            "对关键服务进行渗透测试"
        ]
    }
    return {"success": True, "data": report}

@router.get("/templates")
def report_templates():
    """报告模板列表"""
    return {"success": True, "data": {"templates": [
        {"id": "asm", "name": "ASM攻击面管理报告", "sections": ["目标信息","端口扫描","漏洞扫描","风险评估","攻击路径","修复建议"]},
        {"id": "web", "name": "Web应用安全报告", "sections": ["目标信息","Web指纹","漏洞详情","风险评级","修复方案"]},
        {"id": "network", "name": "网络安全评估报告", "sections": ["拓扑发现","端口扫描","服务识别","漏洞评估","安全建议"]},
    ]}}
