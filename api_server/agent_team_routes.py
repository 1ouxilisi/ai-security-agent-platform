# -*- coding: utf-8 -*-
"""AI代理队 - 多智能体协作渗透测试
参考Strix (strix-agent)的"会动手的AI黑客代理队"设计
四个代理：侦察代理→扫描代理→分析代理→报告代理，链式协作
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import json
import time
from datetime import datetime

router = APIRouter(prefix="/api/v1/agent-team", tags=["AI代理队"])


# ============== 代理定义 ==============
AGENTS = {
    "recon": {
        "name": "侦察代理 (Recon Agent)",
        "role": "信息收集与资产发现",
        "tools": ["subfinder", "dns_collect", "web_fingerprint", "directory_scan"],
        "prompt": "你是一名专业的渗透测试侦察专家。你的任务是对目标进行全面的信息收集，包括子域名枚举、DNS记录收集、Web服务指纹识别、目录路径发现。输出结构化的资产清单。"
    },
    "scanner": {
        "name": "扫描代理 (Scanner Agent)",
        "role": "漏洞扫描与端口探测",
        "tools": ["nmap", "nuclei", "ssl_tls_check", "nikto"],
        "prompt": "你是一名专业的漏洞扫描专家。基于侦察代理提供的资产清单，对每个目标进行端口扫描、服务识别、漏洞检测、SSL/TLS安全评估。输出漏洞列表，包含严重度分级。"
    },
    "analyzer": {
        "name": "分析代理 (Analyzer Agent)",
        "role": "漏洞分析与攻击链构建",
        "tools": ["cve_search", "owasp_classify", "attack_path"],
        "prompt": "你是一名资深的安全分析师。基于扫描代理提供的漏洞列表，进行CVE关联分析、OWASP分类、攻击路径推演、业务影响评估。输出优先级排序的漏洞分析报告。"
    },
    "reporter": {
        "name": "报告代理 (Reporter Agent)",
        "role": "报告生成与修复建议",
        "tools": ["generate_report", "remediation"],
        "prompt": "你是一名专业的安全报告撰写专家。基于分析代理的漏洞分析结果，生成专业的渗透测试报告，包含执行摘要、漏洞详情、修复建议、风险评级。输出HTML和Markdown格式报告。"
    }
}


class TeamTaskReq(BaseModel):
    target: str
    agents: List[str] = ["recon", "scanner", "analyzer", "reporter"]  # 执行顺序
    depth: str = "standard"  # quick/standard/deep
    llm_enabled: bool = False  # 是否启用LLM真实分析（需配置Key）


@router.post("/run")
def run_agent_team(req: TeamTaskReq):
    """运行AI代理队，链式协作完成渗透测试"""
    result = {
        "target": req.target,
        "start_time": datetime.now().isoformat(),
        "depth": req.depth,
        "agents_executed": [],
        "findings": {
            "assets": [],
            "open_ports": [],
            "vulnerabilities": [],
            "analysis": {},
            "report": {}
        },
        "chain_log": []
    }

    shared_context = {"target": req.target, "assets": [], "vulns": []}

    for agent_name in req.agents:
        if agent_name not in AGENTS:
            continue
        agent = AGENTS[agent_name]
        step_result = {"agent": agent_name, "name": agent["name"], "started_at": datetime.now().isoformat()}

        try:
            if agent_name == "recon":
                data = _run_recon_agent(req.target, req.depth)
                shared_context["assets"] = data.get("assets", [])
                result["findings"]["assets"] = data.get("assets", [])
                step_result["output_summary"] = f"发现{len(data.get('assets', []))}个资产"

            elif agent_name == "scanner":
                data = _run_scanner_agent(shared_context, req.depth)
                shared_context["vulns"] = data.get("vulnerabilities", [])
                result["findings"]["open_ports"] = data.get("open_ports", [])
                result["findings"]["vulnerabilities"] = data.get("vulnerabilities", [])
                step_result["output_summary"] = f"发现{len(data.get('open_ports', []))}个开放端口, {len(data.get('vulnerabilities', []))}个漏洞"

            elif agent_name == "analyzer":
                data = _run_analyzer_agent(shared_context)
                result["findings"]["analysis"] = data
                step_result["output_summary"] = f"完成{data.get('total_analyzed', 0)}个漏洞分析"

            elif agent_name == "reporter":
                data = _run_reporter_agent(req.target, result["findings"])
                result["findings"]["report"] = data
                step_result["output_summary"] = f"报告已生成: {data.get('format', 'html')}"

            step_result["status"] = "success"
        except Exception as e:
            step_result["status"] = "error"
            step_result["error"] = str(e)

        step_result["finished_at"] = datetime.now().isoformat()
        result["agents_executed"].append(step_result)
        result["chain_log"].append(f"[{agent_name}] {step_result.get('output_summary', step_result.get('error', ''))}")

    result["end_time"] = datetime.now().isoformat()
    result["summary"] = {
        "total_assets": len(result["findings"]["assets"]),
        "total_open_ports": len(result["findings"]["open_ports"]),
        "total_vulnerabilities": len(result["findings"]["vulnerabilities"]),
        "agents_succeeded": sum(1 for a in result["agents_executed"] if a["status"] == "success"),
        "agents_failed": sum(1 for a in result["agents_executed"] if a["status"] == "error")
    }
    return {"success": True, "data": result}


def _run_recon_agent(target, depth):
    """侦察代理：子域名+DNS+指纹+目录"""
    assets = []
    is_domain = any(c.isalpha() for c in target.split(".")[0])

    # DNS收集
    if is_domain:
        try:
            from asm.dns_workflow import DNSCollector
            dns = DNSCollector().collect(target)
            for sub in dns.get("subdomains", []):
                assets.append({"type": "subdomain", "value": sub, "source": "dns"})
        except: pass

    # Web指纹
    try:
        from asm.web_fingerprint import WebFingerprinter
        url = f"http://{target}" if not target.startswith("http") else target
        fp = WebFingerprinter(timeout=10).identify(url)
        assets.append({"type": "web_service", "value": url, "tech": fp.get("technologies", []), "server": fp.get("server", "")})
    except: pass

    if not assets:
        assets.append({"type": "target", "value": target, "source": "input"})

    return {"assets": assets}


def _run_scanner_agent(context, depth):
    """扫描代理：Nmap端口+Nuclei漏洞+SSL检测"""
    target = context["target"]
    open_ports = []
    vulnerabilities = []

    # Nmap端口扫描
    try:
        from asm.real_tools import NmapRunner
        nmap = NmapRunner(target, timeout=30).quick_scan()
        open_ports = nmap.get("open_ports", [])
    except: pass

    # Nuclei漏洞扫描（仅HTTP目标）
    http_targets = [f"http://{target}"]
    for url in http_targets:
        try:
            from asm.real_tools import NucleiRunner
            nuclei = NucleiRunner(url, timeout=20).scan("high,critical")
            for v in nuclei.get("vulnerabilities", []):
                vulnerabilities.append(v)
            break
        except: pass

    # SSL检测
    try:
        from asm.ssl_report import SSLTLSDetector
        ssl = SSLTLSDetector().detect(target, 443)
        if ssl.get("issues"):
            for issue in ssl["issues"]:
                vulnerabilities.append({"type": "ssl", "name": issue, "severity": "medium", "target": f"{target}:443"})
    except: pass

    return {"open_ports": open_ports, "vulnerabilities": vulnerabilities}


def _run_analyzer_agent(context):
    """分析代理：CVE关联+OWASP分类+优先级排序"""
    vulns = context.get("vulns", [])
    analyzed = []
    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for v in vulns:
        sev = v.get("severity", "info").lower()
        if sev in severity_count:
            severity_count[sev] += 1
        # OWASP分类
        owasp_cat = _map_to_owasp(v.get("name", ""), v.get("type", ""))
        analyzed.append({
            **v,
            "owasp_category": owasp_cat,
            "priority": _calc_priority(sev),
            "business_impact": _estimate_impact(sev, owasp_cat)
        })

    # 攻击路径推演
    attack_paths = _infer_attack_paths(analyzed)

    return {
        "total_analyzed": len(analyzed),
        "severity_distribution": severity_count,
        "analyzed_vulns": analyzed[:50],  # 最多返回50条
        "attack_paths": attack_paths,
        "risk_score": _calc_risk_score(severity_count)
    }


def _run_reporter_agent(target, findings):
    """报告代理：生成HTML/Markdown报告"""
    try:
        from asm.ssl_report import ReportGenerator
        gen = ReportGenerator()
        report = gen.generate_html(target, findings.get("vulnerabilities", []))
        return {"format": "html", "generated": True, "sections": list(report.keys()) if isinstance(report, dict) else ["full_report"]}
    except Exception as e:
        return {"format": "html", "generated": False, "error": str(e)}


def _map_to_owasp(name, vuln_type):
    """漏洞到OWASP Top 10映射"""
    name_lower = name.lower()
    type_lower = vuln_type.lower()
    mappings = [
        (["sql", "injection", "sqli"], "A03: Injection"),
        (["xss", "cross-site", "scripting"], "A03: Injection"),
        (["auth", "authentication", "session", "jwt", "password"], "A07: Identification and Authentication Failures"),
        (["access", "authorization", "privilege", "idor", "bypass"], "A01: Broken Access Control"),
        (["xxe", "xml", "external entity"], "A05: Security Misconfiguration"),
        (["deserializ", "insecure object"], "A08: Software and Data Integrity Failures"),
        (["ssrf", "server-side request"], "A10: Server-Side Request Forgery"),
        (["ssl", "tls", "certificate", "encryption", "crypto"], "A02: Cryptographic Failures"),
        (["misconfig", "default", "exposed", "debug"], "A05: Security Misconfiguration"),
        (["dos", "denial of service", "resource"], "A04: Insecure Design"),
        (["vulnerable", "outdated", "cve", "known"], "A06: Vulnerable and Outdated Components"),
        (["logging", "monitoring", "audit"], "A09: Security Logging and Monitoring Failures"),
    ]
    for keywords, category in mappings:
        for kw in keywords:
            if kw in name_lower or kw in type_lower:
                return category
    return "A05: Security Misconfiguration"


def _calc_priority(severity):
    return {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}.get(severity, 5)


def _estimate_impact(severity, owasp_cat):
    impacts = {
        "critical": "可能导致系统完全沦陷、数据泄露、业务中断",
        "high": "可能导致权限提升、敏感数据访问、服务降级",
        "medium": "可能导致信息泄露、有限权限操作",
        "low": "信息泄露风险较低，需配合其他漏洞利用",
        "info": "仅为信息收集，无直接安全风险"
    }
    return impacts.get(severity, "需进一步评估")


def _infer_attack_paths(vulns):
    """简单攻击路径推演"""
    paths = []
    critical = [v for v in vulns if v.get("severity") == "critical"]
    high = [v for v in vulns if v.get("severity") == "high"]
    if critical:
        paths.append({"path": "初始访问 → 关键漏洞利用 → 系统沦陷", "likelihood": "高", "vulns": [v.get("name") for v in critical[:3]]})
    if high:
        paths.append({"path": "信息收集 → 高危漏洞利用 → 权限提升", "likelihood": "中", "vulns": [v.get("name") for v in high[:3]]})
    if not paths:
        paths.append({"path": "信息收集 → 进一步探测", "likelihood": "低", "vulns": []})
    return paths


def _calc_risk_score(severity_count):
    score = severity_count["critical"] * 10 + severity_count["high"] * 5 + severity_count["medium"] * 2 + severity_count["low"] * 1
    if score >= 30: level = "严重"
    elif score >= 15: level = "高"
    elif score >= 5: level = "中"
    else: level = "低"
    return {"score": min(score, 100), "level": level}


@router.get("/agents")
def list_agents():
    """列出所有代理"""
    return {"success": True, "data": {"agents": AGENTS, "total": len(AGENTS)}}


@router.get("/chain-log/{task_id}")
def get_chain_log(task_id: str):
    """获取代理队执行链日志（简化版，实际应持久化）"""
    return {"success": True, "data": {"task_id": task_id, "note": "链日志需配合持久化存储使用"}}
