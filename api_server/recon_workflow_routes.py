# -*- coding: utf-8 -*-
"""一键真实侦察工作流 v2 - 串联所有真实工具 + 风险分析 + 攻击路径"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import time
from datetime import datetime

router = APIRouter(prefix="/api/v1/recon-workflow", tags=["一键侦察工作流"])


class WorkflowReq(BaseModel):
    target: str
    skip_tools: list = []
    depth: str = "standard"  # quick/standard/deep


def _risk_score(ports: list, vulns: list, services: list) -> Dict:
    """计算风险评分"""
    score = 0
    factors = []
    # 高危端口
    high_risk_ports = {22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB",
                        1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
                        6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}
    for p in ports:
        port_num = p.get("port", 0) if isinstance(p, dict) else p
        if port_num in high_risk_ports:
            score += 15
            factors.append(f"高危端口{port_num}({high_risk_ports[port_num]})暴露")
    # 漏洞
    critical = sum(1 for v in vulns if v.get("severity") == "critical")
    high = sum(1 for v in vulns if v.get("severity") == "high")
    medium = sum(1 for v in vulns if v.get("severity") == "medium")
    score += critical * 25 + high * 15 + medium * 5
    if critical: factors.append(f"{critical}个严重漏洞")
    if high: factors.append(f"{high}个高危漏洞")
    # 服务版本
    for s in services:
        if isinstance(s, dict) and s.get("version"):
            factors.append(f"服务{s.get('service','')}版本信息泄露")
            score += 5
    score = min(score, 100)
    level = "严重" if score >= 75 else "高危" if score >= 50 else "中危" if score >= 25 else "低危"
    return {"score": score, "level": level, "factors": factors}


def _attack_paths(ports: list, vulns: list) -> List[Dict]:
    """推演攻击路径"""
    paths = []
    port_set = set()
    for p in ports:
        port_set.add(p.get("port", 0) if isinstance(p, dict) else p)
    # Web攻击路径
    if 80 in port_set or 443 in port_set or 8000 in port_set or 8080 in port_set:
        web_vulns = [v for v in vulns if "http" in str(v.get("matched_at", "")).lower()]
        paths.append({
            "name": "Web应用攻击链",
            "steps": ["端口探测→Web指纹识别→漏洞扫描→漏洞利用→获取权限"],
            "probability": "高" if web_vulns else "中",
            "impact": "高"
        })
    # 内网攻击路径
    if 445 in port_set or 139 in port_set:
        paths.append({
            "name": "SMB内网渗透链",
            "steps": ["SMB枚举→共享目录探测→NTLM哈希抓取→Pass-the-Hash→横向移动"],
            "probability": "中",
            "impact": "高"
        })
    if 22 in port_set:
        paths.append({
            "name": "SSH攻击链",
            "steps": ["SSH版本探测→弱口令爆破→密钥窃取→权限提升→持久化"],
            "probability": "低",
            "impact": "高"
        })
    if 3389 in port_set:
        paths.append({
            "name": "RDP攻击链",
            "steps": ["RDP版本探测→BlueKeep等漏洞→弱口令→远程桌面控制"],
            "probability": "低",
            "impact": "严重"
        })
    return paths


@router.post("/run")
def run_full_recon(req: WorkflowReq):
    """一键完整真实侦察 v2：子域名→存活→端口→指纹→漏洞→风险评分→攻击路径"""
    from asm.real_tools import SubfinderRunner, HttpxRunner, NmapRunner, NucleiRunner

    start = time.time()
    result = {
        "target": req.target,
        "start_time": datetime.now().isoformat(),
        "steps": {},
        "summary": {}
    }

    is_domain = any(c.isalpha() for c in req.target.split(".")[0])
    http_target = req.target if req.target.startswith("http") else f"http://{req.target}"

    # Step 1: 子域名枚举
    if is_domain and "subfinder" not in req.skip_tools:
        try:
            sub = SubfinderRunner(req.target, timeout=30).enumerate()
            result["steps"]["subfinder"] = {"status": "done", "subdomains": sub.get("subdomains", [])[:50], "count": sub.get("total", 0)}
        except Exception as e:
            result["steps"]["subfinder"] = {"status": "error", "error": str(e)[:200]}

    # Step 2: HTTPX存活检测
    if "httpx" not in req.skip_tools:
        try:
            targets = [req.target]
            if result["steps"].get("subfinder", {}).get("subdomains"):
                targets = result["steps"]["subfinder"]["subdomains"][:10]
            httpx = HttpxRunner(targets, timeout=30).scan()
            result["steps"]["httpx"] = {"status": "done", "alive": httpx.get("alive", []), "count": httpx.get("total_alive", 0)}
        except Exception as e:
            result["steps"]["httpx"] = {"status": "error", "error": str(e)[:200]}

    # Step 3: Nmap端口扫描
    nmap_result = {}
    if "nmap" not in req.skip_tools:
        try:
            timeout = 120 if req.depth == "deep" else 60
            nmap = NmapRunner(req.target, timeout=timeout).detailed_scan() if req.depth == "deep" else NmapRunner(req.target, timeout=timeout).quick_scan()
            nmap_result = nmap
            result["steps"]["nmap"] = {
                "status": "done" if "error" not in nmap else "error",
                "open_ports": nmap.get("open_ports", []),
                "count": nmap.get("open_ports_count", 0),
                "os": nmap.get("os", ""),
                "services": [{"port": p.get("port"), "service": p.get("service"), "product": p.get("product"), "version": p.get("version")} for p in nmap.get("open_ports", [])]
            }
        except Exception as e:
            result["steps"]["nmap"] = {"status": "error", "error": str(e)[:200]}

    # Step 4: Nuclei漏洞扫描
    vulns = []
    if "nuclei" not in req.skip_tools:
        try:
            severity = "all" if req.depth == "deep" else "critical,high,medium"
            timeout = 300 if req.depth == "deep" else 120
            nuclei = NucleiRunner(http_target, timeout=timeout).scan(severity)
            vulns = nuclei.get("vulnerabilities", [])
            result["steps"]["nuclei"] = {
                "status": "done" if not nuclei.get("error") else "error",
                "vulns": vulns[:30],
                "count": len(vulns),
                "error": nuclei.get("error", "")
            }
        except Exception as e:
            result["steps"]["nuclei"] = {"status": "error", "error": str(e)[:200]}

    # Step 5: 风险评分
    ports = nmap_result.get("open_ports", [])
    services = result["steps"].get("nmap", {}).get("services", [])
    risk = _risk_score(ports, vulns, services)
    result["risk_assessment"] = risk

    # Step 6: 攻击路径推演
    result["attack_paths"] = _attack_paths(ports, vulns)

    # 汇总
    result["summary"] = {
        "open_ports": len(ports),
        "vulnerabilities": len(vulns),
        "critical_vulns": sum(1 for v in vulns if v.get("severity") == "critical"),
        "high_vulns": sum(1 for v in vulns if v.get("severity") == "high"),
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "attack_paths_count": len(result["attack_paths"]),
        "tools_used": [k for k, v in result["steps"].items() if v.get("status") == "done"],
        "tools_failed": [k for k, v in result["steps"].items() if v.get("status") == "error"],
        "duration_seconds": round(time.time() - start, 1)
    }
    result["end_time"] = datetime.now().isoformat()
    return {"success": True, "data": result}


@router.get("/quick/{target}")
def quick_recon(target: str):
    """快速侦察：只跑Nmap，10秒出结果"""
    from asm.real_tools import NmapRunner
    nmap = NmapRunner(target, timeout=30).quick_scan()
    return {"success": True, "data": nmap}


@router.post("/report/{target}")
def generate_recon_report(target: str):
    """生成完整侦察报告（HTML+PDF）"""
    from asm.real_tools import NmapRunner, NucleiRunner
    import tempfile, os
    from pdf_report import pdf_engine

    nmap = NmapRunner(target, timeout=60).quick_scan()
    http_target = target if target.startswith("http") else f"http://{target}"
    nuclei = NucleiRunner(http_target, timeout=120).scan("critical,high,medium")
    vulns = nuclei.get("vulnerabilities", [])
    ports = nmap.get("open_ports", [])
    risk = _risk_score(ports, vulns, [])

    sections = [
        {"title": "1. 目标信息", "content": f"目标: {target}\n扫描时间: {datetime.now().isoformat()}"},
        {"title": "2. 端口扫描结果", "content": "\n".join([f"  {p['port']}/{p['protocol']} - {p['service']} {p.get('product','')} {p.get('version','')}" for p in ports]) or "未发现开放端口"},
        {"title": "3. 漏洞扫描结果", "content": "\n".join([f"  [{v['severity'].upper()}] {v['template_id']} - {v.get('template_name','')}" for v in vulns[:20]]) or "未发现漏洞"},
        {"title": "4. 风险评估", "content": f"风险评分: {risk['score']}/100 ({risk['level']})\n风险因素: {'; '.join(risk['factors'])}"},
    ]

    content = pdf_engine.build_content(
        title=f"安全评估报告 - {target}",
        subtitle="AI Hacking Agent 自动生成",
        executive_summary=[f"发现{len(ports)}个开放端口，{len(vulns)}个漏洞，风险等级: {risk['level']}"],
        sections=sections
    )

    out_dir = tempfile.mkdtemp()
    tpl = {}
    res = pdf_engine.generate(content, tpl, out_dir)
    return {"success": True, "data": {"report_path": res.get("path"), "risk": risk, "ports": len(ports), "vulns": len(vulns)}}
