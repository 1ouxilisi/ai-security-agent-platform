# -*- coding: utf-8 -*-
"""攻击链分析 - Kill Chain分析+攻击路径可视化（对标CyberStrikeAI攻击链分析）"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime

router = APIRouter(prefix="/api/v1/kill-chain", tags=["攻击链分析"])

# Cyber Kill Chain 7阶段
KILL_CHAIN_STAGES = [
    {"stage": 1, "name": "Reconnaissance", "name_cn": "侦察", "description": "收集目标信息（IP/域名/端口/服务/员工信息）"},
    {"stage": 2, "name": "Weaponization", "name_cn": "武器化", "description": "制作攻击载荷（恶意文档/Exploit/后门）"},
    {"stage": 3, "name": "Delivery", "name_cn": "投递", "description": "将攻击载荷发送到目标（钓鱼邮件/水坑/U盘）"},
    {"stage": 4, "name": "Exploitation", "name_cn": "利用", "description": "利用漏洞执行代码（RCE/缓冲区溢出/注入）"},
    {"stage": 5, "name": "Installation", "name_cn": "安装", "description": "安装持久化组件（后门/木马/计划任务）"},
    {"stage": 6, "name": "Command & Control", "name_cn": "命令控制", "description": "建立C2通道（反弹Shell/域名前置/隐蔽信道）"},
    {"stage": 7, "name": "Actions on Objectives", "name_cn": "目标行动", "description": "达成攻击目标（数据窃取/横向移动/勒索/破坏）"},
]

# MITRE ATT&CK 战术映射
ATTACK_TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "name_cn": "侦察"},
    {"id": "TA0042", "name": "Resource Development", "name_cn": "资源开发"},
    {"id": "TA0001", "name": "Initial Access", "name_cn": "初始访问"},
    {"id": "TA0002", "name": "Execution", "name_cn": "执行"},
    {"id": "TA0003", "name": "Persistence", "name_cn": "持久化"},
    {"id": "TA0004", "name": "Privilege Escalation", "name_cn": "权限提升"},
    {"id": "TA0005", "name": "Defense Evasion", "name_cn": "防御规避"},
    {"id": "TA0006", "name": "Credential Access", "name_cn": "凭证访问"},
    {"id": "TA0007", "name": "Discovery", "name_cn": "发现"},
    {"id": "TA0008", "name": "Lateral Movement", "name_cn": "横向移动"},
    {"id": "TA0009", "name": "Collection", "name_cn": "收集"},
    {"id": "TA0011", "name": "Command and Control", "name_cn": "命令控制"},
    {"id": "TA0010", "name": "Exfiltration", "name_cn": "数据外泄"},
    {"id": "TA0040", "name": "Impact", "name_cn": "影响"},
]

class KillChainAnalyzeReq(BaseModel):
    target: str
    scan_result: Optional[Dict] = None
    ports: Optional[List] = None
    vulnerabilities: Optional[List] = None

@router.get("/stages")
def get_stages():
    """获取Kill Chain 7阶段定义"""
    return {"success": True, "data": {"kill_chain": KILL_CHAIN_STAGES, "mitre_attack": ATTACK_TACTICS}}

@router.post("/analyze")
def analyze_kill_chain(req: KillChainAnalyzeReq):
    """基于扫描结果分析攻击链（哪些阶段可被利用）"""
    ports = req.ports or []
    vulns = req.vulnerabilities or []
    
    # 阶段1: 侦察 - 开放端口和服务即侦察结果
    recon_findings = []
    for p in ports:
        recon_findings.append({"port": p.get("port"), "service": p.get("service","unknown"), "product": p.get("product",""), "version": p.get("version","")})
    
    # 阶段4: 利用 - 漏洞可被利用
    exploitable = []
    for v in vulns:
        sev = v.get("severity", "info")
        if sev in ("critical", "high", "medium"):
            exploitable.append({"id": v.get("template_id", v.get("id","")), "name": v.get("template_name", v.get("name","")), "severity": sev, "matched_at": v.get("matched_at", v.get("url",""))})
    
    # 阶段6: C2 - 特定端口可能用于C2
    c2_ports = [p for p in ports if p.get("port") in (443, 8080, 8443, 53, 4444)]
    
    # 攻击路径推演
    attack_paths = []
    if exploitable:
        for v in exploitable[:3]:
            path = [
                {"stage": 1, "action": "侦察发现目标服务", "detail": f"目标{req.target}开放服务"},
                {"stage": 4, "action": "利用漏洞", "detail": f"{v['name']}({v['severity']}) at {v.get('matched_at','')}"},
                {"stage": 5, "action": "安装持久化", "detail": "潜在风险：可安装后门/计划任务"},
                {"stage": 6, "action": "建立C2", "detail": "通过HTTP/HTTPS出站建立命令控制通道"},
                {"stage": 7, "action": "达成目标", "detail": "数据窃取/横向移动/进一步渗透"},
            ]
            attack_paths.append({"vulnerability": v["name"], "path": path, "risk": v["severity"]})
    
    # 风险评估
    max_severity = "info"
    if any(v.get("severity")=="critical" for v in vulns): max_severity = "critical"
    elif any(v.get("severity")=="high" for v in vulns): max_severity = "high"
    elif any(v.get("severity")=="medium" for v in vulns): max_severity = "medium"
    
    stages_reachable = [1]  # 侦察总是可达
    if exploitable: stages_reachable.extend([4, 5, 6, 7])
    if c2_ports: stages_reachable.append(6)
    
    return {"success": True, "data": {
        "target": req.target,
        "reconnaissance": {"open_ports": len(ports), "findings": recon_findings[:20]},
        "exploitation": {"vulnerable_count": len(exploitable), "vulnerabilities": exploitable},
        "c2": {"c2_capable_ports": [p.get("port") for p in c2_ports]},
        "attack_paths": attack_paths,
        "risk_assessment": {"max_severity": max_severity, "stages_reachable": sorted(set(stages_reachable)), "total_vulns": len(vulns)},
        "recommendations": [
            "关闭不必要的开放端口和服务",
            "及时修补critical/high级别漏洞",
            "限制出站连接，检测异常C2通信",
            "实施最小权限原则，限制横向移动",
            "部署EDR/HIDS检测持久化和异常进程",
        ]
    }}

@router.get("/mitre/techniques")
def get_mitre_techniques():
    """MITRE ATT&CK常用技术映射（安全测试参考）"""
    techniques = [
        {"tactic": "初始访问", "techniques": ["T1190 面向公众应用的Exploit", "T1566 钓鱼", "T1133 外部远程服务", "T1078 有效账户"]},
        {"tactic": "执行", "techniques": ["T1059 命令和脚本解释器", "T1203 客户端执行", "T1053 计划任务", "T1505 服务器软件组件"]},
        {"tactic": "持久化", "techniques": ["T1547 启动项", "T1053 计划任务", "T1505 Web Shell", "T1136 创建账户"]},
        {"tactic": "权限提升", "techniques": ["T1548 滥用权限控制", "T1068 利用漏洞提权", "T1055 进程注入", "T1574 劫持执行流"]},
        {"tactic": "凭证访问", "techniques": ["T1003 OS凭证转储", "T1056 输入捕获", "T1110 暴力破解", "T1555 凭证文件"]},
        {"tactic": "发现", "techniques": ["T1046 网络服务扫描", "T1018 远程系统发现", "T1087 账户发现", "T1049 网络连接发现"]},
        {"tactic": "横向移动", "techniques": ["T1021 远程服务", "T1570 横向工具传输", "T1550 使用替代认证", "T1210 利用远程服务"]},
        {"tactic": "数据外泄", "techniques": ["T1041 自动外泄", "T1048 自动传输", "T1567 外泄到云存储", "T1030 数据传输大小限制"]},
    ]
    return {"success": True, "data": {"tactics": ATTACK_TACTICS, "techniques": techniques}}
