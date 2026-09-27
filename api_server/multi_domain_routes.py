#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多领域智能体编排层 API路由 v2.0
支持12大安全领域，59个专家Agent，186个工具，285项能力
12条跨领域攻击链，67个真实工具检测
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from multi_domain import get_orchestrator, get_detector, SecurityDomain

router = APIRouter(prefix="/api/v1/multi-domain", tags=["多领域智能体编排"])


class SingleDomainRequest(BaseModel):
    domain: str  # 12大领域: web_security/mobile_security/cloud_security/blockchain_security/ai_security/internal_pentest/binary_reverse/wireless_security/ics_scada_security/iot_security/social_engineering/digital_forensics
    target: str
    dry_run: bool = True


class FireteamRequest(BaseModel):
    targets: Dict[str, str]  # {domain: target}
    dry_run: bool = True
    max_workers: int = 12  # 最大并行线程数
    timeout: int = 300  # 单个领域超时时间(秒)


@router.get("/domains")
async def list_domains():
    """列出所有支持的安全领域及能力"""
    try:
        orch = get_orchestrator()
        summary = orch.get_domain_summary()
        return {
            "success": True,
            "data": {
                "domains": summary,
                "total_domains": len(summary),
                "total_agents": sum(d["agents_count"] for d in summary.values()),
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/domains/{domain}/agents")
async def list_domain_agents(domain: str):
    """列出指定领域的所有Agent"""
    try:
        domain_enum = SecurityDomain(domain)
        orch = get_orchestrator()
        agents = orch.factory.create_agents_for_domain(domain_enum)
        return {
            "success": True,
            "data": {
                "domain": domain,
                "agents": [
                    {
                        "id": a.agent_id,
                        "role": a.role.value,
                        "name": a.name,
                        "description": a.description,
                        "tools": a.tools,
                        "capabilities": a.capabilities,
                    }
                    for a in agents
                ],
                "total": len(agents),
            }
        }
    except ValueError:
        raise HTTPException(status_code=400, detail=f"不支持的领域: {domain}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute/single")
async def execute_single_domain(request: SingleDomainRequest):
    """执行单领域安全评估"""
    try:
        domain_enum = SecurityDomain(request.domain)
        orch = get_orchestrator()
        mission = orch.create_mission(domain_enum, request.target)
        mission = orch.execute_mission(mission, dry_run=request.dry_run)

        return {
            "success": True,
            "data": {
                "mission_id": mission.mission_id,
                "domain": mission.domain.value,
                "target": mission.target,
                "status": mission.status,
                "risk_score": mission.risk_score,
                "findings_count": len(mission.findings),
                "agents_executed": len(mission.agents),
                "findings": mission.findings,
                "agents": [
                    {
                        "id": a.agent_id,
                        "role": a.role.value,
                        "name": a.name,
                        "status": a.status,
                        "findings_count": len(a.findings),
                        "duration": round(a.duration, 3),
                    }
                    for a in mission.agents
                ],
            }
        }
    except ValueError:
        raise HTTPException(status_code=400, detail=f"不支持的领域: {request.domain}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute/fireteam")
async def execute_fireteam(request: FireteamRequest):
    """Fireteam模式：多领域并行执行"""
    try:
        orch = get_orchestrator()
        targets = {}
        for domain_str, target in request.targets.items():
            try:
                targets[SecurityDomain(domain_str)] = target
            except ValueError:
                continue

        if not targets:
            raise HTTPException(status_code=400, detail="没有有效的领域目标")

        result = orch.execute_fireteam(
            targets,
            dry_run=request.dry_run,
            max_workers=request.max_workers,
            timeout=request.timeout
        )

        return {
            "success": True,
            "data": result
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/roles")
async def list_roles():
    """列出所有Agent角色（映射MITRE ATT&CK）"""
    from multi_domain import AgentRole
    roles = [
        {"role": r.value, "name": r.name, "mitre_phase": {
            "recon": "Reconnaissance",
            "scanner": "Initial Access / Discovery",
            "exploiter": "Exploitation",
            "infiltrator": "Lateral Movement",
            "exfiltrator": "Exfiltration",
            "ghost": "Defense Evasion / Persistence",
            "coordinator": "Command & Control",
            "analyst": "Collection / Analysis",
        }.get(r.value, "Unknown")}
        for r in AgentRole
    ]
    return {"success": True, "data": {"roles": roles, "total": len(roles)}}


@router.get("/tools/status")
async def get_tools_status():
    """获取12领域真实工具检测状态"""
    try:
        detector = get_detector()
        summary = detector.get_summary()
        return {
            "success": True,
            "data": {
                "os": summary["os"],
                "total_tools": summary["total_tools"],
                "installed_tools": summary["installed_tools"],
                "coverage": summary["coverage"],
                "domains": summary["domains"],
                "domain_coverage": summary["domain_coverage"],
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools/{domain}")
async def get_domain_tools(domain: str):
    """获取指定领域的工具列表和安装状态"""
    try:
        detector = get_detector()
        tools = detector.get_domain_tools(domain)
        return {
            "success": True,
            "data": {
                "domain": domain,
                "tools": [
                    {
                        "name": t.name,
                        "category": t.category,
                        "description": t.description,
                        "installed": t.installed,
                        "path": t.path,
                    }
                    for t in tools
                ],
                "total": len(tools),
                "installed": len([t for t in tools if t.installed]),
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-chains")
async def list_attack_chains():
    """列出所有12条跨领域攻击链规则"""
    chains = [
        {"id": 1, "name": "Web RCE → 云凭据窃取 → 云权限提升", "severity": "critical",
         "domains": ["web_security", "cloud_security"],
         "description": "通过Web漏洞获取服务器权限，窃取云服务凭据，进而提升云环境权限"},
        {"id": 2, "name": "移动APP硬编码密钥 → AI API滥用 → 模型攻击", "severity": "high",
         "domains": ["mobile_security", "ai_security"],
         "description": "从移动APP提取AI API密钥，滥用API进行模型攻击"},
        {"id": 3, "name": "Web RCE → 内网入口 → AD域渗透 → 域控获取", "severity": "critical",
         "domains": ["web_security", "internal_pentest"],
         "description": "通过Web漏洞获取DMZ服务器权限，以此为跳板进入内网，进行AD域渗透"},
        {"id": 4, "name": "鱼叉钓鱼 → 凭据窃取 → 内网登录 → 横向移动", "severity": "critical",
         "domains": ["social_engineering", "internal_pentest"],
         "description": "通过鱼叉钓鱼邮件获取员工凭据，直接登录内网，进行横向移动和域渗透"},
        {"id": 5, "name": "IoT设备漏洞 → 工控网络渗透 → PLC控制 → 物理破坏", "severity": "critical",
         "domains": ["iot_security", "ics_scada_security"],
         "description": "通过IoT设备漏洞进入OT网络，攻击PLC控制器，可能导致物理破坏"},
        {"id": 6, "name": "无线网络破解 → 内网接入 → 横向移动", "severity": "high",
         "domains": ["wireless_security", "internal_pentest"],
         "description": "破解WiFi密码或Evil Twin攻击获取内网接入权限，进行内网渗透"},
        {"id": 7, "name": "固件逆向 → 漏洞发现 → 固件利用 → IoT设备控制", "severity": "high",
         "domains": ["binary_reverse", "iot_security"],
         "description": "逆向IoT固件发现二进制漏洞，利用漏洞获取设备完全控制权"},
        {"id": 8, "name": "域控获取 → 云同步凭据窃取 → 云环境接管", "severity": "critical",
         "domains": ["internal_pentest", "cloud_security"],
         "description": "获取域控后窃取AD Connect同步的云凭据，接管整个云环境"},
        {"id": 9, "name": "AI提示注入 → 生成高仿真钓鱼内容 → 社工攻击", "severity": "high",
         "domains": ["ai_security", "social_engineering"],
         "description": "利用AI模型生成高仿真钓鱼邮件和语音，大幅提升社工攻击成功率"},
        {"id": 10, "name": "恶意软件植入 → C2通信 → 内网横向移动", "severity": "critical",
         "domains": ["binary_reverse", "internal_pentest"],
         "description": "通过恶意软件建立C2通道，在内网进行横向移动和数据窃取"},
        {"id": 11, "name": "智能合约漏洞 → 训练数据污染 → AI模型投毒", "severity": "medium",
         "domains": ["blockchain_security", "ai_security"],
         "description": "通过区块链智能合约漏洞篡改链上训练数据，对AI模型进行投毒攻击"},
        {"id": 12, "name": "取证分析 → 攻击痕迹发现 → 全领域入侵溯源", "severity": "high",
         "domains": ["digital_forensics", "all_domains"],
         "description": "通过数字取证分析发现入侵痕迹，溯源攻击路径和涉及的所有安全领域"},
    ]
    return {"success": True, "data": {"chains": chains, "total": len(chains)}}


@router.post("/execute/all-domains")
async def execute_all_domains(target: str, dry_run: bool = True, max_workers: int = 12, timeout: int = 300):
    """一键执行全部12领域Fireteam评估"""
    try:
        orch = get_orchestrator()
        targets = {d: target for d in SecurityDomain}
        result = orch.execute_fireteam(
            targets,
            dry_run=dry_run,
            max_workers=max_workers,
            timeout=timeout
        )
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
