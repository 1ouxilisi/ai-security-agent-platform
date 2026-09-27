#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v4.4 新模块统一API路由

- /api/v1/ai-malware/* — AI恶意软件检测引擎
- /api/v1/agentic-soc/* — Agentic SOC威胁狩猎
- /api/v1/mcp-security/* — MCP服务器安全扫描
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from ai_malware_detector import get_ai_malware_detector, BehaviorEvent
from agentic_soc import get_agentic_soc
from mcp_security import get_mcp_scanner, MCPServer

router = APIRouter(tags=["v4.4 防御增强模块"])


# ============ AI恶意软件检测路由 ============

class MalwareScanRequest(BaseModel):
    events: List[Dict] = []  # [{timestamp, event_type, description, target, payload}]
    agent_name: str = ""
    code_content: str = ""
    filename: str = ""


@router.post("/ai-malware/analyze")
async def analyze_malware(req: MalwareScanRequest):
    """分析Agent行为是否为AI恶意软件"""
    try:
        detector = get_ai_malware_detector()

        if req.code_content:
            result = detector.scan_code(req.code_content, req.filename)
        else:
            events = [
                BehaviorEvent(
                    timestamp=e.get("timestamp", 0),
                    event_type=e.get("event_type", ""),
                    description=e.get("description", ""),
                    target=e.get("target", ""),
                    payload=e.get("payload", ""),
                    source=req.agent_name,
                )
                for e in req.events
            ]
            result = detector.analyze_behavior(events, req.agent_name)

        return {
            "success": True,
            "data": {
                "is_malicious": result.is_malicious,
                "threat_level": result.threat_level,
                "threat_score": result.threat_score,
                "family": result.family,
                "confidence": result.confidence,
                "matched_indicators": result.matched_indicators,
                "behavior_chain": result.behavior_chain,
                "votes": result.votes,
                "recommendation": result.recommendation,
                "iocs": result.iocs,
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ai-malware/stats")
async def malware_stats():
    """获取检测统计"""
    try:
        detector = get_ai_malware_detector()
        return {"success": True, "data": detector.get_stats()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ai-malware/families")
async def malware_families():
    """获取已知恶意软件家族"""
    try:
        detector = get_ai_malware_detector()
        families = []
        for fid, fdata in detector.feature_db.FAMILY_FEATURES.items():
            families.append({
                "id": fid,
                "name": fdata["name"],
                "description": fdata["description"],
                "severity": fdata["severity"],
                "indicators": len(fdata["indicators"]),
            })
        return {"success": True, "data": {"families": families, "total": len(families)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============ Agentic SOC路由 ============

class LogIngestRequest(BaseModel):
    logs: List[str]
    source: str = "web"


class HuntRequest(BaseModel):
    query_type: str = "all"
    target: str = ""


class HuntQueryRequest(BaseModel):
    hypothesis: str


@router.post("/agentic-soc/ingest")
async def ingest_logs(req: LogIngestRequest):
    """批量摄入日志"""
    try:
        soc = get_agentic_soc()
        result = soc.ingest_logs_batch(req.logs, req.source)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agentic-soc/hunt")
async def run_hunt(req: HuntRequest):
    """执行威胁狩猎"""
    try:
        soc = get_agentic_soc()
        result = soc.run_hunt(req.query_type, req.target)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agentic-soc/generate-query")
async def generate_hunt_query(req: HuntQueryRequest):
    """基于假设生成狩猎查询"""
    try:
        soc = get_agentic_soc()
        result = soc.generate_hunt_query(req.hypothesis)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agentic-soc/dashboard")
async def soc_dashboard():
    """获取SOC仪表盘"""
    try:
        soc = get_agentic_soc()
        return {"success": True, "data": soc.get_dashboard()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agentic-soc/events")
async def soc_events(limit: int = 20):
    """获取安全事件列表"""
    try:
        soc = get_agentic_soc()
        events = []
        for e in soc.events[-limit:]:
            events.append({
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "title": e.title,
                "severity": e.severity,
                "source": e.source,
                "status": e.status,
                "description": e.description,
            })
        return {"success": True, "data": {"events": events, "total": len(events)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============ MCP安全路由 ============

class MCPScanRequest(BaseModel):
    server_name: str = ""
    command: str = ""
    args: List[str] = []
    env: Dict[str, str] = {}
    url: str = ""
    tools: List[Dict] = []
    code_content: str = ""
    config: Dict = {}


@router.post("/mcp-security/scan")
async def scan_mcp(req: MCPScanRequest):
    """扫描MCP服务器安全"""
    try:
        scanner = get_mcp_scanner()

        if req.config:
            result = scanner.scan_config(req.config, req.code_content)
        else:
            server = MCPServer(
                name=req.server_name or "unknown",
                command=req.command,
                args=req.args,
                env=req.env,
                url=req.url,
                tools=req.tools,
            )
            result = scanner.scan_server(server, req.code_content)

        return {
            "success": True,
            "data": {
                "server": result.server.name,
                "is_trojan": result.is_trojan,
                "risk_score": result.risk_score,
                "risk_level": result.risk_level,
                "permissions": result.permissions,
                "oidc_risk": result.oidc_risk,
                "supply_chain_risk": result.supply_chain_risk,
                "findings": [
                    {
                        "title": f.title,
                        "severity": f.severity,
                        "description": f.description,
                        "category": f.category,
                        "recommendation": f.recommendation,
                    }
                    for f in result.findings
                ],
                "scan_time": round(result.scan_time, 3),
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mcp-security/remediation")
async def mcp_remediation(req: MCPScanRequest):
    """生成MCP修复建议"""
    try:
        scanner = get_mcp_scanner()
        server = MCPServer(
            name=req.server_name or "unknown",
            command=req.command,
            args=req.args,
            env=req.env,
            url=req.url,
            tools=req.tools,
        )
        result = scanner.scan_server(server, req.code_content)
        remediation = scanner.generate_remediation(result)
        return {"success": True, "data": remediation}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mcp-security/trojans")
async def mcp_trojans():
    """获取已知木马MCP列表"""
    try:
        scanner = get_mcp_scanner()
        trojans = []
        for tid, tdata in scanner.trojan_db.TROJAN_MCPS.items():
            trojans.append({
                "id": tid,
                "name": tdata["name"],
                "threat_actor": tdata["threat_actor"],
                "description": tdata["description"],
                "severity": tdata["severity"],
                "disclosed": tdata["disclosed"],
            })
        return {"success": True, "data": {"trojans": trojans, "total": len(trojans)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mcp-security/stats")
async def mcp_stats():
    """获取MCP扫描统计"""
    try:
        scanner = get_mcp_scanner()
        return {"success": True, "data": scanner.get_stats()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
