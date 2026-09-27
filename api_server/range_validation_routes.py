#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
靶场与实战验证 API路由
- 靶场管理：列出/启动/停止/删除/状态
- 端到端验证：执行完整渗透流程/获取报告
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from range_manager import get_range_manager
from e2e_validator import get_validator

router = APIRouter(prefix="/api/v1/range", tags=["靶场与实战验证"])


class StartRangeRequest(BaseModel):
    range_id: str  # dvwa/juice-shop/bwapp/webgoat/mutillidae/dvws-node
    timeout: int = 120


class ValidationRequest(BaseModel):
    target: str
    scope: str = "web"  # web/network/full
    aggressive: bool = False
    report_format: str = "markdown"  # markdown/json


@router.get("/list")
async def list_ranges():
    """列出所有可用靶场"""
    try:
        mgr = get_range_manager()
        return {"success": True, "data": {"ranges": mgr.list_ranges(), "docker": mgr.get_docker_status()}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/start")
async def start_range(req: StartRangeRequest):
    """启动靶场"""
    try:
        mgr = get_range_manager()
        result = mgr.start_range(req.range_id, req.timeout)
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "启动失败"))
        return {"success": True, "data": result}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop/{range_id}")
async def stop_range(range_id: str):
    """停止靶场"""
    try:
        mgr = get_range_manager()
        result = mgr.stop_range(range_id)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/remove/{range_id}")
async def remove_range(range_id: str):
    """删除靶场容器"""
    try:
        mgr = get_range_manager()
        result = mgr.remove_range(range_id)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/{range_id}")
async def range_status(range_id: str):
    """获取靶场状态"""
    try:
        mgr = get_range_manager()
        result = mgr.get_range_status(range_id)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/docker/status")
async def docker_status():
    """获取Docker状态"""
    try:
        mgr = get_range_manager()
        return {"success": True, "data": mgr.get_docker_status()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/validate")
async def run_validation(req: ValidationRequest):
    """执行端到端实战验证"""
    try:
        validator = get_validator()
        result = validator.run_full_validation(
            target=req.target,
            scope=req.scope,
            aggressive=req.aggressive,
        )
        report = validator.generate_report(result, req.report_format)

        return {
            "success": True,
            "data": {
                "target": result.target,
                "duration_seconds": round(result.end_time - result.start_time, 2),
                "risk_score": result.risk_score,
                "phases_completed": result.phases_completed,
                "tools_used": result.tools_used,
                "real_findings": result.real_findings,
                "simulated_findings": result.simulated_findings,
                "total_findings": len(result.findings),
                "findings": [
                    {
                        "phase": f.phase,
                        "type": f.finding_type,
                        "name": f.name,
                        "severity": f.severity,
                        "description": f.description,
                        "evidence": f.evidence[:300] if f.evidence else "",
                        "is_real": f.is_real,
                        "tool": f.tool_used,
                        "cvss": f.cvss,
                    }
                    for f in result.findings
                ],
                "report": report if req.report_format == "markdown" else None,
                "report_json": report if req.report_format == "json" else None,
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools/status")
async def tools_status():
    """获取安全工具安装状态"""
    try:
        validator = get_validator()
        return {"success": True, "data": validator.tool_status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
