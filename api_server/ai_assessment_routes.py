#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI大模型安全评估 API路由

- POST /api/v1/ai-assessment/run — 运行评估
- GET  /api/v1/ai-assessment/result/{id} — 获取结果
- GET  /api/v1/ai-assessment/report/{id} — 生成报告
- POST /api/v1/ai-assessment/bounty-report — 生成漏洞赏金报告
- GET  /api/v1/ai-assessment/payloads — 查看Payload库
- GET  /api/v1/ai-assessment/stats — 引擎统计
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import json
import time

from ai_security_assessment import get_assessment_engine, PAYLOAD_LIBRARY

router = APIRouter(prefix="/api/v1/ai-assessment", tags=["AI大模型安全评估"])

_engine = get_assessment_engine()
_results_store = {}  # id -> result


class AssessmentRequest(BaseModel):
    target: str
    mode: str = "scan"  # scan/deep/full
    api_key: str = ""
    model: str = ""
    categories: Optional[List[str]] = None


class BountyReportRequest(BaseModel):
    vuln_id: str
    result_id: str = ""
    platform: str = "bugcrowd"  # bugcrowd/hackerone
    target: str = ""


@router.post("/run")
async def run_assessment(req: AssessmentRequest):
    """运行AI大模型安全评估"""
    try:
        result_id = f"assessment_{int(time.time()*1000)}"
        result = _engine.run_assessment(
            target=req.target,
            mode=req.mode,
            api_key=req.api_key,
            model=req.model,
            categories=req.categories,
        )
        _results_store[result_id] = result

        return {
            "success": True,
            "data": {
                "result_id": result_id,
                "target": result.target,
                "mode": result.mode,
                "total_tests": result.total_tests,
                "vulnerabilities_found": len(result.vulnerabilities),
                "risk_score": result.risk_score,
                "risk_level": result.risk_level,
                "by_severity": result.by_severity,
                "by_category": result.by_category,
                "vulnerabilities": [
                    {
                        "id": v.vuln_id, "category": v.category, "name": v.name,
                        "severity": v.severity, "cvss": v.cvss, "cwe": v.cwe,
                        "evidence": v.evidence, "payload": v.payload[:100],
                        "recommendation": v.recommendation,
                    }
                    for v in result.vulnerabilities
                ],
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/result/{result_id}")
async def get_result(result_id: str):
    """获取评估结果"""
    result = _results_store.get(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    return {
        "success": True,
        "data": {
            "target": result.target,
            "mode": result.mode,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "total_tests": result.total_tests,
            "vulnerabilities_found": len(result.vulnerabilities),
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "by_severity": result.by_severity,
            "by_category": result.by_category,
            "vulnerabilities": [v.__dict__ for v in result.vulnerabilities],
        }
    }


@router.get("/report/{result_id}")
async def get_report(result_id: str, format: str = "markdown"):
    """生成评估报告"""
    result = _results_store.get(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    report = _engine.generate_report(result)
    return {"success": True, "data": {"format": format, "report": report}}


@router.post("/bounty-report")
async def generate_bounty_report(req: BountyReportRequest):
    """生成Bugcrowd/HackerOne格式漏洞报告"""
    result = _results_store.get(req.result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")

    vuln = next((v for v in result.vulnerabilities if v.vuln_id == req.vuln_id), None)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    report = _engine.generate_bounty_report(vuln, req.platform, req.target or result.target)
    return {"success": True, "data": report}


@router.get("/payloads")
async def list_payloads(category: str = ""):
    """查看Payload库"""
    if category:
        payloads = PAYLOAD_LIBRARY.get(category, [])
        return {
            "success": True,
            "data": {
                "category": category,
                "count": len(payloads),
                "payloads": [
                    {"id": p[0], "name": p[1], "severity": p[2], "cwe": p[3],
                     "description": p[5]}
                    for p in payloads
                ],
            }
        }
    return {
        "success": True,
        "data": {
            "categories": list(PAYLOAD_LIBRARY.keys()),
            "total": sum(len(v) for v in PAYLOAD_LIBRARY.values()),
            "by_category": {k: len(v) for k, v in PAYLOAD_LIBRARY.items()},
        }
    }


@router.get("/stats")
async def get_stats():
    """引擎统计"""
    return {"success": True, "data": _engine.get_stats()}
