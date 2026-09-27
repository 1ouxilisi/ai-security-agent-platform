"""
6阶段自动化渗透流水线API路由 - 一键自主渗透
- /api/v1/pipeline/run - 启动完整流水线
- /api/v1/pipeline/status/{pipeline_id} - 查询状态
- /api/v1/pipeline/result/{pipeline_id} - 获取结果
- /api/v1/pipeline/list - 列出所有流水线
- /api/v1/pipeline/plan - 生成作战计划
- /api/v1/pipeline/report/{pipeline_id} - 生成报告
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import sys
import os
import uuid
import time
import threading
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline import AutomatedPipeline, PipelineStatus

router = APIRouter(prefix="/api/v1/pipeline", tags=["自动化渗透流水线"])

API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")

_pipelines = {}
_pipeline_instances = {}


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


class PipelineRunRequest(BaseModel):
    target: str
    target_type: str = "web"  # web/network/api/cloud/mobile
    dry_run: bool = True
    scope: Dict = {}
    phases: List[str] = []  # 空=全部阶段


class PipelinePlanRequest(BaseModel):
    target: str
    target_type: str = "web"
    scope: Dict = {}


def _run_pipeline_background(pipeline_id: str, request: PipelineRunRequest):
    """后台执行流水线"""
    try:
        pipe = AutomatedPipeline()
        _pipeline_instances[pipeline_id] = pipe

        result = pipe.run(
            target=request.target,
            target_type=request.target_type,
            dry_run=request.dry_run,
        )

        # 序列化结果
        _pipelines[pipeline_id] = {
            "pipeline_id": pipeline_id,
            "target": result.target,
            "status": result.status.value,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "total_duration": result.total_duration,
            "risk_summary": result.risk_summary,
            "phases": {
                name: {
                    "status": phase.status.value,
                    "start_time": phase.start_time,
                    "end_time": phase.end_time,
                    "duration": phase.duration_seconds,
                    "findings_count": len(phase.findings),
                    "tools_used": phase.tools_used,
                    "errors": phase.errors,
                    "findings": phase.findings,
                }
                for name, phase in result.phases.items()
            },
            "all_findings": result.all_findings,
        }
    except Exception as e:
        _pipelines[pipeline_id] = {
            "pipeline_id": pipeline_id,
            "status": "failed",
            "error": str(e),
            "target": request.target,
        }


@router.post("/run")
async def run_pipeline(
    request: PipelineRunRequest,
    x_api_key: Optional[str] = Header(None)
):
    """启动完整自动化渗透流水线（一键自主渗透）"""
    verify_api_key(x_api_key)
    try:
        pipeline_id = f"PIPE-{uuid.uuid4().hex[:8]}"

        _pipelines[pipeline_id] = {
            "pipeline_id": pipeline_id,
            "target": request.target,
            "status": "running",
            "start_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "message": "流水线已启动",
        }

        thread = threading.Thread(
            target=_run_pipeline_background,
            args=(pipeline_id, request),
            daemon=True
        )
        thread.start()

        return {
            "status": "started",
            "pipeline_id": pipeline_id,
            "target": request.target,
            "target_type": request.target_type,
            "dry_run": request.dry_run,
            "message": "6阶段自动化渗透流水线已启动",
            "phases": ["recon", "scan_enum", "vuln_analysis", "exploit", "post_exploit", "report"],
            "status_url": f"/api/v1/pipeline/status/{pipeline_id}",
            "result_url": f"/api/v1/pipeline/result/{pipeline_id}",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/{pipeline_id}")
async def get_pipeline_status(
    pipeline_id: str,
    x_api_key: Optional[str] = Header(None)
):
    """查询流水线状态"""
    verify_api_key(x_api_key)
    pipe = _pipelines.get(pipeline_id)
    if not pipe:
        raise HTTPException(status_code=404, detail="流水线不存在")

    return {
        "status": "success",
        "data": {
            "pipeline_id": pipe.get("pipeline_id"),
            "target": pipe.get("target"),
            "status": pipe.get("status"),
            "start_time": pipe.get("start_time"),
            "end_time": pipe.get("end_time"),
            "total_duration": pipe.get("total_duration"),
            "phases": {
                name: {"status": p.get("status"), "findings_count": p.get("findings_count", 0)}
                for name, p in pipe.get("phases", {}).items()
            } if pipe.get("phases") else {},
            "risk_summary": pipe.get("risk_summary"),
        }
    }


@router.get("/result/{pipeline_id}")
async def get_pipeline_result(
    pipeline_id: str,
    x_api_key: Optional[str] = Header(None)
):
    """获取流水线完整结果"""
    verify_api_key(x_api_key)
    pipe = _pipelines.get(pipeline_id)
    if not pipe:
        raise HTTPException(status_code=404, detail="流水线不存在")
    if pipe.get("status") != "completed":
        return {
            "status": "pending",
            "message": "流水线尚未完成",
            "current_status": pipe.get("status"),
        }
    return {"status": "success", "data": pipe}


@router.get("/list")
async def list_pipelines(
    x_api_key: Optional[str] = Header(None)
):
    """列出所有流水线"""
    verify_api_key(x_api_key)
    return {
        "status": "success",
        "total": len(_pipelines),
        "data": [
            {
                "pipeline_id": p.get("pipeline_id"),
                "target": p.get("target"),
                "status": p.get("status"),
                "start_time": p.get("start_time"),
                "risk_summary": p.get("risk_summary"),
            }
            for p in _pipelines.values()
        ]
    }


@router.post("/plan")
async def generate_battle_plan(
    request: PipelinePlanRequest,
    x_api_key: Optional[str] = Header(None)
):
    """生成作战计划（不执行）"""
    verify_api_key(x_api_key)
    try:
        pipe = AutomatedPipeline()
        plan = pipe.orchestrator.create_battle_plan(
            target=request.target,
            target_type=request.target_type,
            scope=request.scope,
        )
        return {"status": "success", "data": plan}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report/{pipeline_id}")
async def get_pipeline_report(
    pipeline_id: str,
    format: str = "json",
    x_api_key: Optional[str] = Header(None)
):
    """生成流水线报告"""
    verify_api_key(x_api_key)
    pipe = _pipelines.get(pipeline_id)
    if not pipe:
        raise HTTPException(status_code=404, detail="流水线不存在")
    if pipe.get("status") != "completed":
        raise HTTPException(status_code=400, detail="流水线尚未完成")

    if format == "markdown":
        # 生成Markdown报告
        md = f"""# 渗透测试报告

## 基本信息
- 目标: {pipe.get('target')}
- 流水线ID: {pipeline_id}
- 开始时间: {pipe.get('start_time')}
- 结束时间: {pipe.get('end_time')}
- 总耗时: {pipe.get('total_duration'):.2f} 秒

## 风险摘要
- 总发现: {pipe.get('risk_summary', {}).get('total', 0)}
- 严重: {pipe.get('risk_summary', {}).get('by_severity', {}).get('critical', 0)}
- 高危: {pipe.get('risk_summary', {}).get('by_severity', {}).get('high', 0)}
- 中危: {pipe.get('risk_summary', {}).get('by_severity', {}).get('medium', 0)}
- 风险评分: {pipe.get('risk_summary', {}).get('risk_score', 0)}/100
- 总体风险: {pipe.get('risk_summary', {}).get('overall_risk', 'Unknown')}

## 各阶段结果
"""
        for name, phase in pipe.get("phases", {}).items():
            md += f"\n### {name}\n"
            md += f"- 状态: {phase.get('status')}\n"
            md += f"- 耗时: {phase.get('duration', 0):.2f} 秒\n"
            md += f"- 发现: {phase.get('findings_count', 0)} 个\n"
            md += f"- 工具: {', '.join(phase.get('tools_used', []))}\n"

        return {"status": "success", "data": {"format": "markdown", "content": md}}
    else:
        return {"status": "success", "data": pipe}


@router.get("/findings/{pipeline_id}")
async def get_findings(
    pipeline_id: str,
    severity: str = "",
    x_api_key: Optional[str] = Header(None)
):
    """获取流水线发现的漏洞"""
    verify_api_key(x_api_key)
    pipe = _pipelines.get(pipeline_id)
    if not pipe:
        raise HTTPException(status_code=404, detail="流水线不存在")

    findings = pipe.get("all_findings", [])
    if severity:
        findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]

    return {
        "status": "success",
        "total": len(findings),
        "data": findings,
    }
