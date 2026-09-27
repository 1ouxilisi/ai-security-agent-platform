"""一键安全评估API路由。

提供简单易用的API端点，用户只需输入目标IP/域名，一键完成完整安全评估。
"""
import os
import json
import uuid
import threading
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from workflow.quick_assessment import QuickAssessmentEngine, AssessmentResult
from utils.logger import log

router = APIRouter(prefix="/api/v1/assessment", tags=["一键安全评估"])

# 全局引擎和任务存储
engine = QuickAssessmentEngine(output_dir="scan_results")
tasks: Dict[str, Dict[str, Any]] = {}


class AssessmentRequest(BaseModel):
    """评估请求"""
    target: str = Field(..., description="目标IP地址或域名，例如: 192.168.1.1 或 example.com")
    scan_type: str = Field("full", description="扫描类型: quick(快速)/full(完整)/deep(深度)")
    async_mode: bool = Field(True, description="是否异步执行（推荐True，扫描可能需要几分钟）")


def _run_assessment_task(task_id: str, target: str, scan_type: str):
    """后台执行评估任务"""
    try:
        result = engine.run_assessment(target, scan_type)
        tasks[task_id]["status"] = result.status
        tasks[task_id]["result"] = result
        tasks[task_id]["completed_at"] = __import__("datetime").datetime.now().isoformat()
        log.info(f"评估任务完成: {task_id}, 状态: {result.status}")
    except Exception as e:
        tasks[task_id]["status"] = "failed"
        tasks[task_id]["error"] = str(e)
        log.error(f"评估任务失败: {task_id}, 错误: {e}")


@router.post("/start")
async def start_assessment(request: AssessmentRequest):
    """启动一键安全评估

    输入目标IP或域名，自动完成：端口扫描→漏洞扫描→Web检测→风险评级→报告生成。
    异步模式下立即返回task_id，可通过/status端点查询进度。
    """
    # 验证目标格式
    target = request.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="目标不能为空")

    # 简单的目标格式验证
    import re
    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target)
    is_domain = re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', target)
    if not is_ip and not is_domain:
        raise HTTPException(status_code=400, detail="目标格式不正确，请输入有效的IP地址或域名")

    task_id = str(uuid.uuid4())[:8]
    tasks[task_id] = {
        "task_id": task_id,
        "target": target,
        "scan_type": request.scan_type,
        "status": "running",
        "created_at": __import__("datetime").datetime.now().isoformat(),
        "result": None
    }

    if request.async_mode:
        # 异步执行
        thread = threading.Thread(
            target=_run_assessment_task,
            args=(task_id, target, request.scan_type),
            daemon=True
        )
        thread.start()
        log.info(f"异步评估任务已启动: {task_id}, 目标: {target}")

        return {
            "task_id": task_id,
            "target": target,
            "scan_type": request.scan_type,
            "status": "running",
            "message": "评估任务已启动，扫描可能需要1-5分钟，请通过 /api/v1/assessment/status/{task_id} 查询进度",
            "status_url": f"/api/v1/assessment/status/{task_id}",
            "result_url": f"/api/v1/assessment/result/{task_id}"
        }
    else:
        # 同步执行（等待完成）
        result = engine.run_assessment(target, request.scan_type)
        tasks[task_id]["status"] = result.status
        tasks[task_id]["result"] = result
        return _format_result(task_id, result)


@router.get("/status/{task_id}")
async def get_assessment_status(task_id: str):
    """查询评估任务状态"""
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail="任务不存在")

    task = tasks[task_id]
    response = {
        "task_id": task_id,
        "target": task["target"],
        "scan_type": task["scan_type"],
        "status": task["status"],
        "created_at": task["created_at"],
    }

    if task.get("completed_at"):
        response["completed_at"] = task["completed_at"]

    if task["status"] == "failed":
        response["error"] = task.get("error", "未知错误")

    # 如果完成了，附上简要结果
    if task["status"] == "completed" and task.get("result"):
        result = task["result"]
        response["summary"] = {
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "open_ports": len(result.ports),
            "vulnerabilities": len(result.vulnerabilities),
            "web_findings": len(result.web_findings),
            "duration": result.duration
        }
        response["report_url"] = f"/api/v1/assessment/report/{task_id}"

    return response


@router.get("/result/{task_id}")
async def get_assessment_result(task_id: str):
    """获取评估完整结果"""
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail="任务不存在")

    task = tasks[task_id]
    if task["status"] == "running":
        return JSONResponse(
            status_code=202,
            content={"task_id": task_id, "status": "running", "message": "任务仍在执行中，请稍后再试"}
        )

    if task["status"] == "failed":
        raise HTTPException(status_code=500, detail=f"任务失败: {task.get('error', '未知错误')}")

    result = task.get("result")
    if not result:
        raise HTTPException(status_code=404, detail="结果不存在")

    return _format_result(task_id, result)


@router.get("/report/{task_id}")
async def download_report(task_id: str):
    """下载HTML评估报告"""
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail="任务不存在")

    task = tasks[task_id]
    result = task.get("result")
    if not result or not result.report_path:
        raise HTTPException(status_code=404, detail="报告不存在或尚未生成")

    if not os.path.exists(result.report_path):
        raise HTTPException(status_code=404, detail="报告文件不存在")

    filename = os.path.basename(result.report_path)
    return FileResponse(
        path=result.report_path,
        media_type="text/html",
        filename=filename
    )


@router.get("/tasks")
async def list_tasks():
    """列出所有评估任务"""
    task_list = []
    for task_id, task in tasks.items():
        item = {
            "task_id": task_id,
            "target": task["target"],
            "scan_type": task["scan_type"],
            "status": task["status"],
            "created_at": task["created_at"]
        }
        if task.get("result"):
            item["risk_level"] = task["result"].risk_level
            item["risk_score"] = task["result"].risk_score
        task_list.append(item)

    # 按创建时间倒序
    task_list.sort(key=lambda x: x["created_at"], reverse=True)
    return {"total": len(task_list), "tasks": task_list[:20]}


@router.get("/tools/status")
async def get_tools_status():
    """获取评估引擎工具状态"""
    from shutil import which
    return {
        "nmap": {
            "available": engine._nmap_path is not None,
            "path": engine._nmap_path
        },
        "nuclei": {
            "available": engine._nuclei_path is not None,
            "path": engine._nuclei_path
        },
        "output_dir": engine.output_dir
    }


def _format_result(task_id: str, result: AssessmentResult) -> Dict:
    """格式化评估结果"""
    return {
        "task_id": task_id,
        "target": result.target,
        "status": result.status,
        "start_time": result.start_time,
        "end_time": result.end_time,
        "duration": result.duration,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "summary": result.summary,
        "ports": [
            {
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                "service": p.service,
                "version": p.version
            } for p in result.ports
        ],
        "vulnerabilities": [
            {
                "name": v.name,
                "severity": v.severity,
                "description": v.description,
                "target": v.target,
                "evidence": v.evidence,
                "reference": v.reference
            } for v in result.vulnerabilities
        ],
        "web_findings": result.web_findings,
        "recommendations": result.recommendations,
        "tools_used": result.tools_used,
        "errors": result.errors,
        "report_path": result.report_path,
        "report_url": f"/api/v1/assessment/report/{task_id}" if result.report_path else None
    }
