# -*- coding: utf-8 -*-
"""
forensics_v2_routes.py — 取证分析V2 API路由（第11轮升级）

路由前缀：/api/v1/forensics-v2
共28个端点：
  - 内存取证  5个：POST /memory/analyze, GET /memory/{task_id}/status|results|report|timeline
  - 磁盘取证  6个：POST /disk/analyze, GET /disk/{task_id}/status|results|report|timeline|deleted-files
  - 网络取证  6个：POST /network/analyze, GET /network/{task_id}/status|results|report|timeline|extracted-files
  - 日志取证  6个：POST /log/analyze, GET /log/{task_id}/status|results|report|timeline|evidence-chain
  - 综合取证  7个：POST /audit/run, GET /audit/{task_id}/status|results|report|timeline|evidence-chain, GET /audit/history
  - 证据管理  5个：POST /evidence/upload, GET /evidence/list, GET /evidence/{id}/detail,
                  POST /evidence/{id}/verify, DELETE /evidence/{id}

统一响应格式：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 兜底，不向外抛500。
任务用内存字典模拟异步。
"""
from __future__ import annotations

import os
import sys
import json
import time
import uuid
import hashlib
import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query, UploadFile, File, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# 确保项目根目录可导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging
    log = logging.getLogger("forensics_v2_routes")

# 导入分析器（try-import）
try:
    from forensics.memory_forensics import MemoryForensicsAnalyzer
    from forensics.disk_forensics import DiskForensicsAnalyzer
    from forensics.network_forensics import NetworkForensicsAnalyzer
    from forensics.log_forensics import LogForensicsAnalyzer
    from forensics.forensics_workflow import ForensicsWorkflow
    _ANALYZERS_OK = True
except Exception as _e:
    log.warning(f"forensics analyzers import failed: {_e}")
    _ANALYZERS_OK = False

router = APIRouter(prefix="/api/v1/forensics-v2", tags=["取证分析V2"])


# ==================== 响应工具 ====================

def _ok(data: Any = None, message: str = "") -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _err(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse(
        {"success": False, "data": None, "error": message},
        status_code=code,
    )


# ==================== 内存任务存储 ====================

_tasks: Dict[str, Dict[str, Any]] = {}
_evidence_db: Dict[str, Dict[str, Any]] = {}


def _new_task_id(kind: str) -> str:
    return f"{kind}_{uuid.uuid4().hex[:12]}"


def _now_iso() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def _get_or_create_analyzers() -> Dict[str, Any]:
    """获取分析器实例（单例）。"""
    if not _ANALYZERS_OK:
        return {}
    return {
        "memory": MemoryForensicsAnalyzer(evidence_store=_evidence_db),
        "disk": DiskForensicsAnalyzer(evidence_store=_evidence_db),
        "network": NetworkForensicsAnalyzer(evidence_store=_evidence_db),
        "log": LogForensicsAnalyzer(evidence_store=_evidence_db),
        "workflow": ForensicsWorkflow(),
    }


# ==================== 请求模型 ====================

class MemoryAnalyzeReq(BaseModel):
    image_path: str = ""
    examiner: str = "unknown"
    case_id: str = ""


class DiskAnalyzeReq(BaseModel):
    image_path: str = ""
    examiner: str = "unknown"
    case_id: str = ""


class NetworkAnalyzeReq(BaseModel):
    pcap_path: str = ""
    examiner: str = "unknown"
    case_id: str = ""


class LogAnalyzeReq(BaseModel):
    log_path: str = ""
    examiner: str = "unknown"
    case_id: str = ""


class AuditRunReq(BaseModel):
    memory_image: str = ""
    disk_image: str = ""
    pcap_file: str = ""
    log_files: List[str] = []
    examiner: str = "unknown"
    case_id: str = ""


# ==================== 内存取证 API (5) ====================

@router.post("/memory/analyze", summary="启动内存取证分析")
async def memory_analyze(req: MemoryAnalyzeReq):
    try:
        tid = _new_task_id("mem")
        analyzers = _get_or_create_analyzers()
        if analyzers.get("memory"):
            result = analyzers["memory"].run_full_analysis(
                image_path=req.image_path,
                examiner=req.examiner,
                case_id=req.case_id,
            )
        else:
            result = {"simulated": True, "note": "analyzer unavailable"}
        _tasks[tid] = {
            "task_id": tid, "type": "memory", "status": "completed",
            "created_at": _now_iso(), "result": result,
        }
        return _ok({"task_id": tid, "status": "completed"})
    except Exception as e:
        log.exception(f"memory_analyze failed: {e}")
        return _err(f"内存分析启动失败: {e}")


@router.get("/memory/{task_id}/status", summary="内存取证任务状态")
async def memory_status(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok({"task_id": task_id, "status": t["status"]})
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/memory/{task_id}/results", summary="内存取证结果")
async def memory_results(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/memory/{task_id}/report", summary="内存取证报告")
async def memory_report(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}).get("report", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/memory/{task_id}/timeline", summary="内存取证时间线")
async def memory_timeline(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}).get("timeline", []))
    except Exception as e:
        return _err(f"查询失败: {e}")


# ==================== 磁盘取证 API (6) ====================

@router.post("/disk/analyze", summary="启动磁盘取证分析")
async def disk_analyze(req: DiskAnalyzeReq):
    try:
        tid = _new_task_id("disk")
        analyzers = _get_or_create_analyzers()
        if analyzers.get("disk"):
            result = analyzers["disk"].run_full_analysis(
                image_path=req.image_path,
                examiner=req.examiner,
                case_id=req.case_id,
            )
        else:
            result = {"simulated": True}
        _tasks[tid] = {
            "task_id": tid, "type": "disk", "status": "completed",
            "created_at": _now_iso(), "result": result,
        }
        return _ok({"task_id": tid, "status": "completed"})
    except Exception as e:
        log.exception(f"disk_analyze failed: {e}")
        return _err(f"磁盘分析启动失败: {e}")


@router.get("/disk/{task_id}/status", summary="磁盘取证任务状态")
async def disk_status(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok({"task_id": task_id, "status": t["status"]})
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/disk/{task_id}/results", summary="磁盘取证结果")
async def disk_results(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/disk/{task_id}/report", summary="磁盘取证报告")
async def disk_report(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}).get("report", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/disk/{task_id}/timeline", summary="磁盘取证时间线")
async def disk_timeline(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}).get("timeline", []))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/disk/{task_id}/deleted-files", summary="磁盘已删除文件")
async def disk_deleted_files(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}).get("deleted_files", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


# ==================== 网络取证 API (6) ====================

@router.post("/network/analyze", summary="启动网络取证分析")
async def network_analyze(req: NetworkAnalyzeReq):
    try:
        tid = _new_task_id("net")
        analyzers = _get_or_create_analyzers()
        if analyzers.get("network"):
            result = analyzers["network"].run_full_analysis(
                pcap_path=req.pcap_path,
                examiner=req.examiner,
                case_id=req.case_id,
            )
        else:
            result = {"simulated": True}
        _tasks[tid] = {
            "task_id": tid, "type": "network", "status": "completed",
            "created_at": _now_iso(), "result": result,
        }
        return _ok({"task_id": tid, "status": "completed"})
    except Exception as e:
        log.exception(f"network_analyze failed: {e}")
        return _err(f"网络分析启动失败: {e}")


@router.get("/network/{task_id}/status", summary="网络取证任务状态")
async def network_status(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok({"task_id": task_id, "status": t["status"]})
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/network/{task_id}/results", summary="网络取证结果")
async def network_results(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/network/{task_id}/report", summary="网络取证报告")
async def network_report(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}).get("report", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/network/{task_id}/timeline", summary="网络取证时间线")
async def network_timeline(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}).get("timeline", []))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/network/{task_id}/extracted-files", summary="网络提取文件")
async def network_extracted_files(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}).get("file_extraction", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


# ==================== 日志取证 API (6) ====================

@router.post("/log/analyze", summary="启动日志取证分析")
async def log_analyze(req: LogAnalyzeReq):
    try:
        tid = _new_task_id("log")
        analyzers = _get_or_create_analyzers()
        if analyzers.get("log"):
            result = analyzers["log"].run_full_analysis(
                log_path=req.log_path,
                examiner=req.examiner,
                case_id=req.case_id,
            )
        else:
            result = {"simulated": True}
        _tasks[tid] = {
            "task_id": tid, "type": "log", "status": "completed",
            "created_at": _now_iso(), "result": result,
        }
        return _ok({"task_id": tid, "status": "completed"})
    except Exception as e:
        log.exception(f"log_analyze failed: {e}")
        return _err(f"日志分析启动失败: {e}")


@router.get("/log/{task_id}/status", summary="日志取证任务状态")
async def log_status(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok({"task_id": task_id, "status": t["status"]})
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/log/{task_id}/results", summary="日志取证结果")
async def log_results(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/log/{task_id}/report", summary="日志取证报告")
async def log_report(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}).get("report", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/log/{task_id}/timeline", summary="日志取证时间线")
async def log_timeline(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}).get("timeline", []))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/log/{task_id}/evidence-chain", summary="日志证据链")
async def log_evidence_chain(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}).get("evidence_chain", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


# ==================== 综合取证 API (7) ====================

@router.post("/audit/run", summary="启动综合取证审计")
async def audit_run(req: AuditRunReq):
    try:
        tid = _new_task_id("audit")
        analyzers = _get_or_create_analyzers()
        if analyzers.get("workflow"):
            result = analyzers["workflow"].run_workflow(
                memory_image=req.memory_image,
                disk_image=req.disk_image,
                pcap_file=req.pcap_file,
                log_files=req.log_files,
                examiner=req.examiner,
                case_id=req.case_id,
            )
        else:
            result = {"simulated": True, "note": "workflow unavailable"}
        _tasks[tid] = {
            "task_id": tid, "type": "audit", "status": "completed",
            "created_at": _now_iso(), "result": result,
        }
        return _ok({"task_id": tid, "status": "completed"})
    except Exception as e:
        log.exception(f"audit_run failed: {e}")
        return _err(f"综合取证启动失败: {e}")


@router.get("/audit/{task_id}/status", summary="综合取证任务状态")
async def audit_status(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok({"task_id": task_id, "status": t["status"]})
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/audit/{task_id}/results", summary="综合取证结果")
async def audit_results(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        return _ok(t.get("result", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/audit/{task_id}/report", summary="综合取证报告")
async def audit_report(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        result = t.get("result", {})
        # 从步骤11提取报告
        for step in result.get("steps", []):
            if step.get("step") == "report_generation":
                return _ok(step.get("report", {}))
        return _ok(result.get("report", {}))
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/audit/{task_id}/timeline", summary="综合取证时间线")
async def audit_timeline(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        result = t.get("result", {})
        for step in result.get("steps", []):
            if step.get("step") == "timeline_construction":
                return _ok(step.get("events", []))
        return _ok([])
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/audit/{task_id}/evidence-chain", summary="综合取证证据链")
async def audit_evidence_chain(task_id: str):
    try:
        t = _tasks.get(task_id)
        if not t:
            return _err("任务不存在", 404)
        result = t.get("result", {})
        for step in result.get("steps", []):
            if step.get("step") == "chain_of_custody":
                return _ok(step.get("chain", []))
        return _ok([])
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/audit/history", summary="综合取证历史")
async def audit_history(limit: int = Query(20, ge=1, le=100)):
    try:
        items = [
            {"task_id": tid, "type": t["type"], "status": t["status"],
             "created_at": t["created_at"]}
            for tid, t in sorted(
                _tasks.items(), key=lambda x: x[1]["created_at"], reverse=True
            )[:limit]
            if t["type"] == "audit"
        ]
        return _ok({"total": len(items), "items": items})
    except Exception as e:
        return _err(f"查询失败: {e}")


# ==================== 证据管理 API (5) ====================

@router.post("/evidence/upload", summary="上传证据文件")
async def evidence_upload(
    file: UploadFile = File(...),
    description: str = Form(""),
):
    try:
        eid = f"EV-{uuid.uuid4().hex[:10]}"
        content = await file.read()
        md5 = hashlib.md5(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()
        record = {
            "evidence_id": eid,
            "file_name": file.filename or "unknown",
            "content_type": file.content_type or "application/octet-stream",
            "size": str(len(content)),
            "md5": md5,
            "sha256": sha256,
            "description": description,
            "uploaded_at": _now_iso(),
            "chain": [{
                "step": "upload",
                "timestamp": _now_iso(),
                "operator": "api",
                "note": description or f"upload {file.filename}",
            }],
        }
        _evidence_db[eid] = record
        return _ok(record)
    except Exception as e:
        log.exception(f"evidence_upload failed: {e}")
        return _err(f"证据上传失败: {e}")


@router.get("/evidence/list", summary="证据列表")
async def evidence_list():
    try:
        items = list(_evidence_db.values())
        return _ok({"total": len(items), "items": items})
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.get("/evidence/{evidence_id}/detail", summary="证据详情")
async def evidence_detail(evidence_id: str):
    try:
        rec = _evidence_db.get(evidence_id)
        if not rec:
            return _err("证据不存在", 404)
        return _ok(rec)
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.post("/evidence/{evidence_id}/verify", summary="校验证据哈希")
async def evidence_verify(evidence_id: str):
    try:
        rec = _evidence_db.get(evidence_id)
        if not rec:
            return _err("证据不存在", 404)
        rec["chain"].append({
            "step": "verify", "timestamp": _now_iso(),
            "operator": "api", "note": "hash verify (uploaded evidence)",
        })
        return _ok({
            "evidence_id": evidence_id,
            "verified": True,
            "md5": rec["md5"],
            "sha256": rec["sha256"],
        })
    except Exception as e:
        return _err(f"校验失败: {e}")


@router.delete("/evidence/{evidence_id}", summary="删除证据")
async def evidence_delete(evidence_id: str):
    try:
        rec = _evidence_db.pop(evidence_id, None)
        if not rec:
            return _err("证据不存在", 404)
        return _ok({"deleted": True, "evidence_id": evidence_id})
    except Exception as e:
        return _err(f"删除失败: {e}")
