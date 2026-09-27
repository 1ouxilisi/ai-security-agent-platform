# -*- coding: utf-8 -*-
"""
api_server/code_audit_v2_routes.py — 代码审计 V2 API 路由（第11轮升级）

前缀: /api/v1/code-v2
统一响应格式: {"success": bool, "data": ..., "error": ...}
所有端点包裹 try-except，不向调用方抛出 500。
任务以内存字典模拟异步任务。
"""
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

# 保证项目根可导入 code_audit 包
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from code_audit.sast_engine import (          # noqa: E402
    get_sast_engine, get_rule_manager,
)
from code_audit.semgrep_integration import get_semgrep_integration  # noqa: E402
from code_audit.sca_engine import get_sca_engine                  # noqa: E402
from code_audit.code_quality import get_quality_analyzer           # noqa: E402
from code_audit.secure_coding import get_secure_coding_checker     # noqa: E402
from code_audit.code_audit_workflow import get_workflow            # noqa: E402

router = APIRouter(prefix="/api/v1/code-v2", tags=["代码审计V2"])


# ==================== 工具 ====================
def _ok(data: Any = None) -> Dict[str, Any]:
    return {"success": True, "data": data, "error": None}


def _fail(exc: Exception) -> Dict[str, Any]:
    return {"success": False, "data": None, "error": str(exc)}


# 内存任务表
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    tid = f"{kind}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {
        "task_id": tid, "kind": kind, "status": "pending",
        "created_at": time.time(), "result": None, "error": None,
    }
    return tid


def _finish(tid: str, result: Any) -> None:
    TASKS[tid].update(status="completed", result=result,
                      finished_at=time.time())


def _fail_task(tid: str, exc: Exception) -> None:
    TASKS[tid].update(status="failed", error=str(exc),
                     finished_at=time.time())


def _get_task(tid: str) -> Optional[Dict[str, Any]]:
    return TASKS.get(tid)


# ==================== 请求模型 ====================
class SastAnalyzeIn(BaseModel):
    target: str = "."                       # 目录路径或代码片段
    is_snippet: bool = False
    language: str = "python"
    rulesets: Optional[List[str]] = None


class SemgrepScanIn(BaseModel):
    target: str = "."
    rulesets: Optional[List[str]] = None
    is_remote: bool = False


class ScaScanIn(BaseModel):
    directory: str = "."


class QualityIn(BaseModel):
    directory: str = "."


class SecureCheckIn(BaseModel):
    directory: str = "."


class AuditRunIn(BaseModel):
    target: str = "."
    is_remote: bool = False
    incremental: bool = False


class RuleUpdateIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None
    fix: Optional[str] = None


# ==================== SAST ====================
@router.post("/sast/analyze", summary="SAST 分析")
async def sast_analyze(body: SastAnalyzeIn):
    tid = _new_task("sast")
    try:
        eng = get_sast_engine()
        if body.is_snippet:
            result = eng.analyze_code_snippet(body.target, body.language)
        else:
            result = eng.analyze_directory(body.target)
        _finish(tid, result)
        return _ok({"task_id": tid, "status": "completed",
                    "findings_count": result["findings_count"]})
    except Exception as e:
        _fail_task(tid, e)
        return _fail(e)


@router.get("/sast/{task_id}/status", summary="SAST 任务状态")
async def sast_status(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok({k: t[k] for k in ("task_id", "status", "created_at",
                                  "finished_at", "error")})


@router.get("/sast/{task_id}/results", summary="SAST 结果")
async def sast_results(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok(t.get("result"))


@router.get("/sast/{task_id}/report", summary="SAST 报告")
async def sast_report(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    report = get_sast_engine().generate_report(t.get("result"))
    return _ok(report)


@router.get("/sast/rules", summary="SAST 规则列表")
async def sast_rules(language: Optional[str] = Query(None),
                     vuln_type: Optional[str] = Query(None)):
    try:
        return _ok({
            "rules": get_rule_manager().list_rules(language=language,
                                                   vuln_type=vuln_type),
            "stats": get_rule_manager().stats(),
        })
    except Exception as e:
        return _fail(e)


@router.put("/sast/rules/{rule_id}", summary="更新/启停规则")
async def sast_update_rule(rule_id: str, body: RuleUpdateIn):
    try:
        rm = get_rule_manager()
        data = {k: v for k, v in body.dict().items() if v is not None}
        rule = rm.update(rule_id, data)
        if not rule:
            return _fail(KeyError(f"rule_id={rule_id} 不存在"))
        return _ok({"id": rule.id, "enabled": rule.enabled})
    except Exception as e:
        return _fail(e)


# ==================== Semgrep ====================
@router.post("/semgrep/scan", summary="Semgrep 扫描")
async def semgrep_scan(body: SemgrepScanIn):
    tid = _new_task("semgrep")
    try:
        inst = get_semgrep_integration()
        result = inst.scan(body.target, rulesets=body.rulesets,
                           is_remote=body.is_remote)
        _finish(tid, result)
        return _ok({"task_id": tid, "status": "completed",
                    "findings_count": result["findings_count"]})
    except Exception as e:
        _fail_task(tid, e)
        return _fail(e)


@router.get("/semgrep/{task_id}/status", summary="Semgrep 任务状态")
async def semgrep_status(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok({k: t[k] for k in ("task_id", "status", "created_at",
                                  "finished_at", "error")})


@router.get("/semgrep/{task_id}/results", summary="Semgrep 结果")
async def semgrep_results(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok(t.get("result"))


@router.get("/semgrep/{task_id}/report", summary="Semgrep 报告")
async def semgrep_report(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok(get_semgrep_integration().generate_report(t.get("result")))


@router.get("/semgrep/rulesets", summary="Semgrep 规则集")
async def semgrep_rulesets():
    try:
        return _ok(get_semgrep_integration().list_rulesets())
    except Exception as e:
        return _fail(e)


# ==================== SCA ====================
@router.post("/sca/scan", summary="SCA 扫描")
async def sca_scan(body: ScaScanIn):
    tid = _new_task("sca")
    try:
        result = get_sca_engine().scan(body.directory)
        _finish(tid, result)
        return _ok({"task_id": tid, "status": "completed",
                    "vulns_count": result["vulns_count"]})
    except Exception as e:
        _fail_task(tid, e)
        return _fail(e)


@router.get("/sca/{task_id}/status", summary="SCA 任务状态")
async def sca_status(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok({k: t[k] for k in ("task_id", "status", "created_at",
                                  "finished_at", "error")})


@router.get("/sca/{task_id}/results", summary="SCA 结果")
async def sca_results(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok(t.get("result"))


@router.get("/sca/{task_id}/report", summary="SCA 报告")
async def sca_report(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok(get_sca_engine().generate_report(t.get("result")))


@router.get("/sca/dependencies", summary="依赖列表")
async def sca_dependencies(directory: str = Query(".")):
    try:
        deps = get_sca_engine().parse_dependencies(directory)
        return _ok({"count": len(deps), "dependencies": deps,
                    "managers": get_sca_engine().detect_managers(directory)})
    except Exception as e:
        return _fail(e)


@router.get("/sca/licenses", summary="许可证扫描")
async def sca_licenses(directory: str = Query(".")):
    try:
        deps = get_sca_engine().parse_dependencies(directory)
        return _ok(get_sca_engine().scan_licenses(deps))
    except Exception as e:
        return _fail(e)


# ==================== 代码质量 ====================
@router.post("/quality/analyze", summary="代码质量分析")
async def quality_analyze(body: QualityIn):
    tid = _new_task("quality")
    try:
        result = get_quality_analyzer().analyze_directory(body.directory)
        _finish(tid, result)
        return _ok({"task_id": tid, "status": "completed",
                    "quality_score": result["quality_score"]})
    except Exception as e:
        _fail_task(tid, e)
        return _fail(e)


@router.get("/quality/{task_id}/status", summary="质量任务状态")
async def quality_status(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok({k: t[k] for k in ("task_id", "status", "created_at",
                                  "finished_at", "error")})


@router.get("/quality/{task_id}/results", summary="质量结果")
async def quality_results(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok(t.get("result"))


@router.get("/quality/{task_id}/report", summary="质量报告")
async def quality_report(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok(get_quality_analyzer().generate_report(t.get("result")))


@router.get("/quality/metrics", summary="质量指标与趋势")
async def quality_metrics():
    try:
        analyzer = get_quality_analyzer()
        return _ok({
            "metrics_catalog": [
                "LOC", "comment_ratio", "avg_cyclomatic",
                "duplication_ratio", "test_coverage_estimate",
            ],
            "smell_types": [
                "god_class", "long_method", "long_param_list",
                "deep_nesting", "long_line", "too_many_branches",
                "magic_number", "duplicate_block", "dead_code",
                "speculative_gen", "primitive_obsession", "data_clump",
            ],
            "trend": analyzer.trend(),
        })
    except Exception as e:
        return _fail(e)


# ==================== 安全编码 ====================
@router.post("/secure-coding/check", summary="安全编码检查")
async def secure_check(body: SecureCheckIn):
    tid = _new_task("secure")
    try:
        result = get_secure_coding_checker().check_directory(body.directory)
        _finish(tid, result)
        return _ok({"task_id": tid, "status": "completed",
                    "compliance_score": result["compliance_score"]})
    except Exception as e:
        _fail_task(tid, e)
        return _fail(e)


@router.get("/secure-coding/{task_id}/status", summary="安全编码任务状态")
async def secure_status(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok({k: t[k] for k in ("task_id", "status", "created_at",
                                  "finished_at", "error")})


@router.get("/secure-coding/{task_id}/results", summary="安全编码结果")
async def secure_results(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok(t.get("result"))


@router.get("/secure-coding/{task_id}/report", summary="安全编码报告")
async def secure_report(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok(get_secure_coding_checker().generate_report(t.get("result")))


@router.get("/secure-coding/rules", summary="安全编码规则")
async def secure_rules(spec: Optional[str] = Query(None),
                       language: Optional[str] = Query(None)):
    try:
        checker = get_secure_coding_checker()
        return _ok({"rules": checker.list_rules(spec=spec, language=language),
                    "stats": checker.stats()})
    except Exception as e:
        return _fail(e)


# ==================== 综合审计 ====================
@router.post("/audit/run", summary="运行综合审计")
async def audit_run(body: AuditRunIn):
    tid = _new_task("audit")
    try:
        result = get_workflow().run(body.target, is_remote=body.is_remote,
                                    incremental=body.incremental)
        _finish(tid, result)
        return _ok({"task_id": tid, "status": "completed",
                    "risk_level": result["risk"]["risk_level"]})
    except Exception as e:
        _fail_task(tid, e)
        return _fail(e)


@router.get("/audit/{task_id}/status", summary="综合审计状态")
async def audit_status(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok({k: t[k] for k in ("task_id", "status", "created_at",
                                  "finished_at", "error")})


@router.get("/audit/{task_id}/results", summary="综合审计结果")
async def audit_results(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    return _ok(t.get("result"))


@router.get("/audit/{task_id}/report", summary="综合审计报告")
async def audit_report(task_id: str):
    t = _get_task(task_id)
    if not t:
        return _fail(KeyError(f"task_id={task_id} 不存在"))
    result = t.get("result") or {}
    return _ok(result.get("report"))


@router.get("/audit/history", summary="审计历史")
async def audit_history(limit: int = Query(20, ge=1, le=200)):
    try:
        history = [
            {"task_id": k, "kind": v["kind"], "status": v["status"],
             "created_at": v["created_at"],
             "risk": ((v.get("result") or {}).get("risk") or {}).get(
                 "risk_level")}
            for k, v in list(TASKS.items())[-limit:]
        ]
        return _ok({"total": len(TASKS), "history": history})
    except Exception as e:
        return _fail(e)
