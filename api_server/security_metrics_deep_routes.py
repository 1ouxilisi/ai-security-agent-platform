# -*- coding: utf-8 -*-
"""
security_metrics_deep_routes.py — 第25轮升级方向3：安全度量与成熟度平台 REST API（50+ 端点）。

路由前缀: /api/v1/security-metrics
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。

设计定位：成熟度评估/KPI-KRI/ROI/效能/文化 全部真实计算，dry-run 输出。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/security-metrics", tags=["安全度量与成熟度平台"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，带 fallback）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from security_metrics_deep.maturity_assessment import (
        get_maturity_assessor, MATURITY_LEVELS, MATURITY_MODELS,
        INDUSTRY_BENCHMARKS, SCALE_BENCHMARKS, REGION_BENCHMARKS, CONTROL_ITEMS,
    )
    from security_metrics_deep.kpi_kri import get_metrics_manager
    from security_metrics_deep.security_roi import get_roi_manager, INVESTMENT_CATEGORIES
    from security_metrics_deep.security_efficiency import get_efficiency_manager
    from security_metrics_deep.security_culture import get_culture_manager
    from security_metrics_deep.metrics_dashboard import get_metrics_dashboard, SYSTEM_SETTINGS
    _MOD_AVAILABLE = True
    logger.info("security_metrics_deep_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("security_metrics_deep_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from security_metrics_deep.maturity_assessment import (  # noqa
            get_maturity_assessor, MATURITY_LEVELS, MATURITY_MODELS,
            INDUSTRY_BENCHMARKS, SCALE_BENCHMARKS, REGION_BENCHMARKS, CONTROL_ITEMS,
        )
        from security_metrics_deep.kpi_kri import get_metrics_manager  # noqa
        from security_metrics_deep.security_roi import get_roi_manager, INVESTMENT_CATEGORIES  # noqa
        from security_metrics_deep.security_efficiency import get_efficiency_manager  # noqa
        from security_metrics_deep.security_culture import get_culture_manager  # noqa
        from security_metrics_deep.metrics_dashboard import get_metrics_dashboard, SYSTEM_SETTINGS  # noqa
        _MOD_AVAILABLE = True
        logger.info("security_metrics_deep_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("security_metrics_deep_routes: fallback load failed: %s", e2)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    import uuid
    tid = uuid.uuid4().hex[:12]
    TASKS[tid] = {
        "task_id": tid, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return tid


def _finish_task(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in TASKS:
        t = TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        chars = [c for c in obj if ord(c) >= 32 or c in ("\t", "\n", "\r")]
        s = "".join(chars)
        return s.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, tuple):
        return [_clean(v) for v in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("安全度量与成熟度平台模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class AssessmentCreateReq(BaseModel):
    model: str = "nist_csf"
    org_name: str = "示例企业"
    scope: str = "全组织"
    assessor: str = "安全团队"
    evidence: Dict[str, Any] = Field(default_factory=dict)


class CollectReq(BaseModel):
    source: str = "auto"
    ids: List[str] = Field(default_factory=list)


class ProjectCreateReq(BaseModel):
    name: str
    category: str = "技术采购"
    investment: float = 0.0
    duration_months: int = 12
    annual_benefit: float = 0.0
    owner: str = "安全负责人"
    target: str = ""


class SettingsUpdateReq(BaseModel):
    values: Dict[str, Any] = Field(default_factory=dict)


# 解析 from __future__ import annotations 产生的字符串注解，避免 Pydantic 前向引用问题
for _m in (AssessmentCreateReq, CollectReq, ProjectCreateReq, SettingsUpdateReq):
    try:
        _m.model_rebuild()
    except Exception:  # pragma: no cover
        pass


# =========================================================================== #
# 一、成熟度管理
# =========================================================================== #
@router.get("/maturity/models")
def list_models():
    try:
        g = _guard()
        if g:
            return g
        return ok(MATURITY_MODELS)
    except Exception as e:  # pragma: no cover
        logger.exception("list_models error")
        return fail(str(e))


@router.get("/maturity/levels")
def list_levels():
    try:
        return ok(MATURITY_LEVELS)
    except Exception as e:
        return fail(str(e))


@router.post("/maturity/assessments")
def create_assessment(req: AssessmentCreateReq):
    try:
        g = _guard()
        if g:
            return g
        ma = get_maturity_assessor()
        rec = ma.create_assessment(model_key=req.model, org_name=req.org_name,
                                   scope=req.scope, assessor=req.assessor,
                                   evidence=req.evidence)
        return ok(rec)
    except Exception as e:
        logger.exception("create_assessment error")
        return fail(str(e))


@router.get("/maturity/assessments")
def list_assessments():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_maturity_assessor().list_assessments())
    except Exception as e:
        return fail(str(e))


@router.get("/maturity/assessments/{aid}")
def get_assessment(aid: str):
    try:
        rec = get_maturity_assessor().get_assessment(aid)
        if not rec:
            return fail("评估记录不存在", 404)
        return ok(rec)
    except Exception as e:
        return fail(str(e))


@router.get("/maturity/assessments/{aid}/gaps")
def assessment_gaps(aid: str, target_level: int = Query(4, ge=1, le=5)):
    try:
        res = get_maturity_assessor().gap_analysis(aid, target_level)
        if not res:
            return fail("评估记录不存在", 404)
        return ok(res)
    except Exception as e:
        return fail(str(e))


@router.get("/maturity/assessments/{aid}/roadmap")
def assessment_roadmap(aid: str, target_level: int = Query(4, ge=1, le=5),
                      horizon_months: int = Query(18, ge=6, le=60)):
    try:
        res = get_maturity_assessor().roadmap(aid, target_level, horizon_months)
        if not res:
            return fail("评估记录不存在", 404)
        return ok(res)
    except Exception as e:
        return fail(str(e))


@router.get("/maturity/trend")
def maturity_trend(model: str = "nist_csf", periods: int = 6):
    try:
        return ok(get_maturity_assessor().trend(model, periods))
    except Exception as e:
        return fail(str(e))


@router.get("/maturity/assessments/{aid}/report")
def maturity_report(aid: str):
    try:
        res = get_maturity_assessor().report(aid)
        if not res:
            return fail("评估记录不存在", 404)
        return ok(res)
    except Exception as e:
        return fail(str(e))


@router.get("/maturity/benchmark")
def maturity_benchmark(score: float = 60.0, industry: str = "互联网",
                      scale: str = "中型企业(100-1000)", region: str = "华东"):
    try:
        return ok(get_maturity_assessor().benchmark_compare(score, industry, scale, region))
    except Exception as e:
        return fail(str(e))


@router.get("/maturity/benchmarks")
def list_benchmarks():
    try:
        return ok({"industries": INDUSTRY_BENCHMARKS,
                   "scales": SCALE_BENCHMARKS,
                   "regions": REGION_BENCHMARKS})
    except Exception as e:
        return fail(str(e))


@router.get("/maturity/control-items/{model_key}")
def control_items(model_key: str):
    try:
        items = CONTROL_ITEMS.get(model_key, [])
        return ok({"model": model_key, "count": len(items), "items": items})
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 二、KPI / KRI
# =========================================================================== #
@router.get("/kpi")
def list_kpi(group: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok({"count": len(get_metrics_manager().list_kpi(group)),
                   "items": get_metrics_manager().list_kpi(group)})
    except Exception as e:
        return fail(str(e))


@router.get("/kpi/groups")
def kpi_groups():
    try:
        return ok(get_metrics_manager().kpi_groups())
    except Exception as e:
        return fail(str(e))


@router.get("/kpi/{kid}/trend")
def kpi_trend(kid: str, periods: int = 6):
    try:
        res = get_metrics_manager().trend_analysis(kid, periods)
        if not res:
            return fail("KPI 不存在", 404)
        return ok(res)
    except Exception as e:
        return fail(str(e))


@router.get("/kpi/{kid}/forecast")
def kpi_forecast(kid: str, periods: int = 3):
    try:
        res = get_metrics_manager().forecast(kid, periods)
        if not res:
            return fail("KPI 不存在", 404)
        return ok(res)
    except Exception as e:
        return fail(str(e))


@router.post("/kpi/collect")
def kpi_collect(req: CollectReq):
    try:
        return ok(get_metrics_manager().collect(req.source, req.ids))
    except Exception as e:
        return fail(str(e))


@router.get("/kpi/dashboard")
def kpi_dashboard():
    try:
        return ok(get_metrics_manager().kpi_dashboard())
    except Exception as e:
        return fail(str(e))


@router.get("/kpi/compare")
def kpi_compare():
    try:
        return ok(get_metrics_manager().compare_analysis())
    except Exception as e:
        return fail(str(e))


@router.get("/kpi/attainment")
def kpi_attainment():
    try:
        return ok(get_metrics_manager().goal_attainment())
    except Exception as e:
        return fail(str(e))


@router.get("/kpi/anomalies")
def kpi_anomalies():
    try:
        return ok(get_metrics_manager().abnormal_analysis())
    except Exception as e:
        return fail(str(e))


@router.get("/kri")
def list_kri(group: Optional[str] = None):
    try:
        m = get_metrics_manager()
        return ok({"count": len(m.list_kri(group)), "items": m.list_kri(group)})
    except Exception as e:
        return fail(str(e))


@router.get("/kri/groups")
def kri_groups():
    try:
        return ok(get_metrics_manager().kri_groups())
    except Exception as e:
        return fail(str(e))


@router.get("/kri/dashboard")
def kri_dashboard():
    try:
        return ok(get_metrics_manager().kri_dashboard())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 三、安全 ROI
# =========================================================================== #
@router.get("/roi/projects")
def roi_projects():
    try:
        return ok(get_roi_manager().list_projects())
    except Exception as e:
        return fail(str(e))


@router.post("/roi/projects")
def roi_add_project(req: ProjectCreateReq):
    try:
        return ok(get_roi_manager().add_project(req.name, req.category, req.investment,
                                                req.duration_months, req.annual_benefit,
                                                req.owner, req.target))
    except Exception as e:
        return fail(str(e))


@router.get("/roi/projects/{pid}")
def roi_project(pid: str):
    try:
        p = get_roi_manager().get_project(pid)
        if not p:
            return fail("投资项目不存在", 404)
        return ok(p)
    except Exception as e:
        return fail(str(e))


@router.get("/roi/projects/{pid}/benefits")
def roi_benefits(pid: str):
    try:
        res = get_roi_manager().benefits_breakdown(pid)
        if not res:
            return fail("投资项目不存在", 404)
        return ok(res)
    except Exception as e:
        return fail(str(e))


@router.get("/roi/projects/{pid}/metrics")
def roi_metrics(pid: str, discount_rate: float = 0.08):
    try:
        res = get_roi_manager().roi_metrics(pid, discount_rate)
        if not res:
            return fail("投资项目不存在", 404)
        return ok(res)
    except Exception as e:
        return fail(str(e))


@router.get("/roi/comparison")
def roi_comparison():
    try:
        return ok(get_roi_manager().roi_comparison())
    except Exception as e:
        return fail(str(e))


@router.get("/roi/projects/{pid}/trend")
def roi_trend(pid: str, periods: int = 6):
    try:
        res = get_roi_manager().roi_trend(pid, periods)
        if not res:
            return fail("投资项目不存在", 404)
        return ok(res)
    except Exception as e:
        return fail(str(e))


@router.get("/roi/benchmark")
def roi_benchmark():
    try:
        return ok(get_roi_manager().benchmark())
    except Exception as e:
        return fail(str(e))


@router.get("/roi/costs")
def roi_costs():
    try:
        return ok(get_roi_manager().cost_breakdown())
    except Exception as e:
        return fail(str(e))


@router.get("/roi/value")
def roi_value():
    try:
        return ok(get_roi_manager().value_proposition())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 四、安全效能
# =========================================================================== #
@router.get("/efficiency/overview")
def eff_overview():
    try:
        return ok(get_efficiency_manager().overview())
    except Exception as e:
        return fail(str(e))


@router.get("/efficiency/team")
def eff_team():
    try:
        return ok(get_efficiency_manager().team_efficiency())
    except Exception as e:
        return fail(str(e))


@router.get("/efficiency/process")
def eff_process():
    try:
        return ok(get_efficiency_manager().process_efficiency())
    except Exception as e:
        return fail(str(e))


@router.get("/efficiency/tech")
def eff_tech():
    try:
        return ok(get_efficiency_manager().tech_efficiency())
    except Exception as e:
        return fail(str(e))


@router.get("/efficiency/quality")
def eff_quality():
    try:
        return ok(get_efficiency_manager().quality())
    except Exception as e:
        return fail(str(e))


@router.get("/efficiency/efficiency")
def eff_efficiency():
    try:
        return ok(get_efficiency_manager().efficiency())
    except Exception as e:
        return fail(str(e))


@router.get("/efficiency/improvement")
def eff_improvement():
    try:
        return ok(get_efficiency_manager().improvement())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 五、安全文化
# =========================================================================== #
@router.get("/culture/awareness")
def cul_awareness():
    try:
        return ok(get_culture_manager().awareness())
    except Exception as e:
        return fail(str(e))


@router.get("/culture/behavior")
def cul_behavior():
    try:
        return ok(get_culture_manager().behavior())
    except Exception as e:
        return fail(str(e))


@router.get("/culture/communication")
def cul_communication():
    try:
        return ok(get_culture_manager().communication())
    except Exception as e:
        return fail(str(e))


@router.get("/culture/training")
def cul_training():
    try:
        return ok(get_culture_manager().training())
    except Exception as e:
        return fail(str(e))


@router.get("/culture/indicators")
def cul_indicators():
    try:
        return ok(get_culture_manager().culture_indicators())
    except Exception as e:
        return fail(str(e))


@router.get("/culture/improvement")
def cul_improvement():
    try:
        return ok(get_culture_manager().improvement())
    except Exception as e:
        return fail(str(e))


@router.get("/culture/report")
def cul_report():
    try:
        return ok(get_culture_manager().report())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 六、控制台总览与系统设置
# =========================================================================== #
@router.get("/overview")
def dash_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_metrics_dashboard().overview())
    except Exception as e:
        logger.exception("dash_overview error")
        return fail(str(e))


@router.get("/meta")
def dash_meta():
    try:
        return ok(get_metrics_dashboard().meta())
    except Exception as e:
        return fail(str(e))


@router.get("/settings")
def get_settings():
    try:
        return ok(get_metrics_dashboard().get_settings())
    except Exception as e:
        return fail(str(e))


@router.put("/settings/{section}")
def update_settings(section: str, req: SettingsUpdateReq):
    try:
        return ok(get_metrics_dashboard().update_settings(section, req.values))
    except Exception as e:
        return fail(str(e))


@router.get("/health")
def health():
    try:
        return ok({
            "module_available": _MOD_AVAILABLE,
            "kpi_count": len(get_metrics_manager().kpi_library) if _MOD_AVAILABLE else 0,
            "kri_count": len(get_metrics_manager().kri_library) if _MOD_AVAILABLE else 0,
            "investment_categories": INVESTMENT_CATEGORIES if _MOD_AVAILABLE else [],
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        return fail(str(e))


@router.get("/summary")
def summary():
    try:
        ma = get_maturity_assessor()
        km = get_metrics_manager()
        return ok({
            "assessments": len(ma.assessments),
            "kpi_total": len(km.kpi_library),
            "kri_total": len(km.kri_library),
            "roi_projects": len(get_roi_manager().projects),
            "tasks": len(TASKS),
        })
    except Exception as e:
        return fail(str(e))
