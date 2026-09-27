# -*- coding: utf-8 -*-
"""
security_metrics_routes.py — 安全度量与 KPI 体系 REST API（40+ 端点）。

路由前缀: /api/v1/security-metrics
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。

设计定位：仅为 CISO / 管理层提供度量、评估、报告视角的能力，不提供攻击工具。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/security-metrics", tags=["安全度量与KPI"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from security_metrics.maturity_model import (
        SecurityMaturityModel, MATURITY_LEVELS, MATURITY_DIMENSIONS,
    )
    from security_metrics.kpi_library import (
        KPILibrary, KPI_CATEGORIES, KPI_LIBRARY_SIZE,
    )
    from security_metrics.risk_scoring import RiskScoringEngine, RISK_LEVELS
    from security_metrics.operational_efficiency import OperationalEfficiencyMetrics
    from security_metrics.compliance_audit import (
        ComplianceAuditMetrics, COMPLIANCE_FRAMEWORKS,
    )
    from security_metrics.executive_dashboard import ExecutiveDashboard
    from security_metrics.metrics_workflow import (
        MetricsWorkflow, get_metrics_workflow, METRICS_WORKFLOW_STEPS,
    )
    _MOD_AVAILABLE = True
    logger.info("security_metrics_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("security_metrics_routes: load failed: %s", e)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    task_id = uuid.uuid4().hex[:16]
    _TASKS[task_id] = {
        "task_id": task_id, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return task_id


def _finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
    if task_id in _TASKS:
        t = _TASKS[task_id]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


def _get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return _TASKS.get(task_id)


# --------------------------------------------------------------------------- #
# 统一响应 / 清理
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理数据中的控制字符与无效 Unicode，防止 JSON 编码失败。"""
    if isinstance(obj, str):
        obj = "".join(ch for ch in obj if ord(ch) >= 32 or ch in "\n\r\t")
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("安全度量模块不可用，请检查加载日志", 503)
    return None


# 单例（模块级）
def _mm() -> SecurityMaturityModel:
    return SecurityMaturityModel()


def _kpi() -> KPILibrary:
    return KPILibrary()


def _risk() -> RiskScoringEngine:
    return RiskScoringEngine()


def _ops() -> OperationalEfficiencyMetrics:
    return OperationalEfficiencyMetrics()


def _comp() -> ComplianceAuditMetrics:
    return ComplianceAuditMetrics()


def _dash() -> ExecutiveDashboard:
    return ExecutiveDashboard()


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class MaturityAssessRequest(BaseModel):
    industry: str = "金融"
    answers: Dict[str, int] = Field(default_factory=dict)


class KPIReadingsRequest(BaseModel):
    readings: Dict[str, float] = Field(default_factory=dict)


class RiskScoreRequest(BaseModel):
    probability: float = 5.0
    impact: float = 5.0
    exposure: float = 1.0


class RiskAddRequest(BaseModel):
    name: str
    asset_category: str = "general"
    threat_type: str = "general"
    probability: float = 5.0
    impact: float = 5.0
    exposure: float = 1.0
    treatment: str = "mitigate"
    owner: str = "安全部"


class RiskTreatmentRequest(BaseModel):
    treatment: str
    status: Optional[str] = None
    note: str = ""


class WorkflowRunRequest(BaseModel):
    industry: str = "金融"
    include_report: bool = True


# =========================================================================== #
# 1. 安全成熟度模型（6 个端点）
# =========================================================================== #
@router.get("/maturity/levels")
def maturity_levels():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"levels": MATURITY_LEVELS,
                   "dimensions": {k: {"name": v["name"], "weight": v["weight"]}
                                  for k, v in MATURITY_DIMENSIONS.items()}})
    except Exception as e:
        logger.exception("maturity_levels error")
        return fail(f"查询失败: {e}", 500)


@router.get("/maturity/questionnaire")
def maturity_questionnaire():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_mm().get_questionnaire())
    except Exception as e:
        return fail(f"问卷查询失败: {e}", 500)


@router.post("/maturity/assess")
def maturity_assess(req: MaturityAssessRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("maturity")
        result = _mm().assess(req.answers or None, req.industry)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("maturity_assess error")
        return fail(f"成熟度评估失败: {e}", 500)


@router.get("/maturity/benchmarks")
def maturity_benchmarks():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_mm().list_benchmarks())
    except Exception as e:
        return fail(f"对标查询失败: {e}", 500)


@router.get("/maturity/{assessment_id}/report")
def maturity_report(assessment_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        sess = _mm().get_session(assessment_id)
        if not sess:
            return fail("评估记录不存在", 404)
        return ok({"assessment_id": assessment_id,
                   "report_markdown": sess["report_markdown"],
                   "overall_score": sess["overall_score"],
                   "level_name": sess["level_name"]})
    except Exception as e:
        return fail(f"报告查询失败: {e}", 500)


@router.get("/maturity/{assessment_id}/roadmap")
def maturity_roadmap(assessment_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        sess = _mm().get_session(assessment_id)
        if not sess:
            return fail("评估记录不存在", 404)
        return ok({"assessment_id": assessment_id,
                   "roadmap": sess["roadmap"],
                   "gap_analysis": sess["gap_analysis"]})
    except Exception as e:
        return fail(f"路线图查询失败: {e}", 500)


# =========================================================================== #
# 2. KPI 指标库（6 个端点）
# =========================================================================== #
@router.get("/kpi/categories")
def kpi_categories():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"categories": _kpi().categories(),
                   "total_library": KPI_LIBRARY_SIZE,
                   "category_names": KPI_CATEGORIES})
    except Exception as e:
        return fail(f"分类查询失败: {e}", 500)


@router.get("/kpi/list")
def kpi_list(category: Optional[str] = Query(default=None),
             series: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_kpi().list(category, series))
    except Exception as e:
        return fail(f"KPI 查询失败: {e}", 500)


@router.get("/kpi/{kpi_id}")
def kpi_detail(kpi_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        item = _kpi().get(kpi_id)
        if not item:
            return fail("KPI 不存在", 404)
        return ok(item)
    except Exception as e:
        return fail(f"KPI 详情查询失败: {e}", 500)


@router.post("/kpi/evaluate")
def kpi_evaluate(req: KPIReadingsRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("kpi_eval")
        result = _kpi().evaluate(req.readings)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("kpi_evaluate error")
        return fail(f"KPI 评估失败: {e}", 500)


@router.get("/kpi/search")
def kpi_search(q: str = Query(default="")):
    try:
        g = _guard()
        if g is not None:
            return g
        all_items = _kpi().list()["items"]
        ql = q.lower()
        hits = [it for it in all_items
                if ql in it["name"].lower() or ql in it["id"].lower()]
        return ok({"query": q, "total": len(hits), "items": hits[:50]})
    except Exception as e:
        return fail(f"搜索失败: {e}", 500)


@router.get("/kpi/targets")
def kpi_targets():
    """返回所有 KPI 的目标值与阈值（管理层视角摘要）。"""
    try:
        g = _guard()
        if g is not None:
            return g
        items = _kpi().list()["items"]
        summary = {}
        for it in items:
            summary.setdefault(it["category_name"], []).append({
                "id": it["id"], "name": it["name"], "target": it["target"],
                "unit": it["unit"], "warning": it["warning_threshold"],
            })
        return ok({"groups": summary, "total": len(items)})
    except Exception as e:
        return fail(f"目标值查询失败: {e}", 500)


# =========================================================================== #
# 3. 风险度量与评分（9 个端点）
# =========================================================================== #
@router.post("/risk/score")
def risk_score(req: RiskScoreRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(RiskScoringEngine.score(req.probability, req.impact, req.exposure))
    except Exception as e:
        return fail(f"风险评分失败: {e}", 500)


@router.get("/risk/scorecard")
def risk_scorecard():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_risk().overall_scorecard())
    except Exception as e:
        return fail(f"风险记分卡查询失败: {e}", 500)


@router.get("/risk/register")
def risk_register(level: Optional[str] = Query(default=None),
                  treatment: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_risk().list_register(level, treatment))
    except Exception as e:
        return fail(f"风险登记册查询失败: {e}", 500)


@router.post("/risk/register")
def risk_register_add(req: RiskAddRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        item = _risk().add_risk(req.name, req.asset_category, req.threat_type,
                                req.probability, req.impact, req.exposure,
                                req.treatment, req.owner)
        return ok(item)
    except Exception as e:
        logger.exception("risk_register_add error")
        return fail(f"新增风险失败: {e}", 500)


@router.post("/risk/register/{risk_id}/treatment")
def risk_treatment(risk_id: str, req: RiskTreatmentRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        item = _risk().update_treatment(risk_id, req.treatment, req.status, req.note)
        if not item:
            return fail("风险不存在或处置方式非法", 404)
        return ok(item)
    except Exception as e:
        return fail(f"处置更新失败: {e}", 500)


@router.get("/risk/trend")
def risk_trend(periods: int = Query(default=12, ge=3, le=36)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_risk().risk_trend(periods))
    except Exception as e:
        return fail(f"风险趋势查询失败: {e}", 500)


@router.get("/risk/distribution")
def risk_distribution():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_risk().risk_distribution())
    except Exception as e:
        return fail(f"风险分布查询失败: {e}", 500)


@router.get("/risk/heatmap")
def risk_heatmap():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_risk().heatmap())
    except Exception as e:
        return fail(f"风险热力图查询失败: {e}", 500)


@router.get("/risk/attribution")
def risk_attribution():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_risk().attribution())
    except Exception as e:
        return fail(f"风险归因查询失败: {e}", 500)


@router.get("/risk/predict")
def risk_predict(periods_ahead: int = Query(default=3, ge=1, le=12)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_risk().predict(periods_ahead))
    except Exception as e:
        return fail(f"风险预测失败: {e}", 500)


# =========================================================================== #
# 4. 运营效率（6 个端点）
# =========================================================================== #
@router.get("/ops/mt")
def ops_mt(periods: int = Query(default=12, ge=3, le=24)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_ops().mt_metrics(periods))
    except Exception as e:
        return fail(f"MT 指标查询失败: {e}", 500)


@router.get("/ops/alerts")
def ops_alerts(periods: int = Query(default=12, ge=3, le=24)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_ops().alert_metrics(periods))
    except Exception as e:
        return fail(f"告警运营查询失败: {e}", 500)


@router.get("/ops/workload")
def ops_workload():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_ops().analyst_workload())
    except Exception as e:
        return fail(f"工作量查询失败: {e}", 500)


@router.get("/ops/sla")
def ops_sla():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_ops().ticket_sla())
    except Exception as e:
        return fail(f"SLA 查询失败: {e}", 500)


@router.get("/ops/resources")
def ops_resources():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_ops().resource_utilization())
    except Exception as e:
        return fail(f"资源利用率查询失败: {e}", 500)


@router.get("/ops/summary")
def ops_summary():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_ops().summary())
    except Exception as e:
        return fail(f"运营摘要查询失败: {e}", 500)


# =========================================================================== #
# 5. 合规与审计（7 个端点）
# =========================================================================== #
@router.get("/compliance/frameworks")
def compliance_frameworks():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_comp().framework_comparison())
    except Exception as e:
        return fail(f"框架对比查询失败: {e}", 500)


@router.get("/compliance/coverage")
def compliance_coverage():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_comp().coverage())
    except Exception as e:
        return fail(f"合规覆盖率查询失败: {e}", 500)


@router.get("/compliance/findings")
def compliance_findings(severity: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_comp().audit_findings(severity))
    except Exception as e:
        return fail(f"审计发现查询失败: {e}", 500)


@router.get("/compliance/remediation")
def compliance_remediation():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_comp().remediation())
    except Exception as e:
        return fail(f"整改情况查询失败: {e}", 500)


@router.get("/compliance/trend")
def compliance_trend(periods: int = Query(default=12, ge=3, le=24)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_comp().compliance_trend(periods))
    except Exception as e:
        return fail(f"合规趋势查询失败: {e}", 500)


@router.get("/compliance/readiness")
def compliance_readiness():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_comp().audit_readiness())
    except Exception as e:
        return fail(f"审计准备度查询失败: {e}", 500)


@router.get("/compliance/report")
def compliance_report():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"report_markdown": _comp().compliance_report_markdown()})
    except Exception as e:
        return fail(f"合规报告生成失败: {e}", 500)


# =========================================================================== #
# 6. 高管仪表盘（5 个端点）
# =========================================================================== #
@router.get("/executive/dashboard")
def executive_dashboard():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_dash().ciso_dashboard())
    except Exception as e:
        logger.exception("executive_dashboard error")
        return fail(f"CISO 仪表盘查询失败: {e}", 500)


@router.get("/executive/roi")
def executive_roi():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_dash().security_roi())
    except Exception as e:
        return fail(f"ROI 查询失败: {e}", 500)


@router.get("/executive/one-pager")
def executive_one_pager():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_dash().one_pager())
    except Exception as e:
        return fail(f"一页纸查询失败: {e}", 500)


@router.get("/executive/risk-map")
def executive_risk_map():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_dash().risk_map())
    except Exception as e:
        return fail(f"风险地图查询失败: {e}", 500)


@router.post("/executive/report")
def executive_report(period: str = Query(default="weekly")):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("exec_report")
        result = _dash().generate_report(period if period in ("weekly", "monthly") else "weekly")
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("executive_report error")
        return fail(f"报告生成失败: {e}", 500)


# =========================================================================== #
# 7. 综合工作流（3 个端点）
# =========================================================================== #
@router.get("/workflow/steps")
def workflow_steps():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"steps": METRICS_WORKFLOW_STEPS})
    except Exception as e:
        return fail(f"工作流步骤查询失败: {e}", 500)


@router.post("/workflow/run")
def workflow_run(req: WorkflowRunRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("metrics_workflow")
        result = get_metrics_workflow().run(req.industry, req.include_report)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("workflow_run error")
        return fail(f"工作流执行失败: {e}", 500)


@router.get("/workflow/{task_id}/status")
def workflow_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok({"task_id": t["task_id"], "status": t["status"],
                   "kind": t["kind"], "created_at": t["created_at"],
                   "finished_at": t["finished_at"]})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/workflow/{task_id}/result")
def workflow_result(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)
