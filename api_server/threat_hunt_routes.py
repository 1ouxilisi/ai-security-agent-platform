# -*- coding: utf-8 -*-
"""
threat_hunt_routes.py — 威胁狩猎专业级 REST API（40 个端点）。

路由前缀: /api/v1/threat-hunt
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。

设计定位：仅用于经过授权的防御性威胁狩猎，输出检测/分析报告与建议。
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

router = APIRouter(prefix="/api/v1/threat-hunt", tags=["威胁狩猎专业级"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from threat_hunt.api_routes import (
        new_task, finish_task, get_task, get_engines, is_loaded,
    )
    _MOD_AVAILABLE = is_loaded()
    logger.info("threat_hunt_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("threat_hunt_routes: load failed: %s", e)
    # 内存任务回退
    _TASKS: Dict[str, Dict[str, Any]] = {}

    def new_task(kind: str) -> str:
        task_id = uuid.uuid4().hex[:16]
        _TASKS[task_id] = {
            "task_id": task_id, "kind": kind, "status": "pending",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "finished_at": None, "result": None, "error": None,
        }
        return task_id

    def finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
        if task_id in _TASKS:
            t = _TASKS[task_id]
            t["status"] = "error" if error else "done"
            t["result"] = result
            t["error"] = error
            t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    def get_task(task_id: str) -> Optional[Dict[str, Any]]:
        return _TASKS.get(task_id)

    def get_engines() -> Dict[str, Any]:
        return {}

    def is_loaded() -> bool:
        return False


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _sanitize_unicode(obj: Any) -> Any:
    """递归清理数据中的无效Unicode代理对字符。"""
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _sanitize_unicode(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_unicode(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_sanitize_unicode(item) for item in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _sanitize_unicode(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _sanitize_unicode(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("威胁狩猎模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class QueryExecuteRequest(BaseModel):
    query: str = ""
    page: int = 1
    page_size: int = 20


class QuerySaveRequest(BaseModel):
    name: str = ""
    query: str = ""
    description: str = ""
    tags: List[str] = Field(default_factory=list)
    author: str = "analyst"


class HypothesisCreateRequest(BaseModel):
    title: str = ""
    description: str = ""
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    verification_method: str = ""
    priority: str = "medium"
    analyst: str = "analyst"


class ProjectCreateRequest(BaseModel):
    name: str = ""
    goal: str = ""
    scope: str = ""
    timeline: str = ""
    team: List[str] = Field(default_factory=list)


class FindingCreateRequest(BaseModel):
    title: str = ""
    description: str = ""
    iocs: List[str] = Field(default_factory=list)
    ttps: List[str] = Field(default_factory=list)
    affected_systems: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    severity: str = "medium"
    hypothesis_ref: str = ""
    analyst: str = "analyst"
    remediation: str = ""


class IOCAddRequest(BaseModel):
    value: str = ""
    ioc_type: str = "ip"
    classification: str = "unknown"
    tags: List[str] = Field(default_factory=list)
    source: str = "manual"
    confidence: float = 0.8


class DataSourceRegisterRequest(BaseModel):
    name: str = ""
    log_type: str = ""
    collection: str = ""
    retention_days: int = 90
    index_status: str = "healthy"
    data_volume_gb: float = 0.0
    freshness_seconds: int = 60


class CrossSearchRequest(BaseModel):
    query: str = ""
    time_range: str = "last_24h"
    fields: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    aggregation: Optional[str] = None
    group_by: Optional[str] = None
    sort_by: str = "timestamp"
    sort_dir: str = "desc"
    page: int = 1
    page_size: int = 20


class ReportGenerateRequest(BaseModel):
    title: str = ""
    goal: str = ""
    methods: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    impact: str = ""
    recommendations: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    analyst: str = "analyst"


class EvidenceExportRequest(BaseModel):
    evidence_type: str = "hunt_evidence"
    query: str = ""
    include_logs: bool = True
    include_screenshots: bool = True
    include_pcap: bool = False


class BehaviorScoreRequest(BaseModel):
    observations: List[Dict[str, Any]] = Field(default_factory=list)


# =========================================================================== #
# 1. 狩猎查询引擎（8 个端点）
# =========================================================================== #
@router.get("/query/templates")
def list_templates(category: Optional[str] = Query(None)):
    """列出狩猎查询模板库（50+模板）。"""
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_engines()["query_engine"]
        return ok(eng.list_templates(category))
    except Exception as e:
        logger.exception("list_templates error")
        return fail(f"查询模板列表失败: {e}", 500)


@router.get("/query/templates/{template_id}")
def get_template(template_id: str):
    """获取单个查询模板详情。"""
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_engines()["query_engine"]
        tpl = eng.get_template(template_id)
        if not tpl:
            return fail("模板不存在", 404)
        return ok(tpl)
    except Exception as e:
        return fail(f"获取模板失败: {e}", 500)


@router.post("/query/execute")
def execute_query(req: QueryExecuteRequest):
    """执行狩猎查询。"""
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_engines()["query_engine"]
        result = eng.execute_query(req.query, req.page, req.page_size)
        return ok(result)
    except Exception as e:
        logger.exception("execute_query error")
        return fail(f"查询执行失败: {e}", 500)


@router.post("/query/validate")
def validate_query(req: QueryExecuteRequest):
    """验证查询语法。"""
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_engines()["query_engine"]
        result = eng.validate_query(req.query)
        return ok(result)
    except Exception as e:
        return fail(f"查询验证失败: {e}", 500)


@router.post("/query/save")
def save_query(req: QuerySaveRequest):
    """保存查询。"""
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_engines()["query_engine"]
        result = eng.save_query(req.name, req.query, req.description, req.tags, req.author)
        return ok(result)
    except Exception as e:
        return fail(f"保存查询失败: {e}", 500)


@router.get("/query/saved")
def list_saved_queries():
    """列出已保存查询。"""
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_engines()["query_engine"]
        return ok(eng.list_saved_queries())
    except Exception as e:
        return fail(f"查询列表失败: {e}", 500)


@router.get("/query/shared")
def list_shared_queries():
    """列出共享查询。"""
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_engines()["query_engine"]
        return ok(eng.list_shared_queries())
    except Exception as e:
        return fail(f"共享查询列表失败: {e}", 500)


@router.get("/query/history")
def query_history(limit: int = 20):
    """获取查询历史。"""
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_engines()["query_engine"]
        return ok(eng.get_history(limit))
    except Exception as e:
        return fail(f"查询历史失败: {e}", 500)


@router.get("/query/optimize")
def optimize_query(query: str = Query(...)):
    """查询性能优化建议。"""
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_engines()["query_engine"]
        return ok(eng.optimize_query(query))
    except Exception as e:
        return fail(f"查询优化失败: {e}", 500)


# =========================================================================== #
# 2. 假设驱动狩猎（8 个端点）
# =========================================================================== #
@router.post("/hypotheses")
def create_hypothesis(req: HypothesisCreateRequest):
    """创建狩猎假设。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["hypothesis_mgr"]
        result = mgr.create_hypothesis(
            title=req.title, description=req.description,
            mitre_tactics=req.mitre_tactics, mitre_techniques=req.mitre_techniques,
            verification_method=req.verification_method,
            priority=req.priority, analyst=req.analyst,
        )
        return ok(result)
    except Exception as e:
        return fail(f"创建假设失败: {e}", 500)


@router.get("/hypotheses")
def list_hypotheses(status: Optional[str] = Query(None),
                    priority: Optional[str] = Query(None)):
    """列出狩猎假设。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["hypothesis_mgr"]
        return ok(mgr.list_hypotheses(status, priority))
    except Exception as e:
        return fail(f"假设列表失败: {e}", 500)


@router.get("/hypotheses/{hypothesis_id}")
def get_hypothesis(hypothesis_id: str):
    """获取单个假设详情。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["hypothesis_mgr"]
        h = mgr.get_hypothesis(hypothesis_id)
        if not h:
            return fail("假设不存在", 404)
        return ok(h)
    except Exception as e:
        return fail(f"获取假设失败: {e}", 500)


@router.put("/hypotheses/{hypothesis_id}")
def update_hypothesis(hypothesis_id: str, status: Optional[str] = None,
                     priority: Optional[str] = None):
    """更新假设状态/优先级。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["hypothesis_mgr"]
        kwargs: Dict[str, Any] = {}
        if status:
            kwargs["status"] = status
        if priority:
            kwargs["priority"] = priority
        result = mgr.update_hypothesis(hypothesis_id, **kwargs)
        if not result:
            return fail("假设不存在", 404)
        return ok(result)
    except Exception as e:
        return fail(f"更新假设失败: {e}", 500)


@router.post("/projects")
def create_project(req: ProjectCreateRequest):
    """创建狩猎项目。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["project_mgr"]
        result = mgr.create_project(req.name, req.goal, req.scope, req.timeline, req.team)
        return ok(result)
    except Exception as e:
        return fail(f"创建项目失败: {e}", 500)


@router.get("/projects")
def list_projects(status: Optional[str] = Query(None)):
    """列出狩猎项目。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["project_mgr"]
        return ok(mgr.list_projects(status))
    except Exception as e:
        return fail(f"项目列表失败: {e}", 500)


@router.get("/playbooks")
def list_playbooks():
    """列出狩猎剧本。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["playbook_mgr"]
        return ok(mgr.list_playbooks())
    except Exception as e:
        return fail(f"剧本列表失败: {e}", 500)


@router.put("/playbooks/{playbook_id}/steps/{step_index}")
def update_playbook_step(playbook_id: str, step_index: int, status: str = "completed"):
    """更新剧本步骤状态。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["playbook_mgr"]
        result = mgr.update_playbook_step(playbook_id, step_index, status)
        if not result:
            return fail("剧本不存在", 404)
        return ok(result)
    except Exception as e:
        return fail(f"更新剧本步骤失败: {e}", 500)


@router.post("/findings")
def create_finding(req: FindingCreateRequest):
    """创建狩猎发现。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["finding_mgr"]
        result = mgr.create_finding(
            title=req.title, description=req.description, iocs=req.iocs,
            ttps=req.ttps, affected_systems=req.affected_systems,
            evidence=req.evidence, severity=req.severity,
            hypothesis_ref=req.hypothesis_ref, analyst=req.analyst,
            remediation=req.remediation,
        )
        return ok(result)
    except Exception as e:
        return fail(f"创建发现失败: {e}", 500)


@router.get("/findings")
def list_findings(severity: Optional[str] = Query(None),
                  status: Optional[str] = Query(None)):
    """列出狩猎发现。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["finding_mgr"]
        return ok(mgr.list_findings(severity, status))
    except Exception as e:
        return fail(f"发现列表失败: {e}", 500)


@router.get("/findings/summary")
def findings_summary():
    """狩猎发现统计摘要。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["finding_mgr"]
        return ok(mgr.finding_summary())
    except Exception as e:
        return fail(f"发现摘要失败: {e}", 500)


# =========================================================================== #
# 3. 行为分析（5 个端点）
# =========================================================================== #
@router.get("/behavior/baselines")
def list_baselines():
    """列出用户行为基线。"""
    try:
        g = _guard()
        if g is not None:
            return g
        bb = get_engines()["baseline_builder"]
        return ok(bb.list_baselines())
    except Exception as e:
        return fail(f"基线列表失败: {e}", 500)


@router.get("/behavior/profiles")
def list_profiles(entity_type: Optional[str] = Query(None)):
    """列出实体行为画像。"""
    try:
        g = _guard()
        if g is not None:
            return g
        profiler = get_engines()["profiler"]
        return ok(profiler.list_profiles(entity_type))
    except Exception as e:
        return fail(f"画像列表失败: {e}", 500)


@router.get("/behavior/anomalies")
def list_anomalies(anomaly_type: Optional[str] = Query(None),
                   severity: Optional[str] = Query(None)):
    """列出异常行为检测结果。"""
    try:
        g = _guard()
        if g is not None:
            return g
        ad = get_engines()["anomaly_detector"]
        return ok(ad.list_anomalies(anomaly_type, severity))
    except Exception as e:
        return fail(f"异常列表失败: {e}", 500)


@router.get("/behavior/chains")
def list_chains():
    """列出行为链/攻击路径。"""
    try:
        g = _guard()
        if g is not None:
            return g
        ca = get_engines()["chain_analyzer"]
        return ok(ca.list_chains())
    except Exception as e:
        return fail(f"行为链列表失败: {e}", 500)


@router.post("/behavior/score")
def score_behavior(req: BehaviorScoreRequest):
    """对行为观测进行风险评分。"""
    try:
        g = _guard()
        if g is not None:
            return g
        scorer = get_engines()["scorer"]
        result = scorer.score(req.observations)
        return ok(result)
    except Exception as e:
        return fail(f"行为评分失败: {e}", 500)


@router.get("/behavior/scoring-rules")
def scoring_rules():
    """列出行为评分规则。"""
    try:
        g = _guard()
        if g is not None:
            return g
        scorer = get_engines()["scorer"]
        return ok(scorer.list_rules())
    except Exception as e:
        return fail(f"评分规则失败: {e}", 500)


# =========================================================================== #
# 4. IOC富化（6 个端点）
# =========================================================================== #
@router.post("/iocs")
def add_ioc(req: IOCAddRequest):
    """添加IOC。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["ioc_mgr"]
        result = mgr.add_ioc(req.value, req.ioc_type, req.classification,
                             req.tags, req.source, req.confidence)
        return ok(result)
    except Exception as e:
        return fail(f"添加IOC失败: {e}", 500)


@router.get("/iocs")
def list_iocs(ioc_type: Optional[str] = Query(None),
              status: Optional[str] = Query(None),
              classification: Optional[str] = Query(None)):
    """列出IOC。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["ioc_mgr"]
        return ok(mgr.list_iocs(ioc_type, status, classification))
    except Exception as e:
        return fail(f"IOC列表失败: {e}", 500)


@router.get("/iocs/{ioc_id}/enrich")
def enrich_ioc(ioc_id: str):
    """富化单个IOC。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["ioc_mgr"]
        ioc = mgr.get_ioc(ioc_id)
        if not ioc:
            return fail("IOC不存在", 404)
        enricher = get_engines()["ioc_enricher"]
        result = enricher.enrich(ioc)
        return ok(result)
    except Exception as e:
        return fail(f"IOC富化失败: {e}", 500)


@router.get("/iocs/graph")
def ioc_graph():
    """获取IOC关系图谱。"""
    try:
        g = _guard()
        if g is not None:
            return g
        analyzer = get_engines()["ioc_relation"]
        return ok(analyzer.build_graph())
    except Exception as e:
        return fail(f"IOC图谱失败: {e}", 500)


@router.get("/iocs/{ioc_id}/score")
def score_ioc(ioc_id: str):
    """对单个IOC进行威胁评分。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_engines()["ioc_mgr"]
        ioc = mgr.get_ioc(ioc_id)
        if not ioc:
            return fail("IOC不存在", 404)
        scorer = get_engines()["ioc_scorer"]
        result = scorer.score(ioc)
        return ok(result)
    except Exception as e:
        return fail(f"IOC评分失败: {e}", 500)


@router.get("/iocs/export")
def export_iocs(fmt: str = "json"):
    """导出IOC数据。"""
    try:
        g = _guard()
        if g is not None:
            return g
        impexp = get_engines()["ioc_impexp"]
        data = impexp.export(fmt)
        return ok({"format": fmt, "data": data, "exported_at": time.strftime("%Y-%m-%d %H:%M:%S")})
    except Exception as e:
        return fail(f"IOC导出失败: {e}", 500)


# =========================================================================== #
# 5. 数据管理（6 个端点）
# =========================================================================== #
@router.get("/data/sources")
def list_data_sources():
    """列出数据源状态。"""
    try:
        g = _guard()
        if g is not None:
            return g
        sm = get_engines()["source_mgr"]
        return ok(sm.list_sources())
    except Exception as e:
        return fail(f"数据源列表失败: {e}", 500)


@router.post("/data/sources")
def register_data_source(req: DataSourceRegisterRequest):
    """注册新数据源。"""
    try:
        g = _guard()
        if g is not None:
            return g
        sm = get_engines()["source_mgr"]
        result = sm.register_source(
            req.name, req.log_type, req.collection,
            req.retention_days, req.index_status,
            req.data_volume_gb, req.freshness_seconds,
        )
        return ok(result)
    except Exception as e:
        return fail(f"注册数据源失败: {e}", 500)


@router.post("/data/search")
def cross_source_search(req: CrossSearchRequest):
    """跨源搜索。"""
    try:
        g = _guard()
        if g is not None:
            return g
        searcher = get_engines()["searcher"]
        result = searcher.search(
            req.query, req.time_range, req.fields, req.sources,
            req.aggregation, req.group_by, req.sort_by, req.sort_dir,
            req.page, req.page_size,
        )
        return ok(result)
    except Exception as e:
        logger.exception("cross_source_search error")
        return fail(f"跨源搜索失败: {e}", 500)


@router.get("/data/pipelines")
def list_pipelines():
    """列出数据管道。"""
    try:
        g = _guard()
        if g is not None:
            return g
        pl = get_engines()["pipeline"]
        return ok(pl.list_pipelines())
    except Exception as e:
        return fail(f"管道列表失败: {e}", 500)


@router.get("/data/quality")
def data_quality():
    """数据质量监控。"""
    try:
        g = _guard()
        if g is not None:
            return g
        qm = get_engines()["quality_monitor"]
        return ok({"details": qm.check_quality(), "summary": qm.quality_summary()})
    except Exception as e:
        return fail(f"质量监控失败: {e}", 500)


@router.post("/data/export-evidence")
def export_evidence(req: EvidenceExportRequest):
    """导出证据包。"""
    try:
        g = _guard()
        if g is not None:
            return g
        ex = get_engines()["exporter"]
        result = ex.export_evidence(
            req.evidence_type, req.query,
            req.include_logs, req.include_screenshots, req.include_pcap,
        )
        return ok(result)
    except Exception as e:
        return fail(f"证据导出失败: {e}", 500)


# =========================================================================== #
# 6. 报告与度量（6 个端点）
# =========================================================================== #
@router.post("/reports")
def generate_report(req: ReportGenerateRequest):
    """生成狩猎报告。"""
    try:
        g = _guard()
        if g is not None:
            return g
        rg = get_engines()["report_gen"]
        result = rg.generate_report(
            title=req.title, goal=req.goal, methods=req.methods,
            findings=req.findings, impact=req.impact,
            recommendations=req.recommendations, timeline=req.timeline,
            evidence_refs=req.evidence_refs, analyst=req.analyst,
        )
        return ok(result)
    except Exception as e:
        return fail(f"生成报告失败: {e}", 500)


@router.get("/reports")
def list_reports():
    """列出狩猎报告。"""
    try:
        g = _guard()
        if g is not None:
            return g
        rg = get_engines()["report_gen"]
        return ok(rg.list_reports())
    except Exception as e:
        return fail(f"报告列表失败: {e}", 500)


@router.get("/metrics")
def get_metrics():
    """获取狩猎度量指标。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mc = get_engines()["metrics_calc"]
        return ok(mc.calculate())
    except Exception as e:
        return fail(f"度量计算失败: {e}", 500)


@router.get("/metrics/definitions")
def metric_definitions():
    """度量指标定义。"""
    try:
        g = _guard()
        if g is not None:
            return g
        mc = get_engines()["metrics_calc"]
        return ok(mc.metrics_definitions())
    except Exception as e:
        return fail(f"度量定义失败: {e}", 500)


@router.get("/knowledge-base")
def knowledge_base(category: Optional[str] = Query(None)):
    """获取狩猎知识库。"""
    try:
        g = _guard()
        if g is not None:
            return g
        kb = get_engines()["kb"]
        result = {
            "tps": kb.list_tps(),
            "cases": kb.list_cases(),
            "best_practices": kb.list_practices(),
        }
        return ok(result)
    except Exception as e:
        return fail(f"知识库获取失败: {e}", 500)


@router.get("/maturity")
def maturity_assessment():
    """狩猎成熟度评估。"""
    try:
        g = _guard()
        if g is not None:
            return g
        ma = get_engines()["maturity"]
        return ok(ma.assess())
    except Exception as e:
        return fail(f"成熟度评估失败: {e}", 500)


@router.get("/dashboard")
def dashboard():
    """狩猎仪表盘数据。"""
    try:
        g = _guard()
        if g is not None:
            return g
    except Exception as e:
        return fail(f"获取仪表盘失败: {e}", 500)
    try:
        dash = get_engines()["dashboard"]
        return ok(dash.get_dashboard())
    except Exception as e:
        return fail(f"仪表盘数据失败: {e}", 500)
