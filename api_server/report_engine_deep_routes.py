# -*- coding: utf-8 -*-
"""
report_engine_deep_routes.py — 专业级报告引擎深化 REST API（第20轮·方向4）。

路由前缀: /api/v1/report-engine-deep
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/report-engine-deep", tags=["报告引擎做深"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from report_engine_deep.template_system import (
        get_template_system, REPORT_TYPE_TEMPLATES, INDUSTRY_TEMPLATES,
        FRAMEWORK_TEMPLATES, STRUCTURE_TEMPLATES, LANGUAGE_PACKS,
    )
    from report_engine_deep.content_generator import get_content_generator, cvss_base
    from report_engine_deep.chart_visualization import get_chart_visualization
    from report_engine_deep.quality_review import (
        get_quality_review, QUALITY_CHECKS, REVIEW_STAGES, STAGE_LABELS,
    )
    from report_engine_deep.export_distribution import (
        get_exporter, SUPPORTED_FORMATS,
    )
    from report_engine_deep.report_dashboard import get_dashboard
    _MOD_AVAILABLE = True
    logger.info("report_engine_deep_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("report_engine_deep_routes: load failed: %s", e)


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
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理控制字符，保证 UTF-8 安全。"""
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(i) for i in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("报告引擎做深模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ComposeReq(BaseModel):
    report_type: str = "penetration_test"
    industry: str = "internet"
    frameworks: List[str] = Field(default_factory=lambda: ["owasp_top10_2021"])
    language: str = "zh_CN"
    org: str = "default"


class BrandReq(BaseModel):
    org: str = "default"
    patch: Dict[str, Any] = Field(default_factory=dict)


class VulnsReq(BaseModel):
    project_meta: Dict[str, Any] = Field(default_factory=dict)
    vulns: List[Dict[str, Any]] = Field(default_factory=list)
    assets: List[Dict[str, Any]] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=lambda: ["owasp_top10_2021"])


class SingleVulnReq(BaseModel):
    vuln: Dict[str, Any] = Field(default_factory=dict)


class CvssReq(BaseModel):
    av: str = "N"
    ac: str = "L"
    pr: str = "N"
    ui: str = "N"
    scope: str = "U"
    ci: str = "H"
    ii: str = "H"
    ai: str = "H"


class ReviewTransReq(BaseModel):
    action: str = "approve"
    user: str = "reviewer"
    note: str = ""


class VersionCommitReq(BaseModel):
    content: Dict[str, Any] = Field(default_factory=dict)
    user: str = "author"
    message: str = ""


class VersionDiffReq(BaseModel):
    v1: str
    v2: str


class ExportReq(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    watermark: str = "机密"


class DistributeReq(BaseModel):
    report_id: str
    channels: List[str] = Field(default_factory=lambda: ["email", "portal"])
    recipients: List[str] = Field(default_factory=lambda: ["security@example.com"])
    expiry_days: int = 7


class WizardReq(BaseModel):
    report_type: str = "penetration_test"
    industry: str = "internet"
    template_id: str = "TPL-PENTEST-V2"
    client: str = "示例客户"


class TemplateReq(BaseModel):
    name: str = "新模板"
    category: str = "penetration_test"
    description: str = ""


class AutomationReq(BaseModel):
    name: str = "月度报告自动化"
    trigger: str = "schedule"
    template_id: str = "TPL-PENTEST-V2"
    schedule: str = "0 8 * * 1"
    recipients: List[str] = Field(default_factory=list)


class FeedbackReq(BaseModel):
    rating: int = 5
    comment: str = ""


# =========================================================================== #
# 1. 模板体系
# =========================================================================== #
@router.get("/template/report-types", summary="报告类型模板")
def tpl_report_types():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_template_system().list_report_types())
    except Exception as e:
        logger.exception("tpl_report_types: %s", e)
        return fail(str(e))


@router.get("/template/industries", summary="行业模板")
def tpl_industries():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_template_system().list_industries())
    except Exception as e:
        return fail(str(e))


@router.get("/template/frameworks", summary="标准框架模板")
def tpl_frameworks():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_template_system().list_frameworks())
    except Exception as e:
        return fail(str(e))


@router.get("/template/structure", summary="报告结构模板")
def tpl_structure():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_template_system().list_structure())
    except Exception as e:
        return fail(str(e))


@router.get("/template/languages", summary="多语言模板")
def tpl_languages():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_template_system().list_languages())
    except Exception as e:
        return fail(str(e))


@router.put("/template/brand", summary="品牌定制")
def tpl_brand(req: BrandReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_template_system().update_brand(req.org, req.patch))
    except Exception as e:
        return fail(str(e))


@router.post("/template/compose", summary="组合报告蓝图")
def tpl_compose(req: ComposeReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_template_system().compose_blueprint(
            req.report_type, req.industry, req.frameworks, req.language, req.org))
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 2. 内容生成
# =========================================================================== #
@router.post("/content/exec-summary", summary="执行摘要生成")
def cg_exec_summary(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        gen = get_content_generator()
        return ok(gen.exec_summary(req.project_meta, req.vulns, req.assets))
    except Exception as e:
        return fail(str(e))


@router.post("/content/vuln-detail", summary="漏洞详情生成")
def cg_vuln_detail(req: SingleVulnReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_content_generator().vuln_detail(req.vuln))
    except Exception as e:
        return fail(str(e))


@router.post("/content/risk-rating", summary="风险评级计算")
def cg_risk_rating(req: SingleVulnReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_content_generator().risk_rating(req.vuln))
    except Exception as e:
        return fail(str(e))


@router.post("/content/cvss", summary="CVSS v3.1 计算")
def cg_cvss(req: CvssReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(cvss_base(req.av, req.ac, req.pr, req.ui, req.scope,
                            req.ci, req.ii, req.ai))
    except Exception as e:
        return fail(str(e))


@router.post("/content/remediation", summary="修复建议生成")
def cg_remediation(req: SingleVulnReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_content_generator().remediation(req.vuln))
    except Exception as e:
        return fail(str(e))


@router.post("/content/trends", summary="趋势统计生成")
def cg_trends(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_content_generator().trend_stats(req.vulns, req.project_meta.get("history")))
    except Exception as e:
        return fail(str(e))


@router.post("/content/compliance", summary="合规映射生成")
def cg_compliance(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_content_generator().compliance_mapping(req.vulns, req.frameworks))
    except Exception as e:
        return fail(str(e))


@router.post("/content/full", summary="一站式生成完整报告内容")
def cg_full(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("content_full")
        try:
            result = get_content_generator().generate_full(
                req.project_meta, req.vulns, req.assets, req.frameworks)
            _finish_task(task_id, result)
        except Exception as e:
            _finish_task(task_id, None, str(e))
        return ok({"task_id": task_id, "status": _get_task(task_id)["status"]})
    except Exception as e:
        return fail(str(e))


@router.get("/task/{task_id}", summary="查询异步任务")
def task_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 3. 图表可视化
# =========================================================================== #
@router.post("/chart/stats", summary="漏洞统计图表")
def ch_stats(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_chart_visualization().stats_charts(req.vulns))
    except Exception as e:
        return fail(str(e))


@router.post("/chart/risk-matrix", summary="5x5 风险矩阵")
def ch_risk_matrix(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_chart_visualization().risk_matrix(req.vulns))
    except Exception as e:
        return fail(str(e))


@router.post("/chart/attack-chain", summary="攻击链图")
def ch_attack_chain(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_chart_visualization().attack_chain(req.vulns))
    except Exception as e:
        return fail(str(e))


@router.post("/chart/topology", summary="网络拓扑图")
def ch_topology(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_chart_visualization().network_topology(req.assets, req.vulns))
    except Exception as e:
        return fail(str(e))


@router.post("/chart/timeline", summary="时间线图")
def ch_timeline(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_chart_visualization().timeline(
            req.project_meta.get("events"),
            req.project_meta.get("start_date"),
            req.project_meta.get("end_date")))
    except Exception as e:
        return fail(str(e))


@router.post("/chart/table", summary="数据表格规格")
def ch_table(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_chart_visualization().table_spec(req.vulns, "vulns"))
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 4. 质量审核
# =========================================================================== #
@router.get("/quality/checklist", summary="质量检查项库(100+)")
def q_checklist():
    try:
        g = _guard()
        if g:
            return g
        return ok({"total": len(QUALITY_CHECKS), "items": QUALITY_CHECKS})
    except Exception as e:
        return fail(str(e))


@router.post("/quality/check", summary="报告质量检查")
def q_check(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        rep = {"vulnerabilities": req.vulns, "sections": req.project_meta.get("sections", []),
               "desensitized": req.project_meta.get("desensitized", True)}
        return ok(get_quality_review().quality_check(rep))
    except Exception as e:
        return fail(str(e))


@router.post("/quality/dedup", summary="漏洞去重合并")
def q_dedup(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_quality_review().dedup_vulns(req.vulns))
    except Exception as e:
        return fail(str(e))


@router.post("/quality/false-positive", summary="误报检测")
def q_fp(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_quality_review().false_positive_detect(req.vulns))
    except Exception as e:
        return fail(str(e))


@router.post("/quality/review/start", summary="启动审核工作流")
def q_review_start(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        rid = f"RPT-{uuid.uuid4().hex[:6].upper()}"
        doc = get_quality_review().start_review(rid, {"vulns": req.vulns})
        return ok({"report_id": rid, "stages": REVIEW_STAGES,
                   "stage_labels": STAGE_LABELS, "doc": doc})
    except Exception as e:
        return fail(str(e))


@router.post("/quality/review/{report_id}", summary="审核流转/评论")
def q_review_transition(report_id: str, req: ReviewTransReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_quality_review().transition(report_id, req.action, req.user, req.note))
    except Exception as e:
        return fail(str(e))


@router.post("/quality/version/commit", summary="提交版本")
def q_version_commit(req: VersionCommitReq):
    try:
        g = _guard()
        if g:
            return g
        rid = req.content.get("report_id", f"RPT-{uuid.uuid4().hex[:6].upper()}")
        return ok(get_quality_review().commit_version(rid, req.content, req.user, req.message))
    except Exception as e:
        return fail(str(e))


@router.get("/quality/version/{report_id}", summary="版本历史")
def q_version_list(report_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_quality_review().list_versions(report_id))
    except Exception as e:
        return fail(str(e))


@router.post("/quality/score", summary="报告评分")
def q_score(req: VulnsReq):
    try:
        g = _guard()
        if g:
            return g
        rep = {"vulnerabilities": req.vulns, "sections": req.project_meta.get("sections", [])}
        qr = get_quality_review()
        check = qr.quality_check(rep)
        return ok(qr.score_report(rep, check))
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 5. 导出与分发
# =========================================================================== #
@router.get("/export/formats", summary="支持的导出格式")
def ex_formats():
    try:
        g = _guard()
        if g:
            return g
        return ok({"formats": SUPPORTED_FORMATS})
    except Exception as e:
        return fail(str(e))


@router.post("/export/pdf", summary="导出 PDF")
def ex_pdf(req: ExportReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_exporter().export_pdf(req.payload, req.watermark))
    except Exception as e:
        return fail(str(e))


@router.post("/export/word", summary="导出 Word")
def ex_word(req: ExportReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_exporter().export_word(req.payload))
    except Exception as e:
        return fail(str(e))


@router.post("/export/excel", summary="导出 Excel")
def ex_excel(req: ExportReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_exporter().export_excel(req.payload))
    except Exception as e:
        return fail(str(e))


@router.post("/export/html", summary="导出 HTML")
def ex_html(req: ExportReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_exporter().export_html(req.payload))
    except Exception as e:
        return fail(str(e))


@router.post("/export/json", summary="导出 JSON")
def ex_json(req: ExportReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_exporter().export_json(req.payload))
    except Exception as e:
        return fail(str(e))


@router.post("/export/xml", summary="导出 XML")
def ex_xml(req: ExportReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_exporter().export_xml(req.payload))
    except Exception as e:
        return fail(str(e))


@router.post("/export/distribute", summary="报告分发")
def ex_distribute(req: DistributeReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_exporter().distribute(req.report_id, req.channels,
                                            req.recipients, req.expiry_days))
    except Exception as e:
        return fail(str(e))


@router.post("/export/track/{link_id}", summary="分发追踪")
def ex_track(link_id: str, action: str = Query("view")):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_exporter().track(link_id, action))
    except Exception as e:
        return fail(str(e))


@router.get("/export/logs", summary="分发日志")
def ex_logs():
    try:
        g = _guard()
        if g:
            return g
        return ok({"logs": get_exporter().distribution_logs(),
                   "links": get_exporter().list_links()})
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 6. 报告管理控制台
# =========================================================================== #
@router.get("/dashboard/reports", summary="报告库列表")
def db_reports(keyword: Optional[str] = Query(None),
               status: Optional[str] = Query(None),
               report_type: Optional[str] = Query(None),
               sort_by: str = "created_at"):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().list_reports(keyword, status, report_type, sort_by))
    except Exception as e:
        return fail(str(e))


@router.post("/dashboard/reports/{rid}/favorite", summary="收藏/取消")
def db_favorite(rid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().toggle_favorite(rid))
    except Exception as e:
        return fail(str(e))


@router.post("/dashboard/reports/{rid}/archive", summary="归档")
def db_archive(rid: str, archived: bool = True):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().archive_report(rid, archived))
    except Exception as e:
        return fail(str(e))


@router.post("/dashboard/wizard/start", summary="生成向导-启动")
def db_wizard_start(req: WizardReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().wizard_start(req.report_type, req.industry,
                                              req.template_id, req.client))
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/wizard/{rid}/preview", summary="生成向导-预览")
def db_wizard_preview(rid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().wizard_preview(rid))
    except Exception as e:
        return fail(str(e))


@router.post("/dashboard/wizard/{rid}/generate", summary="生成向导-生成")
def db_wizard_generate(rid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().wizard_generate(rid))
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/templates", summary="模板管理列表")
def db_templates():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().list_templates())
    except Exception as e:
        return fail(str(e))


@router.post("/dashboard/templates", summary="创建模板")
def db_create_template(req: TemplateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().create_template(req.name, req.category, req.description))
    except Exception as e:
        return fail(str(e))


@router.post("/dashboard/templates/{tid}/clone", summary="克隆模板")
def db_clone_template(tid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().clone_template(tid))
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/metrics", summary="报告指标统计")
def db_metrics():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().metrics())
    except Exception as e:
        return fail(str(e))


@router.post("/dashboard/portal/login", summary="客户门户登录")
def db_portal_login(customer_id: str = "CUST-001"):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().portal_login(customer_id))
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/portal/{customer_id}/reports", summary="客户门户报告列表")
def db_portal_reports(customer_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().portal_reports(customer_id))
    except Exception as e:
        return fail(str(e))


@router.post("/dashboard/portal/{customer_id}/feedback", summary="客户反馈")
def db_portal_feedback(customer_id: str, req: FeedbackReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().portal_feedback(customer_id, req.rating, req.comment))
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/automation", summary="自动化规则列表")
def db_automation():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().list_automation_rules())
    except Exception as e:
        return fail(str(e))


@router.post("/dashboard/automation", summary="创建自动化规则")
def db_create_automation(req: AutomationReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().create_automation_rule(
            req.name, req.trigger, req.template_id, req.schedule, req.recipients))
    except Exception as e:
        return fail(str(e))


@router.post("/dashboard/automation/{rid}/run", summary="触发自动化规则")
def db_run_automation(rid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().run_automation_rule(rid))
    except Exception as e:
        return fail(str(e))
