# -*- coding: utf-8 -*-
"""fp_optimizer_pro_routes.py — 误报率优化Pro路由（方向1核心，25+端点）。

统一响应 {success, data, error}。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from fp_optimizer_pro import (
    get_rule_optimizer_pro, get_secondary_verifier,
    get_confidence_scorer, get_fp_filter_engine,
    get_fp_pro_dashboard,
)

router = APIRouter(prefix="/api/v1/fp-optimizer-pro", tags=["方向1 误报率优化Pro"])

_opt = get_rule_optimizer_pro()
_verifier = get_secondary_verifier()
_scorer = get_confidence_scorer()
_filter = get_fp_filter_engine()
_dash = get_fp_pro_dashboard()


def _ok(data: Any = None) -> Dict[str, Any]:
    return {"success": True, "data": data, "error": None}


def _err(msg: str) -> Dict[str, Any]:
    return {"success": False, "data": None, "error": msg}


# ---------- 请求模型 ----------
class AddFPSignatureReq(BaseModel):
    sig_id: str
    name: str
    pattern: str
    description: str = ""


class AddWhitelistReq(BaseModel):
    pattern: str
    reason: str = ""


class OptimizeReq(BaseModel):
    fp_per_rule: Dict[str, int] = Field(default_factory=dict)
    tp_per_rule: Dict[str, int] = Field(default_factory=dict)


class VerifyReq(BaseModel):
    finding: Dict[str, Any]
    target_url: str = ""
    param: str = ""
    method: str = "GET"


class BatchVerifyReq(BaseModel):
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    target_url: str = ""


class FilterReq(BaseModel):
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class AddFilterRuleReq(BaseModel):
    category: str = "custom"
    rule_id: str
    pattern: str
    description: str = ""
    action: str = "filter"


class AddWhitelistPathReq(BaseModel):
    path: str
    reason: str = ""
    prefix: bool = False


class RunProReq(BaseModel):
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    target_url: str = ""


# ============================================================
# 端点1-5：仪表盘/概览
# ============================================================
@router.get("/dashboard/overview", summary="仪表盘总览")
def dashboard_overview():
    return _ok(_dash.overview())


@router.get("/dashboard/before-after", summary="优化前后对比")
def before_after():
    return _ok(_dash.get_before_after_comparison())


@router.get("/dashboard/range-results", summary="10靶场验证结果")
def range_results():
    return _ok(_dash.get_range_results())


@router.get("/dashboard/report", summary="误报率优化报告")
def optimization_report():
    return _ok(_dash.get_optimization_report())


@router.get("/health", summary="健康检查")
def health():
    return _ok(_dash.health())


# ============================================================
# 端点6-10：规则优化器Pro
# ============================================================
@router.get("/rules", summary="获取规则集")
def get_rules():
    return _ok(_opt.get_rules())


@router.get("/rules/fp-signatures", summary="获取误报特征库")
def get_fp_signatures():
    return _ok({"signatures": _opt.get_fp_signatures()})


@router.post("/rules/fp-signatures", summary="添加误报特征")
def add_fp_signature(req: AddFPSignatureReq):
    sig = _opt.add_fp_signature(req.sig_id, req.name, req.pattern, req.description)
    return _ok(sig)


@router.post("/rules/optimize", summary="根据FP统计优化规则")
def optimize_rules(req: OptimizeReq):
    return _ok(_opt.optimize_rules(req.fp_per_rule, req.tp_per_rule))


@router.post("/rules/apply", summary="应用规则到finding列表")
def apply_rules(req: FilterReq):
    return _ok(_opt.apply_rules_to_findings(req.findings))


# ============================================================
# 端点11-15：白名单管理
# ============================================================
@router.get("/whitelist", summary="获取白名单")
def get_whitelist():
    return _ok({"whitelist": _opt.get_whitelist()})


@router.post("/whitelist", summary="添加白名单路径")
def add_whitelist(req: AddWhitelistReq):
    entry = _opt.add_whitelist(req.pattern, req.reason)
    return _ok(entry)


@router.get("/whitelist/check", summary="检查URL是否在白名单")
def check_whitelist(url: str = Query(...)):
    wl = _opt.is_whitelisted(url)
    return _ok({"url": url, "whitelisted": wl is not None, "match": wl})


# ============================================================
# 端点16-20：二次验证
# ============================================================
@router.get("/verifier/payloads", summary="获取验证payload库")
def get_verify_payloads():
    return _ok({"payloads": _verifier.get_verify_payloads()})


@router.post("/verifier/verify", summary="验证单个漏洞")
def verify_one(req: VerifyReq):
    result = _verifier.verify_vulnerability(
        req.finding, req.target_url, req.param, req.method
    )
    return _ok(result)


@router.post("/verifier/verify-batch", summary="批量验证漏洞")
def verify_batch(req: BatchVerifyReq):
    results = _verifier.verify_batch(req.findings, req.target_url)
    return _ok({"total": len(results), "results": results})


@router.get("/verifier/history", summary="验证历史")
def verify_history(limit: int = 50):
    return _ok({"items": _verifier.get_history(limit)})


@router.get("/verifier/stats", summary="验证统计")
def verify_stats():
    return _ok(_verifier.get_stats())


@router.post("/verifier/nuclei", summary="调用真实nuclei二次验证")
def nuclei_verify(target: str = Query(...),
                  templates: str = Query("http/cves")):
    result = _verifier.run_nuclei_verification(target, templates)
    if not result.get("success"):
        return _err(result.get("error", "nuclei验证失败"))
    return _ok(result)


# ============================================================
# 端点21-25：置信度评分
# ============================================================
@router.get("/scorer/levels", summary="置信度等级说明")
def scorer_levels():
    return _ok(_scorer.get_levels_info())


@router.get("/scorer/distribution", summary="置信度分布")
def scorer_distribution():
    return _ok(_scorer.get_distribution())


@router.post("/scorer/score-batch", summary="批量评分")
def scorer_batch(findings: List[Dict[str, Any]],
                 show_low: bool = Query(False)):
    _scorer.set_display_low(show_low)
    results = _scorer.score_batch(findings)
    return _ok({
        "total": len(results),
        "shown": len(_scorer.filter_by_display(results)),
        "all_results": results,
    })


@router.post("/scorer/toggle-low", summary="切换低置信度显示")
def toggle_low(show: bool = Query(...)):
    _scorer.set_display_low(show)
    return _ok({"display_low": show})


@router.post("/scorer/reset", summary="重置评分统计")
def scorer_reset():
    _scorer.reset()
    return _ok({"reset": True})


# ============================================================
# 端点26-30：FP过滤引擎
# ============================================================
@router.get("/filter/rules", summary="获取过滤规则库")
def filter_rules():
    return _ok(_filter.get_rules())


@router.post("/filter/rules", summary="添加过滤规则")
def add_filter_rule(req: AddFilterRuleReq):
    rule = _filter.add_rule(req.category, req.rule_id, req.pattern,
                            req.description, req.action)
    return _ok(rule)


@router.delete("/filter/rules/{rule_id}", summary="删除过滤规则")
def del_filter_rule(rule_id: str):
    ok = _filter.remove_rule(rule_id)
    return _ok({"deleted": ok, "rule_id": rule_id})


@router.post("/filter/run", summary="运行过滤流水线")
def run_filter(req: FilterReq):
    return _ok(_filter.filter_findings(req.findings))


@router.get("/filter/stats", summary="过滤统计")
def filter_stats():
    return _ok(_filter.get_stats())


@router.get("/filter/log", summary="过滤日志")
def filter_log(limit: int = 50):
    return _ok({"items": _filter.get_filter_log(limit)})


# ============================================================
# 端点31：运行完整Pro流水线
# ============================================================
@router.post("/run-pro", summary="运行完整Pro优化流水线")
def run_pro(req: RunProReq):
    result = _dash.run_pro_optimization(req.findings, req.target_url)
    return _ok(result)


@router.get("/run-pro/history", summary="Pro优化运行历史")
def run_pro_history(limit: int = 20):
    return _ok({"items": _dash.get_optimization_runs(limit)})
