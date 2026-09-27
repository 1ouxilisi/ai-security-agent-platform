# -*- coding: utf-8 -*-
"""fp_validation_routes.py — 误报率验证做实路由（方向1，20+端点）。

统一响应 {success, data, error}。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from fp_validation import (
    get_repository, get_runner, get_calculator, get_optimizer,
    get_report_generator, get_dashboard,
)

router = APIRouter(prefix="/api/v1/fp-validation", tags=["方向1 误报率验证做实"])

_repo = get_repository()
_runner = get_runner()
_calc = get_calculator()
_opt = get_optimizer()
_rpt = get_report_generator()
_dash = get_dashboard()


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return [_clean(i) for i in obj]
    return obj


def _ok(data: Any = None) -> Dict[str, Any]:
    return {"success": True, "data": _clean(data), "error": None}


def _err(msg: str) -> Dict[str, Any]:
    return {"success": False, "data": None, "error": msg}


# ---------- 请求模型 ----------
class ScanOneReq(BaseModel):
    range_id: str
    timeout: int = 300


class OptimizeReq(BaseModel):
    fp_per_rule: Dict[str, int] = Field(default_factory=dict)
    tp_per_rule: Dict[str, int] = Field(default_factory=dict)
    fn_per_rule: Dict[str, int] = Field(default_factory=dict)


class MetricReq(BaseModel):
    tp: int = 0
    fp: int = 0
    fn: int = 0
    known_total: int = 0
    detected_total: int = 0


# ---------- 仪表盘 / 概览 ----------
@router.get("/dashboard/overview")
def dashboard_overview():
    return _ok(_dash.overview())


@router.get("/tools-status")
def tools_status():
    return _ok(_runner.tools_status())


# ---------- 靶场知识库 ----------
@router.get("/ranges")
def list_ranges():
    return _ok(_repo.list_ranges())


@router.get("/ranges/{range_id}")
def get_range(range_id: str):
    r = _repo.get(range_id)
    if not r:
        return _err(f"range not found: {range_id}")
    return _ok(r)


@router.get("/ranges/{range_id}/known-vulns")
def known_vulns(range_id: str):
    return _ok(_repo.get_known_vulns(range_id))


@router.get("/ranges/{range_id}/negative-control")
def is_negative(range_id: str):
    return _ok({"range_id": range_id,
                "is_negative_control": _repo.is_negative_control(range_id)})


# ---------- 一键靶场验证 ----------
@router.post("/run-all")
def run_all(timeout: int = 300):
    res = _runner.run_all(timeout=timeout)
    if not res.get("success"):
        return _err(res.get("error", "run_all failed"))
    return _ok(res)


@router.post("/scan-one")
def scan_one(req: ScanOneReq):
    res = _runner.scan_range(req.range_id, timeout=req.timeout)
    if not res.get("success"):
        return _err(res.get("error", "scan_one failed"))
    return _ok(res["record"])


@router.get("/history")
def history():
    return _ok(_runner.history())


@router.get("/latest")
def latest():
    return _ok(_runner.latest())


# ---------- 指标计算 ----------
@router.post("/metrics/compute")
def compute_metrics(req: MetricReq):
    return _ok(_calc.compute(req.tp, req.fp, req.fn,
                             req.known_total, req.detected_total))


@router.post("/metrics/aggregate")
def aggregate(per_range: List[Dict[str, Any]]):
    return _ok(_calc.aggregate(per_range))


# ---------- 规则优化 ----------
@router.get("/rules")
def get_rules():
    return _ok(_opt.get_rules())


@router.post("/rules/optimize")
def optimize(req: OptimizeReq):
    snap = _opt.optimize(req.fp_per_rule, req.tp_per_rule, req.fn_per_rule)
    return _ok(snap)


@router.post("/rules/reset")
def reset_rules():
    _opt.reset()
    return _ok({"reset": True})


@router.post("/rules/apply")
def apply_rule(rule_type: str, finding: Dict[str, Any]):
    keep = _opt.apply_to_finding(rule_type, finding)
    return _ok({"keep": keep, "rule_type": rule_type})


# ---------- 报告 ----------
@router.get("/reports/list")
def list_reports():
    return _ok(_dash.list_reports())


@router.get("/reports/{name}")
def get_report(name: str):
    r = _dash.get_report(name)
    if not r:
        return _err(f"report not found: {name}")
    return _ok(r)


@router.post("/reports/generate")
def generate_report(aggregate: Dict[str, Any],
                    per_range: List[Dict[str, Any]],
                    before_metrics: Optional[Dict[str, Any]] = None,
                    filename: Optional[str] = None):
    out = _rpt.generate(aggregate, per_range, before_metrics, filename)
    return _ok(out)


# ---------- 靶场匹配（用于前端手动标注） ----------
@router.post("/match/{range_id}")
def match(range_id: str, findings: List[Dict[str, Any]]):
    return _ok(_repo.match_scan_to_known(range_id, findings))


# ---------- 规则版本/健康 ----------
@router.get("/health")
def health():
    return _ok({
        "package": "fp_validation",
        "ranges": len(_repo.list_ranges()),
        "history": len(_runner.history()),
        "rules_snapshots": len(_opt.get_rules()["history"]),
    })


@router.get("/target-list")
def target_list():
    """10 靶场 ID + URL 列表，供一键验证按钮直接调用。"""
    return _ok([
        {"id": r["id"], "name": r["name"], "url": r["url"],
         "is_negative_control": r.get("is_negative_control", False)}
        for r in _repo.list_ranges()
    ])
