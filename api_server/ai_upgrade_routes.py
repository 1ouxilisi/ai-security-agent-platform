# -*- coding: utf-8 -*-
"""
api_server/ai_upgrade_routes.py — 方向2：AI 能力大升级 REST API。
路由前缀: /api/v1/ai-upgrade
统一响应: {"success": bool, "data": ..., "error": ...}
覆盖: LLM状态/漏洞智能分析/报告生成/智能问答/攻击链规划/SRC助手/决策日志。
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ai-upgrade", tags=["AI能力大升级"])

_MOD_AVAILABLE = False
try:
    from ai_upgrade import (
        get_enhanced_llm, get_decision_log, clear_decision_log,
        get_vuln_analyzer, get_report_writer, get_smart_qa, set_context,
        get_src_assistant, get_ai_dashboard,
    )
    _MOD_AVAILABLE = True
    logger.info("ai_upgrade_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("ai_upgrade_routes: load failed: %s", e)


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
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
        return fail("AI 升级模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class VulnReq(BaseModel):
    id: Optional[str] = None
    name: str
    type: Optional[str] = None
    detail: Optional[str] = ""
    requires_auth: Optional[bool] = None
    has_poc: Optional[bool] = None
    is_internal: Optional[bool] = None


class BatchVulnReq(BaseModel):
    vulns: List[VulnReq] = Field(default_factory=list)


class ReportReq(BaseModel):
    target: str
    vulns: List[VulnReq] = Field(default_factory=list)
    author: str = "AI 渗透助手"
    template: str = "standard"


class QAReq(BaseModel):
    question: str
    user_id: str = "default"


class ContextReq(BaseModel):
    target: str
    vulns: List[VulnReq] = Field(default_factory=list)


class ChainReq(BaseModel):
    target: str
    findings: List[VulnReq] = Field(default_factory=list)


class AdjustReq(BaseModel):
    failure_reason: str


class TargetReq(BaseModel):
    domain: str


class SubmissionReq(BaseModel):
    domain: str
    vuln: Dict[str, Any] = Field(default_factory=dict)
    platform: str = "butian"


# --------------------------------------------------------------------------- #
# 0. 聚合仪表盘 & LLM 状态
# --------------------------------------------------------------------------- #
@router.get("/overview")
def ai_overview():
    g = _guard()
    if g:
        return g
    return ok(get_ai_dashboard().overview())


@router.get("/llm/status")
def llm_status():
    g = _guard()
    if g:
        return g
    return ok(get_enhanced_llm().status())


@router.post("/llm/refresh")
def llm_refresh():
    g = _guard()
    if g:
        return g
    return ok(get_enhanced_llm().refresh())


@router.get("/llm/test")
def llm_test():
    g = _guard()
    if g:
        return g
    el = get_enhanced_llm()
    res = el.simple_chat if hasattr(el, "simple_chat") else None
    from llm_integration import get_llm_client
    try:
        return ok(get_llm_client().test_connection())
    except Exception as e:  # noqa: BLE001
        return ok({"success": False, "error": str(e), "error_code": "error"})


@router.get("/decisions")
def list_decisions(limit: int = Query(50, ge=1, le=200)):
    g = _guard()
    if g:
        return g
    return ok(get_decision_log(limit=limit))


@router.delete("/decisions")
def clear_decisions():
    g = _guard()
    if g:
        return g
    return ok({"cleared": clear_decision_log()})


# --------------------------------------------------------------------------- #
# 1. 漏洞智能分析
# --------------------------------------------------------------------------- #
@router.post("/vuln/analyze")
def analyze_one(v: VulnReq):
    g = _guard()
    if g:
        return g
    return ok(get_vuln_analyzer().analyze_one(v.dict()))


@router.post("/vuln/analyze-batch")
def analyze_batch(req: BatchVulnReq):
    g = _guard()
    if g:
        return g
    return ok(get_vuln_analyzer().analyze_batch([v.dict() for v in req.vulns]))


@router.get("/vuln/knowledge-base")
def vuln_kb():
    g = _guard()
    if g:
        return g
    from ai_upgrade.vuln_analyzer import _RULE_KB
    return ok({k: {"cwe": v["cwe"], "owasp": v["owasp"],
                    "base_score": v["base_score"], "level": v["level"]}
               for k, v in _RULE_KB.items()})


# --------------------------------------------------------------------------- #
# 2. 报告自动生成
# --------------------------------------------------------------------------- #
@router.post("/report/generate")
def gen_report(req: ReportReq):
    g = _guard()
    if g:
        return g
    rw = get_report_writer()
    report = rw.generate(req.target, [v.dict() for v in req.vulns],
                         author=req.author, template=req.template)
    return ok(report)


@router.get("/report/list")
def list_reports():
    g = _guard()
    if g:
        return g
    return ok(get_report_writer().list_reports())


@router.get("/report/{rid}")
def get_report(rid: str):
    g = _guard()
    if g:
        return g
    r = get_report_writer().get_report(rid)
    if not r:
        return fail("report not found", 404)
    return ok(r)


@router.get("/report/{rid}/markdown")
def export_md(rid: str):
    g = _guard()
    if g:
        return g
    md = get_report_writer().export_markdown(rid)
    if md is None:
        return fail("report not found", 404)
    return ok({"report_id": rid, "markdown": md})


# --------------------------------------------------------------------------- #
# 3. 智能问答
# --------------------------------------------------------------------------- #
@router.post("/qa/ask")
def qa_ask(req: QAReq):
    g = _guard()
    if g:
        return g
    return ok(get_smart_qa().ask(req.question, user_id=req.user_id))


@router.get("/qa/history")
def qa_history(limit: int = Query(20, ge=1, le=200)):
    g = _guard()
    if g:
        return g
    return ok(get_smart_qa().history(limit=limit))


@router.get("/qa/suggestions")
def qa_suggestions():
    g = _guard()
    if g:
        return g
    return ok({"suggestions": get_smart_qa().suggestions()})


@router.post("/qa/context")
def qa_set_context(req: ContextReq):
    g = _guard()
    if g:
        return g
    set_context(req.target, [v.dict() for v in req.vulns])
    return ok({"target": req.target, "vulns": len(req.vulns),
               "msg": "上下文已更新"})


# --------------------------------------------------------------------------- #
# 4. 智能攻击链规划
# --------------------------------------------------------------------------- #
@router.post("/chain/plan")
def plan_chain(req: ChainReq):
    g = _guard()
    if g:
        return g
    return ok(get_ai_dashboard().plan_chain(
        req.target, [f.dict() for f in req.findings]))


@router.post("/chain/{chain_id}/step/{step_index}/adjust")
def adjust_step(chain_id: str, step_index: int, req: AdjustReq):
    g = _guard()
    if g:
        return g
    res = get_ai_dashboard().adjust_step(chain_id, step_index, req.failure_reason)
    if not res.get("success"):
        return fail(res.get("error", "adjust failed"), 400)
    return ok(res)


@router.get("/chain/list")
def list_chains():
    g = _guard()
    if g:
        return g
    return ok(get_ai_dashboard().list_chains())


@router.get("/chain/stages")
def chain_stages():
    g = _guard()
    if g:
        return g
    from ai_upgrade.ai_upgrade_dashboard import CHAIN_STAGES
    return ok({"stages": CHAIN_STAGES})


# --------------------------------------------------------------------------- #
# 5. AI 辅助挖 SRC
# --------------------------------------------------------------------------- #
@router.post("/src/analyze-target")
def src_analyze(req: TargetReq):
    g = _guard()
    if g:
        return g
    return ok(get_src_assistant().analyze_target(req.domain))


@router.get("/src/targets")
def src_targets():
    g = _guard()
    if g:
        return g
    return ok(get_src_assistant().list_targets())


@router.post("/src/write-submission")
def src_write(req: SubmissionReq):
    g = _guard()
    if g:
        return g
    return ok(get_src_assistant().write_submission(
        req.domain, req.vuln, platform=req.platform))


@router.get("/src/submissions")
def src_submissions():
    g = _guard()
    if g:
        return g
    return ok(get_src_assistant().list_submissions())


@router.get("/src/platforms")
def src_platforms():
    g = _guard()
    if g:
        return g
    return ok({"platforms": [
        {"id": "butian", "name": "补天", "format": "国内 CNVD 风格"},
        {"id": "hackerone", "name": "HackerOne", "format": "英文 Bug Bounty"},
    ]})
