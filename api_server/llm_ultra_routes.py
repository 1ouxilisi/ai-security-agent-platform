# -*- coding: utf-8 -*-
"""llm_ultra_routes.py — LLM极致优化路由（方向3，25+端点）。

统一响应 {success, data, error}。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from llm_ultra import (
    get_prompt_master, get_context_memory,
    get_multi_turn_chat, get_vuln_knowledge_base,
    get_report_polisher, get_llm_ultra_dashboard,
)

router = APIRouter(prefix="/api/v1/llm-ultra", tags=["方向3 LLM极致优化"])

_prompts = get_prompt_master()
_memory = get_context_memory()
_chat = get_multi_turn_chat()
_kb = get_vuln_knowledge_base()
_polisher = get_report_polisher()
_dash = get_llm_ultra_dashboard()


def _ok(data: Any = None) -> Dict[str, Any]:
    return {"success": True, "data": data, "error": None}


def _err(msg: str) -> Dict[str, Any]:
    return {"success": False, "data": None, "error": msg}


# ---------- 请求模型 ----------
class ChatReq(BaseModel):
    message: str
    session_id: str = "default"
    context: Optional[Dict[str, Any]] = None


class NewSessionReq(BaseModel):
    session_id: str
    topic: str = ""


class CVEQueryReq(BaseModel):
    cve_id: str


class KBSearchReq(BaseModel):
    keyword: str


class KBCorrelateReq(BaseModel):
    vuln_type: str
    tech_stack: str = ""


class PolishReq(BaseModel):
    content: str
    report_type: str = "generic"


class ExecutiveSummaryReq(BaseModel):
    vulns: List[Dict[str, Any]] = Field(default_factory=list)
    target: str = ""


class CustomPromptReq(BaseModel):
    key: str
    name: str
    role: str
    task: str
    output_format: str
    rules: List[str] = Field(default_factory=list)


# ============================================================
# 端点1-5：仪表盘/总览
# ============================================================
@router.get("/dashboard/overview", summary="仪表盘总览")
def dashboard_overview():
    return _ok(_dash.overview())


@router.get("/dashboard/features", summary="功能列表")
def feature_list():
    return _ok(_dash.feature_list())


@router.get("/dashboard/prompt-showcase", summary="Prompt优化对比展示")
def prompt_showcase():
    return _ok(_dash.prompt_showcase())


@router.get("/health", summary="健康检查")
def health():
    return _ok(_dash.health())


@router.get("/demo", summary="LLM极致功能一键演示")
def demo(question: str = "这个SQL注入漏洞严重吗？怎么修？"):
    return _ok({
        "chat_demo": _dash.chat_demo(question),
        "kb_demo": _dash.kb_demo("rce"),
        "polisher_demo": _dash.polisher_demo(),
    })


# ============================================================
# 端点6-10：Prompt大师
# ============================================================
@router.get("/prompts", summary="所有Prompt模板列表")
def list_prompts():
    return _ok({"prompts": _prompts.list_prompts()})


@router.get("/prompts/{key}", summary="获取单个Prompt详情")
def get_prompt(key: str):
    p = _prompts.get_prompt(key)
    if not p:
        return _err(f"未找到Prompt: {key}")
    return _ok(p)


@router.get("/prompts/{key}/build", summary="构建完整Prompt")
def build_prompt(key: str, context: str = "", extra: str = ""):
    return _ok({
        "prompt": _prompts.build_prompt(key, context, extra),
    })


@router.get("/prompts/{key}/compare", summary="新旧Prompt对比")
def compare_prompt(key: str):
    r = _prompts.compare_prompts(key)
    if "error" in r:
        return _err(r["error"])
    return _ok(r)


@router.post("/prompts/custom", summary="添加自定义Prompt")
def add_custom_prompt(req: CustomPromptReq):
    p = _prompts.add_custom_prompt(req.key, req.name, req.role,
                                   req.task, req.output_format, req.rules)
    return _ok(p)


@router.get("/prompts/stats", summary="Prompt使用统计")
def prompt_stats():
    return _ok(_prompts.get_stats())


# ============================================================
# 端点11-15：上下文记忆
# ============================================================
@router.post("/memory/session", summary="创建新会话")
def create_session(req: NewSessionReq):
    return _ok(_memory.create_session(req.session_id, {"topic": req.topic}))


@router.get("/memory/sessions", summary="列出所有会话")
def list_sessions():
    return _ok({"sessions": _memory.list_sessions()})


@router.get("/memory/sessions/{sid}", summary="获取会话详情")
def get_session(sid: str):
    s = _memory.get_session(sid)
    if not s:
        return _err(f"会话不存在: {sid}")
    return _ok(s)


@router.get("/memory/sessions/{sid}/history", summary="获取会话历史")
def get_session_history(sid: str, limit: int = 20):
    return _ok({"messages": _memory.get_history(sid, limit)})


@router.delete("/memory/sessions/{sid}", summary="清除会话")
def clear_session(sid: str):
    return _ok({"cleared": _memory.clear_session(sid)})


@router.post("/memory/scan-result", summary="保存扫描结果到记忆")
def save_scan(target: str = Query(...),
              scan_data: Dict[str, Any] = ...):
    return _ok(_memory.save_scan_result(target, scan_data))


@router.get("/memory/scan-history", summary="获取扫描历史")
def scan_history(target: str = "", limit: int = 20):
    return _ok({"items": _memory.get_scan_history(target or None, limit)})


@router.get("/memory/stats", summary="记忆引擎统计")
def memory_stats():
    return _ok(_memory.get_stats())


# ============================================================
# 端点16-20：多轮对话
# ============================================================
@router.post("/chat/start", summary="开启新对话")
def start_chat(req: NewSessionReq):
    return _ok(_chat.start_new_session(req.session_id, req.topic))


@router.post("/chat/send", summary="发送消息进行多轮对话")
def chat_send(req: ChatReq):
    return _ok(_chat.chat(req.session_id, req.message, req.context))


@router.get("/chat/history", summary="对话历史")
def chat_history(session_id: str = "", limit: int = 50):
    return _ok({"items": _chat.chat_history(session_id or None, limit)})


@router.get("/chat/suggestions", summary="获取追问建议")
def chat_suggestions(vuln_type: str = "default"):
    from .multi_turn_chat import FOLLOWUP_SUGGESTIONS
    return _ok({"suggestions": FOLLOWUP_SUGGESTIONS.get(
        vuln_type, FOLLOWUP_SUGGESTIONS["default"])})


@router.get("/chat/stats", summary="对话统计")
def chat_stats():
    return _ok(_chat.get_stats())


# ============================================================
# 端点21-25：漏洞知识库
# ============================================================
@router.get("/kb/cve/{cve_id}", summary="查询CVE详情")
def query_cve(cve_id: str):
    r = _kb.query_cve(cve_id)
    if not r:
        return _err(f"未找到CVE: {cve_id}")
    return _ok(r)


@router.get("/kb/search", summary="关键词搜索漏洞")
def kb_search(keyword: str = Query(...)):
    return _ok({"results": _kb.search_by_keyword(keyword)})


@router.post("/kb/correlate", summary="自动关联已知漏洞")
def kb_correlate(req: KBCorrelateReq):
    return _ok({
        "correlations": _kb.auto_correlate(req.vuln_type, req.tech_stack),
    })


@router.get("/kb/exploit/{cve_id}", summary="获取Exploit-DB信息")
def get_exploit(cve_id: str):
    return _ok(_kb.get_exploit_info(cve_id))


@router.get("/kb/list", summary="列出所有知识库条目")
def kb_list():
    return _ok({"items": _kb.list_all()})


@router.post("/kb/enrich", summary="AI分析时自动增强漏洞信息")
def kb_enrich(vuln: Dict[str, Any]):
    return _ok(_kb.enrich_vulnerability(vuln))


@router.get("/kb/stats", summary="知识库统计")
def kb_stats():
    return _ok(_kb.get_stats())


@router.get("/kb/query-log", summary="查询日志")
def kb_query_log(limit: int = 50):
    return _ok({"items": _kb.get_query_log(limit)})


# ============================================================
# 端点26-30：报告润色
# ============================================================
@router.post("/polisher/polish", summary="润色报告")
def polish_report(req: PolishReq):
    return _ok(_polisher.polish(req.content, req.report_type))


@router.post("/polisher/quality-check", summary="报告质量检查")
def quality_check(content: str = Query(...)):
    return _ok(_polisher.quality_check(content))


@router.post("/polisher/executive-summary", summary="自动生成执行摘要")
def gen_summary(req: ExecutiveSummaryReq):
    return _ok({"summary": _polisher.generate_executive_summary(
        req.vulns, req.target)})


@router.get("/polisher/rules", summary="润色规则")
def polish_rules():
    return _ok(_polisher.get_polish_rules())


@router.get("/polisher/history", summary="润色历史")
def polish_history(limit: int = 20):
    return _ok({"items": _polisher.get_history(limit)})


@router.get("/polisher/stats", summary="润色统计")
def polish_stats():
    return _ok(_polisher.get_stats())
