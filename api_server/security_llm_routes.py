# -*- coding: utf-8 -*-
"""
security_llm_routes.py — 安全大模型与 AI Agent 深度平台 REST API（第26轮升级方向1）。

路由前缀：/api/v1/security-llm
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500 错误。
任务用内存字典模拟异步。
本模块仅用于授权的安全评估与运营场景。
"""
from __future__ import annotations

import os
import re
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:  # 模块导入失败也不影响 app 启动
    from security_llm.llm_manager import llm_manager
    from security_llm.agent_engine import agent_engine
    from security_llm.code_generator import code_generator
    from security_llm.qa_system import qa_system
    from security_llm.smart_report import smart_report
    from security_llm.llm_dashboard import llm_dashboard
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    import logging
    logging.getLogger("security_llm_routes").warning("模块导入失败: %s", _e)
    llm_manager = None  # type: ignore
    agent_engine = None  # type: ignore
    code_generator = None  # type: ignore
    qa_system = None  # type: ignore
    smart_report = None  # type: ignore
    llm_dashboard = None  # type: ignore
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/security-llm", tags=["安全大模型与AI Agent平台"])

# ==================== 响应工具 ====================
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理无效控制字符，避免 JSON 序列化异常"""
    if isinstance(obj, str):
        return _CTRL_RE.sub("", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(x) for x in obj]
    return obj


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": _clean(data), "error": str(err)})


def _check() -> Optional[JSONResponse]:
    if not _MODULES_OK:
        return _fail("security_llm 模块未正确加载")
    return None


# 内存任务存储（模拟异步）
TASKS: Dict[str, Dict[str, Any]] = {}


def _submit_task(kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    tid = f"task-{uuid.uuid4().hex[:10]}"
    TASKS[tid] = {
        "id": tid, "kind": kind, "payload": payload,
        "status": "queued", "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    return TASKS[tid]


# ==================== Pydantic 请求模型 ====================
class ChatReq(BaseModel):
    message: str = Field(..., min_length=1)
    system: Optional[str] = None


class SwitchModelReq(BaseModel):
    model_id: str


class RegisterModelReq(BaseModel):
    name: str
    vendor: str = "custom"
    type: str = "通用大模型"
    size: str = "7B"
    context: int = 8192
    capabilities: List[str] = Field(default_factory=list)


class KBDocReq(BaseModel):
    title: str
    category: str = "通用"
    content: str


class PromptReq(BaseModel):
    name: str
    content: str
    variables: List[str] = Field(default_factory=list)


class PromptRenderReq(BaseModel):
    variables: Dict[str, str] = Field(default_factory=dict)


class FinetuneReq(BaseModel):
    base_model: str = "sec-llm-7b"
    dataset: List[Dict[str, str]] = Field(default_factory=list)
    epochs: int = 3
    learning_rate: float = 2e-5


class EvalReq(BaseModel):
    model_id: str
    benchmark: str = "sec-bench-v1"


class CompareReq(BaseModel):
    model_ids: List[str]


class AgentCreateReq(BaseModel):
    name: str
    role: str
    tools: List[str] = Field(default_factory=list)
    desc: str = ""


class AgentStatusReq(BaseModel):
    status: str


class TaskReq(BaseModel):
    goal: str
    target: str
    agent_id: Optional[str] = None


class CollabReq(BaseModel):
    goal: str
    target: str
    agent_ids: List[str]


class MemoryReq(BaseModel):
    key: str
    value: str
    agent_id: str


class GenCodeReq(BaseModel):
    requirement: str
    language: str = "python"


class ReviewCodeReq(BaseModel):
    code: str
    language: str = "python"


class ExplainReq(BaseModel):
    code: str
    language: str = "python"


class ConvertReq(BaseModel):
    code: str
    from_lang: str
    to_lang: str


class GenTestsReq(BaseModel):
    code: str
    language: str = "python"


class QAaskReq(BaseModel):
    question: str
    session_id: Optional[str] = None


class FeedbackReq(BaseModel):
    answer_id: str
    satisfied: bool


class FAQReq(BaseModel):
    q: str
    a: str
    category: str = "通用"


class ReportReq(BaseModel):
    title: str
    target: str
    template_id: str = "tpl-tech"
    findings: Optional[List[Dict[str, Any]]] = None


class PlanReq(BaseModel):
    title: str
    target: str
    audience: str = "tech"


class TemplateReq(BaseModel):
    name: str
    audience: str
    sections: List[str]
    style: str = "专业"


# ==================== 1. 模型管理 / LLM ====================

@router.get("/models", summary="模型列表")
def list_models():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.list_models())
    except Exception as e:
        return _fail(e)


@router.get("/models/current", summary="当前模型")
def current_model():
    try:
        r = _check()
        if r:
            return r
        return _ok({"current": llm_manager.current_model})
    except Exception as e:
        return _fail(e)


@router.get("/models/{model_id}", summary="模型详情")
def get_model(model_id: str):
    try:
        r = _check()
        if r:
            return r
        m = llm_manager.get_model(model_id)
        if not m:
            return _fail(f"模型不存在: {model_id}")
        return _ok(m)
    except Exception as e:
        return _fail(e)


@router.post("/models", summary="注册模型")
def register_model(req: RegisterModelReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.register_model(req.name, req.vendor, req.type,
                                              req.size, req.context, req.capabilities))
    except Exception as e:
        return _fail(e)


@router.post("/models/switch", summary="切换模型")
def switch_model(req: SwitchModelReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.switch_model(req.model_id))
    except Exception as e:
        return _fail(e)


@router.get("/models/health/check", summary="模型健康检查")
def model_health():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.model_health())
    except Exception as e:
        return _fail(e)


# ==================== 2. 安全知识库 RAG ====================

@router.get("/kb/docs", summary="知识库文档列表")
def kb_list():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.kb_list())
    except Exception as e:
        return _fail(e)


@router.post("/kb/docs", summary="知识库入库")
def kb_add(doc: KBDocReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.kb_add(doc.title, doc.category, doc.content))
    except Exception as e:
        return _fail(e)


@router.get("/kb/search", summary="知识库检索")
def kb_search(q: str = Query(...), top_k: int = 5):
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.kb_search(q, top_k))
    except Exception as e:
        return _fail(e)


@router.get("/kb/stats", summary="知识库统计")
def kb_stats():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.kb_stats())
    except Exception as e:
        return _fail(e)


# ==================== 3. 安全提示词工程 ====================

@router.get("/prompts", summary="提示词模板列表")
def list_prompts():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.list_prompts())
    except Exception as e:
        return _fail(e)


@router.post("/prompts", summary="新增提示词模板")
def add_prompt(req: PromptReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.add_prompt(req.name, req.content, req.variables))
    except Exception as e:
        return _fail(e)


@router.post("/prompts/{prompt_id}/render", summary="渲染提示词")
def render_prompt(prompt_id: str, req: PromptRenderReq):
    try:
        r = _check()
        if r:
            return r
        rendered = llm_manager.render_prompt(prompt_id, req.variables)
        return _ok({"prompt_id": prompt_id, "rendered": rendered})
    except Exception as e:
        return _fail(e)


# ==================== 4. 安全模型微调 ====================

@router.post("/finetune/start", summary="启动微调任务")
def start_finetune(req: FinetuneReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.start_finetune(req.base_model, req.dataset,
                                             req.epochs, req.learning_rate))
    except Exception as e:
        return _fail(e)


@router.get("/finetune/{job_id}/status", summary="微调任务状态")
def finetune_status(job_id: str):
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.finetune_status(job_id))
    except Exception as e:
        return _fail(e)


@router.get("/finetune", summary="微调任务列表")
def list_finetunes():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.list_finetunes())
    except Exception as e:
        return _fail(e)


# ==================== 5. 安全模型推理 ====================

@router.post("/chat", summary="对话推理")
def chat(req: ChatReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.chat(req.message, req.system))
    except Exception as e:
        return _fail(e)


@router.get("/chat/history", summary="对话历史")
def chat_history():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.list_chat_history())
    except Exception as e:
        return _fail(e)


# ==================== 6. 安全模型评测 ====================

@router.post("/eval/run", summary="运行模型评测")
def run_eval(req: EvalReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.run_eval(req.model_id, req.benchmark))
    except Exception as e:
        return _fail(e)


@router.get("/eval", summary="评测结果列表")
def list_evals():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.list_evals())
    except Exception as e:
        return _fail(e)


@router.post("/eval/compare", summary="模型对比评测")
def compare_models(req: CompareReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_manager.compare_models(req.model_ids))
    except Exception as e:
        return _fail(e)


# ==================== Agent 管理 ====================

@router.get("/agents", summary="Agent列表")
def list_agents():
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.list_agents())
    except Exception as e:
        return _fail(e)


@router.get("/agents/{agent_id}", summary="Agent详情")
def get_agent(agent_id: str):
    try:
        r = _check()
        if r:
            return r
        a = agent_engine.get_agent(agent_id)
        if not a:
            return _fail(f"Agent不存在: {agent_id}")
        return _ok(a)
    except Exception as e:
        return _fail(e)


@router.post("/agents", summary="创建Agent")
def create_agent(req: AgentCreateReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.create_agent(req.name, req.role, req.tools, req.desc))
    except Exception as e:
        return _fail(e)


@router.post("/agents/{agent_id}/status", summary="设置Agent状态")
def set_agent_status(agent_id: str, req: AgentStatusReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.set_agent_status(agent_id, req.status))
    except Exception as e:
        return _fail(e)


@router.get("/tools", summary="可用安全工具")
def list_tools():
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.list_tools())
    except Exception as e:
        return _fail(e)


# ==================== Agent 规划/执行 ====================

@router.post("/tasks/plan", summary="任务规划")
def plan_task(req: TaskReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.plan_task(req.goal, req.target))
    except Exception as e:
        return _fail(e)


@router.post("/tasks/execute", summary="任务执行")
def execute_task(req: TaskReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.execute_task(req.goal, req.target, req.agent_id))
    except Exception as e:
        return _fail(e)


@router.get("/tasks", summary="任务列表")
def list_tasks():
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.list_tasks())
    except Exception as e:
        return _fail(e)


@router.get("/tasks/{task_id}", summary="任务详情")
def get_task(task_id: str):
    try:
        r = _check()
        if r:
            return r
        t = agent_engine.get_task(task_id)
        if not t:
            return _fail(f"任务不存在: {task_id}")
        return _ok(t)
    except Exception as e:
        return _fail(e)


@router.post("/tasks/{task_id}/reflect", summary="Agent反思")
def reflect(task_id: str):
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.reflect(task_id))
    except Exception as e:
        return _fail(e)


# ==================== Agent 记忆 ====================

@router.post("/memory/remember", summary="写入记忆")
def remember(req: MemoryReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.remember(req.key, req.value, req.agent_id))
    except Exception as e:
        return _fail(e)


@router.get("/memory/recall", summary="检索记忆")
def recall(q: str, agent_id: Optional[str] = None):
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.recall(q, agent_id))
    except Exception as e:
        return _fail(e)


@router.get("/memory/stats", summary="记忆统计")
def memory_stats():
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.memory_stats())
    except Exception as e:
        return _fail(e)


# ==================== Agent 协作 ====================

@router.post("/collab", summary="多Agent协作")
def collab(req: CollabReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.collab(req.goal, req.target, req.agent_ids))
    except Exception as e:
        return _fail(e)


@router.get("/collab", summary="协作会话列表")
def list_collabs():
    try:
        r = _check()
        if r:
            return r
        return _ok(agent_engine.list_collabs())
    except Exception as e:
        return _fail(e)


# ==================== 代码生成 ====================

@router.post("/code/generate", summary="生成安全代码")
def gen_code(req: GenCodeReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(code_generator.generate(req.requirement, req.language))
    except Exception as e:
        return _fail(e)


@router.get("/code/generations", summary="代码生成历史")
def list_generations():
    try:
        r = _check()
        if r:
            return r
        return _ok(code_generator.list_generations())
    except Exception as e:
        return _fail(e)


@router.post("/code/review", summary="代码安全审查")
def review_code(req: ReviewCodeReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(code_generator.review(req.code, req.language))
    except Exception as e:
        return _fail(e)


@router.get("/code/reviews", summary="审查历史")
def list_reviews():
    try:
        r = _check()
        if r:
            return r
        return _ok(code_generator.list_reviews())
    except Exception as e:
        return _fail(e)


@router.post("/code/explain", summary="代码解释")
def explain_code(req: ExplainReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(code_generator.explain(req.code, req.language))
    except Exception as e:
        return _fail(e)


@router.post("/code/convert", summary="代码语言转换")
def convert_code(req: ConvertReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(code_generator.convert(req.code, req.from_lang, req.to_lang))
    except Exception as e:
        return _fail(e)


@router.post("/code/tests", summary="生成安全测试")
def gen_tests(req: GenTestsReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(code_generator.gen_tests(req.code, req.language))
    except Exception as e:
        return _fail(e)


@router.get("/code/tests", summary="测试生成历史")
def list_tests():
    try:
        r = _check()
        if r:
            return r
        return _ok(code_generator.list_tests())
    except Exception as e:
        return _fail(e)


@router.get("/code/kb", summary="编码规范知识库")
def code_kb(language: Optional[str] = None):
    try:
        r = _check()
        if r:
            return r
        return _ok(code_generator.list_kb(language))
    except Exception as e:
        return _fail(e)


@router.get("/code/kb/search", summary="编码规范搜索")
def code_kb_search(q: str):
    try:
        r = _check()
        if r:
            return r
        return _ok(code_generator.kb_search(q))
    except Exception as e:
        return _fail(e)


# ==================== 问答系统 ====================

@router.post("/qa/sessions", summary="创建问答会话")
def qa_create_session(user: str = "anonymous"):
    try:
        r = _check()
        if r:
            return r
        return _ok(qa_system.create_session(user))
    except Exception as e:
        return _fail(e)


@router.get("/qa/sessions", summary="问答会话列表")
def qa_list_sessions():
    try:
        r = _check()
        if r:
            return r
        return _ok(qa_system.list_sessions())
    except Exception as e:
        return _fail(e)


@router.get("/qa/sessions/{session_id}", summary="问答会话详情")
def qa_get_session(session_id: str):
    try:
        r = _check()
        if r:
            return r
        s = qa_system.get_session(session_id)
        if not s:
            return _fail(f"会话不存在: {session_id}")
        return _ok(s)
    except Exception as e:
        return _fail(e)


@router.delete("/qa/sessions/{session_id}", summary="删除会话")
def qa_delete_session(session_id: str):
    try:
        r = _check()
        if r:
            return r
        return _ok(qa_system.delete_session(session_id))
    except Exception as e:
        return _fail(e)


@router.post("/qa/ask", summary="提问")
def qa_ask(req: QAaskReq):
    try:
        r = _check()
        if r:
            return r
        sid = req.session_id or qa_system.create_session()["id"]
        return _ok(qa_system.ask(sid, req.question))
    except Exception as e:
        return _fail(e)


@router.get("/qa/answers", summary="答案历史")
def qa_list_answers():
    try:
        r = _check()
        if r:
            return r
        return _ok(qa_system.list_answers())
    except Exception as e:
        return _fail(e)


@router.post("/qa/answers/{answer_id}/review", summary="答案审核")
def qa_review(answer_id: str):
    try:
        r = _check()
        if r:
            return r
        return _ok(qa_system.review_answer(answer_id))
    except Exception as e:
        return _fail(e)


@router.post("/qa/feedback", summary="答案反馈")
def qa_feedback(req: FeedbackReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(qa_system.feedback(req.answer_id, req.satisfied))
    except Exception as e:
        return _fail(e)


@router.get("/qa/stats", summary="问答统计")
def qa_stats():
    try:
        r = _check()
        if r:
            return r
        return _ok(qa_system.stats())
    except Exception as e:
        return _fail(e)


@router.post("/qa/faq", summary="新增FAQ")
def qa_add_faq(req: FAQReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(qa_system.add_faq(req.q, req.a, req.category))
    except Exception as e:
        return _fail(e)


@router.get("/qa/faq", summary="FAQ列表")
def qa_list_faq(category: Optional[str] = None):
    try:
        r = _check()
        if r:
            return r
        return _ok(qa_system.list_faq(category))
    except Exception as e:
        return _fail(e)


@router.delete("/qa/faq/{faq_id}", summary="删除FAQ")
def qa_delete_faq(faq_id: str):
    try:
        r = _check()
        if r:
            return r
        return _ok(qa_system.delete_faq(faq_id))
    except Exception as e:
        return _fail(e)


# ==================== 报告生成 ====================

@router.post("/reports/plan", summary="报告规划")
def report_plan(req: PlanReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(smart_report.plan(req.title, req.target, req.audience))
    except Exception as e:
        return _fail(e)


@router.post("/reports/generate", summary="生成报告")
def report_generate(req: ReportReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(smart_report.generate(req.title, req.target, req.findings, req.template_id))
    except Exception as e:
        return _fail(e)


@router.get("/reports", summary="报告列表")
def list_reports():
    try:
        r = _check()
        if r:
            return r
        return _ok(smart_report.list_reports())
    except Exception as e:
        return _fail(e)


@router.get("/reports/{report_id}", summary="报告详情")
def get_report(report_id: str):
    try:
        r = _check()
        if r:
            return r
        rpt = smart_report.get_report(report_id)
        if not rpt:
            return _fail(f"报告不存在: {report_id}")
        return _ok(rpt)
    except Exception as e:
        return _fail(e)


@router.post("/reports/{report_id}/optimize", summary="优化报告")
def report_optimize(report_id: str):
    try:
        r = _check()
        if r:
            return r
        return _ok(smart_report.optimize(report_id))
    except Exception as e:
        return _fail(e)


@router.post("/reports/{report_id}/audit", summary="审核报告")
def report_audit(report_id: str):
    try:
        r = _check()
        if r:
            return r
        return _ok(smart_report.audit(report_id))
    except Exception as e:
        return _fail(e)


@router.get("/reports/{report_id}/versions", summary="报告版本列表")
def report_versions(report_id: str):
    try:
        r = _check()
        if r:
            return r
        return _ok(smart_report.list_versions(report_id))
    except Exception as e:
        return _fail(e)


@router.post("/reports/{report_id}/rollback", summary="报告回滚")
def report_rollback(report_id: str, version: str = Query(...)):
    try:
        r = _check()
        if r:
            return r
        return _ok(smart_report.rollback(report_id, version))
    except Exception as e:
        return _fail(e)


@router.get("/report-templates", summary="报告模板列表")
def list_report_templates():
    try:
        r = _check()
        if r:
            return r
        return _ok(smart_report.list_templates())
    except Exception as e:
        return _fail(e)


@router.post("/report-templates", summary="新增报告模板")
def add_report_template(req: TemplateReq):
    try:
        r = _check()
        if r:
            return r
        return _ok(smart_report.add_template(req.name, req.audience, req.sections, req.style))
    except Exception as e:
        return _fail(e)


# ==================== 控制台聚合 ====================

@router.get("/dashboard/overview", summary="控制台总览")
def dashboard_overview():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_dashboard.overview())
    except Exception as e:
        return _fail(e)


@router.get("/dashboard/trend", summary="趋势数据")
def dashboard_trend(metric: str = "tasks", days: int = 7):
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_dashboard.trend(metric, days))
    except Exception as e:
        return _fail(e)


@router.get("/dashboard/agent-status", summary="Agent状态聚合")
def dashboard_agent_status():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_dashboard.agent_status())
    except Exception as e:
        return _fail(e)


@router.get("/dashboard/usage", summary="使用量统计")
def dashboard_usage():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_dashboard.usage_stats())
    except Exception as e:
        return _fail(e)


@router.get("/dashboard/alerts", summary="平台告警")
def dashboard_alerts():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_dashboard.alerts())
    except Exception as e:
        return _fail(e)


@router.get("/dashboard/module-health", summary="模块健康")
def dashboard_module_health():
    try:
        r = _check()
        if r:
            return r
        return _ok(llm_dashboard.module_health())
    except Exception as e:
        return _fail(e)
