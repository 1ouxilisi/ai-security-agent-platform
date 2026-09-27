# -*- coding: utf-8 -*-
"""
ai_intelligence_routes.py — AI 大模型智能决策引擎 REST API（第23轮升级方向1）。

路由前缀：/api/v1/ai-intelligence
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500 错误。
任务/会话用内存字典模拟异步。
本模块仅用于授权的安全评估与运营场景。
"""

from __future__ import annotations

import os
import re
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:  # 模块导入失败也不影响 app 启动
    from ai_intelligence.nl_assistant import nl_assistant
    from ai_intelligence.scan_decision import scan_decision_engine
    from ai_intelligence.poc_generator import poc_generator
    from ai_intelligence.smart_report import smart_report
    from ai_intelligence.ai_knowledge_base import ai_knowledge_base
    from ai_intelligence.ai_dashboard import ai_dashboard
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    import logging
    logging.getLogger("ai_intelligence_routes").warning("模块导入失败: %s", _e)
    nl_assistant = None  # type: ignore
    scan_decision_engine = None  # type: ignore
    poc_generator = None  # type: ignore
    smart_report = None  # type: ignore
    ai_knowledge_base = None  # type: ignore
    ai_dashboard = None  # type: ignore
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/ai-intelligence", tags=["AI智能决策引擎"])


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


def _check_modules() -> Optional[JSONResponse]:
    if not _MODULES_OK:
        return _fail("ai_intelligence 模块未正确加载")
    return None


# ==================== 内存任务存储（模拟异步） ====================

TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(task_type: str) -> str:
    tid = f"{task_type}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {
        "task_id": tid, "type": task_type,
        "status": "pending", "result": None, "error": None,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    return tid


# ==================== 请求模型 ====================

class ChatReq(BaseModel):
    message: str
    session_id: Optional[str] = None


class IntentReq(BaseModel):
    text: str


class ExtractReq(BaseModel):
    text: str


class PromptCfgReq(BaseModel):
    updates: Dict[str, Any] = Field(default_factory=dict)


class StrategyReq(BaseModel):
    target: str
    target_type: str = "web"
    asset_scale: str = "small"
    time_window_min: int = 30
    risk_appetite: str = "medium"


class PathReq(BaseModel):
    discovered_ports: List[int] = Field(default_factory=lambda: [80, 443])


class AdaptReq(BaseModel):
    service: str
    stack: str = "web"
    current_depth: str = "quick"


class AnalyzeReq(BaseModel):
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class ScheduleReq(BaseModel):
    target: str
    schedule_type: str = "scheduled"
    cron: str = "0 2 * * *"
    resource_aware: bool = True


class QualityReq(BaseModel):
    strategy_id: str
    scanned_ports: int
    expected_ports: int
    repeat_runs: Optional[List[List[Dict[str, Any]]]] = None


class POCGenReq(BaseModel):
    vuln_id: str
    target: str = "http://target"


class EXPGenReq(BaseModel):
    vuln_id: str
    target: str


class SandboxReq(BaseModel):
    code: str
    timeout_sec: int = 10
    max_memory_mb: int = 128


class ChainReq(BaseModel):
    vulns: List[str] = Field(default_factory=list)
    entry: str = "recon"


class ReportGenReq(BaseModel):
    target: str
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    audience: str = "technical"
    format: str = "markdown"


class RewriteReq(BaseModel):
    finding: Dict[str, Any] = Field(default_factory=dict)


class RemediationReq(BaseModel):
    finding: Dict[str, Any] = Field(default_factory=dict)
    tech_stack: str = ""


class KBAddReq(BaseModel):
    category: str = "custom"
    title: str
    tags: List[str] = Field(default_factory=list)
    summary: str = ""


class AskReq(BaseModel):
    question: str


class SwitchModelReq(BaseModel):
    model_id: str


class CompareReq(BaseModel):
    model_ids: List[str] = Field(default_factory=list)


class EvalReq(BaseModel):
    model_id: str
    samples: int = 50


class FinetuneReq(BaseModel):
    model_id: str
    epochs: int = 3


class PromptVerReq(BaseModel):
    name: str
    prompt: str


class ConvCreateReq(BaseModel):
    title: str
    tags: List[str] = Field(default_factory=list)


class TagReq(BaseModel):
    tags: List[str] = Field(default_factory=list)


class SettingsReq(BaseModel):
    updates: Dict[str, Any] = Field(default_factory=dict)


# ======================================================================
# 健康检查 & 总览
# ======================================================================
@router.get("/health")
def health():
    """模块健康检查与能力总览"""
    try:
        return _ok({
            "module": "ai_intelligence",
            "modules_loaded": _MODULES_OK,
            "capabilities": [
                "自然语言安全助手", "智能扫描决策", "自动POC/EXP生成",
                "智能报告生成", "AI安全知识库", "AI管理控制台",
            ],
        })
    except Exception as e:
        return _fail(str(e))


@router.get("/overview")
def overview():
    """AI 决策引擎总览"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({
            "assistant": nl_assistant.stats(),
            "scan": scan_decision_engine.stats(),
            "poc": poc_generator.stats(),
            "report": smart_report.stats(),
            "kb": ai_knowledge_base.stats(),
            "dashboard": ai_dashboard.stats(),
        })
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 一、自然语言安全助手（10 端点）
# ======================================================================
@router.post("/assistant/chat")
def assistant_chat(req: ChatReq):
    """对话式交互：自然语言 → 意图识别 → 参数提取 → 执行反馈"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(nl_assistant.chat(req.message, req.session_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/assistant/sessions")
def assistant_create_session(title: Optional[str] = None):
    """创建会话"""
    try:
        err = _check_modules()
        if err:
            return err
        s = nl_assistant.create_session(title)
        return _ok({"session_id": s["session_id"], "title": s["title"]})
    except Exception as e:
        return _fail(str(e))


@router.get("/assistant/sessions")
def assistant_list_sessions(keyword: Optional[str] = None):
    """会话列表（支持搜索）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(nl_assistant.list_sessions(keyword))
    except Exception as e:
        return _fail(str(e))


@router.get("/assistant/sessions/{session_id}")
def assistant_get_session(session_id: str):
    """会话详情（含消息历史）"""
    try:
        err = _check_modules()
        if err:
            return err
        s = nl_assistant.get_session(session_id)
        if not s:
            return _fail("session not found")
        return _ok(s)
    except Exception as e:
        return _fail(str(e))


@router.delete("/assistant/sessions/{session_id}")
def assistant_delete_session(session_id: str):
    """删除会话"""
    try:
        err = _check_modules()
        if err:
            return err
        ok = nl_assistant.delete_session(session_id)
        return _ok({"deleted": ok})
    except Exception as e:
        return _fail(str(e))


@router.get("/assistant/sessions/{session_id}/export")
def assistant_export_session(session_id: str):
    """导出会话"""
    try:
        err = _check_modules()
        if err:
            return err
        data = nl_assistant.export_session(session_id)
        if not data:
            return _fail("session not found")
        return _ok(data)
    except Exception as e:
        return _fail(str(e))


@router.post("/assistant/intent")
def assistant_intent(req: IntentReq):
    """单独的意图识别"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(nl_assistant.recognize_intent(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/assistant/extract")
def assistant_extract(req: ExtractReq):
    """单独的参数提取"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(nl_assistant.extract_params(req.text))
    except Exception as e:
        return _fail(str(e))


@router.get("/assistant/prompt-config")
def assistant_prompt_config():
    """获取提示词配置（系统提示/温度/max_tokens）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(nl_assistant.get_prompt_config())
    except Exception as e:
        return _fail(str(e))


@router.put("/assistant/prompt-config")
def assistant_update_prompt_config(req: PromptCfgReq):
    """更新提示词配置"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(nl_assistant.update_prompt_config(req.updates))
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 二、智能扫描决策（9 端点）
# ======================================================================
@router.post("/scan/strategy")
def scan_strategy(req: StrategyReq):
    """生成扫描策略"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(scan_decision_engine.generate_strategy(
            req.target, req.target_type, req.asset_scale,
            req.time_window_min, req.risk_appetite))
    except Exception as e:
        return _fail(str(e))


@router.post("/scan/strategy/{strategy_id}/path")
def scan_path(strategy_id: str, req: PathReq):
    """扫描路径规划"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(scan_decision_engine.plan_path(strategy_id, req.discovered_ports))
    except Exception as e:
        return _fail(str(e))


@router.post("/scan/adapt-depth")
def scan_adapt_depth(req: AdaptReq):
    """扫描深度自适应"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(scan_decision_engine.adapt_depth(req.service, req.stack, req.current_depth))
    except Exception as e:
        return _fail(str(e))


@router.post("/scan/analyze")
def scan_analyze(req: AnalyzeReq):
    """扫描结果智能分析（聚类/去重/误报过滤/优先级）"""
    try:
        err = _check_modules()
        if err:
            return err
        tid = _new_task("scan-analyze")
        TASKS[tid]["status"] = "running"
        result = scan_decision_engine.analyze_results(req.findings)
        TASKS[tid]["status"] = "success"
        TASKS[tid]["result"] = result
        return _ok({"task_id": tid, **result})
    except Exception as e:
        return _fail(str(e))


@router.post("/scan/schedule")
def scan_schedule(req: ScheduleReq):
    """创建扫描调度任务"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(scan_decision_engine.schedule_scan(
            req.target, req.schedule_type, req.cron, req.resource_aware))
    except Exception as e:
        return _fail(str(e))


@router.get("/scan/schedules")
def scan_list_schedules():
    """调度列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(scan_decision_engine.list_schedules())
    except Exception as e:
        return _fail(str(e))


@router.post("/scan/schedules/{schedule_id}/pause")
def scan_pause_schedule(schedule_id: str):
    """暂停调度"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({"paused": scan_decision_engine.pause_schedule(schedule_id)})
    except Exception as e:
        return _fail(str(e))


@router.post("/scan/quality")
def scan_quality(req: QualityReq):
    """扫描质量评估"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(scan_decision_engine.quality_assess(
            req.strategy_id, req.scanned_ports, req.expected_ports, req.repeat_runs))
    except Exception as e:
        return _fail(str(e))


@router.get("/scan/stats")
def scan_stats():
    """扫描决策统计"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(scan_decision_engine.stats())
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 三、自动 POC/EXP 生成（7 端点）
# ======================================================================
@router.post("/poc/parse")
def poc_parse(vuln_id: str, description: str = ""):
    """漏洞信息解析"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(poc_generator.parse_vuln(vuln_id, description))
    except Exception as e:
        return _fail(str(e))


@router.post("/poc/generate")
def poc_generate(req: POCGenReq):
    """自动生成 POC"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(poc_generator.generate_poc(req.vuln_id, req.target))
    except Exception as e:
        return _fail(str(e))


@router.post("/poc/generate-exp")
def poc_generate_exp(req: EXPGenReq):
    """自动生成 EXP 脚手架"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(poc_generator.generate_exp(req.vuln_id, req.target))
    except Exception as e:
        return _fail(str(e))


@router.post("/poc/sandbox")
def poc_sandbox(req: SandboxReq):
    """代码沙箱执行（模拟）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(poc_generator.sandbox_run(req.code, req.timeout_sec, req.max_memory_mb))
    except Exception as e:
        return _fail(str(e))


@router.post("/poc/{poc_id}/verify")
def poc_verify(poc_id: str, actually_execute: bool = False):
    """POC 验证执行"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(poc_generator.verify_poc(poc_id, actually_execute))
    except Exception as e:
        return _fail(str(e))


@router.post("/poc/chain")
def poc_chain(req: ChainReq):
    """利用链自动构建"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(poc_generator.build_chain(req.vulns, req.entry))
    except Exception as e:
        return _fail(str(e))


@router.get("/poc/list")
def poc_list():
    """已生成 POC 列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(list(poc_generator.pocs.values()))
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 四、智能报告生成（6 端点）
# ======================================================================
@router.post("/report/generate")
def report_generate(req: ReportGenReq):
    """生成多格式报告"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(smart_report.generate(req.findings, req.target, req.audience, req.format))
    except Exception as e:
        return _fail(str(e))


@router.post("/report/plan")
def report_plan(req: ReportGenReq):
    """报告结构规划"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(smart_report.plan_structure(req.findings, req.target, req.audience))
    except Exception as e:
        return _fail(str(e))


@router.post("/report/rewrite")
def report_rewrite(req: RewriteReq):
    """漏洞描述智能改写（技术→业务）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(smart_report.rewrite_description(req.finding))
    except Exception as e:
        return _fail(str(e))


@router.post("/report/remediation")
def report_remediation(req: RemediationReq):
    """修复建议生成"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(smart_report.remediation(req.finding, req.tech_stack))
    except Exception as e:
        return _fail(str(e))


@router.post("/report/quality")
def report_quality(req: ReportGenReq):
    """报告质量自动评分"""
    try:
        err = _check_modules()
        if err:
            return err
        plan = smart_report.plan_structure(req.findings, req.target, req.audience)
        summary = smart_report.summary(req.findings)
        fake = {**plan, "findings": req.findings,
                "business_summary": summary["executive_summary"], "remediations": True}
        return _ok(smart_report.quality_score(fake))
    except Exception as e:
        return _fail(str(e))


@router.get("/report/list")
def report_list():
    """报告列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(smart_report.list_reports())
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 五、AI 安全知识库（6 端点）
# ======================================================================
@router.get("/kb/entries")
def kb_entries(category: Optional[str] = None):
    """知识库条目列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_knowledge_base.list_entries(category))
    except Exception as e:
        return _fail(str(e))


@router.post("/kb/entries")
def kb_add(req: KBAddReq):
    """新增知识条目"""
    try:
        err = _check_modules()
        if err:
            return err
        eid = ai_knowledge_base.add_entry(
            {"category": req.category, "title": req.title,
             "tags": req.tags, "summary": req.summary})
        return _ok({"entry_id": eid})
    except Exception as e:
        return _fail(str(e))


@router.get("/kb/search")
def kb_search(q: str, top_k: int = 5):
    """知识库检索"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_knowledge_base.search(q, top_k))
    except Exception as e:
        return _fail(str(e))


@router.get("/kb/related/{entry_id}")
def kb_related(entry_id: str, depth: int = 1):
    """知识图谱关联推理"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_knowledge_base.related(entry_id, depth))
    except Exception as e:
        return _fail(str(e))


@router.post("/kb/ask")
def kb_ask(req: AskReq):
    """知识库问答"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_knowledge_base.ask(req.question))
    except Exception as e:
        return _fail(str(e))


@router.get("/kb/stats")
def kb_stats():
    """知识库统计"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_knowledge_base.stats())
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 六、AI 管理控制台（16 端点）
# ======================================================================
@router.get("/dashboard/overview")
def dash_overview():
    """AI 总览"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.overview())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/models")
def dash_models():
    """模型列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.list_models())
    except Exception as e:
        return _fail(str(e))


@router.post("/dashboard/models/switch")
def dash_switch_model(req: SwitchModelReq):
    """切换模型"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.switch_model(req.model_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/dashboard/models/compare")
def dash_compare_models(req: CompareReq):
    """模型对比"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.compare_models(req.model_ids))
    except Exception as e:
        return _fail(str(e))


@router.post("/dashboard/models/eval")
def dash_eval_model(req: EvalReq):
    """模型评测"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.eval_model(req.model_id, req.samples))
    except Exception as e:
        return _fail(str(e))


@router.post("/dashboard/models/finetune")
def dash_finetune(req: FinetuneReq):
    """模型微调任务"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.fine_tune(req.model_id, req.epochs))
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/prompt-versions")
def dash_prompt_versions():
    """提示词版本列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.list_prompt_versions())
    except Exception as e:
        return _fail(str(e))


@router.post("/dashboard/prompt-versions")
def dash_add_prompt_version(req: PromptVerReq):
    """新增提示词版本"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.add_prompt_version(req.name, req.prompt))
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/ab-tests")
def dash_ab_tests():
    """提示词 A/B 测试结果"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.ab_test_result())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/conversations")
def dash_list_conversations(keyword: Optional[str] = None, tag: Optional[str] = None):
    """会话列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.list_conversations(keyword, tag))
    except Exception as e:
        return _fail(str(e))


@router.post("/dashboard/conversations")
def dash_create_conversation(req: ConvCreateReq):
    """创建会话"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.create_conversation(req.title, tags=req.tags))
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/conversations/{conv_id}")
def dash_get_conversation(conv_id: str):
    """会话详情"""
    try:
        err = _check_modules()
        if err:
            return err
        c = ai_dashboard.get_conversation(conv_id)
        if not c:
            return _fail("conversation not found")
        return _ok(c)
    except Exception as e:
        return _fail(str(e))


@router.delete("/dashboard/conversations/{conv_id}")
def dash_delete_conversation(conv_id: str):
    """删除会话"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({"deleted": ai_dashboard.delete_conversation(conv_id)})
    except Exception as e:
        return _fail(str(e))


@router.post("/dashboard/conversations/{conv_id}/tag")
def dash_tag_conversation(conv_id: str, req: TagReq):
    """会话打标签"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({"tagged": ai_dashboard.tag_conversation(conv_id, req.tags)})
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/tasks")
def dash_list_tasks(status: Optional[str] = None):
    """AI 任务列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.list_tasks(status))
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/tasks/{task_id}")
def dash_get_task(task_id: str):
    """任务详情"""
    try:
        err = _check_modules()
        if err:
            return err
        t = ai_dashboard.get_task(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t)
    except Exception as e:
        return _fail(str(e))


@router.post("/dashboard/tasks/{task_id}/retry")
def dash_retry_task(task_id: str):
    """重试任务"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({"retried": ai_dashboard.retry_task(task_id)})
    except Exception as e:
        return _fail(str(e))


@router.post("/dashboard/tasks/{task_id}/cancel")
def dash_cancel_task(task_id: str):
    """取消任务"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({"cancelled": ai_dashboard.cancel_task(task_id)})
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/settings")
def dash_get_settings():
    """获取系统设置"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.get_settings())
    except Exception as e:
        return _fail(str(e))


@router.put("/dashboard/settings")
def dash_update_settings(req: SettingsReq):
    """更新系统设置"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.update_settings(req.updates))
    except Exception as e:
        return _fail(str(e))


@router.post("/dashboard/rotate-key")
def dash_rotate_key():
    """轮换 API 密钥"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(ai_dashboard.rotate_api_key())
    except Exception as e:
        return _fail(str(e))
