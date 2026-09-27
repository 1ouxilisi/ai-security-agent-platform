# -*- coding: utf-8 -*-
"""
api_server/llm_opt_routes.py — LLM 接入优化（方向5）API 路由

确保「配了 Key 后所有 AI 功能真能用」。16 个端点：

    GET    /api/v1/llm-opt/status                 LLM 配置与运行状态
    GET    /api/v1/llm-opt/overview               仪表盘聚合数据
    GET    /api/v1/llm-opt/functions             三大 AI 功能可用性
    GET    /api/v1/llm-opt/prompts               Prompt 模板列表
    GET    /api/v1/llm-opt/prompts/{key}         单个 Prompt 新旧对照
    POST   /api/v1/llm-opt/test/vuln-analysis    测试漏洞智能分析
    POST   /api/v1/llm-opt/test/report-generation 测试报告自动生成
    POST   /api/v1/llm-opt/test/smart-qa         测试智能问答
    POST   /api/v1/llm-opt/test/custom           自定义场景测试
    POST   /api/v1/llm-opt/e2e-run               端到端测试
    GET    /api/v1/llm-opt/e2e-last              最近一次 e2e 结果
    GET    /api/v1/llm-opt/history               调用历史
    DELETE /api/v1/llm-opt/history               清空调用历史
    GET    /api/v1/llm-opt/stats                 调用统计
    POST   /api/v1/llm-opt/health-check          LLM 连通性健康检查
    POST   /api/v1/llm-opt/reload                热重载配置（立即生效）
    GET    /api/v1/llm-opt/sample-data           示例测试数据

统一响应 {success, data, error}。无 Key 时优雅降级，不 500。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/llm-opt", tags=["LLM接入优化"])


# ---------------------------------------------------------------------------
# 统一响应
# ---------------------------------------------------------------------------
def _ok(data: Any = None) -> Dict[str, Any]:
    return {"success": True, "data": data, "error": None}


def _err(message: str, data: Any = None) -> Dict[str, Any]:
    return {"success": False, "data": data, "error": message}


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------
class VulnAnalysisReq(BaseModel):
    vuln_description: str = "用户登录接口 password 参数存在 SQL 注入"
    target: str = "http://demo.testfire.net/login"
    cve: str = ""


class ReportReq(BaseModel):
    target: str = "http://demo.testfire.net"
    vulns: List[Dict[str, Any]] = Field(default_factory=list)


class SmartQAReq(BaseModel):
    question: str = "这个网站有什么风险？"
    context: str = ""


class CustomTestReq(BaseModel):
    scene: str = Field(..., description="vuln_analysis / report_generation / smart_qa")
    payload: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# 端点 1：LLM 状态
# ---------------------------------------------------------------------------
@router.get("/status", summary="LLM 当前状态")
async def get_status() -> Dict[str, Any]:
    try:
        from llm_optimization import get_dashboard
        return _ok(get_dashboard().config_status())
    except Exception as e:  # noqa: BLE001
        return _err(f"读取状态失败: {e}")


# ---------------------------------------------------------------------------
# 端点 2：仪表盘聚合
# ---------------------------------------------------------------------------
@router.get("/overview", summary="LLM 优化仪表盘聚合数据")
async def get_overview() -> Dict[str, Any]:
    try:
        from llm_optimization import get_dashboard
        return _ok(get_dashboard().overview())
    except Exception as e:  # noqa: BLE001
        return _err(f"获取仪表盘失败: {e}")


# ---------------------------------------------------------------------------
# 端点 3：三大功能可用性
# ---------------------------------------------------------------------------
@router.get("/functions", summary="三大 AI 功能可用性")
async def get_functions() -> Dict[str, Any]:
    try:
        from llm_optimization import get_dashboard
        return _ok({"functions": get_dashboard().function_readiness()})
    except Exception as e:  # noqa: BLE001
        return _err(f"读取功能状态失败: {e}")


# ---------------------------------------------------------------------------
# 端点 4：Prompt 模板列表
# ---------------------------------------------------------------------------
@router.get("/prompts", summary="Prompt 模板列表")
async def list_prompts() -> Dict[str, Any]:
    try:
        from llm_optimization import get_prompt_optimizer
        return _ok({"prompts": get_prompt_optimizer().list_prompts()})
    except Exception as e:  # noqa: BLE001
        return _err(f"读取 Prompt 列表失败: {e}")


# ---------------------------------------------------------------------------
# 端点 5：单个 Prompt 新旧对照
# ---------------------------------------------------------------------------
@router.get("/prompts/{key}", summary="单个 Prompt 新旧对照")
async def get_prompt(key: str) -> Dict[str, Any]:
    try:
        from llm_optimization import get_prompt_optimizer
        p = get_prompt_optimizer().get_prompt(key)
        if not p:
            return _err(f"未找到 Prompt: {key}")
        return _ok(p)
    except Exception as e:  # noqa: BLE001
        return _err(f"读取 Prompt 失败: {e}")


# ---------------------------------------------------------------------------
# 端点 6：测试漏洞智能分析
# ---------------------------------------------------------------------------
@router.post("/test/vuln-analysis", summary="测试漏洞智能分析")
async def test_vuln_analysis(req: VulnAnalysisReq) -> Dict[str, Any]:
    try:
        from llm_optimization import get_ai_tester
        r = get_ai_tester().analyze_vulnerability(
            vuln_description=req.vuln_description,
            target=req.target, cve=req.cve)
        return _ok(r)
    except Exception as e:  # noqa: BLE001
        return _err(f"漏洞分析测试异常: {e}")


# ---------------------------------------------------------------------------
# 端点 7：测试报告自动生成
# ---------------------------------------------------------------------------
@router.post("/test/report-generation", summary="测试报告自动生成")
async def test_report_generation(req: ReportReq) -> Dict[str, Any]:
    try:
        from llm_optimization import get_ai_tester
        vulns = req.vulns or [
            {"name": "登录接口 SQL 注入", "vuln_type": "sql_injection",
             "severity": "critical", "target": "/login",
             "impact": "可能导致拖库"},
            {"name": "反射型 XSS", "vuln_type": "xss",
             "severity": "high", "target": "/search",
             "impact": "可窃取会话 Cookie"},
            {"name": "管理后台暴露", "vuln_type": "path_traversal",
             "severity": "medium", "target": "/admin",
             "impact": "可直接访问后台入口"},
        ]
        r = get_ai_tester().generate_report(vulns=vulns, target=req.target)
        return _ok(r)
    except Exception as e:  # noqa: BLE001
        return _err(f"报告生成测试异常: {e}")


# ---------------------------------------------------------------------------
# 端点 8：测试智能问答
# ---------------------------------------------------------------------------
@router.post("/test/smart-qa", summary="测试智能问答")
async def test_smart_qa(req: SmartQAReq) -> Dict[str, Any]:
    try:
        from llm_optimization import get_ai_tester
        r = get_ai_tester().answer_question(
            question=req.question, context=req.context)
        return _ok(r)
    except Exception as e:  # noqa: BLE001
        return _err(f"智能问答测试异常: {e}")


# ---------------------------------------------------------------------------
# 端点 9：自定义场景测试
# ---------------------------------------------------------------------------
@router.post("/test/custom", summary="自定义场景测试")
async def test_custom(req: CustomTestReq) -> Dict[str, Any]:
    try:
        from llm_optimization import get_ai_tester
        t = get_ai_tester()
        if req.scene == "vuln_analysis":
            r = t.analyze_vulnerability(**req.payload)
        elif req.scene == "report_generation":
            r = t.generate_report(**req.payload)
        elif req.scene == "smart_qa":
            r = t.answer_question(**req.payload)
        else:
            return _err(f"未知场景: {req.scene}（可选: vuln_analysis/report_generation/smart_qa）")
        return _ok(r)
    except Exception as e:  # noqa: BLE001
        return _err(f"自定义测试异常: {e}")


# ---------------------------------------------------------------------------
# 端点 10：端到端测试
# ---------------------------------------------------------------------------
@router.post("/e2e-run", summary="端到端测试（3 个标准用例）")
async def e2e_run() -> Dict[str, Any]:
    try:
        from llm_optimization import get_e2e_runner
        r = get_e2e_runner().run_all()
        return _ok(r)
    except Exception as e:  # noqa: BLE001
        return _err(f"端到端测试异常: {e}")


# ---------------------------------------------------------------------------
# 端点 11：最近一次 e2e 结果
# ---------------------------------------------------------------------------
@router.get("/e2e-last", summary="最近一次端到端测试结果")
async def e2e_last() -> Dict[str, Any]:
    try:
        from llm_optimization import get_e2e_runner
        return _ok(get_e2e_runner().get_last_run())
    except Exception as e:  # noqa: BLE001
        return _err(f"读取 e2e 结果失败: {e}")


# ---------------------------------------------------------------------------
# 端点 12：调用历史
# ---------------------------------------------------------------------------
@router.get("/history", summary="AI 功能调用历史")
async def get_history(limit: int = 50) -> Dict[str, Any]:
    try:
        from llm_optimization.ai_function_tester import get_history as _gh
        return _ok({"items": _gh(limit=limit)})
    except Exception as e:  # noqa: BLE001
        return _err(f"读取历史失败: {e}")


# ---------------------------------------------------------------------------
# 端点 13：清空调用历史
# ---------------------------------------------------------------------------
@router.delete("/history", summary="清空调用历史")
async def clear_history() -> Dict[str, Any]:
    try:
        from llm_optimization.ai_function_tester import clear_history as _ch
        _ch()
        return _ok({"cleared": True})
    except Exception as e:  # noqa: BLE001
        return _err(f"清空历史失败: {e}")


# ---------------------------------------------------------------------------
# 端点 14：调用统计
# ---------------------------------------------------------------------------
@router.get("/stats", summary="调用统计")
async def get_stats() -> Dict[str, Any]:
    try:
        from llm_optimization import get_dashboard
        return _ok(get_dashboard().call_stats())
    except Exception as e:  # noqa: BLE001
        return _err(f"读取统计失败: {e}")


# ---------------------------------------------------------------------------
# 端点 15：健康检查
# ---------------------------------------------------------------------------
@router.post("/health-check", summary="LLM 连通性健康检查")
async def health_check() -> Dict[str, Any]:
    try:
        from llm_optimization import get_dashboard
        r = get_dashboard().health_check()
        if r.get("success"):
            return _ok(r)
        return _err(r.get("message", "健康检查失败"), r)
    except Exception as e:  # noqa: BLE001
        return _err(f"健康检查异常: {e}")


# ---------------------------------------------------------------------------
# 端点 16：热重载配置
# ---------------------------------------------------------------------------
@router.post("/reload", summary="热重载 LLM 配置（立即生效）")
async def reload_config() -> Dict[str, Any]:
    try:
        from llm_integration import reload_config as _rc, reset_llm_client
        _rc()
        reset_llm_client()
        # 同步重置我们自己的单例
        import llm_optimization.ai_function_tester as _aft
        import llm_optimization.llm_e2e_test as _e2e
        import llm_optimization.llm_dashboard as _dash
        _aft._tester = None
        _e2e._runner = None
        _dash._dash = None
        from llm_integration import get_config_manager
        return _ok({"reloaded": True, "status": get_config_manager().status()})
    except Exception as e:  # noqa: BLE001
        return _err(f"热重载失败: {e}")


# ---------------------------------------------------------------------------
# 端点 17：示例数据
# ---------------------------------------------------------------------------
@router.get("/sample-data", summary="示例测试数据")
async def sample_data() -> Dict[str, Any]:
    from llm_optimization.llm_e2e_test import (
        SAMPLE_VULN_DESCRIPTION, SAMPLE_TARGET, SAMPLE_VULNS,
        SAMPLE_QUESTION, SAMPLE_CONTEXT,
    )
    return _ok({
        "vuln_description": SAMPLE_VULN_DESCRIPTION,
        "target": SAMPLE_TARGET,
        "vulns": SAMPLE_VULNS,
        "question": SAMPLE_QUESTION,
        "context": SAMPLE_CONTEXT,
    })
