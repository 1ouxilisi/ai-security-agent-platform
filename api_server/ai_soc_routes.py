# -*- coding: utf-8 -*-
"""
AI 安全运营（AI SOC）API 路由
===================================

模块功能：
    - 异常检测 API（检测/状态/结果/报告）
    - 告警关联 API（关联/攻击链/聚合/报告）
    - 事件分类 API（分类/查询/自动分配/统计）
    - 根因分析 API（分析/结果/证据/报告）
    - 响应建议 API（建议/模板/验证/报告）
    - AI 助手 API（聊天/报告生成/知识检索）

统一 JSON 响应格式：{"success": bool, "data": ..., "error": ...}
所有端点用 try-except 包裹，不返回 500 错误。
本模块仅用于授权的安全运营与防御场景。
"""
import os
import sys
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

# 确保项目根目录在 sys.path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_soc.anomaly_detector import anomaly_detector
from ai_soc.alert_correlator import alert_correlator
from ai_soc.event_classifier import event_classifier
from ai_soc.root_cause_analyzer import root_cause_analyzer
from ai_soc.response_advisor import response_advisor
from ai_soc.soc_assistant import soc_assistant

router = APIRouter(prefix="/api/v1/ai-soc", tags=["AI安全运营"])


# ----------------------------------------------------------------------
# 统一响应工具
# ----------------------------------------------------------------------
def _ok(data: Any = None) -> Dict[str, Any]:
    """成功响应"""
    return {"success": True, "data": data, "error": None}


def _fail(message: str) -> Dict[str, Any]:
    """失败响应"""
    return {"success": False, "data": None, "error": message}


# ----------------------------------------------------------------------
# 请求体模型
# ----------------------------------------------------------------------
class DetectRequest(BaseModel):
    """异常检测请求"""
    traffic_data: Optional[Dict[str, Any]] = Field(default=None, description="流量数据")
    behavior_data: Optional[Dict[str, Any]] = Field(default=None, description="行为数据")
    performance_data: Optional[Dict[str, Any]] = Field(default=None, description="性能数据")
    log_data: Optional[Dict[str, Any]] = Field(default=None, description="日志数据")
    baseline: Optional[Dict[str, Any]] = Field(default=None, description="可选历史基线")


class CorrelateRequest(BaseModel):
    """告警关联请求"""
    alerts: List[Dict[str, Any]] = Field(default_factory=list, description="告警列表")


class ClassifyRequest(BaseModel):
    """事件分类请求"""
    event_id: Optional[str] = None
    title: Optional[str] = None
    message: Optional[str] = None
    impact_scope: int = 0
    asset_criticality: str = "low"
    data_sensitivity: str = "low"


class RootCauseRequest(BaseModel):
    """根因分析请求"""
    event_id: str
    logs: Optional[List[str]] = None
    topology: Optional[Dict[str, Any]] = None
    timeline: Optional[List[Dict[str, Any]]] = None


class ResponseAdviseRequest(BaseModel):
    """响应建议请求"""
    event_id: Optional[str] = None
    event_type: Optional[str] = None
    category: Optional[str] = None
    severity: str = "medium"
    impact_scope: int = 0
    business_impact: str = "low"
    attack_phase: str = "containment"


class VerifyRequest(BaseModel):
    """响应验证请求"""
    response_actions: List[str] = Field(default_factory=list, description="已执行的响应动作")


class ChatRequest(BaseModel):
    """助手聊天请求"""
    message: str
    context: Optional[Dict[str, Any]] = None


class ReportRequest(BaseModel):
    """助手报告生成请求"""
    report_type: str = "daily"
    params: Optional[Dict[str, Any]] = None


# ======================================================================
# 一、异常检测 API
# ======================================================================
@router.post("/anomaly/detect")
def anomaly_detect(req: DetectRequest):
    """启动异常检测，返回 task_id"""
    try:
        if req.baseline:
            anomaly_detector.learn_baseline(req.baseline)
        task_id = anomaly_detector.detect(
            traffic_data=req.traffic_data,
            behavior_data=req.behavior_data,
            performance_data=req.performance_data,
            log_data=req.log_data,
        )
        return _ok({"task_id": task_id})
    except Exception as e:
        return _fail(f"异常检测启动失败: {e}")


@router.get("/anomaly/{task_id}/status")
def anomaly_status(task_id: str):
    """异常检测任务状态"""
    try:
        return _ok(anomaly_detector.get_task_status(task_id))
    except Exception as e:
        return _fail(f"获取状态失败: {e}")


@router.get("/anomaly/{task_id}/results")
def anomaly_results(task_id: str):
    """异常检测结果"""
    try:
        return _ok(anomaly_detector.get_results(task_id))
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/anomaly/{task_id}/report")
def anomaly_report(task_id: str):
    """异常检测报告"""
    try:
        return _ok(anomaly_detector.generate_report(task_id))
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


# ======================================================================
# 二、告警关联 API
# ======================================================================
@router.post("/alert/correlate")
def alert_correlate(req: CorrelateRequest):
    """启动告警关联分析，返回 task_id"""
    try:
        task_id = alert_correlator.correlate(req.alerts)
        return _ok({"task_id": task_id})
    except Exception as e:
        return _fail(f"告警关联启动失败: {e}")


@router.get("/alert/{task_id}/attack-chains")
def alert_attack_chains(task_id: str):
    """攻击链识别结果"""
    try:
        return _ok(alert_correlator.get_attack_chains(task_id))
    except Exception as e:
        return _fail(f"获取攻击链失败: {e}")


@router.get("/alert/{task_id}/aggregated")
def alert_aggregated(task_id: str):
    """聚合告警"""
    try:
        return _ok(alert_correlator.get_aggregated(task_id))
    except Exception as e:
        return _fail(f"获取聚合告警失败: {e}")


@router.get("/alert/{task_id}/report")
def alert_report(task_id: str):
    """告警关联报告"""
    try:
        return _ok(alert_correlator.generate_report(task_id))
    except Exception as e:
        return _fail(f"生成关联报告失败: {e}")


# ======================================================================
# 三、事件分类 API
# ======================================================================
@router.post("/event/classify")
def event_classify(req: ClassifyRequest):
    """分类事件"""
    try:
        event_data = req.dict()
        result = event_classifier.classify(event_data)
        return _ok(result)
    except Exception as e:
        return _fail(f"事件分类失败: {e}")


@router.get("/event/stats")
def event_stats():
    """事件分类统计"""
    try:
        return _ok(event_classifier.get_stats())
    except Exception as e:
        return _fail(f"获取统计失败: {e}")


@router.get("/event/{event_id}/classification")
def event_classification(event_id: str):
    """获取事件分类结果"""
    try:
        return _ok(event_classifier.get_classification(event_id))
    except Exception as e:
        return _fail(f"获取分类结果失败: {e}")


@router.post("/event/{event_id}/auto-assign")
def event_auto_assign(event_id: str, severity: str = "medium"):
    """自动分配事件处理人员"""
    try:
        event = event_classifier.get_classification(event_id)
        event["severity"] = severity
        result = event_classifier.auto_assign(event)
        return _ok(result)
    except Exception as e:
        return _fail(f"自动分配失败: {e}")


# ======================================================================
# 四、根因分析 API
# ======================================================================
@router.post("/root-cause/analyze")
def root_cause_analyze(req: RootCauseRequest):
    """启动根因分析，返回 task_id"""
    try:
        task_id = root_cause_analyzer.analyze(
            event_id=req.event_id,
            logs=req.logs,
            topology=req.topology,
            timeline=req.timeline,
        )
        return _ok({"task_id": task_id})
    except Exception as e:
        return _fail(f"根因分析启动失败: {e}")


@router.get("/root-cause/{task_id}/results")
def root_cause_results(task_id: str):
    """根因分析结果"""
    try:
        return _ok(root_cause_analyzer.get_results(task_id))
    except Exception as e:
        return _fail(f"获取根因结果失败: {e}")


@router.get("/root-cause/{task_id}/evidence")
def root_cause_evidence(task_id: str):
    """证据列表"""
    try:
        return _ok(root_cause_analyzer.get_evidence(task_id))
    except Exception as e:
        return _fail(f"获取证据失败: {e}")


@router.get("/root-cause/{task_id}/report")
def root_cause_report(task_id: str):
    """根因分析报告"""
    try:
        return _ok(root_cause_analyzer.generate_report(task_id))
    except Exception as e:
        return _fail(f"生成根因报告失败: {e}")


# ======================================================================
# 五、响应建议 API
# ======================================================================
@router.post("/response/advise")
def response_advise(req: ResponseAdviseRequest):
    """生成响应建议"""
    try:
        advice = response_advisor.advise(req.dict())
        return _ok(advice)
    except Exception as e:
        return _fail(f"生成响应建议失败: {e}")


@router.get("/response/{event_id}/templates")
def response_templates(event_id: str, event_type: Optional[str] = Query(None)):
    """获取响应模板"""
    try:
        return _ok(response_advisor.get_templates(event_type))
    except Exception as e:
        return _fail(f"获取模板失败: {e}")


@router.post("/response/{event_id}/verify")
def response_verify(event_id: str, req: VerifyRequest):
    """验证响应执行效果"""
    try:
        return _ok(response_advisor.verify_response(event_id, req.response_actions))
    except Exception as e:
        return _fail(f"响应验证失败: {e}")


@router.get("/response/{event_id}/report")
def response_report(event_id: str):
    """响应建议报告"""
    try:
        return _ok(response_advisor.generate_report(event_id))
    except Exception as e:
        return _fail(f"生成响应报告失败: {e}")


# ======================================================================
# 六、AI 助手 API
# ======================================================================
@router.post("/assistant/chat")
def assistant_chat(req: ChatRequest):
    """AI 助手聊天"""
    try:
        return _ok(soc_assistant.chat(req.message, req.context))
    except Exception as e:
        return _fail(f"助手聊天失败: {e}")


@router.post("/assistant/generate-report")
def assistant_generate_report(req: ReportRequest):
    """生成安全运营报告"""
    try:
        return _ok(soc_assistant.generate_report(req.report_type, req.params))
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/assistant/knowledge/search")
def assistant_knowledge_search(query: str = Query("", description="检索关键词")):
    """知识检索"""
    try:
        return _ok(soc_assistant.search_knowledge(query))
    except Exception as e:
        return _fail(f"知识检索失败: {e}")
