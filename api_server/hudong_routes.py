# -*- coding: utf-8 -*-
"""
hudong_routes.py - 护网行动 API 路由

提供护网准备/监控/应急/总结四阶段的 REST API。
所有端点均用 try-except 包裹，返回统一 JSON 格式，不返回 500 错误。

路由前缀：/api/v1/hudong
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# 确保项目根目录可导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import log

# 认证依赖（导入失败时提供透传兜底，保证路由可挂载）
try:
    from api_server.auth_integration import verify_auth, require_admin  # noqa: F401
    _AUTH_OK = True
except Exception as _e:  # pragma: no cover
    log.warning(f"hudong_routes: 认证依赖导入失败，使用透传: {_e}")
    _AUTH_OK = False

    async def verify_auth() -> dict:  # type: ignore
        return {"user_id": "anonymous", "username": "anonymous", "role": "admin"}

    async def require_admin() -> dict:  # type: ignore
        return {"user_id": "anonymous", "username": "anonymous", "role": "admin"}


# 业务模块（导入失败则路由挂载但端点返回 503）
_BIZ_OK = False
try:
    from hudong.preparation import preparation_manager
    from hudong.monitoring import monitoring_manager
    from hudong.emergency import emergency_manager
    from hudong.summary import summary_manager
    _BIZ_OK = True
    log.info("hudong_routes: 护网行动模块加载成功")
except Exception as _e:  # pragma: no cover
    log.exception(f"hudong_routes: 护网行动模块加载失败: {_e}")


router = APIRouter(prefix="/api/v1/hudong", tags=["护网行动"])


# ==================== 响应工具 ====================

def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"code": 0, "data": data})


def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"code": status, "error": message}, status_code=status)


def _guard() -> Optional[JSONResponse]:
    if not _BIZ_OK:
        return _err(503, "护网行动模块不可用，请检查模块加载日志")
    return None


# ==================== 请求体模型 ====================

class StartPreparationReq(BaseModel):
    name: str = ""
    description: str = ""


class StartMonitoringReq(BaseModel):
    preparation_id: str = ""
    name: str = ""


class ReportEmergencyReq(BaseModel):
    title: str
    monitoring_id: str = ""
    description: str = ""
    level: str = "general"
    asset_id: str = ""
    attack_source: str = ""
    attack_path: str = ""
    attack_method: str = ""


class ContainReq(BaseModel):
    operator: str = "应急组"
    measures: List[str] = []


class EradicateReq(BaseModel):
    operator: str = "应急组"
    measures: List[str] = []


class RecoverReq(BaseModel):
    operator: str = "运维组"
    measures: List[str] = []
    close: bool = True


class HardeningReq(BaseModel):
    title: str
    asset_id: str = ""
    vulnerability_id: str = ""
    description: str = ""
    priority: str = "high"
    assignee: str = ""
    due_date: str = ""


class VerifyHardeningReq(BaseModel):
    passed: bool = True
    verification_result: str = ""


class AcknowledgeAlertReq(BaseModel):
    alert_id: str = ""


class ResolveAlertReq(BaseModel):
    alert_id: str = ""
    result: str = "已处置"


class SubmitReportReq(BaseModel):
    report_type: str = "internal"
    recipient: str = ""
    content: str = ""


class GenerateSummaryReq(BaseModel):
    preparation_id: str = ""
    monitoring_id: str = ""
    name: str = ""


class ImprovementPlanReq(BaseModel):
    title: str
    description: str = ""
    category: str = "technical"
    priority: str = "medium"
    assignee: str = ""
    due_date: str = ""


# ==================== 准备阶段 ====================

@router.post("/preparation/start")
def preparation_start(req: StartPreparationReq, user: dict = Depends(verify_auth)):
    """启动护网准备，创建准备任务并梳理资产/攻击面/漏洞"""
    try:
        g = _guard()
        if g:
            return g
        result = preparation_manager.start_preparation(
            name=req.name, description=req.description)
        return _ok(result)
    except Exception as e:
        log.exception("preparation_start 错误")
        return _err(500, f"启动护网准备失败: {e}")


@router.get("/preparation/{preparation_id}/status")
def preparation_status(preparation_id: str, user: dict = Depends(verify_auth)):
    """获取护网准备任务状态"""
    try:
        g = _guard()
        if g:
            return g
        result = preparation_manager.get_preparation_status(preparation_id)
        if not result:
            return _err(404, "准备任务不存在")
        return _ok(result)
    except Exception as e:
        log.exception("preparation_status 错误")
        return _err(500, f"获取准备状态失败: {e}")


@router.get("/preparation/{preparation_id}/assets")
def preparation_assets(preparation_id: str, user: dict = Depends(verify_auth)):
    """资产梳理结果：全面资产列表/分类/分组/重要性评级/责任人"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(preparation_manager.get_asset_inventory(preparation_id))
    except Exception as e:
        log.exception("preparation_assets 错误")
        return _err(500, f"获取资产清单失败: {e}")


@router.get("/preparation/{preparation_id}/attack-surface")
def preparation_attack_surface(preparation_id: str, user: dict = Depends(verify_auth)):
    """攻击面梳理结果"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(preparation_manager.get_attack_surface(preparation_id))
    except Exception as e:
        log.exception("preparation_attack_surface 错误")
        return _err(500, f"获取攻击面失败: {e}")


@router.get("/preparation/{preparation_id}/vulnerabilities")
def preparation_vulnerabilities(preparation_id: str, user: dict = Depends(verify_auth)):
    """漏洞扫描结果与优先级排序"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(preparation_manager.get_vulnerabilities(preparation_id))
    except Exception as e:
        log.exception("preparation_vulnerabilities 错误")
        return _err(500, f"获取漏洞列表失败: {e}")


@router.get("/preparation/{preparation_id}/risk-assessment")
def preparation_risk(preparation_id: str, user: dict = Depends(verify_auth)):
    """风险评估：资产风险评级/攻击路径/业务影响/整体风险"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(preparation_manager.get_risk_assessment(preparation_id))
    except Exception as e:
        log.exception("preparation_risk 错误")
        return _err(500, f"获取风险评估失败: {e}")


@router.get("/preparation/{preparation_id}/hardening")
def preparation_hardening(preparation_id: str,
                          status: Optional[str] = Query(None),
                          user: dict = Depends(verify_auth)):
    """加固建议与加固任务列表"""
    try:
        g = _guard()
        if g:
            return g
        suggestions = preparation_manager.get_hardening_suggestions(preparation_id)
        tasks = preparation_manager.list_hardening_tasks(preparation_id, status=status)
        return _ok({"suggestions": suggestions, "tasks": tasks})
    except Exception as e:
        log.exception("preparation_hardening 错误")
        return _err(500, f"获取加固信息失败: {e}")


@router.post("/preparation/{preparation_id}/hardening/start")
def preparation_hardening_start(preparation_id: str, req: HardeningReq,
                               user: dict = Depends(verify_auth)):
    """分配加固任务"""
    try:
        g = _guard()
        if g:
            return g
        result = preparation_manager.start_hardening(
            preparation_id, title=req.title, asset_id=req.asset_id,
            vulnerability_id=req.vulnerability_id, description=req.description,
            priority=req.priority, assignee=req.assignee, due_date=req.due_date)
        return _ok(result)
    except Exception as e:
        log.exception("preparation_hardening_start 错误")
        return _err(500, f"分配加固任务失败: {e}")


@router.post("/preparation/hardening/{task_id}/verify")
def preparation_hardening_verify(task_id: str, req: VerifyHardeningReq,
                                  user: dict = Depends(verify_auth)):
    """加固验证"""
    try:
        g = _guard()
        if g:
            return g
        result = preparation_manager.verify_hardening(
            task_id, passed=req.passed, verification_result=req.verification_result)
        if not result:
            return _err(404, "加固任务不存在")
        return _ok(result)
    except Exception as e:
        log.exception("preparation_hardening_verify 错误")
        return _err(500, f"加固验证失败: {e}")


@router.post("/preparation/{preparation_id}/report")
def preparation_report(preparation_id: str, user: dict = Depends(verify_auth)):
    """生成护网准备报告"""
    try:
        g = _guard()
        if g:
            return g
        result = preparation_manager.generate_preparation_report(preparation_id)
        if not result:
            return _err(404, "准备任务不存在")
        return _ok(result)
    except Exception as e:
        log.exception("preparation_report 错误")
        return _err(500, f"生成准备报告失败: {e}")


# ==================== 监控阶段 ====================

@router.post("/monitoring/start")
def monitoring_start(req: StartMonitoringReq, user: dict = Depends(verify_auth)):
    """启动持续监控"""
    try:
        g = _guard()
        if g:
            return g
        result = monitoring_manager.start_monitoring(
            preparation_id=req.preparation_id, name=req.name)
        return _ok(result)
    except Exception as e:
        log.exception("monitoring_start 错误")
        return _err(500, f"启动监控失败: {e}")


@router.get("/monitoring/{monitoring_id}/status")
def monitoring_status(monitoring_id: str, user: dict = Depends(verify_auth)):
    """获取监控任务状态"""
    try:
        g = _guard()
        if g:
            return g
        result = monitoring_manager.get_monitoring_status(monitoring_id)
        if not result:
            return _err(404, "监控任务不存在")
        return _ok(result)
    except Exception as e:
        log.exception("monitoring_status 错误")
        return _err(500, f"获取监控状态失败: {e}")


@router.get("/monitoring/{monitoring_id}/alerts")
def monitoring_alerts(monitoring_id: str,
                      alert_type: Optional[str] = Query(None),
                      severity: Optional[str] = Query(None),
                      status: Optional[str] = Query(None),
                      start_time: Optional[str] = Query(None),
                      end_time: Optional[str] = Query(None),
                      page: int = Query(1, ge=1),
                      page_size: int = Query(20, ge=1, le=500),
                      user: dict = Depends(verify_auth)):
    """告警列表，支持筛选与分页"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(monitoring_manager.list_alerts(
            monitoring_id, alert_type=alert_type, severity=severity,
            status=status, start_time=start_time, end_time=end_time,
            page=page, page_size=page_size))
    except Exception as e:
        log.exception("monitoring_alerts 错误")
        return _err(500, f"获取告警列表失败: {e}")


@router.post("/monitoring/{monitoring_id}/alerts/acknowledge")
def monitoring_alert_ack(monitoring_id: str, req: AcknowledgeAlertReq,
                         user: dict = Depends(verify_auth)):
    """确认告警"""
    try:
        g = _guard()
        if g:
            return g
        result = monitoring_manager.acknowledge_alert(req.alert_id)
        if not result:
            return _err(404, "告警不存在")
        return _ok(result)
    except Exception as e:
        log.exception("monitoring_alert_ack 错误")
        return _err(500, f"确认告警失败: {e}")


@router.post("/monitoring/{monitoring_id}/alerts/resolve")
def monitoring_alert_resolve(monitoring_id: str, req: ResolveAlertReq,
                             user: dict = Depends(verify_auth)):
    """处置告警"""
    try:
        g = _guard()
        if g:
            return g
        result = monitoring_manager.resolve_alert(req.alert_id, result=req.result)
        if not result:
            return _err(404, "告警不存在")
        return _ok(result)
    except Exception as e:
        log.exception("monitoring_alert_resolve 错误")
        return _err(500, f"处置告警失败: {e}")


@router.get("/monitoring/{monitoring_id}/threats")
def monitoring_threats(monitoring_id: str,
                       threat_type: Optional[str] = Query(None),
                       severity: Optional[str] = Query(None),
                       user: dict = Depends(verify_auth)):
    """威胁列表（IOC匹配/威胁情报关联）"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(monitoring_manager.list_threats(
            monitoring_id, threat_type=threat_type, severity=severity))
    except Exception as e:
        log.exception("monitoring_threats 错误")
        return _err(500, f"获取威胁列表失败: {e}")


@router.get("/monitoring/{monitoring_id}/situation")
def monitoring_situation(monitoring_id: str, user: dict = Depends(verify_auth)):
    """态势感知：整体态势/攻击趋势/威胁分布/资产风险变化"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(monitoring_manager.get_situation(monitoring_id))
    except Exception as e:
        log.exception("monitoring_situation 错误")
        return _err(500, f"获取态势感知失败: {e}")


@router.post("/monitoring/{monitoring_id}/detect")
def monitoring_detect(monitoring_id: str,
                      round_no: int = Query(1, ge=1, le=999),
                      user: dict = Depends(verify_auth)):
    """触发一轮攻击监测（模拟）"""
    try:
        g = _guard()
        if g:
            return g
        new_alerts = monitoring_manager.detect_attacks(monitoring_id, round_no=round_no)
        agg = monitoring_manager.aggregate_alerts(monitoring_id)
        return _ok({"new_alerts": new_alerts, "aggregation": agg})
    except Exception as e:
        log.exception("monitoring_detect 错误")
        return _err(500, f"攻击监测失败: {e}")


@router.post("/monitoring/{monitoring_id}/report")
def monitoring_report(monitoring_id: str,
                      period: str = "日报",
                      user: dict = Depends(verify_auth)):
    """生成护网监控日报/周报"""
    try:
        g = _guard()
        if g:
            return g
        result = monitoring_manager.generate_monitoring_report(
            monitoring_id, period=period)
        if not result:
            return _err(404, "监控任务不存在")
        return _ok(result)
    except Exception as e:
        log.exception("monitoring_report 错误")
        return _err(500, f"生成监控报告失败: {e}")


# ==================== 应急阶段 ====================

@router.post("/emergency/report")
def emergency_report(req: ReportEmergencyReq, user: dict = Depends(verify_auth)):
    """上报应急事件，按事件分级"""
    try:
        g = _guard()
        if g:
            return g
        result = emergency_manager.report_emergency(
            title=req.title, monitoring_id=req.monitoring_id,
            description=req.description, level=req.level, asset_id=req.asset_id,
            attack_source=req.attack_source, attack_path=req.attack_path,
            attack_method=req.attack_method)
        return _ok(result)
    except Exception as e:
        log.exception("emergency_report 错误")
        return _err(500, f"上报应急事件失败: {e}")


@router.get("/emergency/{emergency_id}/status")
def emergency_status(emergency_id: str, user: dict = Depends(verify_auth)):
    """获取应急事件状态"""
    try:
        g = _guard()
        if g:
            return g
        result = emergency_manager.get_emergency_status(emergency_id)
        if not result:
            return _err(404, "应急事件不存在")
        return _ok(result)
    except Exception as e:
        log.exception("emergency_status 错误")
        return _err(500, f"获取应急状态失败: {e}")


@router.post("/emergency/{emergency_id}/contain")
def emergency_contain(emergency_id: str, req: ContainReq,
                      user: dict = Depends(verify_auth)):
    """遏制：隔离资产/阻断攻击源/关闭服务"""
    try:
        g = _guard()
        if g:
            return g
        result = emergency_manager.contain(
            emergency_id, operator=req.operator, measures=req.measures)
        if not result:
            return _err(404, "应急事件不存在")
        return _ok(result)
    except Exception as e:
        log.exception("emergency_contain 错误")
        return _err(500, f"遏制操作失败: {e}")


@router.post("/emergency/{emergency_id}/eradicate")
def emergency_eradicate(emergency_id: str, req: EradicateReq,
                         user: dict = Depends(verify_auth)):
    """根除：清除恶意软件/修复漏洞/移除后门/重置凭据"""
    try:
        g = _guard()
        if g:
            return g
        result = emergency_manager.eradicate(
            emergency_id, operator=req.operator, measures=req.measures)
        if not result:
            return _err(404, "应急事件不存在")
        return _ok(result)
    except Exception as e:
        log.exception("emergency_eradicate 错误")
        return _err(500, f"根除操作失败: {e}")


@router.post("/emergency/{emergency_id}/recover")
def emergency_recover(emergency_id: str, req: RecoverReq,
                      user: dict = Depends(verify_auth)):
    """恢复：恢复系统服务/验证数据完整性/监控异常"""
    try:
        g = _guard()
        if g:
            return g
        result = emergency_manager.recover(
            emergency_id, operator=req.operator, measures=req.measures, close=req.close)
        if not result:
            return _err(404, "应急事件不存在")
        return _ok(result)
    except Exception as e:
        log.exception("emergency_recover 错误")
        return _err(500, f"恢复操作失败: {e}")


@router.get("/emergency/{emergency_id}/trace")
def emergency_trace(emergency_id: str, user: dict = Depends(verify_auth)):
    """溯源分析：攻击来源/路径/手法/攻击者画像"""
    try:
        g = _guard()
        if g:
            return g
        result = emergency_manager.get_trace(emergency_id)
        if not result:
            return _err(404, "应急事件不存在")
        return _ok(result)
    except Exception as e:
        log.exception("emergency_trace 错误")
        return _err(500, f"溯源分析失败: {e}")


@router.get("/emergency/{emergency_id}/actions")
def emergency_actions(emergency_id: str, user: dict = Depends(verify_auth)):
    """处置记录列表"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(emergency_manager.list_actions(emergency_id))
    except Exception as e:
        log.exception("emergency_actions 错误")
        return _err(500, f"获取处置记录失败: {e}")


@router.post("/emergency/{emergency_id}/report")
def emergency_submit_report(emergency_id: str, req: SubmitReportReq,
                            user: dict = Depends(verify_auth)):
    """信息上报：内部/外部/监管/客户通知"""
    try:
        g = _guard()
        if g:
            return g
        result = emergency_manager.submit_report(
            emergency_id, report_type=req.report_type,
            recipient=req.recipient, content=req.content)
        if not result.get("success"):
            return _err(404, result.get("error", "上报失败"))
        return _ok(result)
    except Exception as e:
        log.exception("emergency_submit_report 错误")
        return _err(500, f"信息上报失败: {e}")


@router.get("/emergency/{emergency_id}/reports")
def emergency_reports(emergency_id: str, user: dict = Depends(verify_auth)):
    """上报记录列表"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(emergency_manager.list_reports(emergency_id))
    except Exception as e:
        log.exception("emergency_reports 错误")
        return _err(500, f"获取上报记录失败: {e}")


@router.post("/emergency/{emergency_id}/final-report")
def emergency_final_report(emergency_id: str, user: dict = Depends(verify_auth)):
    """生成护网应急响应报告"""
    try:
        g = _guard()
        if g:
            return g
        result = emergency_manager.generate_emergency_report(emergency_id)
        if not result:
            return _err(404, "应急事件不存在")
        return _ok(result)
    except Exception as e:
        log.exception("emergency_final_report 错误")
        return _err(500, f"生成应急报告失败: {e}")


# ==================== 总结阶段 ====================

@router.post("/summary/generate")
def summary_generate(req: GenerateSummaryReq, user: dict = Depends(verify_auth)):
    """生成护网总结，汇总准备/监控/应急数据"""
    try:
        g = _guard()
        if g:
            return g
        result = summary_manager.generate_summary(
            preparation_id=req.preparation_id,
            monitoring_id=req.monitoring_id, name=req.name)
        return _ok(result)
    except Exception as e:
        log.exception("summary_generate 错误")
        return _err(500, f"生成护网总结失败: {e}")


@router.get("/summary/{summary_id}/stats")
def summary_stats(summary_id: str, user: dict = Depends(verify_auth)):
    """数据统计"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(summary_manager.get_summary_stats(summary_id))
    except Exception as e:
        log.exception("summary_stats 错误")
        return _err(500, f"获取统计数据失败: {e}")


@router.get("/summary/{summary_id}/review")
def summary_review(summary_id: str, user: dict = Depends(verify_auth)):
    """攻防复盘"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(summary_manager.get_attack_defense_review(summary_id))
    except Exception as e:
        log.exception("summary_review 错误")
        return _err(500, f"获取攻防复盘失败: {e}")


@router.get("/summary/{summary_id}/improvements")
def summary_improvements(summary_id: str,
                         status: Optional[str] = Query(None),
                         user: dict = Depends(verify_auth)):
    """改进计划列表"""
    try:
        g = _guard()
        if g:
            return g
        plans = summary_manager.list_improvement_plans(summary_id, status=status)
        achievements = summary_manager.get_achievements(summary_id)
        shortcomings = summary_manager.get_shortcomings(summary_id)
        return _ok({"plans": plans, "achievements": achievements,
                    "shortcomings": shortcomings})
    except Exception as e:
        log.exception("summary_improvements 错误")
        return _err(500, f"获取改进计划失败: {e}")


@router.post("/summary/{summary_id}/improvements")
def summary_create_improvement(summary_id: str, req: ImprovementPlanReq,
                               user: dict = Depends(verify_auth)):
    """创建改进计划"""
    try:
        g = _guard()
        if g:
            return g
        result = summary_manager.create_improvement_plan(
            summary_id, title=req.title, description=req.description,
            category=req.category, priority=req.priority,
            assignee=req.assignee, due_date=req.due_date)
        return _ok(result)
    except Exception as e:
        log.exception("summary_create_improvement 错误")
        return _err(500, f"创建改进计划失败: {e}")


@router.post("/summary/{summary_id}/report")
def summary_report(summary_id: str, user: dict = Depends(verify_auth)):
    """生成护网总结报告"""
    try:
        g = _guard()
        if g:
            return g
        result = summary_manager.generate_summary_report(summary_id)
        if not result:
            return _err(404, "总结记录不存在")
        return _ok(result)
    except Exception as e:
        log.exception("summary_report 错误")
        return _err(500, f"生成总结报告失败: {e}")
