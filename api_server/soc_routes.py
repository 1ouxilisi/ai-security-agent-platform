"""
SOC安全运营中心 API路由

模块功能：
    - 安全事件 / 告警 / 工单 / 应急响应 / 仪表盘 的REST接口
    - 统一JSON响应包装 {"success": bool, "data": ..., "error": ...}
    - 所有端点均包裹try-except，不返回500

合法定位：
    本路由仅服务于防御性安全运营。

注意事项：
    - 本模块仅用于授权的安全运营
    - 请勿用于非法用途
"""
import os
import sys
from typing import Optional, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api_server.auth_integration import verify_auth
from soc.incident_manager import incident_manager
from soc.alert_manager import alert_manager
from soc.ticket_manager import ticket_manager
from soc.incident_response import incident_response
from soc.soc_dashboard import soc_dashboard
from utils.logger import log

router = APIRouter(prefix="/api/v1/soc", tags=["SOC安全运营"])


# ==================== 请求模型 ====================

class IncidentCreateRequest(BaseModel):
    """创建事件请求体"""
    title: str = Field(..., description="事件标题")
    description: str = Field("", description="事件描述")
    severity: str = Field("medium", description="严重级别 critical/high/medium/low/info")
    category: str = Field("other", description="事件分类")
    source: str = Field("manual", description="来源")
    asset_id: Optional[str] = Field(None, description="关联资产ID")
    vulnerability_id: Optional[str] = Field(None, description="关联漏洞ID")
    assigned_to: Optional[str] = Field(None, description="指派处理人")
    tenant_id: str = Field("default", description="租户ID")


class IncidentUpdateRequest(BaseModel):
    """更新事件请求体"""
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    category: Optional[str] = None
    source: Optional[str] = None
    asset_id: Optional[str] = None
    vulnerability_id: Optional[str] = None
    assigned_to: Optional[str] = None


class AssignRequest(BaseModel):
    """指派请求体"""
    assignee: str = Field(..., description="处理人")
    operator: str = Field("system", description="操作人")


class EscalateRequest(BaseModel):
    """升级请求体"""
    reason: str = Field("", description="升级原因")
    operator: str = Field("system", description="操作人")


class AlertCreateRequest(BaseModel):
    """创建告警请求体"""
    title: str
    description: str = ""
    severity: str = "medium"
    source: str = "manual"
    rule_id: Optional[str] = None
    asset_id: Optional[str] = None
    incident_id: Optional[str] = None
    aggregation_key: Optional[str] = None
    tenant_id: str = "default"


class AlertUpdateRequest(BaseModel):
    """更新告警请求体"""
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    source: Optional[str] = None
    rule_id: Optional[str] = None
    incident_id: Optional[str] = None
    asset_id: Optional[str] = None


class RuleCreateRequest(BaseModel):
    """创建告警规则请求体"""
    name: str
    description: str = ""
    condition: dict = Field(default_factory=dict)
    threshold: int = 1
    severity: str = "medium"
    notification_channels: List[str] = Field(default_factory=list)
    suppression_rules: List[dict] = Field(default_factory=list)
    enabled: bool = True


class TicketCreateRequest(BaseModel):
    """创建工单请求体"""
    title: str
    description: str = ""
    priority: str = "medium"
    type: str = "other"
    incident_id: Optional[str] = None
    vulnerability_id: Optional[str] = None
    assigned_to: Optional[str] = None
    created_by: str = "system"
    due_date: Optional[str] = None
    tenant_id: str = "default"
    auto_assign: bool = True


class TicketUpdateRequest(BaseModel):
    """更新工单请求体"""
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    type: Optional[str] = None
    incident_id: Optional[str] = None
    vulnerability_id: Optional[str] = None
    assigned_to: Optional[str] = None
    due_date: Optional[str] = None


class TicketAssignRequest(BaseModel):
    """工单分配请求体"""
    assignee: Optional[str] = None
    operator: str = "system"
    strategy: str = "auto"


class CommentRequest(BaseModel):
    """工单评论请求体"""
    content: str
    author: str = "system"
    mentions: List[str] = Field(default_factory=list)


class PlanCreateRequest(BaseModel):
    """创建应急预案请求体"""
    name: str
    incident_type: str = "other"
    severity: str = "medium"
    steps: List[str] = Field(default_factory=list)
    responsible_roles: List[str] = Field(default_factory=list)
    communication_templates: dict = Field(default_factory=dict)


class StartResponseRequest(BaseModel):
    """启动应急响应请求体"""
    plan_id: Optional[str] = None
    assignee: str = "soc_oncall"


class EvidenceRequest(BaseModel):
    """证据采集请求体"""
    evidence_type: str = Field(..., description="日志/快照/内存/网络流量")
    description: str = ""
    file_path: str = ""
    hash: str = ""
    collected_by: str = "system"


class ExerciseCreateRequest(BaseModel):
    """应急演练请求体"""
    name: str
    exercise_type: str = "tabletop"
    scenario: str = ""
    participants: List[str] = Field(default_factory=list)
    result: str = ""
    improvement_actions: List[str] = Field(default_factory=list)


# ==================== 统一响应工具 ====================

def _ok(data=None) -> dict:
    """成功响应"""
    return {"success": True, "data": data, "error": None}


def _err(msg: str) -> dict:
    """失败响应"""
    log.error(f"SOC API错误: {msg}")
    return {"success": False, "data": None, "error": msg}


# ==================== 安全事件 ====================

# 注意：静态路径必须先于 /{id} 声明，避免被路径参数捕获

@router.get("/incidents/stats", summary="事件统计")
async def list_incident_stats(
    days: int = 30,
    tenant_id: Optional[str] = None,
    current_user: dict = Depends(verify_auth),
):
    """事件多维度统计"""
    try:
        return _ok(incident_manager.get_incident_stats(days=days, tenant_id=tenant_id))
    except Exception as e:
        return _err(f"获取事件统计失败: {e}")


@router.get("/incidents", summary="事件列表")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    keyword: Optional[str] = None,
    assigned_to: Optional[str] = None,
    tenant_id: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    current_user: dict = Depends(verify_auth),
):
    """事件列表，支持筛选/分页/搜索"""
    try:
        data = incident_manager.list_incidents(
            status=status, severity=severity, category=category, source=source,
            start_time=start_time, end_time=end_time, keyword=keyword,
            assigned_to=assigned_to, tenant_id=tenant_id,
            page=page, page_size=page_size,
        )
        return _ok(data)
    except Exception as e:
        return _err(f"获取事件列表失败: {e}")


@router.post("/incidents", summary="创建事件")
async def create_incident(
    req: IncidentCreateRequest,
    current_user: dict = Depends(verify_auth),
):
    """创建安全事件"""
    try:
        data = incident_manager.create_incident(
            title=req.title, description=req.description, severity=req.severity,
            category=req.category, source=req.source, asset_id=req.asset_id,
            vulnerability_id=req.vulnerability_id, assigned_to=req.assigned_to,
            tenant_id=req.tenant_id,
            operator=current_user.get("username", "system"),
        )
        return _ok(data)
    except Exception as e:
        return _err(f"创建事件失败: {e}")


@router.get("/incidents/{incident_id}", summary="事件详情")
async def get_incident(
    incident_id: str,
    current_user: dict = Depends(verify_auth),
):
    """获取事件详情"""
    try:
        data = incident_manager.get_incident(incident_id)
        if not data:
            return _err("事件不存在")
        return _ok(data)
    except Exception as e:
        return _err(f"获取事件详情失败: {e}")


@router.put("/incidents/{incident_id}", summary="更新事件")
async def update_incident(
    incident_id: str,
    req: IncidentUpdateRequest,
    current_user: dict = Depends(verify_auth),
):
    """更新事件字段"""
    try:
        fields = {k: v for k, v in req.dict().items() if v is not None}
        data = incident_manager.update_incident(
            incident_id, operator=current_user.get("username", "system"), **fields
        )
        if not data:
            return _err("事件不存在")
        return _ok(data)
    except Exception as e:
        return _err(f"更新事件失败: {e}")


@router.delete("/incidents/{incident_id}", summary="删除事件")
async def delete_incident(
    incident_id: str,
    current_user: dict = Depends(verify_auth),
):
    """删除事件"""
    try:
        ok = incident_manager.delete_incident(incident_id)
        return _ok({"deleted": ok}) if ok else _err("事件不存在")
    except Exception as e:
        return _err(f"删除事件失败: {e}")


@router.post("/incidents/{incident_id}/assign", summary="指派事件")
async def assign_incident(
    incident_id: str,
    req: AssignRequest,
    current_user: dict = Depends(verify_auth),
):
    """指派事件处理人"""
    try:
        data = incident_manager.assign_incident(
            incident_id, req.assignee, operator=current_user.get("username", req.operator)
        )
        return _ok(data) if data else _err("事件不存在")
    except Exception as e:
        return _err(f"指派事件失败: {e}")


@router.post("/incidents/{incident_id}/escalate", summary="升级事件")
async def escalate_incident(
    incident_id: str,
    req: EscalateRequest,
    current_user: dict = Depends(verify_auth),
):
    """升级事件严重级别"""
    try:
        data = incident_manager.escalate_incident(
            incident_id, reason=req.reason,
            operator=current_user.get("username", req.operator),
        )
        return _ok(data) if data else _err("事件不存在")
    except Exception as e:
        return _err(f"升级事件失败: {e}")


@router.get("/incidents/{incident_id}/timeline", summary="事件时间线")
async def get_incident_timeline(
    incident_id: str,
    current_user: dict = Depends(verify_auth),
):
    """获取事件完整时间线"""
    try:
        return _ok(incident_manager.get_incident_timeline(incident_id))
    except Exception as e:
        return _err(f"获取事件时间线失败: {e}")


# ==================== 告警 ====================

@router.get("/alerts/rules", summary="告警规则列表")
async def list_alert_rules(
    enabled_only: bool = False,
    current_user: dict = Depends(verify_auth),
):
    """列出告警规则"""
    try:
        return _ok(alert_manager.list_rules(enabled_only=enabled_only))
    except Exception as e:
        return _err(f"获取告警规则失败: {e}")


@router.post("/alerts/rules", summary="创建告警规则")
async def create_alert_rule(
    req: RuleCreateRequest,
    current_user: dict = Depends(verify_auth),
):
    """创建告警规则"""
    try:
        data = alert_manager.create_rule(
            name=req.name, description=req.description, condition=req.condition,
            threshold=req.threshold, severity=req.severity,
            notification_channels=req.notification_channels,
            suppression_rules=req.suppression_rules, enabled=req.enabled,
        )
        return _ok(data)
    except Exception as e:
        return _err(f"创建告警规则失败: {e}")


@router.get("/alerts/stats", summary="告警统计")
async def alert_stats(
    days: int = 7,
    current_user: dict = Depends(verify_auth),
):
    """告警多维度统计"""
    try:
        return _ok(alert_manager.get_alert_stats(days=days))
    except Exception as e:
        return _err(f"获取告警统计失败: {e}")


@router.get("/alerts", summary="告警列表")
async def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    rule_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    keyword: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    current_user: dict = Depends(verify_auth),
):
    """告警列表，支持筛选/分页/搜索"""
    try:
        data = alert_manager.list_alerts(
            status=status, severity=severity, source=source, rule_id=rule_id,
            asset_id=asset_id, start_time=start_time, end_time=end_time,
            keyword=keyword, page=page, page_size=page_size,
        )
        return _ok(data)
    except Exception as e:
        return _err(f"获取告警列表失败: {e}")


@router.post("/alerts", summary="创建告警")
async def create_alert(
    req: AlertCreateRequest,
    current_user: dict = Depends(verify_auth),
):
    """创建告警"""
    try:
        data = alert_manager.create_alert(
            title=req.title, description=req.description, severity=req.severity,
            source=req.source, rule_id=req.rule_id, asset_id=req.asset_id,
            incident_id=req.incident_id, aggregation_key=req.aggregation_key,
            tenant_id=req.tenant_id,
        )
        return _ok(data)
    except Exception as e:
        return _err(f"创建告警失败: {e}")


@router.get("/alerts/{alert_id}", summary="告警详情")
async def get_alert(
    alert_id: str,
    current_user: dict = Depends(verify_auth),
):
    """获取告警详情"""
    try:
        data = alert_manager.get_alert(alert_id)
        return _ok(data) if data else _err("告警不存在")
    except Exception as e:
        return _err(f"获取告警详情失败: {e}")


@router.put("/alerts/{alert_id}", summary="更新告警")
async def update_alert(
    alert_id: str,
    req: AlertUpdateRequest,
    current_user: dict = Depends(verify_auth),
):
    """更新告警"""
    try:
        fields = {k: v for k, v in req.dict().items() if v is not None}
        data = alert_manager.update_alert(alert_id, **fields)
        return _ok(data) if data else _err("告警不存在")
    except Exception as e:
        return _err(f"更新告警失败: {e}")


@router.post("/alerts/{alert_id}/acknowledge", summary="确认告警")
async def acknowledge_alert(
    alert_id: str,
    current_user: dict = Depends(verify_auth),
):
    """确认告警"""
    try:
        data = alert_manager.acknowledge_alert(
            alert_id, operator=current_user.get("username", "system")
        )
        return _ok(data) if data else _err("告警不存在")
    except Exception as e:
        return _err(f"确认告警失败: {e}")


@router.post("/alerts/{alert_id}/suppress", summary="抑制告警")
async def suppress_alert(
    alert_id: str,
    reason: str = "",
    current_user: dict = Depends(verify_auth),
):
    """抑制告警"""
    try:
        data = alert_manager.suppress_alert(
            alert_id, operator=current_user.get("username", "system"), reason=reason
        )
        return _ok(data) if data else _err("告警不存在")
    except Exception as e:
        return _err(f"抑制告警失败: {e}")


# ==================== 工单 ====================

@router.get("/tickets/templates", summary="工单模板列表")
async def list_ticket_templates(
    current_user: dict = Depends(verify_auth),
):
    """列出工单模板"""
    try:
        return _ok(ticket_manager.list_templates())
    except Exception as e:
        return _err(f"获取工单模板失败: {e}")


@router.get("/tickets/stats", summary="工单统计")
async def ticket_stats(
    current_user: dict = Depends(verify_auth),
):
    """工单多维度统计"""
    try:
        return _ok(ticket_manager.get_ticket_stats())
    except Exception as e:
        return _err(f"获取工单统计失败: {e}")


@router.get("/tickets", summary="工单列表")
async def list_tickets(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    type: Optional[str] = None,
    assigned_to: Optional[str] = None,
    incident_id: Optional[str] = None,
    keyword: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    current_user: dict = Depends(verify_auth),
):
    """工单列表，支持筛选/分页/搜索"""
    try:
        data = ticket_manager.list_tickets(
            status=status, priority=priority, ticket_type=type,
            assigned_to=assigned_to, incident_id=incident_id, keyword=keyword,
            page=page, page_size=page_size,
        )
        return _ok(data)
    except Exception as e:
        return _err(f"获取工单列表失败: {e}")


@router.post("/tickets", summary="创建工单")
async def create_ticket(
    req: TicketCreateRequest,
    current_user: dict = Depends(verify_auth),
):
    """创建工单"""
    try:
        data = ticket_manager.create_ticket(
            title=req.title, description=req.description, priority=req.priority,
            ticket_type=req.type, incident_id=req.incident_id,
            vulnerability_id=req.vulnerability_id, assigned_to=req.assigned_to,
            created_by=req.created_by, due_date=req.due_date,
            tenant_id=req.tenant_id, auto_assign=req.auto_assign,
        )
        return _ok(data)
    except Exception as e:
        return _err(f"创建工单失败: {e}")


@router.get("/tickets/{ticket_id}", summary="工单详情")
async def get_ticket(
    ticket_id: str,
    current_user: dict = Depends(verify_auth),
):
    """获取工单详情（含评论）"""
    try:
        ticket = ticket_manager.get_ticket(ticket_id)
        if not ticket:
            return _err("工单不存在")
        ticket["comments"] = ticket_manager.list_comments(ticket_id)
        return _ok(ticket)
    except Exception as e:
        return _err(f"获取工单详情失败: {e}")


@router.put("/tickets/{ticket_id}", summary="更新工单")
async def update_ticket(
    ticket_id: str,
    req: TicketUpdateRequest,
    current_user: dict = Depends(verify_auth),
):
    """更新工单"""
    try:
        fields = {k: v for k, v in req.dict().items() if v is not None}
        data = ticket_manager.update_ticket(
            ticket_id, operator=current_user.get("username", "system"), **fields
        )
        return _ok(data) if data else _err("工单不存在")
    except Exception as e:
        return _err(f"更新工单失败: {e}")


@router.post("/tickets/{ticket_id}/assign", summary="分配工单")
async def assign_ticket(
    ticket_id: str,
    req: TicketAssignRequest,
    current_user: dict = Depends(verify_auth),
):
    """分配工单（自动/轮询/指定人）"""
    try:
        data = ticket_manager.assign_ticket(
            ticket_id, assignee=req.assignee,
            operator=current_user.get("username", req.operator),
            strategy=req.strategy,
        )
        return _ok(data) if data else _err("工单不存在")
    except Exception as e:
        return _err(f"分配工单失败: {e}")


@router.post("/tickets/{ticket_id}/comment", summary="工单评论")
async def add_ticket_comment(
    ticket_id: str,
    req: CommentRequest,
    current_user: dict = Depends(verify_auth),
):
    """添加工单评论"""
    try:
        data = ticket_manager.add_comment(
            ticket_id, content=req.content,
            author=current_user.get("username", req.author),
            mentions=req.mentions,
        )
        return _ok(data)
    except Exception as e:
        return _err(f"添加评论失败: {e}")


# ==================== 应急响应 ====================

@router.get("/incident-response/plans", summary="应急预案列表")
async def list_plans(
    incident_type: Optional[str] = None,
    current_user: dict = Depends(verify_auth),
):
    """列出应急预案"""
    try:
        return _ok(incident_response.list_plans(incident_type=incident_type))
    except Exception as e:
        return _err(f"获取预案列表失败: {e}")


@router.post("/incident-response/plans", summary="创建应急预案")
async def create_plan(
    req: PlanCreateRequest,
    current_user: dict = Depends(verify_auth),
):
    """创建应急预案"""
    try:
        data = incident_response.create_plan(
            name=req.name, incident_type=req.incident_type, severity=req.severity,
            steps=req.steps, responsible_roles=req.responsible_roles,
            communication_templates=req.communication_templates,
        )
        return _ok(data)
    except Exception as e:
        return _err(f"创建预案失败: {e}")


@router.post("/incident-response/{incident_id}/start", summary="启动应急响应")
async def start_response(
    incident_id: str,
    req: StartResponseRequest,
    current_user: dict = Depends(verify_auth),
):
    """为事件启动NIST应急响应流程"""
    try:
        data = incident_response.start_response(
            incident_id, plan_id=req.plan_id, assignee=req.assignee
        )
        return _ok(data)
    except Exception as e:
        return _err(f"启动应急响应失败: {e}")


@router.get("/incident-response/{incident_id}/tasks", summary="响应任务列表")
async def get_response_tasks(
    incident_id: str,
    current_user: dict = Depends(verify_auth),
):
    """获取事件的响应任务"""
    try:
        return _ok(incident_response.get_response_tasks(incident_id))
    except Exception as e:
        return _err(f"获取响应任务失败: {e}")


@router.post("/incident-response/{incident_id}/tasks/{task_id}/complete",
             summary="完成响应任务")
async def complete_response_task(
    incident_id: str,
    task_id: str,
    current_user: dict = Depends(verify_auth),
):
    """标记响应任务完成"""
    try:
        data = incident_response.complete_task(
            incident_id, task_id,
            operator=current_user.get("username", "system"),
        )
        return _ok(data) if data else _err("任务不存在或不属于该事件")
    except Exception as e:
        return _err(f"完成响应任务失败: {e}")


@router.post("/incident-response/{incident_id}/evidence", summary="采集证据")
async def collect_evidence(
    incident_id: str,
    req: EvidenceRequest,
    current_user: dict = Depends(verify_auth),
):
    """为事件采集响应证据"""
    try:
        data = incident_response.collect_evidence(
            incident_id, evidence_type=req.evidence_type,
            description=req.description, file_path=req.file_path,
            hash_value=req.hash,
            collected_by=current_user.get("username", req.collected_by),
        )
        return _ok(data)
    except Exception as e:
        return _err(f"采集证据失败: {e}")


@router.post("/incident-response/{incident_id}/report", summary="生成复盘报告")
async def generate_debrief(
    incident_id: str,
    current_user: dict = Depends(verify_auth),
):
    """生成事件复盘报告"""
    try:
        return _ok(incident_response.generate_debrief_report(incident_id))
    except Exception as e:
        return _err(f"生成复盘报告失败: {e}")


# ==================== 仪表盘 ====================

@router.get("/dashboard/overview", summary="仪表盘概览")
async def dashboard_overview(
    current_user: dict = Depends(verify_auth),
):
    """实时概览：活跃事件/告警/工单/今日新增/MTTR"""
    try:
        return _ok(soc_dashboard.get_overview())
    except Exception as e:
        return _err(f"获取概览失败: {e}")


@router.get("/dashboard/trends", summary="事件/告警趋势")
async def dashboard_trends(
    days: int = 14,
    current_user: dict = Depends(verify_auth),
):
    """事件趋势 + 告警趋势"""
    try:
        return _ok({
            "incidents": soc_dashboard.get_incident_trends(days=days),
            "alerts": soc_dashboard.get_alert_trends(days=min(days, 7)),
            "tickets": soc_dashboard.get_ticket_board(),
            "risk_heatmap": soc_dashboard.get_risk_heatmap(),
        })
    except Exception as e:
        return _err(f"获取趋势失败: {e}")


@router.get("/dashboard/sla", summary="SLA合规率")
async def dashboard_sla(
    current_user: dict = Depends(verify_auth),
):
    """工单SLA合规率 + 事件响应时间达标率"""
    try:
        return _ok(soc_dashboard.get_sla_compliance())
    except Exception as e:
        return _err(f"获取SLA数据失败: {e}")


@router.get("/dashboard/mttr", summary="MTTR/MTTD")
async def dashboard_mttr(
    days: int = 30,
    current_user: dict = Depends(verify_auth),
):
    """平均检测时间/响应时间/解决时间"""
    try:
        return _ok(soc_dashboard.get_mttr_mttd(days=days))
    except Exception as e:
        return _err(f"获取MTTR数据失败: {e}")
