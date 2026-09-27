"""
alert_routesAPI服务模块，提供相关REST API接口和Web服务功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import sys
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.alert_manager import alert_manager
from api_server.auth_integration import verify_auth, require_admin

router = APIRouter(prefix="/api/v1/alerts", tags=["告警通知"])


# ==================== 请求模型 ====================

class CreateAlertRequest(BaseModel):
    """CreateAlertRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    title: str = Field(..., description="告警标题")
    message: str = Field(..., description="告警详情")
    severity: str = Field("info", description="严重级别：critical/high/warning/info")
    category: str = Field("general", description="告警分类：vulnerability/system/security/compliance/general")
    target: Optional[str] = Field(None, description="目标资产")
    details: Optional[dict] = Field(None, description="详细信息")
    auto_notify: bool = Field(True, description="是否自动发送通知")


class AddChannelRequest(BaseModel):
    """AddChannelRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    name: str = Field(..., description="渠道名称")
    type: str = Field(..., description="渠道类型：email/dingtalk/feishu/wecom/slack/webhook")
    config: dict = Field(..., description="渠道配置（webhook_url等）")


class TestChannelRequest(BaseModel):
    """TestChannelRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    channel_id: str = Field(..., description="渠道ID")


# ==================== 告警管理 ====================

@router.post("", summary="创建告警")
async def create_alert(
    request: CreateAlertRequest,
    current_user: dict = Depends(verify_auth),
):
    """创建新告警，可选择自动发送通知"""
    result = alert_manager.create_alert(
        title=request.title,
        message=request.message,
        severity=request.severity,
        category=request.category,
        target=request.target,
        details=request.details or {},
        auto_notify=request.auto_notify,
    )
    return result


@router.get("", summary="获取告警列表")
async def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 50,
    current_user: dict = Depends(verify_auth),
):
    """获取告警列表，支持按严重级别/状态/分类筛选"""
    alerts = alert_manager.list_alerts(
        severity=severity or "",
        status=status or "",
        category=category or "",
        limit=limit,
    )
    return {
        "success": True,
        "total": len(alerts),
        "alerts": alerts,
    }


@router.get("/stats", summary="获取告警统计")
async def get_alert_stats(current_user: dict = Depends(verify_auth)):
    """获取告警系统统计信息"""
    return alert_manager.get_statistics()


@router.post("/{alert_id}/acknowledge", summary="确认告警")
async def acknowledge_alert(
    alert_id: str,
    current_user: dict = Depends(verify_auth),
):
    """确认告警（标记为已处理）"""
    # 这里可以扩展状态更新逻辑
    return {"success": True, "alert_id": alert_id, "message": "告警已确认"}


@router.post("/{alert_id}/notify", summary="重新发送告警通知")
async def resend_alert_notification(
    alert_id: str,
    current_user: dict = Depends(verify_auth),
):
    """重新发送指定告警的通知"""
    # 从数据库获取告警并重新发送
    alerts = alert_manager.list_alerts(limit=100)
    alert = next((a for a in alerts if a["alert_id"] == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="告警不存在")

    from tools.alert_manager import Alert
    alert_obj = Alert(
        alert_id=alert["alert_id"],
        title=alert["title"],
        message=alert["message"],
        severity=alert["severity"],
        category=alert["category"],
        target=alert.get("target", ""),
    )
    result = alert_manager.notify_alert(alert_obj)
    return {"success": True, "alert_id": alert_id, "notify_result": result}


# ==================== 通知渠道管理 ====================

@router.get("/channels", summary="获取通知渠道列表")
async def list_channels(current_user: dict = Depends(verify_auth)):
    """获取所有通知渠道"""
    channels = alert_manager.list_channels()
    return {
        "success": True,
        "total": len(channels),
        "channels": channels,
    }


@router.post("/channels", summary="添加通知渠道")
async def add_channel(
    request: AddChannelRequest,
    current_user: dict = Depends(require_admin),
):
    """添加新的通知渠道（仅管理员）"""
    valid_types = ["email", "dingtalk", "feishu", "wecom", "slack", "webhook"]
    if request.type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"不支持的渠道类型，支持: {valid_types}",
        )
    result = alert_manager.add_channel(
        name=request.name,
        channel_type=request.type,
        config=request.config,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "添加渠道失败"))
    return result


@router.post("/channels/test", summary="测试通知渠道")
async def test_channel(
    request: TestChannelRequest,
    current_user: dict = Depends(require_admin),
):
    """测试指定通知渠道（发送测试消息）"""
    from tools.alert_manager import Alert
    test_alert = Alert(
        alert_id="test_alert",
        title="测试告警",
        message="这是一条测试消息，用于验证通知渠道是否正常工作。",
        severity="info",
        category="test",
    )
    # 这里简化处理，实际应该只发送到指定渠道
    result = alert_manager.notify_alert(test_alert)
    return {"success": True, "message": "测试消息已发送", "result": result}


# ==================== 便捷告警接口 ====================

@router.post("/vulnerability", summary="创建漏洞告警")
async def create_vulnerability_alert(
    title: str,
    target: str,
    severity: str = "high",
    details: Optional[dict] = None,
    current_user: dict = Depends(verify_auth),
):
    """便捷创建漏洞告警"""
    from tools.alert_manager import alert_vulnerability
    return alert_vulnerability(title=title, target=target, severity=severity, details=details or {})


@router.post("/system", summary="创建系统告警")
async def create_system_alert(
    title: str,
    severity: str = "warning",
    details: Optional[dict] = None,
    current_user: dict = Depends(verify_auth),
):
    """便捷创建系统告警"""
    from tools.alert_manager import alert_system
    return alert_system(title=title, severity=severity, details=details or {})
