#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
integrations_routes 模块，提供集成生态管理 REST API。

模块功能：
    - SIEM / 工单 / 通知渠道 / LDAP / 漏洞库 五大集成的配置与操作接口
    - 所有端点 try-except 包裹，异常时返回 success=False 而非 500

注意事项：
    - 本模块仅用于授权的安全运营场景
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import os
import sys
from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrations.siem_connector import siem_connector
from integrations.ticket_connector import ticket_connector
from integrations.notification_channels import notification_manager
from integrations.ldap_auth import ldap_auth
from integrations.vuln_db_sync import vuln_db_sync


router = APIRouter(prefix="/api/v1/integrations", tags=["集成管理"])


# ==================== 请求模型 ====================

class ConfigBody(BaseModel):
    """通用配置更新请求体。"""
    config: Dict[str, Any] = Field(default_factory=dict, description="待合并的配置")


class TicketCreateBody(BaseModel):
    """创建工单请求体。"""
    vuln_data: Dict[str, Any] = Field(default_factory=dict, description="漏洞数据")
    summary: Optional[str] = Field(None, description="自定义工单标题")


class NotificationSendBody(BaseModel):
    """发送通知请求体。"""
    alert: Dict[str, Any] = Field(default_factory=dict, description="告警数据")
    channels: Optional[list] = Field(None, description="指定渠道列表")


class VulnSyncBody(BaseModel):
    """漏洞库同步请求体。"""
    source: str = Field("nvd", description="nvd / cnvd / incremental")
    keyword: Optional[str] = Field(None, description="NVD 关键字")
    cve_id: Optional[str] = Field(None, description="指定 CVE ID")
    max_results: int = Field(100, description="最大条数")


# ==================== SIEM 路由 ====================

@router.get("/siem/config", summary="获取 SIEM 配置")
def get_siem_config():
    try:
        return {"success": True, "config": siem_connector.config}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.put("/siem/config", summary="更新 SIEM 配置")
def put_siem_config(body: ConfigBody):
    try:
        return {"success": True, "config": siem_connector.update_config(body.config)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/siem/test", summary="测试 SIEM 连接")
def test_siem():
    try:
        return siem_connector.test_connection()
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/siem/push-test", summary="推送测试告警到 SIEM")
def push_test_siem():
    try:
        return siem_connector.send_alert({
            "title": "SIEM 连通性测试",
            "message": "AI Hacking Agent SIEM 推送测试消息",
            "severity": "info",
            "target": "test",
        })
    except Exception as e:
        return {"success": False, "error": str(e)}


# ==================== 工单路由 ====================

@router.get("/ticket/config", summary="获取工单系统配置")
def get_ticket_config():
    try:
        return {"success": True, "config": ticket_connector.config}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.put("/ticket/config", summary="更新工单系统配置")
def put_ticket_config(body: ConfigBody):
    try:
        return {"success": True, "config": ticket_connector.update_config(body.config)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/ticket/test", summary="测试工单系统连接")
def test_ticket():
    try:
        return ticket_connector.test_connection()
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/ticket/create", summary="自动创建漏洞工单")
def create_ticket(body: TicketCreateBody):
    try:
        return ticket_connector.create_vulnerability_ticket(body.vuln_data)
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/ticket/{ticket_id}/sync", summary="同步工单状态")
def sync_ticket(ticket_id: str):
    try:
        return ticket_connector.sync_ticket_status(ticket_id)
    except Exception as e:
        return {"success": False, "error": str(e)}


# ==================== 通知渠道路由 ====================

@router.get("/notification/channels", summary="获取通知渠道状态")
def get_notification_channels():
    try:
        return notification_manager.get_channel_status()
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.put("/notification/{channel}/config", summary="更新通知渠道配置")
def put_notification_config(channel: str, body: ConfigBody):
    try:
        cfg = notification_manager.update_channel_config(channel, body.config)
        return {"success": True, "channel": channel, "config": cfg}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/notification/{channel}/test", summary="发送渠道测试消息")
def test_notification(channel: str):
    try:
        return notification_manager.send_test(channel)
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/notification/send", summary="推送告警到通知渠道")
def send_notification(body: NotificationSendBody):
    try:
        return notification_manager.send_alert(body.alert, channels=body.channels)
    except Exception as e:
        return {"success": False, "error": str(e)}


# ==================== LDAP 路由 ====================

@router.get("/ldap/config", summary="获取 LDAP 配置")
def get_ldap_config():
    try:
        return {"success": True, "config": ldap_auth.config,
                "ldap_lib_available": ldap_auth.LDAP_AVAILABLE if hasattr(ldap_auth, "LDAP_AVAILABLE") else None}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.put("/ldap/config", summary="更新 LDAP 配置")
def put_ldap_config(body: ConfigBody):
    try:
        return {"success": True, "config": ldap_auth.update_config(body.config)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/ldap/test", summary="测试 LDAP 连接")
def test_ldap():
    try:
        return ldap_auth.test_connection()
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/ldap/sync-users", summary="查看已同步的 LDAP 用户")
def sync_ldap_users():
    try:
        return ldap_auth.list_synced_users()
    except Exception as e:
        return {"success": False, "error": str(e)}


# ==================== 漏洞库路由 ====================

@router.post("/vuln-db/sync", summary="触发漏洞库同步")
def sync_vuln_db(body: VulnSyncBody):
    try:
        if body.source == "cnvd":
            return vuln_db_sync.sync_cnvd(max_results=body.max_results)
        if body.source == "incremental":
            return vuln_db_sync.incremental_sync()
        # 默认 NVD
        return vuln_db_sync.sync_nvd(
            keyword=body.keyword, cve_id=body.cve_id, max_results=body.max_results)
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/vuln-db/status", summary="获取漏洞库同步状态")
def vuln_db_status():
    try:
        return vuln_db_sync.get_sync_status()
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/vuln-db/stats", summary="获取漏洞库统计")
def vuln_db_stats():
    try:
        return vuln_db_sync.get_stats()
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/vuln-db/search", summary="本地漏洞库搜索")
def search_vuln_db(keyword: str = "", severity: Optional[str] = None):
    try:
        return vuln_db_sync.search_local(keyword, severity=severity)
    except Exception as e:
        return {"success": False, "error": str(e)}
