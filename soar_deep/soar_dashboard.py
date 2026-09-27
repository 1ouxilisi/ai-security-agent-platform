#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar_deep/soar_dashboard.py — SOAR 深度管理控制台数据层。

聚合 6 大视图：
    1. SOAR总览：剧本数/执行次数/成功率/平均执行时间/自动化率/告警处理量/响应时间趋势
    2. 剧本管理：列表/详情/编辑/版本/测试/执行/调度
    3. 动作管理：动作库/分类/配置/测试/版本/市场
    4. 告警管理：列表/详情/分诊/聚合/丰富化/响应/统计
    5. 案例管理：列表/详情/协作/时间线/知识库/分析
    6. 系统设置：触发器/连接器/变量/权限/通知/审计/SLA配置
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .playbook_engine import get_playbook_engine
from .response_actions import get_action_executor, ACTION_REGISTRY, ACTION_CATEGORIES
from .alert_triage import get_alert_triage
from .case_management import get_case_manager
from .threat_intel_integration import get_threat_intel


# --------------------------------------------------------------------------- #
# 系统设置
# --------------------------------------------------------------------------- #
SYSTEM_SETTINGS: Dict[str, Dict[str, Any]] = {
    "triggers": {
        "alert_trigger_enabled": True,
        "webhook_trigger_enabled": True,
        "schedule_trigger_enabled": True,
        "manual_trigger_enabled": True,
        "auto_start_on_alert": True,
        "auto_start_severity": "high",
    },
    "connectors": {
        "siem_connected": True,
        "edr_connected": True,
        "firewall_connected": True,
        "waf_connected": True,
        "iam_connected": True,
        "cloud_connected": False,
        "ticketing_connected": True,
        "im_connected": True,
    },
    "variables": {
        "global_var_count": 5,
        "env_var_count": 6,
        "secret_count": 3,
        "dynamic_var_count": 0,
    },
    "permissions": {
        "roles": ["admin", "operator", "analyst", "viewer"],
        "auto_response_roles": ["admin", "operator"],
        "approval_required_roles": ["admin"],
        "audit_all_actions": True,
    },
    "notification": {
        "email_enabled": True,
        "sms_enabled": False,
        "im_enabled": True,
        "im_channel": "soc-alerts",
        "notify_on_critical": True,
        "notify_on_high": False,
        "digest_hourly": True,
    },
    "audit": {
        "audit_log_retention_days": 365,
        "audit_all_playbook_executions": True,
        "audit_all_action_executions": True,
        "audit_config_changes": True,
        "export_enabled": True,
    },
    "sla": {
        "P0_response_minutes": 15,
        "P0_resolution_hours": 4,
        "P1_response_minutes": 60,
        "P1_resolution_hours": 24,
        "P2_response_hours": 4,
        "P2_resolution_hours": 72,
        "P3_response_hours": 24,
        "P3_resolution_hours": 168,
        "escalation_after_minutes": 30,
    },
}


# --------------------------------------------------------------------------- #
# 仪表盘聚合器
# --------------------------------------------------------------------------- #
class SOARDashboard:
    """SOAR 控制台数据聚合器。"""

    def __init__(self) -> None:
        self.pb_engine = get_playbook_engine()
        self.action_exec = get_action_executor()
        self.triage = get_alert_triage()
        self.case_mgr = get_case_manager()
        self.intel = get_threat_intel()

    # ---- 1. 总览 ----
    def overview(self) -> Dict[str, Any]:
        pb_stats = self.pb_engine.stats()
        action_stats = self.action_exec.stats()
        alert_stats = self.triage.stats()
        case_stats = self.case_mgr.analytics()
        intel_stats = self.intel.quality_report()

        # 模拟趋势数据（最近7天）
        trend = []
        base = 100
        for i in range(7):
            day = time.strftime("%m-%d", time.localtime(time.time() - (6 - i) * 86400))
            trend.append({
                "date": day,
                "alerts": base + i * 15 + (i * i * 3),
                "automated_responses": int(base * 0.6) + i * 10,
                "cases": 5 + i,
            })

        return {
            "playbooks": {
                "total": pb_stats["total_playbooks"],
                "published": pb_stats["published"],
                "draft": pb_stats["draft"],
            },
            "executions": {
                "total": pb_stats["total_instances"],
                "running": pb_stats["running"],
                "completed": pb_stats["completed"],
                "failed": pb_stats["failed"],
                "success_rate": pb_stats["success_rate"],
            },
            "actions": {
                "defined": action_stats["total_actions_defined"],
                "executed": action_stats["total_executed"],
                "failed": action_stats["total_failed"],
                "success_rate": action_stats["success_rate"],
            },
            "alerts": {
                "total": alert_stats["total_alerts"],
                "ingested": alert_stats["ingested"],
                "deduplicated": alert_stats["deduplicated"],
                "triaged": alert_stats["triaged"],
                "enriched": alert_stats["enriched"],
            },
            "cases": {
                "total": case_stats["total_cases"],
                "open": case_stats["open_cases"],
                "closed": case_stats["closed_cases"],
                "resolution_rate": case_stats["resolution_rate"],
            },
            "threat_intel": {
                "indicators": intel_stats["total_indicators"],
                "active": intel_stats["active"],
                "avg_confidence": intel_stats["avg_confidence"],
            },
            "automation_rate": round(
                action_stats["total_executed"] / max(1, alert_stats["total_alerts"]) * 100, 1),
            "response_time_avg_min": 12.5,
            "trend_7d": trend,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---- 2. 剧本管理视图 ----
    def playbook_view(self) -> Dict[str, Any]:
        return {
            "playbooks": self.pb_engine.list_playbooks(),
            "node_types": self.pb_engine.list_node_types(),
            "trigger_types": self.pb_engine.list_trigger_types(),
            "data_functions": self.pb_engine.list_data_functions(),
            "stats": self.pb_engine.stats(),
        }

    # ---- 3. 动作管理视图 ----
    def action_view(self) -> Dict[str, Any]:
        return {
            "actions": self.action_exec.list_actions(),
            "categories": self.action_exec.list_categories(),
            "history": self.action_exec.get_history(limit=20),
            "stats": self.action_exec.stats(),
        }

    # ---- 4. 告警管理视图 ----
    def alert_view(self) -> Dict[str, Any]:
        return {
            "alerts": self.triage.list_alerts(limit=50),
            "sources": self.triage.list_sources(),
            "stats": self.triage.stats(),
        }

    # ---- 5. 案例管理视图 ----
    def case_view(self) -> Dict[str, Any]:
        return {
            "cases": self.case_mgr.list_cases(),
            "templates": self.case_mgr.list_templates(),
            "knowledge_base": self.case_mgr.search_knowledge(),
            "analytics": self.case_mgr.analytics(),
        }

    # ---- 6. 系统设置视图 ----
    def settings_view(self) -> Dict[str, Any]:
        return {
            "settings": SYSTEM_SETTINGS,
            "variable_manager": self.pb_engine.var_mgr.to_dict(),
            "intel_sources": self.intel.list_sources(),
            "ioc_types": self.intel.list_ioc_types(),
        }

    # ---- 威胁情报视图 ----
    def intel_view(self) -> Dict[str, Any]:
        return {
            "indicators": self.intel.list_indicators(),
            "sources": self.intel.list_sources(),
            "ioc_types": self.intel.list_ioc_types(),
            "threat_actors": self.intel.list_threat_actors(),
            "quality": self.intel.quality_report(),
            "match_history": self.intel.match_history[-20:],
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_dashboard: Optional[SOARDashboard] = None


def get_soar_dashboard() -> SOARDashboard:
    global _dashboard
    if _dashboard is None:
        _dashboard = SOARDashboard()
    return _dashboard
