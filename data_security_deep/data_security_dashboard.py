#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
data_security_dashboard.py — 数据安全控制台聚合引擎（Round24 方向3）。

覆盖：
    1. 数据安全总览：资产数/分类分级覆盖率/敏感数据量/风险事件/合规评分/安全趋势
    2. 数据资产管理：资产发现/分类/分级/地图/目录/生命周期
    3. 防护管理：DLP策略/加密策略/脱敏策略/访问控制/审批流程/水印策略
    4. 隐私合规：合规框架/评估/数据主体权利/同意管理/隐私政策/培训
    5. 监控告警：访问监控/异常检测/泄漏事件/告警规则/通知/统计
    6. 系统设置：分类分级标准/防护策略/合规配置/通知/审计/权限配置

设计定位：聚合各子引擎数据，提供统一控制台视图，纯内存模拟。
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from data_security_deep.data_classification import get_classification_engine
from data_security_deep.dlp_engine import get_dlp_engine
from data_security_deep.privacy_compute import get_privacy_compute_engine
from data_security_deep.access_audit import get_access_audit_engine
from data_security_deep.privacy_compliance import get_privacy_compliance_manager


# 控制台指标定义
DASHBOARD_METRICS: Dict[str, Dict[str, Any]] = {
    "total_assets": {"name": "数据资产总数", "unit": "个", "icon": "database"},
    "classification_coverage": {"name": "分类分级覆盖率", "unit": "%", "icon": "tag"},
    "sensitive_data_volume": {"name": "敏感数据量", "unit": "GB", "icon": "alert"},
    "risk_events": {"name": "风险事件数", "unit": "起", "icon": "warning"},
    "compliance_score": {"name": "合规评分", "unit": "分", "icon": "shield"},
    "dlp_policy_count": {"name": "DLP策略数", "unit": "条", "icon": "filter"},
    "encryption_rate": {"name": "加密覆盖率", "unit": "%", "icon": "lock"},
    "open_alerts": {"name": "未处理告警", "unit": "条", "icon": "bell"},
}

# 系统设置项
SYSTEM_SETTINGS: Dict[str, Dict[str, Any]] = {
    "classification_standard": {
        "name": "分类分级标准", "current": "四级分类(L1-L4)",
        "options": ["四级分类(L1-L4)", "三级分类(L1-L3)", "自定义"],
    },
    "dlp_mode": {
        "name": "DLP运行模式", "current": "balanced",
        "options": ["strict", "balanced", "permissive"],
    },
    "encryption_default": {
        "name": "默认加密算法", "current": "aes-256-gcm",
        "options": ["aes-256-gcm", "aes-256-cbc", "sm4"],
    },
    "retention_days": {
        "name": "审计日志保留天数", "current": 180,
        "options": [90, 180, 365],
    },
    "alert_channels": {
        "name": "告警通知渠道", "current": ["email", "sms", "webhook"],
        "options": ["email", "sms", "webhook", "im"],
    },
    "session_timeout": {
        "name": "管理会话超时(分钟)", "current": 30,
        "options": [15, 30, 60],
    },
}


class DataSecurityDashboard:
    """数据安全控制台聚合器"""

    def __init__(self) -> None:
        self.classification = get_classification_engine()
        self.dlp = get_dlp_engine()
        self.privacy = get_privacy_compute_engine()
        self.audit = get_access_audit_engine()
        self.compliance = get_privacy_compliance_manager()
        self.alerts: Dict[str, Dict[str, Any]] = {}
        self.settings: Dict[str, Any] = {k: v["current"] for k, v in SYSTEM_SETTINGS.items()}
        self._seed_alerts()

    def _seed_alerts(self) -> None:
        samples = [
            {"level": "critical", "title": "检测到绝密数据外发尝试", "source": "DLP"},
            {"level": "high", "title": "非工作时间批量导出", "source": "审计"},
            {"level": "medium", "title": "同意记录过期", "source": "合规"},
        ]
        for s in samples:
            aid = f"alert-{uuid.uuid4().hex[:8]}"
            self.alerts[aid] = {
                "alert_id": aid, **s,
                "status": "open",
                "time": datetime.now().isoformat(timespec="seconds"),
            }

    # ---------- 1. 数据安全总览 ----------
    def get_overview(self) -> Dict[str, Any]:
        """总览仪表盘"""
        cls_stats = self.classification.stats()
        dlp_stats = self.dlp.stats()
        pc_stats = self.privacy.stats()
        audit_stats = self.audit.stats()
        comp_stats = self.compliance.stats()
        open_alerts = sum(1 for a in self.alerts.values() if a["status"] == "open")
        return {
            "total_assets": cls_stats["total_assets"],
            "classification_coverage": cls_stats["classification_coverage"],
            "sensitive_data_volume": round(cls_stats["total_assets"] * 2.4, 1),
            "risk_events": dlp_stats["open_events"],
            "compliance_score": 82.5,
            "dlp_policies": dlp_stats["policies_total"],
            "encryption_rate": 94.2,
            "open_alerts": open_alerts,
            "open_anomalies": audit_stats["anomaly_alerts"],
            "consent_active": comp_stats["consents"],
            "frameworks_active": comp_stats["frameworks"],
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }

    def get_security_trend(self, days: int = 14) -> List[Dict[str, Any]]:
        """安全趋势（模拟）"""
        trend = []
        for i in range(days):
            trend.append({
                "day": f"D-{days - i}",
                "events": 3 + (i * 2) % 8,
                "alerts": 2 + (i * 3) % 6,
                "blocked": 1 + (i * 5) % 4,
                "coverage": 70 + i * 1.5,
            })
        return trend

    # ---------- 2. 数据资产管理视图 ----------
    def get_asset_view(self) -> Dict[str, Any]:
        return {
            "classification": self.classification.stats(),
            "map": self.classification.get_data_map(),
            "templates": len(self.classification.get_templates()),
            "lineage": self.classification.get_data_lineage(),
            "flow": self.classification.get_data_flow(),
        }

    # ---------- 3. 防护管理视图 ----------
    def get_protection_view(self) -> Dict[str, Any]:
        return {
            "dlp_policies": self.dlp.list_policies(),
            "encryption_policies": self.privacy.stats(),
            "masking_methods": list(self.privacy.get_masking_methods().keys()),
            "watermarks": len(self.privacy.list_watermarks()),
            "access_control": self.audit.stats(),
            "approval_pending": len([r for r in self.audit.list_requests() if r["status"] == "pending"]),
            "anti_abuse": self.audit.get_anti_abuse_policies(),
        }

    # ---------- 4. 隐私合规视图 ----------
    def get_compliance_view(self) -> Dict[str, Any]:
        return {
            "frameworks": self.compliance.list_frameworks(),
            "ropa_count": len(self.compliance.list_ropa()),
            "dsr_pending": len([r for r in self.compliance.list_dsr("received")]),
            "consent_audit": self.compliance.consent_audit(),
            "policies": self.compliance.list_policies(),
            "trainings": self.compliance.list_trainings(),
            "rights": self.compliance.list_rights(),
        }

    # ---------- 5. 监控告警视图 ----------
    def get_monitoring_view(self) -> Dict[str, Any]:
        return {
            "dlp_events": self.dlp.event_statistics(),
            "dlp_trend": self.dlp.event_trend(),
            "anomaly_alerts": list(self.alerts.values()),
            "anomaly_rules": self.audit.list_anomaly_rules(),
            "audit_logs_count": len(self.audit.audit_logs) if hasattr(self.audit, "audit_logs") else 0,
            "log_channels": self.dlp.get_channels(),
        }

    # ---------- 6. 系统设置 ----------
    def get_settings(self) -> Dict[str, Any]:
        return {
            "settings": self.settings,
            "definitions": SYSTEM_SETTINGS,
        }

    def update_setting(self, key: str, value: Any) -> Dict[str, Any]:
        if key not in SYSTEM_SETTINGS:
            return {"error": f"未知设置项: {key}"}
        self.settings[key] = value
        return {"key": key, "value": value, "updated": True}

    def get_settings_schema(self) -> Dict[str, Any]:
        return SYSTEM_SETTINGS

    # ---------- 告警 ----------
    def list_alerts(self, level: Optional[str] = None,
                   status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.alerts.values())
        if level:
            items = [a for a in items if a["level"] == level]
        if status:
            items = [a for a in items if a["status"] == status]
        return items

    def resolve_alert(self, alert_id: str, resolution: str = "已处理") -> Dict[str, Any]:
        if alert_id not in self.alerts:
            return {"error": "告警不存在"}
        self.alerts[alert_id]["status"] = "resolved"
        self.alerts[alert_id]["resolution"] = resolution
        self.alerts[alert_id]["resolved_at"] = datetime.now().isoformat(timespec="seconds")
        return {"alert_id": alert_id, "status": "resolved"}

    # ---------- 健康检查 ----------
    def health(self) -> Dict[str, Any]:
        return {
            "module": "data_security_deep_dashboard",
            "status": "healthy",
            "engines": {
                "classification": self.classification.stats(),
                "dlp": self.dlp.stats(),
                "privacy_compute": self.privacy.stats(),
                "access_audit": self.audit.stats(),
                "privacy_compliance": self.compliance.stats(),
            },
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }

    def stats(self) -> Dict[str, Any]:
        return {
            "metrics_defined": len(DASHBOARD_METRICS),
            "alerts": len(self.alerts),
            "settings_items": len(self.settings),
            "engines_integrated": 5,
        }


_instance: Optional[DataSecurityDashboard] = None


def get_dashboard() -> DataSecurityDashboard:
    global _instance
    if _instance is None:
        _instance = DataSecurityDashboard()
    return _instance
