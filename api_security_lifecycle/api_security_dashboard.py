#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_security_lifecycle/api_security_dashboard.py — API 安全生命周期控制台数据聚合层。

聚合 7 大模块的数据，提供统一的总览、模块汇总、系统设置接口。
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from .api_assets import get_api_assets
from .design_security import get_design_security
from .dev_security import get_dev_security
from .runtime_security import get_runtime_security
from .abuse_logic import get_abuse_logic
from .governance_compliance import get_governance_compliance


# 系统设置
SYSTEM_SETTINGS: Dict[str, Any] = {
    "platform_name": "API 安全全生命周期管理平台",
    "version": "29.3.0",
    "data_retention_days": 90,
    "auto_discovery_enabled": True,
    "threat_blocking_enabled": True,
    "alert_channels": ["webhook", "email"],
    "default_rate_limit_rpm": 600,
    "session_timeout_minutes": 30,
    "log_level": "info",
}


class APISecurityDashboard:
    """API 安全生命周期数据聚合层。"""

    def __init__(self) -> None:
        self.assets = get_api_assets()
        self.design = get_design_security()
        self.dev = get_dev_security()
        self.runtime = get_runtime_security()
        self.abuse = get_abuse_logic()
        self.governance = get_governance_compliance()

    def overview(self) -> Dict[str, Any]:
        """全局总览数据。"""
        asset_catalog = self.assets.api_catalog()
        health = self.assets.health_overview()
        inv = self.assets.asset_inventory()
        threat = self.runtime.threat_overview()
        abuse_alerts = self.abuse.list_abuse_alerts()
        flaw_ov = self.abuse.flaw_overview()
        comp_ov = self.governance.compliance_overview()
        maturity = self.governance.get_maturity()

        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "platform": SYSTEM_SETTINGS["platform_name"],
            "version": SYSTEM_SETTINGS["version"],
            "assets": {
                "total_apis": asset_catalog["total"],
                "stable": asset_catalog["by_status"].get("stable", 0),
                "deprecated": asset_catalog["by_status"].get("deprecated", 0),
                "compliance_score": inv["compliance_score"],
            },
            "health": {
                "avg_score": health["avg_score"],
                "healthy": health["healthy"],
                "degraded": health["degraded"],
                "critical": health["critical"],
            },
            "threat": {
                "total_events": threat["total_events"],
                "by_category": threat["by_category"],
            },
            "abuse": {
                "open_alerts": sum(1 for a in abuse_alerts if a["status"] == "open"),
                "total_alerts": len(abuse_alerts),
            },
            "logic_flaws": {
                "total_findings": flaw_ov["total_findings"],
                "critical": flaw_ov.get("critical_count", 0),
            },
            "compliance": {
                "avg_score": comp_ov["avg_score"],
                "assessments": comp_ov["total_assessments"],
            },
            "maturity": maturity.get("maturity_name", "未评估"),
            "security_score": round(
                (health["avg_score"] * 0.25 +
                 inv["compliance_score"] * 0.25 +
                 (comp_ov["avg_score"] if comp_ov["total_assessments"] > 0 else 70) * 0.25 +
                 (100 - min(100, flaw_ov.get("critical_count", 0) * 10)) * 0.25),
                1),
        }

    def summary_by_module(self) -> Dict[str, Any]:
        """按模块汇总。"""
        return {
            "api_assets": {
                "apis": len(self.assets.apis),
                "dependencies": sum(len(d) for d in self.assets.dependencies.values()),
                "discoveries": len(self.assets.discoveries),
            },
            "design_security": {
                "specs": len(self.design.specs),
                "auth_configs": len(self.design.auth_configs),
                "schemas": len(self.design.schemas),
                "reviews": len(self.design.reviews),
                "error_codes": len(self.design.error_catalog),
            },
            "dev_security": {
                "keys": len(self.dev.keys),
                "versions": len(self.dev.versions),
                "pipelines": len(self.dev.pipelines),
                "test_runs": len(self.dev.test_runs),
                "docs": len(self.dev.docs),
            },
            "runtime_security": {
                "routes": len(self.runtime.routes),
                "rate_limit_rules": len(self.runtime.rate_limit_rules),
                "threat_events": len(self.runtime.threat_events),
                "alert_rules": len(self.runtime.alert_rules),
                "metrics_services": len(self.runtime.metrics),
            },
            "abuse_logic": {
                "abuse_alerts": len(self.abuse.abuse_alerts),
                "logic_flaws": len(self.abuse.logic_flaws),
                "bot_records": len(self.abuse.bot_records),
                "tiers": len(self.abuse.quotas),
                "security_events": len(self.abuse.security_events),
            },
            "governance_compliance": {
                "policies": len(self.governance.policies),
                "assessments": len(self.governance.compliance_assessments),
                "audit_logs": len(self.governance.audit_logs),
                "reports": len(self.governance.reports),
                "maturity_assessed": bool(self.governance.maturity_assessment),
            },
        }

    def get_settings(self) -> Dict[str, Any]:
        return dict(SYSTEM_SETTINGS)

    def update_settings(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in fields.items():
            if k in SYSTEM_SETTINGS:
                SYSTEM_SETTINGS[k] = v
        return dict(SYSTEM_SETTINGS)


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_dashboard: Optional[APISecurityDashboard] = None


def get_api_security_dashboard() -> APISecurityDashboard:
    global _dashboard
    if _dashboard is None:
        _dashboard = APISecurityDashboard()
    return _dashboard
