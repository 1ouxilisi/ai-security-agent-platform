#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mobile_security_dashboard.py — 移动安全深度控制台数据聚合层（第29轮升级方向2）。

聚合 Android / iOS / 鸿蒙三大引擎 + 漏洞POC + 隐私合规 + 测试评测，
提供统一控制台视图：总览 / 平台分布 / 漏洞热力 / 合规概览 / 告警 / 系统设置。
纯内存聚合。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from mobile_security_deep.android_deep import get_android_engine
from mobile_security_deep.ios_deep import get_ios_engine
from mobile_security_deep.harmonyos_deep import get_harmonyos_engine
from mobile_security_deep.mobile_vuln_poc import get_vuln_poc_engine
from mobile_security_deep.privacy_compliance import get_privacy_engine
from mobile_security_deep.mobile_test_eval import get_test_eval_engine


DASHBOARD_METRICS: Dict[str, Dict[str, Any]] = {
    "apps_tracked": {"name": "受管应用数", "unit": "个", "icon": "mobile"},
    "vulns_total": {"name": "漏洞总数", "unit": "条", "icon": "bug"},
    "critical_open": {"name": "未修严重漏洞", "unit": "条", "icon": "alert"},
    "compliance_score": {"name": "隐私合规均分", "unit": "分", "icon": "shield"},
    "sdks_detected": {"name": "检测到的第三方SDK", "unit": "个", "icon": "code"},
    "open_alerts": {"name": "待处理告警", "unit": "条", "icon": "bell"},
}

SYSTEM_SETTINGS: Dict[str, Dict[str, Any]] = {
    "scan_mode": {"name": "扫描模式", "current": "deep",
                  "options": ["fast", "deep", "full"]},
    "auto_scan": {"name": "自动定时扫描", "current": True, "options": [True, False]},
    "privacy_mode": {"name": "隐私保护等级", "current": "strict",
                     "options": ["strict", "balanced", "permissive"]},
    "report_format": {"name": "报告导出格式", "current": "html",
                      "options": ["html", "pdf", "xlsx", "json"]},
    "notify_channel": {"name": "告警通知渠道", "current": ["email", "webhook"],
                       "options": ["email", "sms", "webhook", "im"]},
}


class MobileSecurityDashboard:
    """移动安全深度控制台聚合器。"""

    def __init__(self) -> None:
        self.android = get_android_engine()
        self.ios = get_ios_engine()
        self.harmonyos = get_harmonyos_engine()
        self.vuln = get_vuln_poc_engine()
        self.privacy = get_privacy_engine()
        self.test_eval = get_test_eval_engine()
        self.alerts: Dict[str, Dict[str, Any]] = {}
        self.settings: Dict[str, Any] = {k: v["current"] for k, v in SYSTEM_SETTINGS.items()}
        self._seed_alerts()

    def _seed_alerts(self) -> None:
        samples = [
            {"level": "critical", "title": "检测到高危移动漏洞 Stagefright 影响版本", "source": "漏洞库"},
            {"level": "high", "title": "App 存在硬编码 AWS AccessKey", "source": "代码扫描"},
            {"level": "medium", "title": "隐私政策未披露数据跨境", "source": "合规"},
            {"level": "high", "title": "Meta/Firebase SDK 触发跨境传输待评估", "source": "SDK合规"},
        ]
        for s in samples:
            aid = f"alrt-{uuid.uuid4().hex[:8]}"
            self.alerts[aid] = {
                "alert_id": aid, **s, "status": "open",
                "time": datetime.now().isoformat(timespec="seconds"),
            }

    def get_overview(self) -> Dict[str, Any]:
        vs = self.vuln.stats()
        ps = self.privacy.stats()
        crit = sum(1 for v in self.vuln.list_vulns() if v["severity"] == "critical")
        open_alerts = sum(1 for a in self.alerts.values() if a["status"] == "open")
        return {
            "apps_tracked": 128,
            "vulns_total": vs["vulns_in_db"],
            "critical_open": crit,
            "compliance_score": 82.5,
            "sdks_detected": ps["known_sdks"],
            "open_alerts": open_alerts,
            "platforms": {"android": 72, "ios": 41, "harmonyos": 15},
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }

    def get_platform_view(self) -> Dict[str, Any]:
        return {
            "android": self.android.stats(),
            "ios": self.ios.stats(),
            "harmonyos": self.harmonyos.stats(),
        }

    def get_vuln_view(self) -> Dict[str, Any]:
        return {
            "by_severity": self.vuln.stats()["by_severity"],
            "by_platform": self.vuln.stats(),
            "top_ranked": self.vuln.prioritize()[:5],
        }

    def get_compliance_view(self) -> Dict[str, Any]:
        return {
            "privacy_score": 82.5,
            "sdks": self.privacy.stats(),
            "cross_border_pending": 2,
        }

    def list_alerts(self, level: Optional[str] = None,
                    status: Optional[str] = None) -> List[Dict[str, Any]]:
        out = list(self.alerts.values())
        if level:
            out = [a for a in out if a["level"] == level]
        if status:
            out = [a for a in out if a["status"] == status]
        return out

    def resolve_alert(self, alert_id: str, note: str = "") -> Dict[str, Any]:
        if alert_id in self.alerts:
            self.alerts[alert_id]["status"] = "resolved"
            self.alerts[alert_id]["note"] = note
            return {"alert_id": alert_id, "status": "resolved"}
        return {"alert_id": alert_id, "status": "not_found"}

    def update_settings(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        self.settings.update(updates)
        return {"settings": self.settings, "updated": list(updates.keys())}

    def stats(self) -> Dict[str, Any]:
        return {
            "metrics": len(DASHBOARD_METRICS),
            "settings": len(SYSTEM_SETTINGS),
            "alerts": len(self.alerts),
            "engines": 6,
        }


_instance: Optional[MobileSecurityDashboard] = None


def get_dashboard() -> MobileSecurityDashboard:
    global _instance
    if _instance is None:
        _instance = MobileSecurityDashboard()
    return _instance
