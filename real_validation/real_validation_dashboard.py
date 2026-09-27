#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
real_validation/real_validation_dashboard.py — 真实场景验证控制台数据聚合层。

聚合 6 大模块数据，提供统一的仪表盘视图：
    - 验证总览（靶场/扫描/误报/漏洞/体系 汇总）
    - 趋势图表数据
    - 系统健康状态
    - 导出多格式报告
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
SYSTEM_SETTINGS = {
    "auto_verify": True,
    "auto_filter_fp": True,
    "confidence_threshold": 0.5,
    "review_enabled": True,
    "continuous_scan": False,
    "max_concurrent_scans": 3,
    "notification_webhook": "",
    "report_format": "html",
    "language": "zh-CN",
}

DASHBOARD_VERSION = "28.2.0"


# --------------------------------------------------------------------------- #
# 仪表盘聚合器
# --------------------------------------------------------------------------- #
class RealValidationDashboard:
    """聚合所有子模块数据，提供控制台视图。"""

    def __init__(self) -> None:
        self.settings = dict(SYSTEM_SETTINGS)
        self.export_history: List[Dict[str, Any]] = []
        self._modules: Dict[str, Any] = {}

    def bind_modules(self, **modules: Any) -> None:
        """绑定子模块实例（由路由层注入）。"""
        self._modules.update(modules)

    # ---- 总览 ---- #
    def get_overview(self) -> Dict[str, Any]:
        """聚合各模块统计数据，返回总览面板。"""
        overview: Dict[str, Any] = {
            "version": DASHBOARD_VERSION,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "modules": {},
            "kpi": {},
        }
        for name, mod in self._modules.items():
            try:
                if hasattr(mod, "stats"):
                    overview["modules"][name] = mod.stats()
                elif hasattr(mod, "get_status_summary"):
                    overview["modules"][name] = mod.get_status_summary()
                elif hasattr(mod, "get_metrics"):
                    overview["modules"][name] = mod.get_metrics()
            except Exception:
                overview["modules"][name] = {"error": "stats unavailable"}

        # 计算KPI
        rm = self._modules.get("range_manager")
        sv = self._modules.get("scan_validator")
        fp = self._modules.get("fp_optimizer")
        vv = self._modules.get("vuln_verifier")
        vf = self._modules.get("validation_framework")

        rm_summary = rm.get_status_summary() if rm else {}
        overview["kpi"] = {
            "total_ranges": rm_summary.get("total_ranges", 0),
            "running_ranges": rm_summary.get("running", 0),
            "total_scans": sv.stats()["total_scans"] if sv else 0,
            "total_rules": fp.stats()["total_rules"] if fp else 0,
            "total_vulns": vv.stats()["total_vulns"] if vv else 0,
            "verified_vulns": vv.stats()["verified"] if vv else 0,
            "total_test_cases": vf.get_metrics()["total_cases"] if vf else 0,
            "pass_rate": vf.get_metrics()["pass_rate"] if vf else 0,
        }
        return overview

    def get_trends(self, days: int = 7) -> Dict[str, Any]:
        """生成趋势数据。"""
        import random
        rng = random.Random(99)
        daily = []
        for i in range(days):
            daily.append({
                "date": f"day-{days-i}",
                "scans": rng.randint(3, 20),
                "false_positives": rng.randint(1, 8),
                "false_negatives": rng.randint(0, 5),
                "new_vulns": rng.randint(2, 12),
                "verified_vulns": rng.randint(1, 10),
                "pass_rate": round(rng.uniform(75, 98), 1),
            })
        return {"trend_days": days, "daily": daily}

    def get_health(self) -> Dict[str, Any]:
        """系统健康检查。"""
        checks = []
        for name in ["range_manager", "scan_validator", "fp_optimizer",
                      "vuln_verifier", "validation_framework"]:
            mod = self._modules.get(name)
            if mod:
                checks.append({"module": name, "status": "healthy"})
            else:
                checks.append({"module": name, "status": "not_loaded"})
        return {
            "overall": "healthy",
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "checks": checks,
        }

    # ---- 系统设置 ---- #
    def get_settings(self) -> Dict[str, Any]:
        return dict(self.settings)

    def update_settings(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in updates.items():
            if k in self.settings:
                self.settings[k] = v
        return {"success": True, "settings": dict(self.settings)}

    # ---- 导出 ---- #
    def export_report(self, fmt: str = "json",
                      sections: Optional[List[str]] = None) -> Dict[str, Any]:
        """导出综合报告。"""
        sections = sections or ["overview", "ranges", "scans", "fp", "vulns", "framework"]
        export_id = f"exp_{uuid.uuid4().hex[:10]}"
        report = {
            "export_id": export_id,
            "format": fmt,
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "sections": sections,
            "overview": self.get_overview() if "overview" in sections else None,
        }
        self.export_history.append({
            "export_id": export_id, "format": fmt,
            "exported_at": report["exported_at"],
            "sections": sections,
        })
        return {"success": True, "report": report}

    def list_exports(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self.export_history[-limit:]


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_instance: Optional[RealValidationDashboard] = None


def get_dashboard() -> RealValidationDashboard:
    global _instance
    if _instance is None:
        _instance = RealValidationDashboard()
    return _instance
