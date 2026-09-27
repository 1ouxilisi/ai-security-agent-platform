# -*- coding: utf-8 -*-
"""
validation_dashboard.py — 验证中心仪表盘。

聚合各验证模块的概览数据，供前端仪表盘渲染。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .tool_detector import get_tool_detector
from .range_deployer import get_range_deployer
from .scan_validator import get_scan_validator
from .report_validator import get_report_validator
from .performance_tester import get_performance_tester
from .security_tester import get_security_tester
from .validation_orchestrator import get_orchestrator


class ValidationDashboard:
    """验证中心仪表盘。"""

    def overview(self) -> Dict[str, Any]:
        tools = get_tool_detector().detect_all()
        return {
            "tools": {"total": tools["total"],
                      "installed": tools["installed_count"],
                      "missing": tools["missing_count"],
                      "score": tools["score"]},
            "ranges": {"catalog": len(get_range_deployer().list_catalog()),
                       "running": len([i for i in get_range_deployer().list_instances()
                                       if i["status"] == "running"])},
            "scan_projects": len(get_scan_validator().list_projects()),
            "report_dimensions": len(get_report_validator().list_dimensions()),
            "performance_scenarios": list(get_performance_tester().list_scenarios().keys()),
            "security_projects": len(get_security_tester().list_projects()),
            "history_count": len(get_orchestrator().history(limit=1000)),
        }

    def full(self) -> Dict[str, Any]:
        return {"overview": self.overview(),
                "config": get_orchestrator().get_config(),
                "history": get_orchestrator().history(limit=10)}


_dash: Optional[ValidationDashboard] = None


def get_dashboard() -> ValidationDashboard:
    global _dash
    if _dash is None:
        _dash = ValidationDashboard()
    return _dash
