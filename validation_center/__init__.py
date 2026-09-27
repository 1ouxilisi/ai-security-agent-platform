# -*- coding: utf-8 -*-
"""
validation_center — 真实环境验证体系。

模块：
    - tool_detector       : 30+ 真实安全工具检测
    - range_deployer     : 10+ 靶场一键部署（Docker / http.server 模拟兜底）
    - scan_validator     : 真实扫描准确性验证
    - report_validator   : 报告质量评分
    - performance_tester : locust/wrk/threading 压测
    - security_tester    : 系统自身安全测试
    - validation_orchestrator : 一键全量验证编排
    - validation_dashboard   : 验证中心仪表盘
"""

from __future__ import annotations

from .tool_detector import get_tool_detector, TOOL_CATALOG  # noqa: F401
from .range_deployer import get_range_deployer, RANGES  # noqa: F401
from .scan_validator import get_scan_validator, SCAN_PROJECTS  # noqa: F401
from .report_validator import get_report_validator, DIMENSIONS  # noqa: F401
from .performance_tester import get_performance_tester, SCENARIOS  # noqa: F401
from .security_tester import get_security_tester  # noqa: F401
from .validation_orchestrator import get_orchestrator  # noqa: F401
from .validation_dashboard import get_dashboard  # noqa: F401

__all__ = [
    "get_tool_detector", "TOOL_CATALOG",
    "get_range_deployer", "RANGES",
    "get_scan_validator", "SCAN_PROJECTS",
    "get_report_validator", "DIMENSIONS",
    "get_performance_tester", "SCENARIOS",
    "get_security_tester",
    "get_orchestrator", "get_dashboard",
]
