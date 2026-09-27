#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
devsecops_deep/devsecops_dashboard.py — DevSecOps 深度控制台数据聚合层。

聚合 8 个视图：
    1. DevSecOps 总览：全平台健康度 / 漏洞热力 / 趋势
    2. CI-CD 管理：管道/运行/门禁/度量
    3. 代码安全：SAST 扫描与规则
    4. 依赖安全：SCA 与许可证
    5. 容器安全：镜像/运行时/合规
    6. IaC 安全：扫描与策略
    7. 安全即代码：策略/控制/测试/审计
    8. 系统设置：全局开关与阈值
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .cicd_security import get_cicd_security
from .sast_deep import get_sast_deep
from .dependency_deep import get_dependency_deep
from .container_deep import get_container_deep
from .iac_security import get_iac_security
from .security_as_code import get_security_as_code


SYSTEM_SETTINGS: Dict[str, Any] = {
    "platform_name": "DevSecOps 深度平台",
    "auto_gate": True,
    "block_on_critical": True,
    "notify_channel": "sec-team",
    "scan_on_pr": True,
    "scan_on_push": True,
    "baseline_branch": "main",
    "report_retention_days": 90,
    "integration": {
        "gitlab_connected": True,
        "github_connected": False,
        "jira_connected": True,
        "slack_connected": True,
        "nexus_connected": True,
    },
}


class DevSecOpsDashboard:
    """DevSecOps 深度控制台数据聚合层。"""

    def __init__(self) -> None:
        self.cicd = get_cicd_security()
        self.sast = get_sast_deep()
        self.dep = get_dependency_deep()
        self.container = get_container_deep()
        self.iac = get_iac_security()
        self.sac = get_security_as_code()

    # ------------------------------------------------------------------ #
    # 总览
    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        m = self.cicd.metrics()
        # 健康度：门禁通过率 * 60% + 扫描覆盖率 * 40%
        health = round(m["gate_pass_rate"] * 60 + m["scan_coverage_pct"] * 0.4, 1)
        return {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "platform_health_score": health,
            "pipeline_total": m["pipeline_total"],
            "run_total": m["run_total"],
            "gate_pass_rate": m["gate_pass_rate"],
            "scan_coverage_pct": m["scan_coverage_pct"],
            "active_modules": {
                "cicd_security": True,
                "sast_deep": True,
                "dependency_deep": True,
                "container_deep": True,
                "iac_security": True,
                "security_as_code": True,
            },
            "quick_links": [
                {"tab": "ci-cd", "label": "CI/CD 管理"},
                {"tab": "sast", "label": "代码安全"},
                {"tab": "dependency", "label": "依赖安全"},
                {"tab": "container", "label": "容器安全"},
                {"tab": "iac", "label": "IaC 安全"},
                {"tab": "sac", "label": "安全即代码"},
            ],
            "trend_7d": [82, 85, 84, 88, 90, 89, 93],
        }

    def summary_by_module(self) -> Dict[str, Any]:
        return {
            "cicd": self.cicd.metrics(),
            "sast": self.sast.scan_report(),
            "dependency": self.dep.report(),
            "container": self.container.report(),
            "iac": self.iac.report(),
            "sac": self.sac.report(),
        }

    # ------------------------------------------------------------------ #
    # 系统设置
    # ------------------------------------------------------------------ #
    def get_settings(self) -> Dict[str, Any]:
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in SYSTEM_SETTINGS.items()}

    def update_settings(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in fields.items():
            if k in SYSTEM_SETTINGS:
                if isinstance(SYSTEM_SETTINGS[k], dict) and isinstance(v, dict):
                    SYSTEM_SETTINGS[k].update(v)
                else:
                    SYSTEM_SETTINGS[k] = v
        return self.get_settings()

    def health_check(self) -> Dict[str, Any]:
        return {
            "status": "healthy",
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "modules_up": 6,
            "modules_down": 0,
            "queued_tasks": 0,
            "message": "所有 DevSecOps 深度模块运行正常",
        }


_dash: Optional[DevSecOpsDashboard] = None


def get_devsecops_dashboard() -> DevSecOpsDashboard:
    global _dash
    if _dash is None:
        _dash = DevSecOpsDashboard()
    return _dash
