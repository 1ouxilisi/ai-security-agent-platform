# -*- coding: utf-8 -*-
"""
validation_orchestrator.py — 验证编排器（一键运行所有验证）。

聚合：工具检测 / 靶场部署 / 扫描验证 / 报告验证 / 性能压测 / 安全测试。
维护验证历史与启用/禁用/配置。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from .tool_detector import get_tool_detector
from .range_deployer import get_range_deployer
from .scan_validator import get_scan_validator
from .report_validator import get_report_validator
from .performance_tester import get_performance_tester
from .security_tester import get_security_tester


class ValidationOrchestrator:
    """验证编排器。"""

    def __init__(self) -> None:
        self._history: List[Dict[str, Any]] = []
        self._config: Dict[str, Dict[str, Any]] = {
            "tool_detect": {"enabled": True},
            "range_deploy": {"enabled": True, "range": "dvwa"},
            "scan_validate": {"enabled": True, "target": "127.0.0.1"},
            "report_validate": {"enabled": True},
            "performance": {"enabled": False, "target": "http://127.0.0.1:8000"},
            "security": {"enabled": True, "target": "http://127.0.0.1:8000"},
        }

    # ------------------------------------------------------------------ #
    def get_config(self) -> Dict[str, Dict[str, Any]]:
        return self._config

    def update_config(self, key: str, props: Dict[str, Any]) -> Dict[str, Any]:
        if key in self._config:
            self._config[key].update(props)
        return self._config.get(key, {})

    # ------------------------------------------------------------------ #
    def run_all(self) -> Dict[str, Any]:
        rid = f"val_{uuid.uuid4().hex[:10]}"
        started = time.strftime("%Y-%m-%d %H:%M:%S")
        result: Dict[str, Any] = {"id": rid, "started_at": started, "stages": {}}
        cfg = self._config

        if cfg["tool_detect"]["enabled"]:
            result["stages"]["tool_detect"] = get_tool_detector().detect_all()

        if cfg["range_deploy"]["enabled"]:
            result["stages"]["range_deploy"] = \
                get_range_deployer().deploy(cfg["range_deploy"]["range"])

        if cfg["scan_validate"]["enabled"]:
            result["stages"]["scan_validate"] = \
                get_scan_validator().run_all(cfg["scan_validate"]["target"])

        if cfg["report_validate"]["enabled"]:
            sample = ("# 安全报告\n## 执行摘要\n发现风险。\n"
                       "## 风险发现\nCVE-2021-41773 CVSS 9.8\n"
                       "## 修复建议\n升级 patch\n## 附录\nOWASP")
            result["stages"]["report_validate"] = \
                get_report_validator().validate_report(sample)

        if cfg["performance"]["enabled"]:
            result["stages"]["performance"] = \
                get_performance_tester().run(cfg["performance"]["target"],
                                             concurrencies=[10])

        if cfg["security"]["enabled"]:
            result["stages"]["security"] = \
                get_security_tester().run(cfg["security"]["target"])

        result["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        result["overall"] = self._overall(result)
        self._history.append(result)
        return result

    @staticmethod
    def _overall(result: Dict[str, Any]) -> Dict[str, Any]:
        stages = result.get("stages", {})
        passed = sum(1 for s in stages.values()
                     if isinstance(s, dict) and
                     (s.get("status") in ("done", "healthy", "running", "ready")
                      or s.get("total") is not None and s.get("installed_count") is not None
                      or s.get("ok")))
        return {"stages_run": len(stages), "stages_passed": passed,
                "verdict": "完成" if stages else "无启用阶段"}

    # ------------------------------------------------------------------ #
    def history(self, limit: int = 20) -> List[Dict[str, Any]]:
        return sorted(self._history,
                      key=lambda x: x.get("started_at", ""), reverse=True)[:limit]

    def get(self, rid: str) -> Optional[Dict[str, Any]]:
        return next((h for h in self._history if h["id"] == rid), None)


_orch: Optional[ValidationOrchestrator] = None


def get_orchestrator() -> ValidationOrchestrator:
    global _orch
    if _orch is None:
        _orch = ValidationOrchestrator()
    return _orch
