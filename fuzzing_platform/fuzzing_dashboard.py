#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fuzzing_platform/fuzzing_dashboard.py — Fuzzing 控制台数据聚合层。

聚合 7 大模块数据，对外提供：
    - 总览 KPI（协议/文件/API/浏览器/内核用例与崩溃数、项目/任务/报告数）
    - 实时崩溃墙
    - 漏洞热力
    - 系统设置
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


SYSTEM_SETTINGS = {
    "platform_name": "AI Hacking Agent 安全 Fuzzing 与模糊测试平台",
    "version": "27.2.0",
    "timezone": "Asia/Shanghai",
    "max_parallel_tasks": 8,
    "default_timeout_s": 30,
    "sandbox_enabled": True,
    "asan_integration": True,
    "crash_auto_dedup": True,
    "notification_webhook": "",
    "retain_crashes_days": 90,
}


class FuzzingDashboard:
    """聚合层。"""

    def __init__(self) -> None:
        self._ok = False
        self._err = ""
        try:
            from .protocol_fuzzer import get_protocol_fuzzer, PROTOCOLS, MUTATION_STRATEGIES
            from .file_fuzzer import get_file_fuzzer, FILE_FORMATS
            from .api_fuzzer import get_api_fuzzer, HTTP_METHODS, PROTOCOLS as API_PROTOS
            from .browser_fuzzer import get_browser_fuzzer, BROWSERS, TEST_TARGETS
            from .kernel_fuzzer import get_kernel_fuzzer, KERNELS
            from .fuzzing_manager import get_fuzzing_manager

            self.proto = get_protocol_fuzzer()
            self.file = get_file_fuzzer()
            self.api = get_api_fuzzer()
            self.browser = get_browser_fuzzer()
            self.kernel = get_kernel_fuzzer()
            self.mgr = get_fuzzing_manager()
            self.PROTOCOLS = PROTOCOLS
            self.FILE_FORMATS = FILE_FORMATS
            self.HTTP_METHODS = HTTP_METHODS
            self.API_PROTOS = API_PROTOS
            self.BROWSERS = BROWSERS
            self.TEST_TARGETS = TEST_TARGETS
            self.KERNELS = KERNELS
            self.MUTATION_STRATEGIES = MUTATION_STRATEGIES
            self._ok = True
        except Exception as e:  # pragma: no cover
            self._err = str(e)

    def overview(self) -> Dict[str, Any]:
        if not self._ok:
            return {"error": self._err}
        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "platform": SYSTEM_SETTINGS["platform_name"],
            "version": SYSTEM_SETTINGS["version"],
            "protocol": self.proto.stats(),
            "file": self.file.stats(),
            "api": self.api.stats(),
            "browser": self.browser.stats(),
            "kernel": self.kernel.stats(),
            "manager": self.mgr.overview(),
        }

    def crash_wall(self) -> Dict[str, Any]:
        """实时崩溃墙：汇总各引擎最近崩溃。"""
        if not self._ok:
            return {"error": self._err}
        return {
            "protocol_crashes": self.proto.list_crashes(limit=10),
            "file_crashes": self.file.list_crashes(limit=10),
            "browser_crashes": self.browser.list_crashes(limit=10),
            "kernel_crashes": self.kernel.list_crashes(limit=10),
            "api_vulns": self.api.list_vulns(limit=10),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def coverage_matrix(self) -> Dict[str, Any]:
        """覆盖率矩阵：各引擎覆盖率汇总。"""
        if not self._ok:
            return {"error": self._err}
        return {
            "protocol": self.mgr.coverage_report("protocol"),
            "file": self.mgr.coverage_report("file"),
            "api": self.mgr.coverage_report("api"),
            "browser": self.mgr.coverage_report("browser"),
            "kernel": self.mgr.coverage_report("kernel"),
        }

    def performance_matrix(self) -> Dict[str, Any]:
        if not self._ok:
            return {"error": self._err}
        return {
            "protocol": self.mgr.performance_report("protocol"),
            "file": self.mgr.performance_report("file"),
            "api": self.mgr.performance_report("api"),
            "browser": self.mgr.performance_report("browser"),
            "kernel": self.mgr.performance_report("kernel"),
        }

    def supported(self) -> Dict[str, Any]:
        if not self._ok:
            return {"error": self._err}
        return {
            "protocols": list(self.PROTOCOLS.keys()),
            "file_formats": list(self.FILE_FORMATS.keys()),
            "http_methods": self.HTTP_METHODS,
            "api_protocols": self.API_PROTOS,
            "browsers": self.BROWSERS,
            "browser_targets": self.TEST_TARGETS,
            "kernels": self.KERNELS,
            "mutation_strategies": self.MUTATION_STRATEGIES,
        }

    def health(self) -> Dict[str, Any]:
        return {
            "modules_loaded": self._ok,
            "settings": SYSTEM_SETTINGS,
            "uptime": "simulated",
        }


_instance: Optional[FuzzingDashboard] = None


def get_fuzzing_dashboard() -> FuzzingDashboard:
    global _instance
    if _instance is None:
        _instance = FuzzingDashboard()
    return _instance
