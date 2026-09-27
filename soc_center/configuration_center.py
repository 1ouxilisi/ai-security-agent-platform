# -*- coding: utf-8 -*-
"""
configuration_center.py — 统一配置中心（所有领域配置：工具路径/API Key/扫描参数/报告模板/通知设置）。
"""

from __future__ import annotations

import copy
from typing import Any, Dict, Optional

from .data_aggregator import DOMAINS


class ConfigurationCenter:
    """统一配置中心（单例，内存字典）。"""

    DEFAULTS: Dict[str, Dict[str, Any]] = {}

    def __init__(self) -> None:
        self._config: Dict[str, Dict[str, Any]] = {}
        self._init_defaults()

    def _init_defaults(self) -> None:
        for d in DOMAINS:
            self._config[d["key"]] = {
                "tool_path": f"/opt/tools/{d['key']}",
                "api_key": f"sk-{d['key']}-demo",
                "scan_params": {
                    "threads": 10,
                    "timeout": 30,
                    "deep_scan": False,
                },
                "report_template": "默认模板",
                "notify_channels": ["webhook"],
                "enabled": True,
            }

    def get(self, domain: Optional[str] = None) -> Dict[str, Any]:
        if domain:
            return copy.deepcopy(self._config.get(domain, {}))
        return {k: copy.deepcopy(v) for k, v in self._config.items()}

    def update(self, domain: str, patch: Dict[str, Any]) -> Dict[str, Any]:
        if domain not in self._config:
            self._config[domain] = {}
        self._config[domain].update(patch)
        return copy.deepcopy(self._config[domain])

    def reset(self, domain: str) -> Dict[str, Any]:
        self._init_defaults()
        return copy.deepcopy(self._config.get(domain, {}))

    def list_domains(self) -> Dict[str, Any]:
        return {
            "domains": [{"key": d["key"], "name": d["name"],
                         "icon": d["icon"]} for d in DOMAINS]
        }


_default: Optional[ConfigurationCenter] = None


def get_configuration_center() -> ConfigurationCenter:
    global _default
    if _default is None:
        _default = ConfigurationCenter()
    return _default
