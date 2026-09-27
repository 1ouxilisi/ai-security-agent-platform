# -*- coding: utf-8 -*-
"""
llm_config/llm_dashboard.py — LLM 配置仪表盘聚合
"""
from __future__ import annotations

from typing import Any, Dict

from . import llm_usage
from .llm_config_manager import get_config_manager
from .llm_providers import list_providers


def get_dashboard() -> Dict[str, Any]:
    cm = get_config_manager()
    status = cm.status()
    return {
        "providers": list_providers(),
        "configured_keys": status,
        "usage_24h": llm_usage.stats_range(86400),
        "usage_7d": llm_usage.stats_range(86400 * 7),
        "notice": "所有 Key 加密存储于本地 data/llm_config.json，不明文落盘。",
    }
