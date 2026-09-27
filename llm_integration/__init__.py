# -*- coding: utf-8 -*-
"""
llm_integration 包 — 统一 LLM 接入

为整个项目提供：
    - LLMConfigManager: .env 中 LLM_* 配置的读写与状态
    - LLMClient: OpenAI 兼容统一客户端（智谱/DeepSeek/硅基流动/任意兼容接口）
    - PROVIDERS / quick_config: 配置引导数据

所有 AI 模块通过 get_llm_client() 复用同一客户端；未配置 Key 时优雅降级，
不抛异常、不崩溃。
"""
from __future__ import annotations

from .llm_config import (
    LLMConfigManager,
    get_config_manager,
    reload_config,
)
from .llm_client import (
    LLMClient,
    get_llm_client,
    reset_llm_client,
    get_fresh_client,
)
from .llm_config_guide import (
    PROVIDERS,
    list_providers,
    get_provider,
    quick_config,
)

__all__ = [
    "LLMConfigManager", "get_config_manager", "reload_config",
    "LLMClient", "get_llm_client", "reset_llm_client", "get_fresh_client",
    "PROVIDERS", "list_providers", "get_provider", "quick_config",
]
