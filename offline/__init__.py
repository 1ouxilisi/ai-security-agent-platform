#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
离线模式模块 - 本地规则引擎 / AI降级 / 本地知识库

在无网络或AI API不可用时，提供本地分析能力。
"""
from offline.rules_engine import RuleEngine, _rules
from offline.ai_fallback import AIFallbackManager
from offline.local_knowledge import LocalKnowledge

__all__ = ["RuleEngine", "AIFallbackManager", "LocalKnowledge", "_rules"]
