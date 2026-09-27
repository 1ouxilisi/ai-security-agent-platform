# -*- coding: utf-8 -*-
"""
llm_config/llm_model_comparison.py — 多模型对比

对同一 prompt 同时发到多个 provider/model，
对比响应时间、Token 用量、费用、返回内容。
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

from .llm_tester import test_key


def compare_models(cases: List[Dict[str, str]],
                   prompt: str = "用一句话解释 SQL 注入。",
                   timeout: int = 60) -> Dict[str, Any]:
    """
    cases: [{"provider": "deepseek", "api_key": "...", "model": "...",
             "base_url": "..."}]
    """
    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(4, len(cases) or 1)) as ex:
        futs = {}
        for c in cases:
            fut = ex.submit(test_key, c["provider"], c["api_key"],
                            c.get("base_url"), c.get("model"),
                            timeout, None, prompt)
            futs[fut] = c
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:  # noqa: BLE001
                results.append({"success": False, "error": str(e)})

    results.sort(key=lambda r: (not r.get("success"),
                                r.get("elapsed_ms", 1e9)))
    return {
        "prompt": prompt,
        "results": results,
        "winner": results[0] if results and results[0].get("success") else None,
    }


def recommend_model(scene: str) -> Dict[str, Any]:
    """根据场景推荐模型。"""
    table = {
        "code": {"recommend": "deepseek-coder / qwen-coder",
                 "reason": "代码场景性价比高"},
        "chat": {"recommend": "deepseek-chat / qwen-plus",
                 "reason": "通用对话性价比高"},
        "reasoning": {"recommend": "deepseek-reasoner / o-mini",
                       "reason": "推理能力强"},
        "long": {"recommend": "moonshot-v1-128k / qwen-long",
                 "reason": "长上下文"},
        "local": {"recommend": "ollama/qwen2", "reason": "本地免费"},
    }
    return table.get(scene, {"recommend": "deepseek-chat",
                             "reason": "通用推荐"})
