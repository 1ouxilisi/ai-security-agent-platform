# -*- coding: utf-8 -*-
"""
llm_config/llm_usage.py — LLM 用量统计

内存记录每次 API 调用：
  - 时间 / provider / model
  - prompt / completion / total tokens
  - 费用估算（按 provider 单价表）
按日/周/月聚合。
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Dict, List

# 粗略单价（每 1K tokens，美元），仅用于估算
PRICE_TABLE: Dict[str, Dict[str, float]] = {
    "deepseek": {"in": 0.00014, "out": 0.00028},
    "openai": {"in": 0.0025, "out": 0.01},
    "anthropic": {"in": 0.003, "out": 0.015},
    "qwen": {"in": 0.0008, "out": 0.002},
    "zhipu": {"in": 0.0007, "out": 0.0007},
    "moonshot": {"in": 0.0006, "out": 0.0024},
    "hunyuan": {"in": 0.0005, "out": 0.0015},
}

_RECORDS: List[Dict[str, Any]] = []


def record_call(provider: str, model: str,
                prompt_tokens: int, completion_tokens: int,
                latency_ms: int, success: bool = True) -> Dict[str, Any]:
    price = PRICE_TABLE.get(provider, {"in": 0.001, "out": 0.002})
    cost = (prompt_tokens / 1000.0) * price["in"] + \
           (completion_tokens / 1000.0) * price["out"]
    rec = {
        "ts": time.time(),
        "provider": provider, "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
        "latency_ms": latency_ms,
        "success": success,
        "cost_usd": round(cost, 6),
    }
    _RECORDS.append(rec)
    if len(_RECORDS) > 5000:
        _RECORDS[:] = _RECORDS[-3000:]
    return rec


def stats_range(seconds: int = 86400) -> Dict[str, Any]:
    now = time.time()
    cutoff = now - seconds
    items = [r for r in _RECORDS if r["ts"] >= cutoff]
    by_provider: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"calls": 0, "total_tokens": 0, "cost_usd": 0.0})
    total_calls = len(items)
    total_tokens = sum(r["total_tokens"] for r in items)
    total_cost = sum(r["cost_usd"] for r in items)
    for r in items:
        p = by_provider[r["provider"]]
        p["calls"] += 1
        p["total_tokens"] += r["total_tokens"]
        p["cost_usd"] += r["cost_usd"]
    return {
        "window_seconds": seconds,
        "total_calls": total_calls,
        "total_tokens": total_tokens,
        "total_cost_usd": round(total_cost, 4),
        "by_provider": {k: {kk: (round(vv, 4) if kk == "cost_usd" else vv)
                            for kk, vv in v.items()}
                        for k, v in by_provider.items()},
        "recent": items[-20:][::-1],
    }


def clear() -> int:
    n = len(_RECORDS)
    _RECORDS.clear()
    return n
