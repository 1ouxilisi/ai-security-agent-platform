# -*- coding: utf-8 -*-
"""
ai_upgrade/llm_integration.py — LLM 真实接入（增强版）

复用项目根目录 llm_integration 包（OpenAI 兼容统一客户端），并在此之上提供
AI 升级专用的高层封装：

    - AIEnhancedLLM：在真实 LLM 不可用时自动降级到规则/模板模式，不崩溃
    - analyze()：统一的「推理 + 降级」入口
    - capability 状态：实时反映 LLM 是否配置、provider、模型、延迟
    - 决策链记录：每次推理记录输入摘要 / 模式(llm|rule) / 耗时 / 依据

无 API Key 时所有功能走规则模式，返回结构化结果并标注 engine="rule"。
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

# 复用已有 llm_integration 包
try:
    from llm_integration import get_llm_client, get_config_manager
    _BASE_AVAILABLE = True
except Exception:  # pragma: no cover
    _BASE_AVAILABLE = False
    get_llm_client = None  # type: ignore
    get_config_manager = None  # type: ignore


# --------------------------------------------------------------------------- #
# 决策链记录（内存字典模拟）
# --------------------------------------------------------------------------- #
DECISION_LOG: List[Dict[str, Any]] = []
MAX_LOG = 500


def _record(engine: str, task: str, prompt_summary: str,
            result_summary: str, latency_ms: int,
            meta: Optional[Dict[str, Any]] = None) -> None:
    entry = {
        "decision_id": uuid.uuid4().hex[:12],
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "engine": engine,          # llm | rule
        "task": task,
        "prompt_summary": prompt_summary[:300],
        "result_summary": result_summary[:300],
        "latency_ms": latency_ms,
        "meta": meta or {},
    }
    DECISION_LOG.append(entry)
    if len(DECISION_LOG) > MAX_LOG:
        del DECISION_LOG[: len(DECISION_LOG) - MAX_LOG]


class AIEnhancedLLM:
    """增强 LLM：真实推理 + 规则降级。"""

    def __init__(self) -> None:
        self.base_available = _BASE_AVAILABLE

    # ------------------------------------------------------------------ #
    # 状态
    # ------------------------------------------------------------------ #
    def status(self) -> Dict[str, Any]:
        cfg: Dict[str, Any] = {"configured": False, "provider": "unknown",
                               "model": "n/a", "base_url": ""}
        client_ok = False
        if self.base_available:
            try:
                cm = get_config_manager()
                cfg = cm.status() if hasattr(cm, "status") else cm.get_config()
                cli = get_llm_client()
                client_ok = bool(getattr(cli, "llm_available", False))
            except Exception as e:  # noqa: BLE001
                cfg["error"] = str(e)
        return {
            "base_package": "llm_integration",
            "base_available": self.base_available,
            "llm_available": client_ok,
            "mode": "llm" if client_ok else "rule",
            "config": cfg,
            "decision_log_size": len(DECISION_LOG),
            "capabilities": ["vuln_analysis", "report_writing", "smart_qa",
                             "attack_chain_planning", "src_assistant"],
        }

    def refresh(self) -> Dict[str, Any]:
        if self.base_available:
            try:
                cli = get_llm_client()
                if hasattr(cli, "refresh"):
                    cli.refresh()
            except Exception:  # noqa: BLE001
                pass
        return self.status()

    # ------------------------------------------------------------------ #
    # 统一推理入口
    # ------------------------------------------------------------------ #
    def chat(self, system_prompt: str, user_prompt: str,
             rule_fallback: str = "",
             temperature: float = 0.2,
             max_tokens: int = 1024,
             task: str = "general") -> Dict[str, Any]:
        """真实调用 LLM；失败或未配置时返回 rule_fallback。"""
        t0 = time.time()
        if self.base_available:
            try:
                cli = get_llm_client()
                if getattr(cli, "llm_available", False):
                    res = cli.chat(
                        messages=[{"role": "system", "content": system_prompt},
                                  {"role": "user", "content": user_prompt}],
                        temperature=temperature, max_tokens=max_tokens)
                    latency = int((time.time() - t0) * 1000)
                    if res.get("success"):
                        content = res.get("content", "")
                        _record("llm", task, user_prompt, content, latency,
                                {"model": res.get("model"),
                                 "error_code": None})
                        return {"engine": "llm", "content": content,
                                "latency_ms": latency,
                                "raw": {k: res.get(k) for k in
                                        ("model", "usage", "latency_ms")}}
                    # 调用失败 -> 降级
                    fallback = rule_fallback or "（规则降级）推理服务暂不可用，已返回基于规则的分析结果。"
                    latency = int((time.time() - t0) * 1000)
                    _record("rule", task, user_prompt, fallback, latency,
                            {"reason": res.get("error_code"),
                             "error": res.get("error")})
                    return {"engine": "rule", "content": fallback,
                            "latency_ms": latency,
                            "raw": {"error_code": res.get("error_code"),
                                    "error": res.get("error")}}
            except Exception as e:  # noqa: BLE001
                fallback = rule_fallback or "（规则降级）推理异常，已返回规则分析结果。"
                latency = int((time.time() - t0) * 1000)
                _record("rule", task, user_prompt, fallback, latency,
                        {"reason": "exception", "error": str(e)})
                return {"engine": "rule", "content": fallback,
                        "latency_ms": latency, "raw": {"error": str(e)}}
        # 完全无 LLM 包
        fallback = rule_fallback or "（规则模式）未接入 LLM，返回规则分析结果。"
        latency = int((time.time() - t0) * 1000)
        _record("rule", task, user_prompt, fallback, latency,
                {"reason": "base_package_unavailable"})
        return {"engine": "rule", "content": fallback,
                "latency_ms": latency, "raw": {}}


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_singleton: Optional[AIEnhancedLLM] = None


def get_enhanced_llm() -> AIEnhancedLLM:
    global _singleton
    if _singleton is None:
        _singleton = AIEnhancedLLM()
    return _singleton


def get_decision_log(limit: int = 50) -> List[Dict[str, Any]]:
    return list(reversed(DECISION_LOG[-limit:]))


def clear_decision_log() -> int:
    n = len(DECISION_LOG)
    DECISION_LOG.clear()
    return n
