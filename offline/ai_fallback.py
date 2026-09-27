#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 降级管理器 - 在AI不可用时自动切换到本地规则引擎

模式:
- ai:     仅AI
- local:  仅本地规则
- hybrid: 混合（默认），AI不可用时自动降级到local，恢复后自动切回
"""
import os
import threading
import time
from typing import Any, Dict, Optional

from offline.rules_engine import RuleEngine


class AIFallbackManager:
    """AI可用性感知与降级管理器（线程安全）"""

    VALID_MODES = ("ai", "local", "hybrid")

    def __init__(self, mode: str = "hybrid"):
        self._lock = threading.Lock()
        self._mode = mode if mode in self.VALID_MODES else "hybrid"
        self._engine = RuleEngine()
        # 统计
        self._ai_requests = 0
        self._local_requests = 0
        self._degrade_count = 0
        self._recover_count = 0
        self._ai_latencies = []
        # 状态
        self._ai_available: bool = True
        self._ai_latency_ms: float = 0.0
        self._last_degrade_time: Optional[float] = None
        self._last_recover_time: Optional[float] = None

    # ---------------- AI 可用性检测（模拟） ----------------
    def check_ai_availability(self) -> Dict[str, Any]:
        """检测AI API是否可用（模拟：检查配置中的API key，不实际发起外部请求）"""
        try:
            start = time.time()
            # 模拟轻量健康检查：检查常见AI key环境变量是否配置
            has_key = any(
                os.environ.get(k) for k in (
                    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DASHSCOPE_API_KEY",
                    "DEEPSEEK_API_KEY", "AI_API_KEY",
                )
            )
            time.sleep(0.01)  # 模拟网络开销
            latency = round((time.time() - start) * 1000, 2)
            available = bool(has_key)
            with self._lock:
                self._ai_available = available
                self._ai_latency_ms = latency
            return {
                "available": available,
                "latency_ms": latency,
                "error": "" if available else "未检测到AI API密钥（离线模式）",
            }
        except Exception as e:
            with self._lock:
                self._ai_available = False
            return {"available": False, "latency_ms": 0.0, "error": str(e)}

    # ---------------- 模式管理 ----------------
    def get_current_mode(self) -> str:
        with self._lock:
            return self._mode

    def set_mode(self, mode: str) -> Dict[str, Any]:
        if mode not in self.VALID_MODES:
            raise ValueError(f"无效模式: {mode}，可选 {self.VALID_MODES}")
        with self._lock:
            self._mode = mode
        return {"mode": mode}

    def auto_degrade(self) -> bool:
        """AI不可用且当前为hybrid时，自动切到local"""
        try:
            check = self.check_ai_availability()
            with self._lock:
                if not check["available"] and self._mode == "hybrid":
                    self._mode = "local"
                    self._degrade_count += 1
                    self._last_degrade_time = time.time()
                    return True
            return False
        except Exception:
            return False

    def auto_recover(self) -> bool:
        """AI恢复可用后，切回hybrid"""
        try:
            check = self.check_ai_availability()
            with self._lock:
                if check["available"] and self._mode == "local":
                    self._mode = "hybrid"
                    self._recover_count += 1
                    self._last_recover_time = time.time()
                    return True
            return False
        except Exception:
            return False

    # ---------------- 请求处理 ----------------
    def process_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """根据当前模式选择AI或本地规则引擎处理请求"""
        try:
            mode = self.get_current_mode()
            # 自动降级
            if mode == "hybrid":
                if self.auto_degrade():
                    mode = "local"

            if mode == "ai":
                with self._lock:
                    self._ai_requests += 1
                return {
                    "result": {"note": "AI分析结果（模拟）", "input_summary": str(request_data)[:200]},
                    "source": "ai", "mode": "ai",
                    "note": "模拟AI分析，未实际调用外部API",
                }

            # local / hybrid降级后走本地规则
            hits = self._engine.apply_rules(request_data)
            with self._lock:
                self._local_requests += 1
            return {
                "result": {"hits": hits, "hit_count": len(hits)},
                "source": "local", "mode": mode,
                "note": "由本地规则引擎处理",
            }
        except Exception as e:
            return {"result": {}, "source": "local", "mode": self.get_current_mode(), "note": f"错误: {e}"}

    # ---------------- 状态 / 统计 ----------------
    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "current_mode": self._mode,
                "ai_available": self._ai_available,
                "ai_latency_ms": self._ai_latency_ms,
                "local_rules_count": len(self._engine.list_rules()),
                "last_degrade_time": self._last_degrade_time,
                "last_recover_time": self._last_recover_time,
                "degrade_count": self._degrade_count,
            }

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            avg = round(sum(self._ai_latencies) / len(self._ai_latencies), 2) if self._ai_latencies else 0.0
            return {
                "ai_requests": self._ai_requests,
                "local_requests": self._local_requests,
                "degrade_count": self._degrade_count,
                "recover_count": self._recover_count,
                "avg_ai_latency_ms": avg,
            }


# 模块级单例
_fallback_manager = AIFallbackManager()


def get_fallback_manager() -> AIFallbackManager:
    return _fallback_manager
