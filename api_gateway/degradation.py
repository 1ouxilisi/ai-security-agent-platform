# -*- coding: utf-8 -*-
"""
degradation.py - API 降级器。

在熔断/限流/超时/错误/手动触发时，返回降级数据（缓存/默认/简化/错误提示），
降低后端压力，保证核心链路可用。纯 Python 实现。
"""

from __future__ import annotations

import os
import json
import time
import threading
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional


_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "api_gateway",
)


class DegradationManager:
    """API 降级管理器（线程安全，单例）。

    支持四种降级策略：cache（缓存数据）/ default（默认数据）/
    simplified（简化数据）/ error（错误提示）。
    """

    VALID_STRATEGIES = ("cache", "default", "simplified", "error")

    def __init__(self, data_dir: Optional[str] = None) -> None:
        """初始化降级管理器。"""
        self._lock = threading.RLock()
        self._data_dir = data_dir or _DATA_DIR
        os.makedirs(self._data_dir, exist_ok=True)

        # 全局降级开关
        self._global_degraded: bool = False
        # 全局降级策略
        self._global_strategy: str = "default"

        # 端点级配置：endpoint -> {enabled, strategy, data, default_response,
        #                           simplified_fields, message, trigger_reason}
        self._configs: Dict[str, Dict[str, Any]] = {}

        # 统计
        self._stats: Dict[str, Any] = {
            "total_degraded": 0,
            "recovered": 0,
            "by_endpoint": defaultdict(int),
            "by_reason": defaultdict(int),
            "history": deque(maxlen=500),
        }
        self._load()

    # ------------------------------------------------------------------ #
    # 降级开关
    # ------------------------------------------------------------------ #
    def should_degrade(self, endpoint: str, reason: Optional[str] = None) -> bool:
        """判断端点是否应降级。

        Args:
            endpoint: API 端点。
            reason: 触发原因（熔断/限流/超时/错误/手动）。

        Returns:
            True 表示应降级。
        """
        with self._lock:
            # 全局降级开关
            if self._global_degraded:
                return True
            cfg = self._configs.get(endpoint)
            if cfg and cfg.get("enabled"):
                return True
            return False

    def enable_degradation(self, endpoint: str, strategy: str = "default",
                           data: Optional[Any] = None,
                           reason: str = "manual") -> Dict[str, Any]:
        """手动启用某端点降级。

        Args:
            endpoint: API 端点。
            strategy: 降级策略。
            data: 降级数据（default/simplified 时使用）。
            reason: 触发原因。

        Returns:
            该端点降级配置。
        """
        if strategy not in self.VALID_STRATEGIES:
            strategy = "default"
        with self._lock:
            cfg = self._configs.setdefault(endpoint, {})
            cfg.update({
                "enabled": True,
                "strategy": strategy,
                "data": data if data is not None else cfg.get("data"),
                "trigger_reason": reason,
                "enabled_at": time.time(),
            })
            self._stats["total_degraded"] += 1
            self._stats["by_endpoint"][endpoint] += 1
            self._stats["by_reason"][reason] += 1
            self._stats["history"].appendleft({
                "time": time.time(), "endpoint": endpoint,
                "action": "enable", "reason": reason, "strategy": strategy,
            })
            self._save()
            return dict(cfg)

    def disable_degradation(self, endpoint: str) -> bool:
        """关闭某端点降级（恢复）。"""
        with self._lock:
            cfg = self._configs.get(endpoint)
            if cfg and cfg.get("enabled"):
                cfg["enabled"] = False
                cfg["recovered_at"] = time.time()
                self._stats["recovered"] += 1
                self._stats["history"].appendleft({
                    "time": time.time(), "endpoint": endpoint,
                    "action": "disable", "reason": "recover",
                })
                self._save()
                return True
            return False

    def set_global(self, enabled: bool, strategy: str = "default") -> Dict[str, Any]:
        """设置全局降级开关。"""
        with self._lock:
            self._global_degraded = bool(enabled)
            if strategy in self.VALID_STRATEGIES:
                self._global_strategy = strategy
            self._save()
            return {"global_degraded": self._global_degraded,
                    "strategy": self._global_strategy}

    # ------------------------------------------------------------------ #
    # 默认降级数据
    # ------------------------------------------------------------------ #
    def set_default_response(self, endpoint: str, response_data: Any) -> None:
        """配置端点默认降级响应 JSON。"""
        with self._lock:
            cfg = self._configs.setdefault(endpoint, {})
            cfg["default_response"] = response_data
            self._save()

    def get_degraded_response(self, endpoint: str) -> Dict[str, Any]:
        """获取降级响应（含 X-Degraded 标识与原因）。

        Args:
            endpoint: API 端点。

        Returns:
            降级响应字典，包含 data / reason / strategy。
        """
        with self._lock:
            cfg = self._configs.get(endpoint, {})
            strategy = cfg.get("strategy") or self._global_strategy
            reason = cfg.get("trigger_reason", "unknown")

            if strategy == "error":
                data = {"error": "服务暂时不可用，请稍后重试", "degraded": True}
            elif strategy == "simplified":
                # 简化数据：仅保留必要字段
                data = cfg.get("data") or cfg.get("default_response") or {
                    "message": "当前返回简化数据", "degraded": True,
                }
            elif strategy == "cache":
                data = cfg.get("data") or cfg.get("default_response") or {
                    "message": "返回缓存数据", "degraded": True,
                }
            else:  # default
                data = cfg.get("default_response") or cfg.get("data") or {
                    "message": "服务降级中，返回默认数据", "degraded": True,
                }

            return {
                "degraded": True,
                "X-Degraded": "true",
                "endpoint": endpoint,
                "strategy": strategy,
                "reason": reason,
                "data": data,
            }

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def get_degraded_endpoints(self) -> List[str]:
        """获取当前处于降级状态的端点列表。"""
        with self._lock:
            result = [ep for ep, cfg in self._configs.items() if cfg.get("enabled")]
            if self._global_degraded:
                result.append("*global*")
            return result

    def get_config(self, endpoint: Optional[str] = None) -> Any:
        """获取降级配置。"""
        with self._lock:
            if endpoint:
                return self._configs.get(endpoint, {})
            return {
                "global_degraded": self._global_degraded,
                "global_strategy": self._global_strategy,
                "endpoints": {ep: dict(cfg) for ep, cfg in self._configs.items()},
            }

    def get_stats(self) -> Dict[str, Any]:
        """获取降级统计。"""
        with self._lock:
            s = self._stats
            active = len([ep for ep, c in self._configs.items() if c.get("enabled")])
            return {
                "total_degraded": s["total_degraded"],
                "recovered": s["recovered"],
                "active_degraded_endpoints": active,
                "global_degraded": self._global_degraded,
                "by_endpoint": dict(s["by_endpoint"]),
                "by_reason": dict(s["by_reason"]),
                "history": list(s["history"])[:20],
            }

    # ------------------------------------------------------------------ #
    # 持久化
    # ------------------------------------------------------------------ #
    def _save(self) -> None:
        try:
            path = os.path.join(self._data_dir, "degradation.json")
            data = {
                "global_degraded": self._global_degraded,
                "global_strategy": self._global_strategy,
                "configs": self._configs,
            }
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        except Exception:
            pass

    def _load(self) -> None:
        try:
            path = os.path.join(self._data_dir, "degradation.json")
            if not os.path.exists(path):
                return
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._global_degraded = data.get("global_degraded", False)
            self._global_strategy = data.get("global_strategy", "default")
            self._configs = data.get("configs", {})
        except Exception:
            pass


# 模块级单例
degradation_manager = DegradationManager()
