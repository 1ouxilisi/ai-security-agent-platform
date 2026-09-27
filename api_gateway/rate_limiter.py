# -*- coding: utf-8 -*-
"""
rate_limiter.py - API 网关限流器。

提供多算法、多维度、可配置的限流能力，纯 Python 实现，不依赖第三方库。

支持算法：
    - 滑动窗口（sliding_window，默认）
    - 固定窗口（fixed_window）
    - 令牌桶（token_bucket）
    - 漏桶（leaky_bucket）

限流维度：ip / user / tenant / endpoint / api_key / global，支持多维度组合。
限流时返回 429 语义与 Retry-After、X-RateLimit-* 头所需信息。
"""

from __future__ import annotations

import os
import json
import time
import threading
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple


# 数据持久化目录（相对项目根）
_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "api_gateway",
)


def _now() -> float:
    """返回当前时间戳（秒）。"""
    return time.time()


class RateLimiter:
    """API 限流器（线程安全，单例）。

    支持四种限流算法、六种限流维度、按端点/IP/用户自定义策略、
    白名单豁免、限流统计持久化。
    """

    VALID_ALGORITHMS = ("sliding_window", "fixed_window", "token_bucket", "leaky_bucket")
    VALID_DIMENSIONS = ("ip", "user", "tenant", "endpoint", "api_key", "global")

    def __init__(self, algorithm: str = "sliding_window", data_dir: Optional[str] = None) -> None:
        """初始化限流器。

        Args:
            algorithm: 默认限流算法，默认滑动窗口。
            data_dir: 持久化目录，默认 data/api_gateway/。
        """
        self._lock = threading.RLock()
        self._algorithm = algorithm if algorithm in self.VALID_ALGORITHMS else "sliding_window"
        self._data_dir = data_dir or _DATA_DIR
        os.makedirs(self._data_dir, exist_ok=True)

        # 默认全局策略：60 请求/分钟，突发 10
        self._default_policy: Dict[str, Any] = {
            "requests_per_minute": 60,
            "burst": 10,
            "window_seconds": 60,
        }
        # 自定义策略：key = f"{dimension}:{endpoint or '*'}" -> policy
        self._policies: Dict[str, Dict[str, Any]] = {}

        # 白名单：dimension -> set(identifier)
        self._whitelist: Dict[str, set] = defaultdict(set)

        # 计数状态：key = f"{dimension}:{identifier}:{endpoint or '*'}" -> 状态对象
        self._counters: Dict[str, Dict[str, Any]] = {}

        # 统计
        self._stats: Dict[str, Any] = {
            "total_blocked": 0,
            "blocked_by_ip": defaultdict(int),
            "blocked_by_user": defaultdict(int),
            "blocked_by_endpoint": defaultdict(int),
            "request_count": 0,
            "history": deque(maxlen=1000),  # 时间分布记录
        }
        self._load()

    # ------------------------------------------------------------------ #
    # 策略管理
    # ------------------------------------------------------------------ #
    def _policy_key(self, endpoint: Optional[str], dimension: str) -> str:
        """生成策略键。"""
        return f"{dimension}:{endpoint or '*'}"

    def set_policy(self, endpoint: Optional[str] = None, dimension: str = "ip",
                   requests_per_minute: int = 60, burst: int = 10,
                   window_seconds: Optional[int] = None) -> Dict[str, Any]:
        """设置限流策略。

        Args:
            endpoint: 目标端点，None 表示该维度全局默认。
            dimension: 限流维度。
            requests_per_minute: 每分钟允许请求数。
            burst: 突发请求数（令牌桶/漏桶容量）。
            window_seconds: 窗口时长，默认 60 秒。

        Returns:
            生效后的策略字典。
        """
        if dimension not in self.VALID_DIMENSIONS:
            dimension = "ip"
        policy = {
            "requests_per_minute": int(requests_per_minute),
            "burst": int(burst),
            "window_seconds": int(window_seconds or 60),
        }
        with self._lock:
            self._policies[self._policy_key(endpoint, dimension)] = policy
            self._save()
        return policy

    def get_policy(self, endpoint: Optional[str] = None, dimension: str = "ip") -> Dict[str, Any]:
        """获取限流策略（先精确匹配，再回退到全局默认）。"""
        if dimension not in self.VALID_DIMENSIONS:
            dimension = "ip"
        with self._lock:
            pk = self._policy_key(endpoint, dimension)
            if pk in self._policies:
                return dict(self._policies[pk])
            # 回退到该维度全局
            gk = self._policy_key(None, dimension)
            if gk in self._policies:
                return dict(self._policies[gk])
            return dict(self._default_policy)

    # ------------------------------------------------------------------ #
    # 白名单
    # ------------------------------------------------------------------ #
    def add_whitelist(self, identifier: str, dimension: str = "ip") -> None:
        """添加限流白名单。"""
        with self._lock:
            self._whitelist[dimension].add(str(identifier))
            self._save()

    def remove_whitelist(self, identifier: str, dimension: str = "ip") -> None:
        """移除限流白名单。"""
        with self._lock:
            self._whitelist[dimension].discard(str(identifier))
            self._save()

    def get_whitelist(self) -> Dict[str, List[str]]:
        """获取白名单（按维度分组）。"""
        with self._lock:
            return {dim: sorted(set(ids)) for dim, ids in self._whitelist.items()}

    def _is_whitelisted(self, identifier: str, dimension: str) -> bool:
        """判断是否在白名单内（含 global 维度与通用维度）。"""
        sid = str(identifier)
        if sid in self._whitelist.get(dimension, set()):
            return True
        if sid in self._whitelist.get("global", set()):
            return True
        return False

    # ------------------------------------------------------------------ #
    # 核心限流判定
    # ------------------------------------------------------------------ #
    def _counter_key(self, identifier: str, endpoint: Optional[str], dimension: str) -> str:
        return f"{dimension}:{identifier}:{endpoint or '*'}"

    def is_allowed(self, identifier: str, endpoint: Optional[str] = None,
                   dimension: str = "ip") -> bool:
        """判定请求是否被允许。

        Args:
            identifier: 限流标识（IP/用户ID/租户/Key 等）。
            endpoint: 请求的 API 端点。
            dimension: 限流维度。

        Returns:
            True 表示放行，False 表示被限流（429）。
        """
        if dimension not in self.VALID_DIMENSIONS:
            dimension = "ip"
        sid = str(identifier)
        now = _now()

        with self._lock:
            # 白名单直接放行
            if self._is_whitelisted(sid, dimension):
                return True

            policy = self.get_policy(endpoint, dimension)
            key = self._counter_key(sid, endpoint, dimension)
            state = self._counters.get(key)
            if state is None:
                state = self._init_state(policy)
                self._counters[key] = state

            allowed = self._consume(state, policy, now)
            self._stats["request_count"] += 1

            if not allowed:
                self._stats["total_blocked"] += 1
                self._stats["blocked_by_ip" if dimension == "ip" else "blocked_by_user"][sid] += 1
                if endpoint:
                    self._stats["blocked_by_endpoint"][endpoint] += 1
                self._stats["history"].append({
                    "time": now, "identifier": sid, "dimension": dimension,
                    "endpoint": endpoint, "action": "block",
                })
                self._save_stats()
            return allowed

    def _init_state(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """按算法初始化计数状态。"""
        now = _now()
        rpm = max(1, policy["requests_per_minute"])
        burst = policy["burst"]
        if self._algorithm == "token_bucket":
            return {"tokens": float(burst), "last_refill": now,
                    "capacity": float(burst), "rate": rpm / 60.0}
        if self._algorithm == "leaky_bucket":
            return {"water": 0.0, "last_leak": now,
                    "capacity": float(burst), "leak_rate": rpm / 60.0}
        if self._algorithm == "fixed_window":
            win = policy["window_seconds"]
            return {"window_start": now - (now % win), "count": 0,
                    "window": win, "limit": rpm}
        # sliding_window（默认）
        return {"times": deque(), "limit": rpm, "window": policy["window_seconds"]}

    def _consume(self, state: Dict[str, Any], policy: Dict[str, Any], now: float) -> bool:
        """根据算法消费一次请求，返回是否放行。"""
        algo = self._algorithm
        if algo == "token_bucket":
            refill = (now - state["last_refill"]) * state["rate"]
            state["tokens"] = min(state["capacity"], state["tokens"] + refill)
            state["last_refill"] = now
            if state["tokens"] >= 1.0:
                state["tokens"] -= 1.0
                return True
            return False
        if algo == "leaky_bucket":
            leaked = (now - state["last_leak"]) * state["leak_rate"]
            state["water"] = max(0.0, state["water"] - leaked)
            state["last_leak"] = now
            if state["water"] + 1.0 <= state["capacity"]:
                state["water"] += 1.0
                return True
            return False
        if algo == "fixed_window":
            win = state["window"]
            cur_window = now - (now % win)
            if cur_window != state["window_start"]:
                state["window_start"] = cur_window
                state["count"] = 0
            if state["count"] < state["limit"]:
                state["count"] += 1
                return True
            return False
        # sliding_window
        times = state["times"]
        cutoff = now - state["window"]
        while times and times[0] < cutoff:
            times.popleft()
        if len(times) < state["limit"]:
            times.append(now)
            return True
        return False

    # ------------------------------------------------------------------ #
    # 查询剩余额度
    # ------------------------------------------------------------------ #
    def get_remaining(self, identifier: str, endpoint: Optional[str] = None) -> int:
        """获取剩余可请求数（用于 X-RateLimit-Remaining）。"""
        sid = str(identifier)
        now = _now()
        with self._lock:
            if self._is_whitelisted(sid, "ip") or self._is_whitelisted(sid, "global"):
                return 10_000_000
            policy = self.get_policy(endpoint, "ip")
            key = self._counter_key(sid, endpoint, "ip")
            state = self._counters.get(key)
            if state is None:
                return max(0, policy["requests_per_minute"])
            if self._algorithm == "token_bucket":
                refill = (now - state["last_refill"]) * state["rate"]
                return int(max(0.0, min(state["capacity"], state["tokens"] + refill)))
            if self._algorithm == "leaky_bucket":
                leaked = (now - state["last_leak"]) * state["leak_rate"]
                water = max(0.0, state["water"] - leaked)
                return int(max(0.0, state["capacity"] - water))
            if self._algorithm == "fixed_window":
                cur_window = now - (now % state["window"])
                if cur_window != state["window_start"]:
                    return state["limit"]
                return max(0, state["limit"] - state["count"])
            # sliding_window
            cutoff = now - state["window"]
            active = sum(1 for t in state["times"] if t >= cutoff)
            return max(0, state["limit"] - active)

    def get_retry_after(self, identifier: str, endpoint: Optional[str] = None) -> int:
        """计算 Retry-After（秒），供限流响应头使用。"""
        with self._lock:
            policy = self.get_policy(endpoint, "ip")
            return int(max(1, policy["window_seconds"] // 4))

    def reset_counter(self, identifier: str) -> None:
        """重置指定标识的所有计数器。"""
        sid = str(identifier)
        with self._lock:
            for key in list(self._counters.keys()):
                if key.endswith(f":{sid}:*") or f":{sid}:" in key:
                    del self._counters[key]

    # ------------------------------------------------------------------ #
    # 统计
    # ------------------------------------------------------------------ #
    def get_stats(self) -> Dict[str, Any]:
        """获取限流统计。"""
        with self._lock:
            sb = self._stats
            return {
                "algorithm": self._algorithm,
                "total_blocked": sb["total_blocked"],
                "request_count": sb["request_count"],
                "blocked_by_ip_count": len(sb["blocked_by_ip"]),
                "blocked_by_user_count": len(sb["blocked_by_user"]),
                "top_blocked_ips": sorted(sb["blocked_by_ip"].items(),
                                         key=lambda x: x[1], reverse=True)[:10],
                "top_blocked_endpoints": sorted(sb["blocked_by_endpoint"].items(),
                                                key=lambda x: x[1], reverse=True)[:10],
                "active_counters": len(self._counters),
                "policies": {k: v for k, v in self._policies.items()},
                "whitelist": {d: sorted(set(i)) for d, i in self._whitelist.items()},
                "recent_history": list(sb["history"])[-20:],
            }

    # ------------------------------------------------------------------ #
    # 持久化
    # ------------------------------------------------------------------ #
    def _save(self) -> None:
        """持久化策略与白名单。"""
        try:
            path = os.path.join(self._data_dir, "rate_limiter_state.json")
            data = {
                "algorithm": self._algorithm,
                "policies": self._policies,
                "whitelist": {d: list(i) for d, i in self._whitelist.items()},
            }
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        except Exception:
            pass

    def _save_stats(self) -> None:
        """持久化统计（低频，仅写阻塞计数）。"""
        try:
            path = os.path.join(self._data_dir, "rate_limiter_stats.json")
            data = {
                "total_blocked": self._stats["total_blocked"],
                "request_count": self._stats["request_count"],
                "blocked_by_ip": dict(self._stats["blocked_by_ip"]),
                "blocked_by_user": dict(self._stats["blocked_by_user"]),
                "blocked_by_endpoint": dict(self._stats["blocked_by_endpoint"]),
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _load(self) -> None:
        """加载持久化状态。"""
        try:
            path = os.path.join(self._data_dir, "rate_limiter_state.json")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._algorithm = data.get("algorithm", self._algorithm)
                self._policies = data.get("policies", {})
                for d, ids in data.get("whitelist", {}).items():
                    self._whitelist[d] = set(ids)
        except Exception:
            pass
        try:
            path = os.path.join(self._data_dir, "rate_limiter_stats.json")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._stats["total_blocked"] = data.get("total_blocked", 0)
                self._stats["request_count"] = data.get("request_count", 0)
                for k in ("blocked_by_ip", "blocked_by_user", "blocked_by_endpoint"):
                    for ident, cnt in data.get(k, {}).items():
                        self._stats[k][ident] = cnt
        except Exception:
            pass


# 模块级单例
rate_limiter = RateLimiter()
