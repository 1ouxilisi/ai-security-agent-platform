# -*- coding: utf-8 -*-
"""
circuit_breaker.py - API 熔断器。

实现经典三态熔断器状态机：CLOSED / OPEN / HALF_OPEN，纯 Python 实现。

状态转换：
    - CLOSED --(窗口内失败率 > 阈值 且请求数 >= 最小请求数)--> OPEN
    - OPEN  --(等待 open_timeout 后)--> HALF_OPEN（放行探测请求）
    - HALF_OPEN --(探测成功)--> CLOSED
    - HALF_OPEN --(探测失败)--> OPEN
"""

from __future__ import annotations

import os
import json
import time
import threading
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional


_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "api_gateway",
)


class CircuitState:
    """熔断状态常量。"""
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreaker:
    """API 熔断器（线程安全，单例）。

    按端点/服务/外部依赖独立维护熔断状态。
    """

    def __init__(self, data_dir: Optional[str] = None) -> None:
        """初始化熔断器。"""
        self._lock = threading.RLock()
        self._data_dir = data_dir or _DATA_DIR
        os.makedirs(self._data_dir, exist_ok=True)

        # 默认配置
        self._default_config: Dict[str, Any] = {
            "failure_rate_threshold": 0.5,   # 失败率阈值 50%
            "time_window": 60,               # 统计时间窗口 60s
            "open_timeout": 30,              # OPEN 持续 30s 后进入半开
            "half_open_requests": 5,          # 半开放行探测请求数
            "min_requests": 10,               # 最小请求数，未达不熔断
        }
        # 端点级配置覆盖
        self._configs: Dict[str, Dict[str, Any]] = {}

        # 每个端点的运行时状态
        self._states: Dict[str, Dict[str, Any]] = {}

        # 告警事件
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=500)

        self._load()

    # ------------------------------------------------------------------ #
    # 配置
    # ------------------------------------------------------------------ #
    def get_config(self, endpoint: Optional[str] = None) -> Dict[str, Any]:
        """获取熔断配置（端点覆盖 + 默认回退）。"""
        with self._lock:
            cfg = dict(self._default_config)
            if endpoint and endpoint in self._configs:
                cfg.update(self._configs[endpoint])
            return cfg

    def set_config(self, endpoint: Optional[str] = None, **config: Any) -> Dict[str, Any]:
        """设置熔断配置。

        Args:
            endpoint: 目标端点，None 表示更新默认配置。
            **config: failure_rate_threshold / time_window / open_timeout /
                      half_open_requests / min_requests。

        Returns:
            生效后的配置。
        """
        allowed = {"failure_rate_threshold", "time_window", "open_timeout",
                   "half_open_requests", "min_requests"}
        with self._lock:
            if endpoint:
                target = self._configs.setdefault(endpoint, {})
                for k, v in config.items():
                    if k in allowed:
                        target[k] = v
                result = self.get_config(endpoint)
            else:
                for k, v in config.items():
                    if k in allowed:
                        self._default_config[k] = v
                result = dict(self._default_config)
            self._save()
            return result

    # ------------------------------------------------------------------ #
    # 状态管理
    # ------------------------------------------------------------------ #
    def _ensure_state(self, endpoint: str) -> Dict[str, Any]:
        """获取或初始化端点运行时状态。"""
        if endpoint not in self._states:
            self._states[endpoint] = {
                "state": CircuitState.CLOSED,
                "started_at": time.time(),
                "requests": deque(),        # [(timestamp, success: bool)]
                "opened_at": None,
                "half_open_count": 0,
                "total_calls": 0,
                "total_failures": 0,
                "total_opened": 0,
                "history": deque(maxlen=200),
            }
        return self._states[endpoint]

    def get_state(self, endpoint: str) -> str:
        """获取指定端点当前熔断状态。"""
        with self._lock:
            st = self._states.get(endpoint)
            if st is None:
                return CircuitState.CLOSED
            return self._evaluate_transition(endpoint, st)

    def get_all_states(self) -> Dict[str, str]:
        """获取所有端点的熔断状态。"""
        with self._lock:
            result: Dict[str, str] = {}
            for ep in list(self._states.keys()):
                st = self._states[ep]
                result[ep] = self._evaluate_transition(ep, st)
            return result

    def _evaluate_transition(self, endpoint: str, st: Dict[str, Any]) -> str:
        """根据时间与记录推进状态机，返回当前状态。"""
        now = time.time()
        cfg = self.get_config(endpoint)
        if st["state"] == CircuitState.OPEN:
            if st["opened_at"] is not None and now - st["opened_at"] >= cfg["open_timeout"]:
                st["state"] = CircuitState.HALF_OPEN
                st["half_open_count"] = 0
                st["history"].append({"time": now, "event": "open->half_open"})
                self._alert(endpoint, "熔断进入半开状态，开始探测", st["state"])
        return st["state"]

    # ------------------------------------------------------------------ #
    # 调用包装
    # ------------------------------------------------------------------ #
    def call(self, endpoint: str, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """在熔断保护下调用 func。

        - 状态为 OPEN 时快速失败，抛出 CircuitBreakerError。
        - 状态为 HALF_OPEN 时放行有限探测请求。
        - CLOSED 时正常调用并记录成功/失败。

        Args:
            endpoint: 熔断维度标识。
            func: 实际执行的可调用对象。
            *args, **kwargs: 透传给 func。

        Returns:
            func 的返回值。

        Raises:
            CircuitBreakerError: 熔断打开时快速失败。
        """
        with self._lock:
            st = self._ensure_state(endpoint)
            state = self._evaluate_transition(endpoint, st)

            if state == CircuitState.OPEN:
                raise CircuitBreakerError(
                    f"端点 {endpoint} 熔断打开，快速失败",
                    retry_after=self.get_retry_after(endpoint),
                )

            if state == CircuitState.HALF_OPEN:
                if st["half_open_count"] >= self.get_config(endpoint)["half_open_requests"]:
                    raise CircuitBreakerError(
                        f"端点 {endpoint} 半开探测已满，稍后重试",
                        retry_after=self.get_retry_after(endpoint),
                    )
                st["half_open_count"] += 1

        # 实际调用在锁外执行，避免阻塞
        try:
            result = func(*args, **kwargs)
        except Exception as exc:
            self.record_failure(endpoint)
            raise exc
        self.record_success(endpoint)
        return result

    # ------------------------------------------------------------------ #
    # 成功/失败记录
    # ------------------------------------------------------------------ #
    def record_success(self, endpoint: str) -> None:
        """记录一次成功调用。"""
        now = time.time()
        with self._lock:
            st = self._ensure_state(endpoint)
            cfg = self.get_config(endpoint)
            st["requests"].append((now, True))
            st["total_calls"] += 1
            self._trim(st, cfg["time_window"])

            if st["state"] == CircuitState.HALF_OPEN:
                # 半开探测成功 -> 关闭
                st["state"] = CircuitState.CLOSED
                st["requests"].clear()
                st["history"].append({"time": now, "event": "half_open->closed"})
                self._alert(endpoint, "熔断恢复，状态关闭", st["state"])
            self._save()

    def record_failure(self, endpoint: str) -> None:
        """记录一次失败调用，并按规则推进状态机。"""
        now = time.time()
        with self._lock:
            st = self._ensure_state(endpoint)
            cfg = self.get_config(endpoint)
            st["requests"].append((now, False))
            st["total_calls"] += 1
            st["total_failures"] += 1
            self._trim(st, cfg["time_window"])

            if st["state"] == CircuitState.HALF_OPEN:
                # 半开探测失败 -> 重新打开
                st["state"] = CircuitState.OPEN
                st["opened_at"] = now
                st["total_opened"] += 1
                st["history"].append({"time": now, "event": "half_open->open"})
                self._alert(endpoint, "半开探测失败，熔断重新打开", st["state"])
            elif st["state"] == CircuitState.CLOSED:
                # 窗口内失败率超阈值 -> 打开
                total = len(st["requests"])
                fails = sum(1 for _, ok in st["requests"] if not ok)
                if total >= cfg["min_requests"]:
                    rate = fails / total
                    if rate >= cfg["failure_rate_threshold"]:
                        st["state"] = CircuitState.OPEN
                        st["opened_at"] = now
                        st["total_opened"] += 1
                        st["history"].append({"time": now,
                                             "event": f"closed->open (rate={rate:.2f})"})
                        self._alert(endpoint, f"失败率 {rate:.0%} 超阈值，熔断打开", st["state"])
            self._save()

    @staticmethod
    def _trim(st: Dict[str, Any], window: int) -> None:
        """清理时间窗口外的记录。"""
        cutoff = time.time() - window
        reqs = st["requests"]
        while reqs and reqs[0][0] < cutoff:
            reqs.popleft()

    def get_retry_after(self, endpoint: str) -> int:
        """获取熔断打开时的 Retry-After（秒）。"""
        return int(self.get_config(endpoint)["open_timeout"])

    # ------------------------------------------------------------------ #
    # 重置
    # ------------------------------------------------------------------ #
    def reset(self, endpoint: str) -> None:
        """重置指定端点的熔断状态。"""
        with self._lock:
            if endpoint in self._states:
                del self._states[endpoint]
                self._alert(endpoint, "熔断状态被手动重置", CircuitState.CLOSED)
            self._save()

    def reset_all(self) -> None:
        """重置所有端点熔断状态。"""
        with self._lock:
            self._states.clear()
            self._save()

    # ------------------------------------------------------------------ #
    # 告警
    # ------------------------------------------------------------------ #
    def _alert(self, endpoint: str, message: str, state: str) -> None:
        """记录一条熔断告警事件。"""
        self._alerts.appendleft({
            "time": time.time(),
            "endpoint": endpoint,
            "state": state,
            "message": message,
        })

    # ------------------------------------------------------------------ #
    # 统计
    # ------------------------------------------------------------------ #
    def get_stats(self, endpoint: Optional[str] = None) -> Dict[str, Any]:
        """获取熔断统计。"""
        with self._lock:
            if endpoint:
                st = self._states.get(endpoint)
                if st is None:
                    return {"endpoint": endpoint, "state": CircuitState.CLOSED,
                            "failure_rate": 0.0, "total_calls": 0, "total_failures": 0}
                self._evaluate_transition(endpoint, st)
                reqs = st["requests"]
                fails = sum(1 for _, ok in reqs if not ok)
                rate = (fails / len(reqs)) if reqs else 0.0
                return {
                    "endpoint": endpoint,
                    "state": st["state"],
                    "failure_rate": round(rate, 4),
                    "window_requests": len(reqs),
                    "total_calls": st["total_calls"],
                    "total_failures": st["total_failures"],
                    "total_opened": st["total_opened"],
                    "opened_at": st["opened_at"],
                    "history": list(st["history"])[-20:],
                }

            # 汇总
            summary = {
                "total_endpoints": len(self._states),
                "open_endpoints": 0,
                "half_open_endpoints": 0,
                "closed_endpoints": 0,
                "alerts": list(self._alerts)[:20],
                "endpoints": {},
            }
            for ep, st in self._states.items():
                state = self._evaluate_transition(ep, st)
                summary["endpoints"][ep] = state
                if state == CircuitState.OPEN:
                    summary["open_endpoints"] += 1
                elif state == CircuitState.HALF_OPEN:
                    summary["half_open_endpoints"] += 1
                else:
                    summary["closed_endpoints"] += 1
            return summary

    # ------------------------------------------------------------------ #
    # 持久化
    # ------------------------------------------------------------------ #
    def _save(self) -> None:
        try:
            path = os.path.join(self._data_dir, "circuit_breaker.json")
            data = {
                "configs": self._configs,
                "default_config": self._default_config,
                "states": {
                    ep: {
                        "state": st["state"],
                        "opened_at": st["opened_at"],
                        "total_calls": st["total_calls"],
                        "total_failures": st["total_failures"],
                        "total_opened": st["total_opened"],
                    }
                    for ep, st in self._states.items()
                },
            }
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        except Exception:
            pass

    def _load(self) -> None:
        try:
            path = os.path.join(self._data_dir, "circuit_breaker.json")
            if not os.path.exists(path):
                return
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._configs = data.get("configs", {})
            self._default_config.update(data.get("default_config", {}))
            for ep, sd in data.get("states", {}).items():
                self._states[ep] = {
                    "state": sd.get("state", CircuitState.CLOSED),
                    "started_at": time.time(),
                    "requests": deque(),
                    "opened_at": sd.get("opened_at"),
                    "half_open_count": 0,
                    "total_calls": sd.get("total_calls", 0),
                    "total_failures": sd.get("total_failures", 0),
                    "total_opened": sd.get("total_opened", 0),
                    "history": deque(),
                }
        except Exception:
            pass


class CircuitBreakerError(Exception):
    """熔断器快速失败异常。"""

    def __init__(self, message: str, retry_after: int = 30) -> None:
        """初始化异常。

        Args:
            message: 错误信息。
            retry_after: Retry-After 秒数。
        """
        super().__init__(message)
        self.retry_after = retry_after


# 模块级单例
circuit_breaker = CircuitBreaker()
