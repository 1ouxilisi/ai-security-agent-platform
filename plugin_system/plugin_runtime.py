# -*- coding: utf-8 -*-
"""
plugin_runtime.py - 插件运行时

负责插件加载、执行（同步/异步/并行/超时）、通信（事件总线/回调）、
生命周期、监控、日志、错误处理、性能优化。
"""

from __future__ import annotations

import time
import asyncio
import traceback
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class EventBus:
    """简单事件总线。"""

    def __init__(self) -> None:
        self.handlers: Dict[str, List[Callable[..., Any]]] = defaultdict(list)
        self.history: deque = deque(maxlen=500)

    def on(self, event: str, handler: Callable[..., Any]) -> None:
        self.handlers[event].append(handler)

    def emit(self, event: str, payload: Any = None) -> int:
        called = 0
        self.history.append({"ts": _now(), "event": event, "payload": payload})
        for h in self.handlers.get(event, []):
            try:
                h(payload)
                called += 1
            except Exception:  # noqa: BLE001
                traceback.print_exc()
        return called


class PluginRuntime:
    """插件运行时：内存注册 + 监控 + 日志。"""

    def __init__(self) -> None:
        self.loaded: Dict[str, Dict[str, Any]] = {}
        self.event_bus = EventBus()
        self.logs: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self.metrics: Dict[str, Dict[str, Any]] = {}
        self.error_count: Dict[str, int] = defaultdict(int)
        self._seed_runtime()

    def _seed_runtime(self) -> None:
        seeds = [
            ("ex-nuclei-scanner", "scanner"),
            ("ex-payload-analyzer", "analyzer"),
            ("ex-slack-notify", "notification"),
            ("ex-dashboard-viz", "visualization"),
            ("ex-soar-workflow", "workflow"),
            ("ex-ldap-connector", "connector"),
            ("ex-llm-triage", "ai"),
        ]
        for pid, ptype in seeds:
            self.loaded[pid] = {
                "id": pid, "type": ptype, "state": "running",
                "loaded_at": _now(), "uptime_s": 0,
            }
            self.metrics[pid] = {
                "calls": 0, "errors": 0, "avg_ms": 0.0,
                "last_call": None, "cpu_pct": 0.0, "mem_mb": 0.0,
            }

    # ---------- 加载 ----------
    def load(self, plugin_id: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if plugin_id in self.loaded:
            return {"ok": True, "id": plugin_id, "state": self.loaded[plugin_id]["state"], "reused": True}
        entry = {
            "id": plugin_id, "type": (metadata or {}).get("type", "other"),
            "state": "loaded", "loaded_at": _now(), "uptime_s": 0,
        }
        self.loaded[plugin_id] = entry
        self.metrics.setdefault(plugin_id, {
            "calls": 0, "errors": 0, "avg_ms": 0.0, "last_call": None,
            "cpu_pct": 0.0, "mem_mb": 0.0,
        })
        self.event_bus.emit("plugin.loaded", plugin_id)
        self._log(plugin_id, "loaded", "info")
        return {"ok": True, "id": plugin_id, "state": "loaded"}

    def unload(self, plugin_id: str) -> Dict[str, Any]:
        if plugin_id not in self.loaded:
            return {"ok": False, "error": "未加载"}
        self.loaded.pop(plugin_id, None)
        self.event_bus.emit("plugin.unloaded", plugin_id)
        return {"ok": True}

    # ---------- 执行 ----------
    def invoke(self, plugin_id: str, method: str = "run",
               payload: Optional[Dict[str, Any]] = None,
               timeout: float = 5.0) -> Dict[str, Any]:
        if plugin_id not in self.loaded:
            return {"ok": False, "error": "插件未加载"}
        start = time.time()
        try:
            # 模拟执行：仅记录指标
            self._log(plugin_id, f"invoke {method}", "info")
            result = {"ok": True, "method": method, "echo": payload or {}}
            duration_ms = (time.time() - start) * 1000
            m = self.metrics.setdefault(plugin_id, {})
            m["calls"] = m.get("calls", 0) + 1
            m["avg_ms"] = round((m.get("avg_ms", 0.0) + duration_ms) / 2, 2)
            m["last_call"] = _now()
            return result
        except Exception as e:  # noqa: BLE001
            self.error_count[plugin_id] += 1
            self._log(plugin_id, f"error: {e}", "error")
            return {"ok": False, "error": str(e)}

    async def invoke_async(self, plugin_id: str, method: str = "run",
                           payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        await asyncio.sleep(0)
        return self.invoke(plugin_id, method, payload)

    def restart(self, plugin_id: str) -> Dict[str, Any]:
        if plugin_id not in self.loaded:
            return {"ok": False, "error": "未加载"}
        self.loaded[plugin_id]["state"] = "restarting"
        time.sleep(0.05)
        self.loaded[plugin_id]["state"] = "running"
        self._log(plugin_id, "restarted", "info")
        self.event_bus.emit("plugin.restarted", plugin_id)
        return {"ok": True, "state": "running"}

    # ---------- 监控 ----------
    def status(self, plugin_id: str) -> Dict[str, Any]:
        p = self.loaded.get(plugin_id)
        if not p:
            return {"ok": False, "error": "未加载"}
        return {"ok": True, **p, "metrics": self.metrics.get(plugin_id, {})}

    def metrics_all(self) -> Dict[str, Any]:
        return self.metrics

    # ---------- 日志 ----------
    def _log(self, plugin_id: str, message: str, level: str = "info") -> None:
        self.logs[plugin_id].append({
            "ts": _now(), "level": level, "message": message,
        })

    def get_logs(self, plugin_id: str, level: Optional[str] = None,
                 limit: int = 100) -> List[Dict[str, Any]]:
        items = list(self.logs.get(plugin_id, []))
        if level:
            items = [x for x in items if x["level"] == level]
        return items[-limit:]

    # ---------- 统计 ----------
    def stats(self) -> Dict[str, Any]:
        running = sum(1 for p in self.loaded.values() if p["state"] == "running")
        return {
            "loaded": len(self.loaded),
            "running": running,
            "events": len(self.event_bus.history),
            "errors": sum(self.error_count.values()),
        }


_default_runtime: Optional[PluginRuntime] = None


def get_runtime() -> PluginRuntime:
    global _default_runtime
    if _default_runtime is None:
        _default_runtime = PluginRuntime()
    return _default_runtime
