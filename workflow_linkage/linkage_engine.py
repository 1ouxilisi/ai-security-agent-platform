# -*- coding: utf-8 -*-
"""
linkage_engine.py — 联动执行引擎。

职责:
    - 事件监听（监听所有领域的事件）
    - 规则匹配（根据触发条件匹配联动规则）
    - 动作执行（执行配置的联动动作）
    - 联动失败重试（最多 3 次）
    - 联动去重（相同事件在时间窗口内只触发一次）
"""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Any, Dict, List, Optional

from .linkage_logger import get_linkage_logger
from .linkage_rules import get_rule_manager

# 严重程度数值化（阈值比较）
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

MAX_RETRY = 3


class LinkageEngine:
    """联动执行引擎（单例）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._dedup: Dict[str, float] = {}  # dedup_key -> last_fire_ts
        self.logger = get_linkage_logger()
        self.rm = get_rule_manager()

    # ------------------------------------------------------------------ #
    @staticmethod
    def _dedup_key(source_domain: str, event_type: str,
                   data: Any) -> str:
        raw = f"{source_domain}|{event_type}|{str(data)}"
        return hashlib.md5(raw.encode("utf-8")).hexdigest()

    def _match(self, rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """规则匹配：源领域 + 事件类型 + 严重程度阈值 + 字段匹配。"""
        if not rule.get("enabled", True):
            return False
        if rule["source_domain"] != event.get("domain"):
            return False
        trig = rule["trigger"]
        if trig["event_type"] != event.get("type"):
            return False
        # 严重程度阈值：事件严重程度 >= 规则阈值
        ev_sev = _SEV_RANK.get(event.get("severity", "low"), 1)
        rl_sev = _SEV_RANK.get(trig["severity_threshold"], 1)
        if ev_sev < rl_sev:
            return False
        # 字段匹配
        for k, v in (trig.get("field_match") or {}).items():
            if str((event.get("data") or {}).get(k, "")) != str(v):
                return False
        return True

    def _do_action(self, action: str, rule: Dict[str, Any],
                   event: Dict[str, Any]) -> Dict[str, Any]:
        """执行单个联动动作（内存模拟）。"""
        return {
            "action": action,
            "rule": rule["name"],
            "target_domain": rule["target_domain"],
            "event": event.get("type"),
            "executed_at": time.time(),
            "result": f"已将 {rule['source_domain']} 的事件同步到 {rule['target_domain']}",
        }

    # ------------------------------------------------------------------ #
    def dispatch(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """事件入口：监听 -> 匹配 -> 去重 -> 执行。"""
        matched = []
        fired = []
        failed = []
        rules = self.rm.list_enabled()
        for rule in rules:
            if not self._match(rule, event):
                continue
            matched.append(rule["id"])
            # 去重
            dk = self._dedup_key(rule["source_domain"], event["type"],
                                  event.get("data"))
            window = rule["trigger"]["time_window_sec"]
            now = time.time()
            last = self._dedup.get(dk, 0)
            if now - last < window:
                self.logger.log(rule["id"], rule["name"],
                                rule["source_domain"], rule["target_domain"],
                                event, "retried",
                                detail="时间窗口内去重跳过")
                continue
            self._dedup[dk] = now
            # 执行动作（带重试）
            ok_all = True
            action_results = []
            for attempt in range(1, MAX_RETRY + 1):
                try:
                    action_results = [self._do_action(a, rule, event)
                                      for a in rule["actions"]]
                    break
                except Exception as e:  # pragma: no cover
                    if attempt == MAX_RETRY:
                        ok_all = False
                        self.logger.log(rule["id"], rule["name"],
                                        rule["source_domain"],
                                        rule["target_domain"], event,
                                        "failed", detail=str(e),
                                        retry=attempt)
            if ok_all:
                self.rm.record_hit(rule["id"], True)
                self.logger.log(rule["id"], rule["name"],
                                rule["source_domain"], rule["target_domain"],
                                event, "success",
                                detail=f"执行 {len(rule['actions'])} 个动作")
                fired.append({"rule_id": rule["id"], "name": rule["name"],
                              "actions": action_results})
            else:
                self.rm.record_hit(rule["id"], False)
                failed.append(rule["id"])
        return {
            "event": event,
            "matched": matched,
            "fired": fired,
            "failed": failed,
            "fired_count": len(fired),
        }

    # ------------------------------------------------------------------ #
    def test_rule(self, rule_id: str,
                  event: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """手动测试一条规则（注入一条模拟事件）。"""
        rule = self.rm.get(rule_id)
        if rule is None:
            return {"success": False, "error": "rule not found"}
        if event is None:
            event = {
                "domain": rule["source_domain"],
                "type": rule["trigger"]["event_type"],
                "severity": "critical",
                "data": {"test": True, "title": "联动测试事件"},
            }
        result = self.dispatch(event)
        return {"success": True, "result": result}

    def replay(self, log_id: str) -> Dict[str, Any]:
        """按联动日志重放。"""
        for entry in self.logger.list(limit=1000):
            if entry["id"] == log_id:
                event = {
                    "domain": entry["source_domain"],
                    "type": entry["event_type"],
                    "severity": "high",
                    "data": {"replay": True},
                }
                return self.dispatch(event)
        return {"success": False, "error": "log not found"}


_default: Optional[LinkageEngine] = None


def get_linkage_engine() -> LinkageEngine:
    global _default
    if _default is None:
        _default = LinkageEngine()
    return _default
