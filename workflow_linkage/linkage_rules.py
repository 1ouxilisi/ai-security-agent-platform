# -*- coding: utf-8 -*-
"""
linkage_rules.py — 联动规则管理（8 条预设规则 + 自定义规则）。

规则属性: 名称/描述/源领域/目标领域/触发条件/执行动作/优先级/启用状态。
触发条件: 事件类型/严重程度阈值/字段匹配/时间窗口。
执行动作: 创建任务/生成告警/同步数据/发送通知/调用 API。
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional


# 动作类型
ACTIONS = ["create_task", "generate_alert", "sync_data",
           "send_notification", "call_api"]

# 事件类型
EVENT_TYPES = ["vuln_found", "alert_created", "task_done",
               "ioc_detected", "attack_trace", "data_discovered",
               "device_vuln", "challenge_created", "submission_received"]


class LinkageRuleManager:
    """联动规则管理器（单例，线程安全）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._rules: Dict[str, Dict[str, Any]] = {}
        self._seq = 0

    def _new_id(self) -> str:
        self._seq += 1
        return f"lrule-{self._seq}"

    def create(self, name: str, source_domain: str, target_domain: str,
               description: str = "", event_type: str = "vuln_found",
               severity_threshold: str = "low",
               field_match: Optional[Dict[str, str]] = None,
               time_window_sec: int = 300,
               actions: Optional[List[str]] = None,
               priority: int = 5,
               enabled: bool = True,
               rule_id: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            rid = rule_id or self._new_id()
            rule = {
                "id": rid,
                "name": name,
                "description": description,
                "source_domain": source_domain,
                "target_domain": target_domain,
                "trigger": {
                    "event_type": event_type,
                    "severity_threshold": severity_threshold,
                    "field_match": field_match or {},
                    "time_window_sec": time_window_sec,
                },
                "actions": actions or ["generate_alert"],
                "priority": priority,
                "enabled": enabled,
                "created_at": time.time(),
                "hit_count": 0,
                "success_count": 0,
                "fail_count": 0,
            }
            self._rules[rid] = rule
            return dict(rule)

    def update(self, rule_id: str,
               patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            r = self._rules.get(rule_id)
            if r is None:
                return None
            # 触发条件合并
            if "trigger" in patch and isinstance(patch["trigger"], dict):
                r["trigger"].update(patch["trigger"])
                patch = {k: v for k, v in patch.items() if k != "trigger"}
            r.update(patch)
            return dict(r)

    def delete(self, rule_id: str) -> bool:
        with self._lock:
            return self._rules.pop(rule_id, None) is not None

    def toggle(self, rule_id: str, enabled: bool) -> Optional[Dict[str, Any]]:
        return self.update(rule_id, {"enabled": enabled})

    def get(self, rule_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            r = self._rules.get(rule_id)
            return dict(r) if r else None

    def list(self, enabled: Optional[bool] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = [dict(r) for r in self._rules.values()]
        if enabled is not None:
            items = [i for i in items if i["enabled"] == enabled]
        items.sort(key=lambda x: (x["priority"], x["created_at"]))
        return items

    def list_enabled(self) -> List[Dict[str, Any]]:
        return self.list(enabled=True)

    # ------------------------------------------------------------------ #
    def record_hit(self, rule_id: str, success: bool) -> None:
        with self._lock:
            r = self._rules.get(rule_id)
            if r is None:
                return
            r["hit_count"] += 1
            if success:
                r["success_count"] += 1
            else:
                r["fail_count"] += 1

    def stats(self) -> Dict[str, Any]:
        items = self.list()
        enabled = sum(1 for i in items if i["enabled"])
        return {
            "total": len(items),
            "enabled": enabled,
            "disabled": len(items) - enabled,
            "rules": items,
        }


_default: Optional[LinkageRuleManager] = None


def get_rule_manager() -> LinkageRuleManager:
    global _default
    if _default is None:
        _default = LinkageRuleManager()
    return _default
