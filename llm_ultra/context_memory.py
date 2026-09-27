# -*- coding: utf-8 -*-
"""context_memory.py — 上下文记忆。

AI能记住之前的扫描结果，持续分析，基于历史数据。
会话上下文管理。
"""
from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional


class ContextMemory:
    """上下文记忆引擎：存储扫描历史和会话上下文。"""

    def __init__(self, max_sessions: int = 100,
                 max_messages_per_session: int = 50) -> None:
        self._max_sessions = max_sessions
        self._max_messages = max_messages_per_session
        self._sessions: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._scan_history: List[Dict[str, Any]] = []
        self._vuln_memory: Dict[str, List[Dict[str, Any]]] = {}

    def create_session(self, session_id: str,
                       metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """创建新会话。"""
        if session_id in self._sessions:
            return self._sessions[session_id]
        if len(self._sessions) >= self._max_sessions:
            # LRU淘汰最久未使用的
            self._sessions.popitem(last=False)
        self._sessions[session_id] = {
            "id": session_id,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "messages": [],
            "metadata": metadata or {},
            "scan_context": {},
        }
        return self._sessions[session_id]

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self._sessions.get(session_id)

    def add_message(self, session_id: str, role: str,
                    content: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """向会话添加一条消息。"""
        s = self._sessions.get(session_id)
        if not s:
            s = self.create_session(session_id)
        msg = {
            "role": role,
            "content": content,
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "metadata": metadata or {},
        }
        s["messages"].append(msg)
        if len(s["messages"]) > self._max_messages:
            s["messages"] = s["messages"][-self._max_messages:]
        s["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return msg

    def get_history(self, session_id: str,
                    limit: int = 20) -> List[Dict[str, Any]]:
        """获取会话历史消息。"""
        s = self._sessions.get(session_id)
        if not s:
            return []
        return s["messages"][-limit:]

    def get_context_summary(self, session_id: str) -> str:
        """生成会话上下文摘要，用于注入到LLM prompt。"""
        s = self._sessions.get(session_id)
        if not s or not s["messages"]:
            return "新会话，无历史上下文。"
        lines = [f"会话ID: {session_id}"]
        lines.append(f"消息数: {len(s['messages'])}")
        lines.append("最近对话摘要:")
        for m in s["messages"][-5:]:
            role_label = "用户" if m["role"] == "user" else "AI"
            content = m["content"][:150]
            lines.append(f"  [{role_label}] {content}...")
        if s.get("scan_context"):
            lines.append(f"扫描上下文: {s['scan_context']}")
        return "\n".join(lines)

    def save_scan_result(self, target: str,
                         scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """保存一次扫描结果到记忆中。"""
        entry = {
            "target": target,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vuln_count": len(scan_data.get("vulns", [])),
            "critical": scan_data.get("critical_count", 0),
            "high": scan_data.get("high_count", 0),
            "medium": scan_data.get("medium_count", 0),
            "summary": scan_data.get("summary", ""),
            "raw": scan_data,
        }
        self._scan_history.append(entry)
        if target not in self._vuln_memory:
            self._vuln_memory[target] = []
        self._vuln_memory[target].append(entry)
        return entry

    def get_scan_history(self, target: Optional[str] = None,
                         limit: int = 20) -> List[Dict[str, Any]]:
        """获取扫描历史。"""
        if target:
            return list(reversed(self._vuln_memory.get(target, [])))[-limit:]
        return list(reversed(self._scan_history))[-limit:]

    def get_target_summary(self, target: str) -> Dict[str, Any]:
        """获取目标的历史安全概况。"""
        history = self._vuln_memory.get(target, [])
        if not history:
            return {"target": target, "scans": 0, "note": "无历史扫描记录"}
        total_vulns = sum(h["vuln_count"] for h in history)
        all_critical = sum(h["critical"] for h in history)
        all_high = sum(h["high"] for h in history)
        return {
            "target": target,
            "scans": len(history),
            "first_scan": history[0]["timestamp"],
            "last_scan": history[-1]["timestamp"],
            "total_vulns_ever_found": total_vulns,
            "total_critical": all_critical,
            "total_high": all_high,
            "trend": "improving" if len(history) >= 2 and
                     history[-1]["vuln_count"] < history[-2]["vuln_count"]
                     else "stable",
        }

    def inject_context_to_prompt(self, session_id: str,
                                  base_prompt: str) -> str:
        """将会话上下文注入到基础prompt中。"""
        ctx = self.get_context_summary(session_id)
        return f"{base_prompt}\n\n# 当前会话上下文\n{ctx}"

    def clear_session(self, session_id: str) -> bool:
        """清除会话。"""
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def list_sessions(self) -> List[Dict[str, Any]]:
        """列出所有会话。"""
        return [
            {"id": s["id"], "created_at": s["created_at"],
             "updated_at": s["updated_at"],
             "messages_count": len(s["messages"]),
             "metadata": s["metadata"]}
            for s in self._sessions.values()
        ]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "sessions": len(self._sessions),
            "total_scans_recorded": len(self._scan_history),
            "tracked_targets": len(self._vuln_memory),
            "max_sessions": self._max_sessions,
            "max_messages_per_session": self._max_messages,
        }


_singleton: Optional[ContextMemory] = None


def get_context_memory() -> ContextMemory:
    global _singleton
    if _singleton is None:
        _singleton = ContextMemory()
    return _singleton
