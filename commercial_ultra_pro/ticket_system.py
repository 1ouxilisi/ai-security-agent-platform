#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
commercial_ultra_pro/ticket_system.py — 工单系统。

- 工单创建（Web/邮件/API）
- 工单分配（自动/手动/认领/转派）
- 工单跟踪（状态/时间线/回复/附件/关联）
- 满意度评价（1-5星/好评率）
- 工单统计（数量/时效/绩效/SLA达标）
"""

from __future__ import annotations

import statistics
import threading
import time
from typing import Any, Dict, List, Optional


TICKET_TYPES = ["技术支持", "功能咨询", "故障报告", "投诉建议", "其他"]
PRIORITIES = ["低", "中", "高", "紧急"]
PRIORITY_SLA_HOURS = {"低": 24, "中": 8, "高": 2, "紧急": 0.5}
STATUS_FLOW = ["新建", "已分配", "处理中", "待客户回复", "已解决", "已关闭"]


class TicketSystem:
    """工单系统（内存存储）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tickets: Dict[str, Dict[str, Any]] = {}
        # agent_id -> tickets assigned
        self._agents: Dict[str, List[str]] = {}
        self._seq = 0

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}{time.strftime('%Y%m%d')}-{self._seq:05d}"

    def _now(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def _timeline(self, ticket: Dict[str, Any], event: str, operator: str = "") -> None:
        ticket["timeline"].append({"event": event, "operator": operator,
                                    "at": self._now()})

    # ------------------------------------------------------------------ #
    # 创建
    # ------------------------------------------------------------------ #
    def create_ticket(self, customer_id: str, title: str, ttype: str = "技术支持",
                       priority: str = "中", description: str = "",
                       attachments: Optional[List[str]] = None,
                       channel: str = "web") -> Dict[str, Any]:
        if ttype not in TICKET_TYPES:
            raise ValueError(f"类型必须为 {TICKET_TYPES}")
        if priority not in PRIORITIES:
            raise ValueError(f"优先级必须为 {PRIORITIES}")
        with self._lock:
            tid = self._next_id("TK")
            t = {
                "ticket_id": tid, "customer_id": customer_id,
                "title": title, "type": ttype, "priority": priority,
                "description": description, "attachments": attachments or [],
                "channel": channel, "status": "新建",
                "assignee": "", "replies": [], "rating": 0, "rating_text": "",
                "timeline": [], "linked": [],
                "created_at": self._now(),
                "first_response_at": "", "resolved_at": "",
            }
            self._timeline(t, "创建", customer_id)
            self._tickets[tid] = t
            return t

    # ------------------------------------------------------------------ #
    # 分配
    # ------------------------------------------------------------------ #
    def auto_assign(self, ticket_id: str) -> Dict[str, Any]:
        """按负载自动分配给最闲的处理人。"""
        with self._lock:
            t = self._tickets.get(ticket_id)
            if not t:
                raise ValueError("工单不存在")
            if not self._agents:
                raise ValueError("暂无处理人，请先注册处理人")
            # 找当前工单最少的处理人
            agent = min(self._agents.keys(),
                        key=lambda a: len(self._agents[a]))
            t["assignee"] = agent
            t["status"] = "已分配"
            self._agents.setdefault(agent, []).append(ticket_id)
            self._timeline(t, "自动分配", agent)
            return t

    def assign(self, ticket_id: str, agent: str) -> Dict[str, Any]:
        with self._lock:
            t = self._tickets.get(ticket_id)
            if not t:
                raise ValueError("工单不存在")
            old = t["assignee"]
            t["assignee"] = agent
            t["status"] = "已分配"
            self._agents.setdefault(agent, []).append(ticket_id)
            self._timeline(t, f"手动分配 {old or '无'} -> {agent}", agent)
            return t

    def claim(self, ticket_id: str, agent: str) -> Dict[str, Any]:
        with self._lock:
            t = self._tickets.get(ticket_id)
            if not t:
                raise ValueError("工单不存在")
            if t["assignee"]:
                raise ValueError("工单已被认领")
            t["assignee"] = agent
            t["status"] = "处理中"
            self._agents.setdefault(agent, []).append(ticket_id)
            self._timeline(t, f"认领", agent)
            return t

    def transfer(self, ticket_id: str, to_agent: str) -> Dict[str, Any]:
        with self._lock:
            t = self._tickets.get(ticket_id)
            if not t:
                raise ValueError("工单不存在")
            old = t["assignee"]
            t["assignee"] = to_agent
            self._agents.setdefault(to_agent, []).append(ticket_id)
            self._timeline(t, f"转派 {old} -> {to_agent}", to_agent)
            return t

    def register_agent(self, agent: str) -> Dict[str, Any]:
        with self._lock:
            self._agents.setdefault(agent, [])
            return {"agent": agent, "tickets": len(self._agents[agent])}

    # ------------------------------------------------------------------ #
    # 跟踪 / 回复
    # ------------------------------------------------------------------ #
    def reply(self, ticket_id: str, content: str,
               author: str = "", internal: bool = False) -> Dict[str, Any]:
        with self._lock:
            t = self._tickets.get(ticket_id)
            if not t:
                raise ValueError("工单不存在")
            t["replies"].append({"author": author or t["assignee"],
                                  "content": content, "internal": internal,
                                  "at": self._now()})
            if not internal:
                if not t["first_response_at"]:
                    t["first_response_at"] = self._now()
                t["status"] = "处理中"
                self._timeline(t, "回复", author or t["assignee"])
            else:
                self._timeline(t, f"内部备注(by {author or t['assignee']})")
            return t

    def set_status(self, ticket_id: str, status: str) -> Dict[str, Any]:
        if status not in STATUS_FLOW:
            raise ValueError(f"状态必须为 {STATUS_FLOW}")
        with self._lock:
            t = self._tickets.get(ticket_id)
            if not t:
                raise ValueError("工单不存在")
            t["status"] = status
            if status == "已解决":
                t["resolved_at"] = self._now()
            self._timeline(t, f"状态 -> {status}", t["assignee"])
            return t

    def link_ticket(self, ticket_id: str, related_id: str) -> Dict[str, Any]:
        with self._lock:
            t = self._tickets.get(ticket_id)
            if not t or related_id not in self._tickets:
                raise ValueError("工单不存在")
            if related_id not in t["linked"]:
                t["linked"].append(related_id)
            return t

    # ------------------------------------------------------------------ #
    # 满意度
    # ------------------------------------------------------------------ #
    def rate(self, ticket_id: str, stars: int, text: str = "") -> Dict[str, Any]:
        if not (1 <= stars <= 5):
            raise ValueError("评分必须为 1-5")
        with self._lock:
            t = self._tickets.get(ticket_id)
            if not t:
                raise ValueError("工单不存在")
            t["rating"] = stars
            t["rating_text"] = text
            return t

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def get_ticket(self, ticket_id: str) -> Dict[str, Any]:
        with self._lock:
            t = self._tickets.get(ticket_id)
            if not t:
                raise ValueError("工单不存在")
            return dict(t)

    def list_tickets(self, status: Optional[str] = None,
                      ttype: Optional[str] = None,
                      priority: Optional[str] = None,
                      customer_id: Optional[str] = None,
                      assignee: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._tickets.values())
            if status:
                out = [t for t in out if t["status"] == status]
            if ttype:
                out = [t for t in out if t["type"] == ttype]
            if priority:
                out = [t for t in out if t["priority"] == priority]
            if customer_id:
                out = [t for t in out if t["customer_id"] == customer_id]
            if assignee:
                out = [t for t in out if t["assignee"] == assignee]
            return sorted(out, key=lambda x: x["created_at"], reverse=True)

    # ------------------------------------------------------------------ #
    # 统计
    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            tickets = list(self._tickets.values())
            by_type: Dict[str, int] = {}
            by_priority: Dict[str, int] = {}
            by_status: Dict[str, int] = {}
            rated = [t for t in tickets if t["rating"] > 0]
            for t in tickets:
                by_type[t["type"]] = by_type.get(t["type"], 0) + 1
                by_priority[t["priority"]] = by_priority.get(t["priority"], 0) + 1
                by_status[t["status"]] = by_status.get(t["status"], 0) + 1
            # 处理时效
            first_resp = []
            resolve_times = []
            for t in tickets:
                if t["first_response_at"]:
                    mins = self._diff_min(t["created_at"], t["first_response_at"])
                    if mins is not None:
                        first_resp.append(mins)
                if t["resolved_at"]:
                    mins = self._diff_min(t["created_at"], t["resolved_at"])
                    if mins is not None:
                        resolve_times.append(mins)
            avg_first = round(statistics.mean(first_resp), 1) if first_resp else 0
            avg_resolve = round(statistics.mean(resolve_times), 1) if resolve_times else 0
            # SLA 达标（首次响应 vs 优先级 SLA）
            sla_met = 0
            sla_total = 0
            for t in tickets:
                if t["first_response_at"]:
                    mins = self._diff_min(t["created_at"], t["first_response_at"])
                    if mins is not None:
                        sla_total += 1
                        if mins <= PRIORITY_SLA_HOURS[t["priority"]] * 60:
                            sla_met += 1
            avg_rating = round(statistics.mean([t["rating"] for t in rated]), 2) if rated else 0
            good = sum(1 for t in rated if t["rating"] >= 4)
            return {
                "total": len(tickets),
                "by_type": by_type, "by_priority": by_priority,
                "by_status": by_status,
                "avg_first_response_min": avg_first,
                "avg_resolve_min": avg_resolve,
                "rated": len(rated), "avg_rating": avg_rating,
                "good_rate": round(good / len(rated) * 100, 1) if rated else 0,
                "sla_met": sla_met, "sla_total": sla_total,
                "sla_rate": round(sla_met / sla_total * 100, 1) if sla_total else 0,
                "agents": {a: len(v) for a, v in self._agents.items()},
            }

    @staticmethod
    def _diff_min(a: str, b: str) -> Optional[float]:
        try:
            ta = time.mktime(time.strptime(a, "%Y-%m-%d %H:%M:%S"))
            tb = time.mktime(time.strptime(b, "%Y-%m-%d %H:%M:%S"))
            return (tb - ta) / 60.0
        except ValueError:
            return None


_ticket: TicketSystem | None = None


def get_ticket_system() -> TicketSystem:
    global _ticket
    if _ticket is None:
        _ticket = TicketSystem()
    return _ticket
