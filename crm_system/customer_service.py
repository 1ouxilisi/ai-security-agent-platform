# -*- coding: utf-8 -*-
"""customer_service.py — 客户服务与支持。

工单 / 知识库 / 客户社区 / 满意度调查 / 客户成功 / 服务报告。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from crm_system import DB, now_str, new_id, seed_if_needed


class CustomerService:
    """服务工单、知识库、社区、调查、客户成功、服务报告。"""

    # ------------------------------------------------------------------ #
    # 工单
    # ------------------------------------------------------------------ #
    def create_ticket(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        tid = new_id("tk")
        ticket = {
            "id": tid, "customer_id": data.get("customer_id", ""),
            "title": data.get("title", "新工单"),
            "category": data.get("category", "技术支持"),
            "priority": data.get("priority", "中"),
            "status": "待处理",
            "assignee": data.get("assignee", "未分配"),
            "sla_due": data.get("sla_due", now_str()),
            "description": data.get("description", ""),
            "rating": None, "satisfaction": None,
            "created_at": now_str(), "resolved_at": None,
        }
        with DB.lock:
            DB.tickets[tid] = ticket
            DB.ticket_replies[tid] = []
        return ticket

    def list_tickets(self, status: str = "", customer_id: str = "",
                     priority: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.tickets.values())
        if status:
            rows = [r for r in rows if r.get("status") == status]
        if customer_id:
            rows = [r for r in rows if r.get("customer_id") == customer_id]
        if priority:
            rows = [r for r in rows if r.get("priority") == priority]
        return rows

    def reply_ticket(self, tid: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with DB.lock:
            if tid not in DB.tickets:
                return None
            rep = {
                "time": now_str(), "author": data.get("author", "客服"),
                "content": data.get("content", ""), "is_internal": False,
            }
            DB.ticket_replies.setdefault(tid, []).append(rep)
            return rep

    def resolve_ticket(self, tid: str, rating: Optional[int] = None) -> Optional[Dict[str, Any]]:
        with DB.lock:
            t = DB.tickets.get(tid)
            if not t:
                return None
            t["status"] = "已解决"
            t["resolved_at"] = now_str()
            if rating is not None:
                t["rating"] = rating
                t["satisfaction"] = "满意" if rating >= 4 else "一般" if rating == 3 else "不满意"
            return t

    # ------------------------------------------------------------------ #
    # 知识库
    # ------------------------------------------------------------------ #
    def list_kb(self, keyword: str = "", category: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.kb_articles.values())
        if keyword:
            rows = [r for r in rows if keyword.lower() in r.get("title", "").lower()
                    or keyword.lower() in r.get("content", "").lower()]
        if category:
            rows = [r for r in rows if r.get("category") == category]
        return sorted(rows, key=lambda x: x.get("views", 0), reverse=True)

    # ------------------------------------------------------------------ #
    # 客户社区
    # ------------------------------------------------------------------ #
    def list_community(self, section: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.community_posts.values())
        if section:
            rows = [r for r in rows if r.get("section") == section]
        return sorted(rows, key=lambda x: (x.get("is_top", False), x.get("likes", 0)),
                      reverse=True)

    def create_post(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        pid = new_id("post")
        post = {
            "id": pid, "title": data.get("title", "新帖子"),
            "section": data.get("section", "经验交流"),
            "author": data.get("author", "匿名"),
            "content": data.get("content", ""),
            "replies": 0, "likes": 0,
            "is_top": False, "is_essence": False,
            "created_at": now_str(),
        }
        with DB.lock:
            DB.community_posts[pid] = post
        return post

    # ------------------------------------------------------------------ #
    # 满意度调查
    # ------------------------------------------------------------------ #
    def create_survey(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        sid = new_id("sv")
        survey = {
            "id": sid, "name": data.get("name", "新调查"),
            "template": data.get("template", "标准NPS"),
            "questions": list(data.get("questions", ["总体满意度", "推荐意愿(NPS)"])),
            "channel": data.get("channel", "邮件"),
            "target_customer_ids": list(data.get("customer_ids", [])),
            "responses": [],
            "sent_at": now_str(),
            "created_at": now_str(),
        }
        with DB.lock:
            DB.surveys[sid] = survey
        return survey

    def submit_survey_response(self, sid: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with DB.lock:
            s = DB.surveys.get(sid)
            if not s:
                return None
            resp = {
                "respondent": data.get("respondent", ""),
                "answers": data.get("answers", {}),
                "nps": int(data.get("nps", 0)),
                "submitted_at": now_str(),
            }
            s["responses"].append(resp)
            return resp

    def survey_stats(self, sid: str) -> Optional[Dict[str, Any]]:
        with DB.lock:
            s = DB.surveys.get(sid)
            if not s:
                return None
            resps = s.get("responses", [])
        nps_vals = [r["nps"] for r in resps if "nps" in r]
        promoters = len([n for n in nps_vals if n >= 9])
        detractors = len([n for n in nps_vals if n <= 6])
        nps = round((promoters - detractors) / max(1, len(nps_vals)) * 100, 1)
        return {
            "survey_id": sid, "name": s.get("name"),
            "response_count": len(resps),
            "avg_nps": nps,
            "promoters": promoters, "detractors": detractors,
            "responses": resps[-20:],
        }

    # ------------------------------------------------------------------ #
    # 客户成功
    # ------------------------------------------------------------------ #
    def customer_success_list(self) -> List[Dict[str, Any]]:
        seed_if_needed()
        from crm_system.customer_manager import manager as cm
        out = []
        with DB.lock:
            customers = list(DB.customers.values())
        for c in customers:
            health = cm.compute_health(c["id"])
            plan = {
                "customer_id": c["id"], "name": c["name"],
                "health": health,
                "risk_flags": health.get("risk_flags", []),
                "expansion_opportunity": c.get("stage") in ("付费", "续费"),
                "next_qbr": now_str()[:10],
                "retention_strategy": "客户成功经理季度回顾" if health["score"] >= 60
                                      else "挽留计划+高管介入",
            }
            with DB.lock:
                DB.customer_success[c["id"]] = plan
            out.append(plan)
        return out

    # ------------------------------------------------------------------ #
    # 服务报告
    # ------------------------------------------------------------------ #
    def service_report(self) -> Dict[str, Any]:
        with DB.lock:
            tickets = list(DB.tickets.values())
        total = len(tickets)
        resolved = len([t for t in tickets if t.get("status") == "已解决"])
        open_cnt = len([t for t in tickets if t.get("status") not in ("已解决",)])
        rated = [t for t in tickets if t.get("rating") is not None]
        avg_rating = round(sum(t["rating"] for t in rated) / max(1, len(rated)), 2)
        sla_ok = len([t for t in tickets if t.get("status") == "已解决"])
        by_priority: Dict[str, int] = {}
        for t in tickets:
            by_priority[t.get("priority", "中")] = by_priority.get(t.get("priority", "中"), 0) + 1
        by_category: Dict[str, int] = {}
        for t in tickets:
            by_category[t.get("category", "其他")] = by_category.get(t.get("category", "其他"), 0) + 1
        return {
            "total_tickets": total,
            "resolved": resolved,
            "open": open_cnt,
            "resolution_rate": round(resolved / max(1, total), 3),
            "avg_rating": avg_rating,
            "sla_compliance": round(sla_ok / max(1, total), 3),
            "first_contact_resolution": round(resolved / max(1, total), 3),
            "avg_response_time_min": 15,
            "avg_resolution_time_hours": 8,
            "by_priority": by_priority,
            "by_category": by_category,
            "improvements": ["补充知识库文章", "优化SLA预警", "加强产品易用性"],
        }


service = CustomerService()

__all__ = ["CustomerService", "service"]
