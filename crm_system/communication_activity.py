# -*- coding: utf-8 -*-
"""communication_activity.py — 沟通与活动管理。

沟通记录 / 市场活动 / 任务 / 提醒通知 / 邮件集成 / 电话集成。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from crm_system import DB, now_str, new_id, seed_if_needed


class CommunicationActivity:
    """沟通、活动、任务、提醒、邮件、电话一体化管理。"""

    # ------------------------------------------------------------------ #
    # 沟通记录
    # ------------------------------------------------------------------ #
    def list_communications(self, customer_id: str = "",
                             ctype: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        rows = list(DB.communication)
        if customer_id:
            rows = [r for r in rows if r.get("customer_id") == customer_id]
        if ctype:
            rows = [r for r in rows if r.get("type") == ctype]
        return list(reversed(rows))

    def add_communication(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        rec = {
            "id": new_id("cm"),
            "customer_id": data.get("customer_id", ""),
            "contact_id": data.get("contact_id", ""),
            "type": data.get("type", "电话"),
            "content": data.get("content", ""),
            "participants": list(data.get("participants", [])),
            "result": data.get("result", ""),
            "next_action": data.get("next_action", ""),
            "time": now_str(),
        }
        with DB.lock:
            DB.communication.append(rec)
        return rec

    # ------------------------------------------------------------------ #
    # 市场活动
    # ------------------------------------------------------------------ #
    def create_activity(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        aid = new_id("act")
        activity = {
            "id": aid, "name": data.get("name", "新活动"),
            "type": data.get("type", "线上研讨会"),
            "time": data.get("time", now_str()),
            "location": data.get("location", ""),
            "content": data.get("content", ""),
            "customer_ids": list(data.get("customer_ids", [])),
            "contact_ids": list(data.get("contact_ids", [])),
            "cost": float(data.get("cost", 0)),
            "leads": int(data.get("leads", 0)),
            "result": data.get("result", ""),
            "revenue_generated": float(data.get("revenue_generated", 0)),
            "created_at": now_str(),
        }
        activity["roi"] = round(
            (activity["revenue_generated"] - activity["cost"]) / max(1.0, activity["cost"]), 3)
        with DB.lock:
            DB.activities[aid] = activity
        return activity

    def list_activities(self) -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            return list(DB.activities.values())

    # ------------------------------------------------------------------ #
    # 任务
    # ------------------------------------------------------------------ #
    def create_task(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        tid = new_id("task")
        task = {
            "id": tid, "title": data.get("title", "新任务"),
            "type": data.get("type", "跟进"),
            "customer_id": data.get("customer_id", ""),
            "opportunity_id": data.get("opportunity_id", ""),
            "owner": data.get("owner", "未分配"),
            "due_date": data.get("due_date", ""),
            "priority": data.get("priority", "中"),
            "status": "待办",
            "repeat": data.get("repeat", "不重复"),
            "remind": data.get("remind", True),
            "created_at": now_str(), "done_at": None,
        }
        with DB.lock:
            DB.tasks[tid] = task
        return task

    def list_tasks(self, status: str = "", owner: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.tasks.values())
        if status:
            rows = [r for r in rows if r.get("status") == status]
        if owner:
            rows = [r for r in rows if r.get("owner") == owner]
        return rows

    def complete_task(self, tid: str) -> Optional[Dict[str, Any]]:
        with DB.lock:
            t = DB.tasks.get(tid)
            if not t:
                return None
            t["status"] = "已完成"
            t["done_at"] = now_str()
            return t

    # ------------------------------------------------------------------ #
    # 提醒与通知
    # ------------------------------------------------------------------ #
    def list_reminders(self, include_done: bool = False) -> List[Dict[str, Any]]:
        seed_if_needed()
        rows = list(DB.reminders)
        if not include_done:
            rows = [r for r in rows if not r.get("done")]
        return rows

    def add_reminder(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        rem = {
            "id": new_id("rm"),
            "type": data.get("type", "自定义"),
            "customer_id": data.get("customer_id", ""),
            "title": data.get("title", "提醒"),
            "due": data.get("due", now_str()),
            "channel": data.get("channel", "站内"),
            "done": False,
        }
        with DB.lock:
            DB.reminders.append(rem)
        return rem

    def check_reminders(self) -> Dict[str, Any]:
        """扫描生日/纪念日/合同到期/续费提醒。"""
        seed_if_needed()
        today = now_str()[5:10]
        with DB.lock:
            contacts = list(DB.contacts.values())
            contracts = list(DB.contracts.values())
        birthday = [c for c in contacts if c.get("birthday", "")[5:10] == today]
        anniv = [c for c in contacts if c.get("anniversary", "")[5:10] == today]
        expiring = [c for c in contracts
                    if c.get("end_date", "") and c["end_date"][5:10] <= today
                    and c.get("sign_status") == "已签署"]
        return {
            "birthday_reminders": birthday,
            "anniversary_reminders": anniv,
            "contract_expiring": expiring,
            "pending_tasks": len([t for t in DB.tasks.values() if t.get("status") == "待办"]),
        }

    # ------------------------------------------------------------------ #
    # 邮件集成（模拟）
    # ------------------------------------------------------------------ #
    def send_email(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        mail = {
            "id": new_id("em"),
            "customer_id": data.get("customer_id", ""),
            "to": data.get("to", ""),
            "subject": data.get("subject", ""),
            "body": data.get("body", ""),
            "template": data.get("template", ""),
            "direction": "out",
            "status": "已发送",
            "opened": False, "clicked": False,
            "time": now_str(),
        }
        with DB.lock:
            DB.email_log.append(mail)
        return mail

    def list_emails(self, customer_id: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        rows = list(DB.email_log)
        if customer_id:
            rows = [r for r in rows if r.get("customer_id") == customer_id]
        return list(reversed(rows))

    def email_stats(self) -> Dict[str, Any]:
        rows = list(DB.email_log)
        sent = [r for r in rows if r.get("direction") == "out"]
        opened = [r for r in sent if r.get("opened") or r.get("status") == "opened"]
        return {
            "total_sent": len(sent),
            "opened": len(opened),
            "open_rate": round(len(opened) / max(1, len(sent)), 3),
            "tracked": len(sent),
        }

    # ------------------------------------------------------------------ #
    # 电话集成（模拟）
    # ------------------------------------------------------------------ #
    def log_call(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        call = {
            "id": new_id("ph"),
            "customer_id": data.get("customer_id", ""),
            "direction": data.get("direction", "out"),
            "phone": data.get("phone", ""),
            "duration_sec": int(data.get("duration_sec", 0)),
            "recording": data.get("recording", ""),
            "result": data.get("result", ""),
            "time": now_str(),
        }
        with DB.lock:
            DB.phone_log.append(call)
        return call

    def list_calls(self, customer_id: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        rows = list(DB.phone_log)
        if customer_id:
            rows = [r for r in rows if r.get("customer_id") == customer_id]
        return list(reversed(rows))

    def call_stats(self) -> Dict[str, Any]:
        rows = list(DB.phone_log)
        total_dur = sum(int(r.get("duration_sec", 0)) for r in rows)
        return {
            "total_calls": len(rows),
            "total_duration_sec": total_dur,
            "avg_duration_sec": round(total_dur / max(1, len(rows)), 1),
            "outgoing": len([r for r in rows if r.get("direction") == "out"]),
        }


comm = CommunicationActivity()

__all__ = ["CommunicationActivity", "comm"]
