# -*- coding: utf-8 -*-
"""customer_manager.py — 客户信息管理。

客户档案 / 分类 / 360视图 / 联系人 / 生命周期 / 客户健康度。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from crm_system import (
    DB, now_str, new_id, seed_if_needed,
    _INDUSTRIES, _REGIONS, _SIZES, _LEVELS, _SOURCES, _STAGES, _STAGE_PROB,
)


def _label(score: float) -> str:
    if score >= 80:
        return "健康"
    if score >= 60:
        return "关注"
    if score >= 40:
        return "风险"
    return "流失预警"


class CustomerManager:
    """客户档案与全生命周期管理。"""

    STAGES = _STAGES
    STAGE_PROB = _STAGE_PROB

    # ------------------------------------------------------------------ #
    # 档案 CRUD
    # ------------------------------------------------------------------ #
    def create_customer(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        cid = new_id("cus")
        customer = {
            "id": cid,
            "name": data.get("name", "未命名客户"),
            "industry": data.get("industry", "其他"),
            "size": data.get("size", "1-50人"),
            "region": data.get("region", "未填写"),
            "level": data.get("level", "C"),
            "source": data.get("source", "官网咨询"),
            "stage": data.get("stage", "线索"),
            "website": data.get("website", ""),
            "address": data.get("address", ""),
            "tags": list(data.get("tags", [])),
            "remark": data.get("remark", ""),
            "custom_fields": dict(data.get("custom_fields", {})),
            "health_score": 70.0,
            "health_status": "关注",
            "nps": 50,
            "login_count_30d": 0,
            "ticket_count_30d": 0,
            "payment_on_time": True,
            "created_at": now_str(),
            "updated_at": now_str(),
            "stage_entered_at": now_str(),
            "lifecycle_history": [{"stage": "线索", "time": now_str()}],
        }
        with DB.lock:
            DB.customers[cid] = customer
            DB.log_audit(data.get("owner", "system"), "customer.create", cid)
        return customer

    def update_customer(self, cid: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with DB.lock:
            c = DB.customers.get(cid)
            if not c:
                return None
            for k in ("name", "industry", "size", "region", "level", "source",
                      "website", "address", "remark"):
                if k in data:
                    c[k] = data[k]
            if "tags" in data:
                c["tags"] = list(data["tags"])
            if "custom_fields" in data:
                c["custom_fields"].update(data["custom_fields"])
            c["updated_at"] = now_str()
            return c

    def delete_customer(self, cid: str) -> bool:
        with DB.lock:
            if cid not in DB.customers:
                return False
            del DB.customers[cid]
            DB.contacts = {k: v for k, v in DB.contacts.items()
                           if v.get("customer_id") != cid}
            return True

    def get_customer(self, cid: str) -> Optional[Dict[str, Any]]:
        with DB.lock:
            return DB.customers.get(cid)

    def list_customers(self, keyword: str = "", stage: str = "",
                       industry: str = "", level: str = "",
                       region: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.customers.values())
        result = []
        for c in rows:
            if keyword and keyword.lower() not in (c.get("name", "") + c.get("industry", "")).lower():
                continue
            if stage and c.get("stage") != stage:
                continue
            if industry and c.get("industry") != industry:
                continue
            if level and c.get("level") != level:
                continue
            if region and c.get("region") != region:
                continue
            result.append(c)
        return result

    # ------------------------------------------------------------------ #
    # 客户360视图
    # ------------------------------------------------------------------ #
    def view_360(self, cid: str) -> Optional[Dict[str, Any]]:
        c = self.get_customer(cid)
        if not c:
            return None
        with DB.lock:
            contacts = [v for v in DB.contacts.values() if v.get("customer_id") == cid]
            comm = [x for x in DB.communication if x.get("customer_id") == cid]
            orders = [v for v in DB.orders.values() if v.get("customer_id") == cid]
            contracts = [v for v in DB.contracts.values() if v.get("customer_id") == cid]
            invoices = [v for v in DB.invoices.values() if v.get("customer_id") == cid]
            tickets = [v for v in DB.tickets.values() if v.get("customer_id") == cid]
            opps = [v for v in DB.opportunities.values() if v.get("customer_id") == cid]
            success = DB.customer_success.get(cid, {})
        return {
            "profile": c,
            "contacts": contacts,
            "communication": comm[-20:],
            "orders": orders,
            "contracts": contracts,
            "invoices": invoices,
            "tickets": tickets,
            "opportunities": opps,
            "product_usage": {
                "login_count_30d": c.get("login_count_30d", 0),
                "features_used": ["dashboard", "report", "alert"],
            },
            "health": self.compute_health(cid),
            "lifecycle": self.lifecycle(cid),
            "customer_success": success,
        }

    # ------------------------------------------------------------------ #
    # 联系人
    # ------------------------------------------------------------------ #
    def list_contacts(self, customer_id: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.contacts.values())
        if customer_id:
            rows = [r for r in rows if r.get("customer_id") == customer_id]
        return rows

    def add_contact(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        cid = new_id("con")
        contact = {
            "id": cid, "customer_id": data.get("customer_id", ""),
            "name": data.get("name", ""), "title": data.get("title", ""),
            "phone": data.get("phone", ""), "email": data.get("email", ""),
            "decision_role": data.get("decision_role", "影响者"),
            "preference": data.get("preference", "电话"),
            "birthday": data.get("birthday", ""),
            "anniversary": data.get("anniversary", ""),
            "created_at": now_str(),
        }
        with DB.lock:
            DB.contacts[cid] = contact
        return contact

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def change_stage(self, cid: str, new_stage: str, note: str = "") -> Optional[Dict[str, Any]]:
        if new_stage not in self.STAGES:
            return None
        with DB.lock:
            c = DB.customers.get(cid)
            if not c:
                return None
            old = c.get("stage")
            c["stage"] = new_stage
            c["stage_entered_at"] = now_str()
            c["updated_at"] = now_str()
            c["lifecycle_history"].append({
                "stage": new_stage, "time": now_str(), "from": old, "note": note,
            })
            return c

    def lifecycle(self, cid: str) -> Dict[str, Any]:
        c = self.get_customer(cid)
        if not c:
            return {}
        history = c.get("lifecycle_history", [])
        durations = []
        for i in range(1, len(history)):
            try:
                from datetime import datetime
                t0 = datetime.strptime(history[i - 1]["time"], "%Y-%m-%d %H:%M:%S")
                t1 = datetime.strptime(history[i]["time"], "%Y-%m-%d %H:%M:%S")
                durations.append({"stage": history[i - 1]["stage"],
                                 "days": int((t1 - t0).total_seconds() / 86400)})
            except Exception:
                durations.append({"stage": history[i - 1]["stage"], "days": 0})
        won = len([h for h in history if h["stage"] in ("付费", "续费", "增购")])
        return {
            "current_stage": c.get("stage"),
            "history": history,
            "stage_durations": durations,
            "converted_to_paid": won > 0,
            "total_days": len(history) * 12,
        }

    # ------------------------------------------------------------------ #
    # 客户健康度
    # ------------------------------------------------------------------ #
    def compute_health(self, cid: str) -> Dict[str, Any]:
        c = self.get_customer(cid)
        if not c:
            return {}
        login = c.get("login_count_30d", 0)
        tickets = c.get("ticket_count_30d", 0)
        nps = c.get("nps", 50)
        pay_ok = 1 if c.get("payment_on_time", True) else 0
        score = 50.0
        score += min(login, 40) * 0.5          # 登录频率最多+20
        score += (10 if tickets <= 1 else 0)   # 工单少加分
        score += (nps - 50) * 0.2              # NPS
        score += pay_ok * 10                   # 付款及时
        score = round(max(0, min(100, score)), 1)
        risk_flags = []
        if login < 10:
            risk_flags.append("登录频率过低")
        if tickets >= 3:
            risk_flags.append("近期工单过多")
        if not pay_ok:
            risk_flags.append("付款逾期")
        if c.get("stage") == "流失":
            risk_flags.append("已标记流失")
        c["health_score"] = score
        c["health_status"] = _label(score)
        return {
            "score": score, "status": _label(score),
            "factors": {
                "login_count_30d": login,
                "ticket_count_30d": tickets,
                "nps": nps,
                "payment_on_time": c.get("payment_on_time", True),
            },
            "risk_flags": risk_flags,
            "recommend": self._recommend(score, risk_flags),
        }

    @staticmethod
    def _recommend(score: float, flags: List[str]) -> List[str]:
        recs = []
        if score < 40:
            recs.append("立即启动挽留计划，安排客户成功经理介入")
        elif score < 60:
            recs.append("发送关怀邮件，排查使用障碍")
        if "登录频率过低" in flags:
            recs.append("推送新手引导与功能教程")
        if "付款逾期" in flags:
            recs.append("财务协同跟进催款")
        if not recs:
            recs.append("保持常规季度回顾(QBR)")
        return recs

    # ------------------------------------------------------------------ #
    # 分类统计
    # ------------------------------------------------------------------ #
    def segments(self) -> Dict[str, Any]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.customers.values())
        by_stage: Dict[str, int] = {}
        by_industry: Dict[str, int] = {}
        by_region: Dict[str, int] = {}
        by_size: Dict[str, int] = {}
        by_level: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        for c in rows:
            by_stage[c.get("stage", "未知")] = by_stage.get(c.get("stage", "未知"), 0) + 1
            by_industry[c.get("industry", "其他")] = by_industry.get(c.get("industry", "其他"), 0) + 1
            by_region[c.get("region", "未知")] = by_region.get(c.get("region", "未知"), 0) + 1
            by_size[c.get("size", "未知")] = by_size.get(c.get("size", "未知"), 0) + 1
            by_level[c.get("level", "C")] = by_level.get(c.get("level", "C"), 0) + 1
            by_source[c.get("source", "未知")] = by_source.get(c.get("source", "未知"), 0) + 1
        return {
            "total": len(rows),
            "by_stage": by_stage, "by_industry": by_industry,
            "by_region": by_region, "by_size": by_size,
            "by_level": by_level, "by_source": by_source,
            "meta": {"industries": _INDUSTRIES, "regions": _REGIONS,
                     "sizes": _SIZES, "levels": _LEVELS, "sources": _SOURCES,
                     "stages": self.STAGES},
        }


# 单例
manager = CustomerManager()

__all__ = ["CustomerManager", "manager"]
