# -*- coding: utf-8 -*-
"""sales_pipeline.py — 销售漏斗与商机管理。

销售漏斗 / 商机 / 跟进 / 报价 / 合同 / 订单。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from crm_system import DB, now_str, new_id, seed_if_needed, _STAGES, _STAGE_PROB


FUNNEL_STAGES = ["线索", "潜在", "意向", "试用", "付费"]


class SalesPipeline:
    """销售漏斗、商机、报价、合同、订单一体化管理。"""

    # ------------------------------------------------------------------ #
    # 商机
    # ------------------------------------------------------------------ #
    def create_opportunity(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        oid = new_id("opp")
        stage = data.get("stage", "线索")
        opp = {
            "id": oid, "name": data.get("name", "新商机"),
            "customer_id": data.get("customer_id", ""),
            "contact_id": data.get("contact_id", ""),
            "amount": float(data.get("amount", 0)),
            "stage": stage,
            "probability": _STAGE_PROB.get(stage, 0.2),
            "expected_close": data.get("expected_close", ""),
            "owner": data.get("owner", "未分配"),
            "competitor": data.get("competitor", ""),
            "status": "open", "win_reason": "", "lose_reason": "",
            "created_at": now_str(), "updated_at": now_str(),
        }
        with DB.lock:
            DB.opportunities[oid] = opp
            DB.opportunity_followups[oid] = []
        return opp

    def list_opportunities(self, stage: str = "", customer_id: str = "",
                           owner: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.opportunities.values())
        if stage:
            rows = [r for r in rows if r.get("stage") == stage]
        if customer_id:
            rows = [r for r in rows if r.get("customer_id") == customer_id]
        if owner:
            rows = [r for r in rows if r.get("owner") == owner]
        return rows

    def get_opportunity(self, oid: str) -> Optional[Dict[str, Any]]:
        with DB.lock:
            opp = DB.opportunities.get(oid)
            if not opp:
                return None
            followups = DB.opportunity_followups.get(oid, [])
            out = dict(opp)
            out["followups"] = followups
            return out

    def advance_stage(self, oid: str, new_stage: str,
                      result_note: str = "") -> Optional[Dict[str, Any]]:
        with DB.lock:
            opp = DB.opportunities.get(oid)
            if not opp:
                return None
            opp["stage"] = new_stage
            opp["probability"] = _STAGE_PROB.get(new_stage, opp["probability"])
            opp["updated_at"] = now_str()
            if new_stage == "流失":
                opp["status"] = "lost"
                opp["lose_reason"] = result_note
            return opp

    def win_opportunity(self, oid: str, reason: str = "") -> Optional[Dict[str, Any]]:
        with DB.lock:
            opp = DB.opportunities.get(oid)
            if not opp:
                return None
            opp["status"] = "won"
            opp["stage"] = "付费"
            opp["probability"] = 1.0
            opp["win_reason"] = reason
            opp["updated_at"] = now_str()
            return opp

    def lose_opportunity(self, oid: str, reason: str = "") -> Optional[Dict[str, Any]]:
        with DB.lock:
            opp = DB.opportunities.get(oid)
            if not opp:
                return None
            opp["status"] = "lost"
            opp["stage"] = "流失"
            opp["probability"] = 0.0
            opp["lose_reason"] = reason
            opp["updated_at"] = now_str()
            return opp

    def add_followup(self, oid: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with DB.lock:
            if oid not in DB.opportunities:
                return None
            rec = {
                "time": now_str(), "type": data.get("type", "电话"),
                "content": data.get("content", ""),
                "result": data.get("result", ""),
                "next_action": data.get("next_action", ""),
                "next_followup": data.get("next_followup", ""),
            }
            DB.opportunity_followups.setdefault(oid, []).append(rec)
            return rec

    # ------------------------------------------------------------------ #
    # 漏斗分析
    # ------------------------------------------------------------------ #
    def funnel(self) -> Dict[str, Any]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.opportunities.values())
        stage_rows = {s: {"count": 0, "amount": 0.0} for s in FUNNEL_STAGES}
        won_amt = lost_amt = 0.0
        won_cnt = lost_cnt = 0
        for o in rows:
            s = o.get("stage", "线索")
            amt = float(o.get("amount", 0))
            if o.get("status") == "won":
                won_amt += amt
                won_cnt += 1
            elif o.get("status") == "lost":
                lost_amt += amt
                lost_cnt += 1
            if s in stage_rows:
                stage_rows[s]["count"] += 1
                stage_rows[s]["amount"] += amt
        # 逐级转化率
        ordered = FUNNEL_STAGES
        steps = []
        prev_count = None
        for s in ordered:
            cnt = stage_rows[s]["count"]
            conv = (cnt / prev_count) if prev_count else 1.0
            steps.append({
                "stage": s, "count": cnt,
                "amount": round(stage_rows[s]["amount"], 2),
                "conversion_from_prev": round(conv, 3),
                "probability": _STAGE_PROB.get(s, 0.2),
            })
            prev_count = cnt or prev_count
        weighted = sum(float(o.get("amount", 0)) * float(o.get("probability", 0))
                      for o in rows if o.get("status") == "open")
        return {
            "stages": steps,
            "total_open": len([o for o in rows if o.get("status") == "open"]),
            "total_open_amount": round(sum(float(o.get("amount", 0))
                                          for o in rows if o.get("status") == "open"), 2),
            "weighted_forecast": round(weighted, 2),
            "won_count": won_cnt, "won_amount": round(won_amt, 2),
            "lost_count": lost_cnt, "lost_amount": round(lost_amt, 2),
            "overall_win_rate": round(won_cnt / max(1, won_cnt + lost_cnt), 3),
        }

    # ------------------------------------------------------------------ #
    # 报价
    # ------------------------------------------------------------------ #
    def create_quote(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        qid = new_id("quo")
        items = data.get("items", [])
        subtotal = sum(float(i.get("price", 0)) * int(i.get("qty", 1)) for i in items)
        discount = float(data.get("discount", 0))
        total = round(subtotal * (1 - discount), 2)
        quote = {
            "id": qid, "name": data.get("name", "新报价单"),
            "customer_id": data.get("customer_id", ""),
            "opportunity_id": data.get("opportunity_id", ""),
            "items": items, "subtotal": round(subtotal, 2),
            "discount": discount, "total": total,
            "valid_until": data.get("valid_until", ""),
            "status": "草稿", "version": 1, "customer_confirmed": False,
            "created_at": now_str(), "updated_at": now_str(),
        }
        with DB.lock:
            DB.quotes[qid] = quote
        return quote

    def list_quotes(self, customer_id: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.quotes.values())
        if customer_id:
            rows = [r for r in rows if r.get("customer_id") == customer_id]
        return rows

    def confirm_quote(self, qid: str) -> Optional[Dict[str, Any]]:
        with DB.lock:
            q = DB.quotes.get(qid)
            if not q:
                return None
            q["customer_confirmed"] = True
            q["status"] = "已确认"
            q["updated_at"] = now_str()
            return q

    def quote_to_order(self, qid: str) -> Optional[Dict[str, Any]]:
        q = self.confirm_quote(qid)
        if not q:
            return None
        return self.create_order({
            "customer_id": q["customer_id"],
            "source_quote_id": qid,
            "items": q["items"],
            "discount": q["discount"],
            "amount": q["total"],
        })

    # ------------------------------------------------------------------ #
    # 合同
    # ------------------------------------------------------------------ #
    def create_contract(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        cid = new_id("con")
        contract = {
            "id": cid, "name": data.get("name", "新合同"),
            "customer_id": data.get("customer_id", ""),
            "amount": float(data.get("amount", 0)),
            "period": data.get("period", "12个月"),
            "payment_method": data.get("payment_method", "年付"),
            "terms": list(data.get("terms", [])),
            "template_id": data.get("template_id", ""),
            "sign_status": "待签署", "esigned": False,
            "attachments": list(data.get("attachments", [])),
            "start_date": data.get("start_date", now_str()[:10]),
            "end_date": data.get("end_date", ""),
            "created_at": now_str(), "updated_at": now_str(),
        }
        with DB.lock:
            DB.contracts[cid] = contract
        return contract

    def list_contracts(self, customer_id: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.contracts.values())
        if customer_id:
            rows = [r for r in rows if r.get("customer_id") == customer_id]
        return rows

    def sign_contract(self, cid: str, esigned: bool = True) -> Optional[Dict[str, Any]]:
        with DB.lock:
            c = DB.contracts.get(cid)
            if not c:
                return None
            c["sign_status"] = "已签署"
            c["esigned"] = esigned
            c["updated_at"] = now_str()
            return c

    # ------------------------------------------------------------------ #
    # 订单
    # ------------------------------------------------------------------ #
    def create_order(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        oid = new_id("ord")
        items = data.get("items", [])
        subtotal = sum(float(i.get("price", 0)) * int(i.get("qty", 1)) for i in items)
        discount = float(data.get("discount", 0))
        tax = round(subtotal * 0.06, 2)
        amount = round(data.get("amount", subtotal * (1 - discount)) + tax, 2)
        order = {
            "id": oid, "customer_id": data.get("customer_id", ""),
            "source_quote_id": data.get("source_quote_id", ""),
            "items": items, "subtotal": round(subtotal, 2),
            "discount": discount, "tax": tax, "amount": amount,
            "pay_status": "待支付", "ship_status": "待发货",
            "invoice_status": "未开票", "status": "待支付",
            "history": [{"time": now_str(), "event": "订单创建"}],
            "created_at": now_str(), "updated_at": now_str(),
        }
        with DB.lock:
            DB.orders[oid] = order
        return order

    def list_orders(self, customer_id: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.orders.values())
        if customer_id:
            rows = [r for r in rows if r.get("customer_id") == customer_id]
        return rows

    def update_order_status(self, oid: str, field: str, value: str) -> Optional[Dict[str, Any]]:
        allowed = {"pay_status", "ship_status", "invoice_status", "status"}
        if field not in allowed:
            return None
        with DB.lock:
            o = DB.orders.get(oid)
            if not o:
                return None
            o[field] = value
            o["history"].append({"time": now_str(), "event": f"{field}={value}"})
            o["updated_at"] = now_str()
            return o


pipeline = SalesPipeline()

__all__ = ["SalesPipeline", "pipeline", "FUNNEL_STAGES"]
