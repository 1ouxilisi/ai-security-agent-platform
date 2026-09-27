#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bounty_finance.py — 赏金与财务管理。

覆盖：
    - 赏金评定（严重程度/影响范围/利用难度/报告质量 自动建议+人工调整、倍数、上限、最低）
    - 奖励发放（积分/现金/礼品/证书，发放记录/状态/凭证/时间/发放人/收款确认）
    - 财务统计（总支出/月度/按项目/按类型/按严重程度/预算使用/趋势/Top支出）
    - 税务与合规（个税/发票/合同/合规声明/税率/税后金额/合规文件）
    - 预算管理（项目预算/已用/剩余/预警/调整/审批/超预算处理/趋势）
    - 赏金规则版本管理（规则历史/版本对比/生效时间/变更记录/模板/导入导出）

全部内存字典模拟。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


SEVERITY_BASE_AMOUNT = {"info": 300, "low": 1000, "medium": 6000,
                        "high": 25000, "critical": 100000}
PAYMENT_METHODS = ["points", "cash", "gift", "certificate"]
PAYMENT_STATUS = ["pending", "approved", "paid", "confirmed", "failed"]
TAX_RATE = 0.20  # 劳务报酬预扣简化示例


class _Store:
    def __init__(self) -> None:
        self.payments: Dict[str, Dict[str, Any]] = {}
        self.budgets: Dict[str, Dict[str, Any]] = {}
        self.rule_versions: Dict[str, List[Dict[str, Any]]] = {}
        self.tax_records: Dict[str, Dict[str, Any]] = {}

    def reset(self) -> None:
        self.__init__()


STORE = _Store()


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- #
# 赏金评定
# --------------------------------------------------------------------------- #
def estimate_bounty(severity: str, impact_scope: str,
                    exploit_difficulty: str, report_quality: str,
                    level_multiplier: float = 1.0,
                    cap: float = 200000.0,
                    floor: float = 100.0) -> Dict[str, Any]:
    """根据维度给出建议赏金区间与单值。"""
    base = SEVERITY_BASE_AMOUNT.get(severity, 1000)
    impact_adj = {"local": 0.6, "dept": 0.9, "corp": 1.2, "global": 1.6}.get(impact_scope, 1.0)
    diff_adj = {"trivial": 1.2, "easy": 1.0, "medium": 0.9,
                "hard": 0.7, "expert": 0.5}.get(exploit_difficulty, 0.9)
    quality_adj = {"poor": 0.7, "fair": 0.9, "good": 1.0,
                   "excellent": 1.2}.get(report_quality, 1.0)
    suggested = base * impact_adj * diff_adj * quality_adj * level_multiplier
    suggested = max(floor, min(cap, suggested))
    lo = max(floor, suggested * 0.6)
    hi = min(cap, suggested * 1.4)
    return {
        "suggested": round(suggested, 2),
        "range": [round(lo, 2), round(hi, 2)],
        "dimensions": {
            "base": base, "impact_adj": impact_adj, "diff_adj": diff_adj,
            "quality_adj": quality_adj, "level_multiplier": level_multiplier,
        },
        "cap": cap, "floor": floor,
        "human_adjusted": False,
    }


# --------------------------------------------------------------------------- #
# 发放
# --------------------------------------------------------------------------- #
def issue_payment(payload: Dict[str, Any]) -> Dict[str, Any]:
    pid = payload.get("id") or _uid("pay")
    gross = float(payload.get("amount", 0.0))
    tax = round(gross * TAX_RATE, 2) if payload.get("need_tax", True) else 0.0
    net = round(gross - tax, 2)
    p = {
        "id": pid,
        "vuln_id": payload.get("vuln_id", ""),
        "project_id": payload.get("project_id", ""),
        "hunter_id": payload.get("hunter_id", ""),
        "method": payload.get("method", "cash"),
        "gross": gross,
        "tax": tax,
        "net": net,
        "currency": payload.get("currency", "CNY"),
        "status": payload.get("status", "pending"),
        "voucher": payload.get("voucher", ""),
        "approved_by": payload.get("approved_by", ""),
        "paid_at": payload.get("paid_at", ""),
        "confirmed_at": "",
        "note": payload.get("note", ""),
        "created_at": _now(),
    }
    STORE.payments[pid] = p
    _update_budget_spent(p["project_id"], gross)
    return p


def list_payments(project_id: Optional[str] = None,
                  hunter_id: Optional[str] = None,
                  status: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(STORE.payments.values())
    if project_id:
        items = [p for p in items if p["project_id"] == project_id]
    if hunter_id:
        items = [p for p in items if p["hunter_id"] == hunter_id]
    if status:
        items = [p for p in items if p["status"] == status]
    return items


def confirm_payment(pay_id: str, confirmed_by: str) -> Dict[str, Any]:
    p = STORE.payments.get(pay_id)
    if not p:
        return {"ok": False, "reason": "支付单不存在"}
    p["status"] = "confirmed"
    p["confirmed_at"] = _now()
    p["confirmed_by"] = confirmed_by
    return {"ok": True, "payment": p}


# --------------------------------------------------------------------------- #
# 预算
# --------------------------------------------------------------------------- #
def set_budget(project_id: str, total: float,
               warning_pct: float = 0.8) -> Dict[str, Any]:
    b = STORE.budgets.get(project_id) or {
        "project_id": project_id, "total": total, "used": 0.0,
        "warning_pct": warning_pct, "adjust_history": [],
    }
    b["total"] = total
    b["warning_pct"] = warning_pct
    STORE.budgets[project_id] = b
    return b


def _update_budget_spent(project_id: str, amount: float) -> None:
    b = STORE.budgets.get(project_id)
    if not b:
        return
    b["used"] = round(b["used"] + amount, 2)


def adjust_budget(project_id: str, new_total: float,
                  approver: str, reason: str = "") -> Dict[str, Any]:
    b = STORE.budgets.get(project_id)
    if not b:
        b = set_budget(project_id, new_total)
    old = b["total"]
    b["total"] = new_total
    b["adjust_history"].append({
        "from": old, "to": new_total, "approver": approver,
        "reason": reason, "time": _now(),
    })
    return b


def budget_status(project_id: str) -> Dict[str, Any]:
    b = STORE.budgets.get(project_id, {
        "project_id": project_id, "total": 0, "used": 0.0,
        "warning_pct": 0.8, "adjust_history": [],
    })
    remaining = round(b["total"] - b["used"], 2)
    pct = (b["used"] / b["total"]) if b["total"] else 0.0
    alert = pct >= b.get("warning_pct", 0.8)
    over = pct > 1.0
    return {**b, "remaining": remaining, "usage_pct": round(pct, 4),
            "warning": alert, "over_budget": over}


# --------------------------------------------------------------------------- #
# 财务统计
# --------------------------------------------------------------------------- #
def finance_summary(project_id: Optional[str] = None) -> Dict[str, Any]:
    items = list(STORE.payments.values())
    if project_id:
        items = [p for p in items if p["project_id"] == project_id]
    total_gross = round(sum(p["gross"] for p in items), 2)
    total_tax = round(sum(p["tax"] for p in items), 2)
    total_net = round(sum(p["net"] for p in items), 2)
    by_month: Dict[str, float] = {}
    by_method: Dict[str, float] = {}
    by_severity: Dict[str, float] = {}
    for p in items:
        month = p["created_at"][:7]
        by_month[month] = round(by_month.get(month, 0) + p["gross"], 2)
        by_method[p["method"]] = round(by_method.get(p["method"], 0) + p["gross"], 2)
    top = sorted(items, key=lambda x: x["gross"], reverse=True)[:10]
    return {
        "total_gross": total_gross, "total_tax": total_tax, "total_net": total_net,
        "payment_count": len(items),
        "by_month": by_month, "by_method": by_method, "by_severity": by_severity,
        "top_payments": [{"id": p["id"], "hunter_id": p["hunter_id"],
                          "gross": p["gross"], "project_id": p["project_id"]}
                         for p in top],
    }


# --------------------------------------------------------------------------- #
# 税务/合规
# --------------------------------------------------------------------------- #
def tax_info(payment_id: str) -> Optional[Dict[str, Any]]:
    p = STORE.payments.get(payment_id)
    if not p:
        return None
    return {
        "payment_id": payment_id, "hunter_id": p["hunter_id"],
        "gross": p["gross"], "tax_rate": TAX_RATE, "tax": p["tax"],
        "net": p["net"], "invoice_required": p["gross"] >= 800,
        "compliance": ["个人所得税代扣代缴", "签订劳务协议", "保留支付凭证"],
        "contract_signed": False,
    }


def set_tax_record(hunter_id: str, tax_id: str, bank: str,
                   invoice_type: str) -> Dict[str, Any]:
    rec = {
        "hunter_id": hunter_id, "tax_id": tax_id, "bank": bank,
        "invoice_type": invoice_type, "updated_at": _now(),
    }
    STORE.tax_records[hunter_id] = rec
    return rec


# --------------------------------------------------------------------------- #
# 规则版本
# --------------------------------------------------------------------------- #
def save_rule_version(project_id: str, rules: Dict[str, Any],
                      effective_at: str, note: str = "") -> Dict[str, Any]:
    vid = len(STORE.rule_versions.get(project_id, [])) + 1
    v = {
        "version": vid, "rules": rules, "effective_at": effective_at,
        "note": note, "created_at": _now(),
    }
    STORE.rule_versions.setdefault(project_id, []).append(v)
    return v


def list_rule_versions(project_id: str) -> List[Dict[str, Any]]:
    return list(STORE.rule_versions.get(project_id, []))


def diff_versions(project_id: str, v1: int, v2: int) -> Dict[str, Any]:
    versions = STORE.rule_versions.get(project_id, [])
    a = next((x for x in versions if x["version"] == v1), None)
    b = next((x for x in versions if x["version"] == v2), None)
    if not a or not b:
        return {"ok": False}
    changed = []
    for k in set(a["rules"]) | set(b["rules"]):
        if a["rules"].get(k) != b["rules"].get(k):
            changed.append({"key": k, "old": a["rules"].get(k),
                            "new": b["rules"].get(k)})
    return {"ok": True, "v1": v1, "v2": v2, "changed": changed}


# --------------------------------------------------------------------------- #
# 种子
# --------------------------------------------------------------------------- #
def seed_demo() -> None:
    if STORE.payments:
        return
    set_budget("demo_proj_1", 500000.0, 0.8)
    issue_payment({
        "vuln_id": "vuln_demo1", "project_id": "demo_proj_1",
        "hunter_id": "hunter_001", "method": "cash",
        "amount": 22000.0, "status": "paid",
        "note": "IDOR 高危",
    })
    issue_payment({
        "vuln_id": "vuln_demo2", "project_id": "demo_proj_1",
        "hunter_id": "hunter_002", "method": "points",
        "amount": 3000.0, "status": "pending",
        "note": "XSS 中危",
    })
