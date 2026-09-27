# -*- coding: utf-8 -*-
"""
bounty_management_phase.py — 阶段4：赏金管理。

功能:
    - 赏金计算（严重程度+影响+质量+首次发现）
    - 赏金标准 / 赏金发放 / 赏金统计
    - 税务处理 / 排行榜 / 赏金调整 / 发放记录 / 争议处理
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

BASE_BOUNTY = {
    "critical": 20000, "high": 3000, "medium": 800,
    "low": 150, "info": 0,
}
TAX_RATE = 0.20  # 劳务报酬预扣示意


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class BountyManagementPhase:
    """阶段4：赏金管理。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._payments: Dict[str, Dict[str, Any]] = {}
        self._ranking_boost: Dict[str, float] = {}
        self._seed()

    # ------------------------------------------------------------------ #
    def _seed(self) -> None:
        from .vulnerability_submission_phase import get_submission_phase
        sub = get_submission_phase()
        for v in sub.list(limit=4):
            amount = self.calculate(v["severity"], impact_score=8,
                                    quality=9, first_found=True)["amount"]
            pid = "pay_" + uuid.uuid4().hex[:10]
            self._payments[pid] = {
                "payment_id": pid, "vuln_id": v["vuln_id"],
                "hacker_id": v["hacker_id"],
                "gross": amount, "tax": int(amount * TAX_RATE),
                "net": int(amount * (1 - TAX_RATE)),
                "status": "paid", "month": datetime.now().strftime("%Y-%m"),
                "created_at": _now(),
            }

    # ------------------------------------------------------------------ #
    def calculate(self, severity: str, impact_score: int = 5,
                  quality: int = 5, first_found: bool = False
                  ) -> Dict[str, Any]:
        base = BASE_BOUNTY.get(severity, 0)
        mult = 1.0
        reasons = [f"基础({severity})={base}"]
        if impact_score >= 8:
            mult *= 1.3
            reasons.append("影响范围广 +30%")
        if quality >= 9:
            mult *= 1.2
            reasons.append("报告质量优 +20%")
        if first_found:
            mult *= 1.5
            reasons.append("首次发现 +50%")
        amount = int(base * mult)
        return {"amount": amount, "multiplier": round(mult, 2),
                "reasons": reasons,
                "tax": int(amount * TAX_RATE),
                "net": int(amount * (1 - TAX_RATE))}

    def grant(self, vuln_id: str, hacker_id: str,
              gross: int, status: str = "granted") -> Dict[str, Any]:
        pid = "pay_" + uuid.uuid4().hex[:10]
        with self._lock:
            rec = {
                "payment_id": pid, "vuln_id": vuln_id,
                "hacker_id": hacker_id,
                "gross": gross, "tax": int(gross * TAX_RATE),
                "net": int(gross * (1 - TAX_RATE)),
                "status": status,
                "month": datetime.now().strftime("%Y-%m"),
                "created_at": _now(),
            }
            self._payments[pid] = rec
            return rec

    def adjust(self, payment_id: str, delta: int,
               reason: str = "") -> Optional[Dict[str, Any]]:
        with self._lock:
            p = self._payments.get(payment_id)
            if not p:
                return None
            p["gross"] += delta
            p["tax"] = int(p["gross"] * TAX_RATE)
            p["net"] = int(p["gross"] * (1 - TAX_RATE))
            p["adjustment"] = {"delta": delta, "reason": reason,
                               "time": _now()}
            return p

    def list_payments(self, hacker_id: Optional[str] = None
                      ) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._payments.values())
        if hacker_id:
            out = [p for p in out if p["hacker_id"] == hacker_id]
        return out[::-1]

    # ------------------------------------------------------------------ #
    def leaderboard(self, by: str = "bounty",
                    limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            rows: Dict[str, Dict[str, Any]] = {}
            for p in self._payments.values():
                h = rows.setdefault(p["hacker_id"],
                                    {"hacker_id": p["hacker_id"],
                                     "bounty": 0, "count": 0})
                h["bounty"] += p["gross"]
                h["count"] += 1
        if by == "count":
            rows = dict(sorted(rows.items(),
                               key=lambda x: x[1]["count"],
                               reverse=True))
        else:
            rows = dict(sorted(rows.items(),
                               key=lambda x: x[1]["bounty"],
                               reverse=True))
        out = list(rows.values())[:limit]
        for i, r in enumerate(out, 1):
            r["rank"] = i
        return out

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            ps = list(self._payments.values())
        total_gross = sum(p["gross"] for p in ps)
        by_month: Dict[str, int] = {}
        by_sev_est: Dict[str, int] = {}
        for p in ps:
            by_month[p["month"]] = by_month.get(p["month"], 0) + p["gross"]
        return {
            "total_payments": len(ps),
            "total_gross": total_gross,
            "total_tax": int(total_gross * TAX_RATE),
            "total_net": int(total_gross * (1 - TAX_RATE)),
            "by_month": by_month,
            "tax_rate": TAX_RATE,
            "bounty_standard": BASE_BOUNTY,
            "leaderboard_bounty": self.leaderboard("bounty"),
            "leaderboard_count": self.leaderboard("count"),
        }


_default: Optional[BountyManagementPhase] = None


def get_bounty_phase() -> BountyManagementPhase:
    global _default
    if _default is None:
        _default = BountyManagementPhase()
    return _default
