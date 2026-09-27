# -*- coding: utf-8 -*-
"""
enterprise_portal_phase.py — 阶段6：企业门户。

功能:
    - 企业资产范围 / 漏洞看板 / 修复进度
    - 安全态势 / 报告导出 / 联系人 / 通知 / SLA / 安全评分
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

FIX_SLA_HOURS = {"critical": 72, "high": 168, "medium": 336,
                 "low": 720, "info": 1440}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class EnterprisePortalPhase:
    """阶段6：企业门户。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._notifications: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    def dashboard(self, enterprise_id: str) -> Dict[str, Any]:
        from .vulnerability_submission_phase import get_submission_phase
        sub = get_submission_phase()
        vs = [v for v in sub.list(limit=500)
              if v["enterprise_id"] == enterprise_id]
        by_status: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        open_v = fixed = retest = 0
        for v in vs:
            by_status[v["status"]] = by_status.get(v["status"], 0) + 1
            by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
            if v["status"] in ("confirmed", "reviewing", "submitted"):
                open_v += 1
            if v["status"] == "fixed":
                fixed += 1
            if v["status"] == "retest" or v["status"] == "closed":
                retest += 1
        score = self.security_score(by_sev, len(vs))
        return {
            "enterprise_id": enterprise_id,
            "total": len(vs), "open": open_v,
            "fixed": fixed, "retest": retest,
            "by_status": by_status, "by_severity": by_sev,
            "security_score": score,
            "fix_rate": round(fixed / max(1, len(vs)), 2),
        }

    def security_score(self, by_sev: Dict[str, int],
                       total: int) -> int:
        """扣分制：critical 扣 15，high 扣 6，medium 扣 2，low 扣 0.5。"""
        penalty = (by_sev.get("critical", 0) * 15 +
                   by_sev.get("high", 0) * 6 +
                   by_sev.get("medium", 0) * 2 +
                   by_sev.get("low", 0) * 0.5)
        score = max(0, min(100, 100 - int(penalty)))
        return score

    def fix_progress(self, enterprise_id: str) -> Dict[str, Any]:
        from .vulnerability_submission_phase import get_submission_phase
        sub = get_submission_phase()
        vs = [v for v in sub.list(limit=500)
              if v["enterprise_id"] == enterprise_id]
        buckets = {"待修复": 0, "修复中": 0, "已修复": 0, "已复测": 0}
        for v in vs:
            if v["status"] in ("confirmed", "reviewing"):
                buckets["待修复"] += 1
            elif v["status"] == "fixing":
                buckets["修复中"] += 1
            elif v["status"] == "fixed":
                buckets["已修复"] += 1
            elif v["status"] in ("retest", "closed"):
                buckets["已复测"] += 1
        return {"enterprise_id": enterprise_id, "progress": buckets,
                "sla_hours": FIX_SLA_HOURS}

    def trend(self, enterprise_id: str) -> List[Dict[str, Any]]:
        from .vulnerability_submission_phase import get_submission_phase
        sub = get_submission_phase()
        vs = [v for v in sub.list(limit=500)
              if v["enterprise_id"] == enterprise_id]
        # 按近 7 天聚合
        days: Dict[str, int] = {}
        for v in vs:
            day = (v.get("submitted_at") or "")[:10]
            days[day] = days.get(day, 0) + 1
        return [{"day": k, "count": v}
                for k, v in sorted(days.items())[-14:]]

    # ------------------------------------------------------------------ #
    def notify(self, enterprise_id: str, title: str,
               content: str, level: str = "info") -> Dict[str, Any]:
        nid = "entn_" + uuid.uuid4().hex[:10]
        with self._lock:
            self._notifications[nid] = {
                "notif_id": nid, "enterprise_id": enterprise_id,
                "title": title, "content": content, "level": level,
                "read": False, "created_at": _now(),
            }
            return self._notifications[nid]

    def list_notifications(self, enterprise_id: str
                           ) -> List[Dict[str, Any]]:
        with self._lock:
            return [n for n in self._notifications.values()
                    if n["enterprise_id"] == enterprise_id][::-1]

    def export_report(self, enterprise_id: str,
                      period: str = "month") -> Dict[str, Any]:
        dash = self.dashboard(enterprise_id)
        return {
            "enterprise_id": enterprise_id, "period": period,
            "generated_at": _now(),
            "summary": dash,
            "sla_hours": FIX_SLA_HOURS,
            "recommendation": [
                "优先修复 critical/high 级别漏洞",
                "建立月度复测机制",
                "接入自动化扫描持续监控",
            ],
        }


_default: Optional[EnterprisePortalPhase] = None


def get_enterprise_phase() -> EnterprisePortalPhase:
    global _default
    if _default is None:
        _default = EnterprisePortalPhase()
    return _default
