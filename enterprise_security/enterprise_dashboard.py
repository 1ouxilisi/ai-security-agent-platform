# -*- coding: utf-8 -*-
"""enterprise_dashboard.py — 企业安全控制台聚合视图。

聚合 RBAC / 审计 / 加密 / 基线 / 合规 各模块的 KPI 与概览。
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional


class EnterpriseDashboard:
    """聚合各子系统，输出控制台卡片数据。"""

    def __init__(self, rbac, audit, crypto, baseline, compliance) -> None:
        self.rbac = rbac
        self.audit = audit
        self.crypto = crypto
        self.baseline = baseline
        self.compliance = compliance

    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        users = self.rbac.list_users()
        role_counts: Dict[str, int] = {}
        for u in users:
            role_counts[u["role"]] = role_counts.get(u["role"], 0) + 1

        astats = self.audit.stats()
        enc = self.crypto.self_test()
        bl = self.baseline.last_report or {}
        bl_sum = bl.get("summary", {})

        return {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "kpis": {
                "total_users": len(users),
                "active_roles": list(role_counts.keys()),
                "role_counts": role_counts,
                "audit_events": astats["total_events"],
                "audit_failed": astats["failed_events"],
                "audit_success_rate": astats["success_rate"],
                "encryption": enc["algorithm"],
                "enc_roundtrip_ok": enc["roundtrip_ok"],
                "baseline_score": bl_sum.get("score", None),
                "baseline_grade": bl_sum.get("grade", "—"),
                "baseline_failed": bl_sum.get("failed", 0),
            },
            "compliance_reports": self.compliance.list_reports()[-5:],
            "recent_audit": self.audit.query(limit=8)["items"],
            "top_actors": astats["top_users"],
        }

    # ------------------------------------------------------------------ #
    def health(self) -> Dict[str, Any]:
        enc = self.crypto.self_test()
        users = self.rbac.list_users()
        return {
            "status": "healthy" if enc["roundtrip_ok"] and users else "degraded",
            "components": {
                "rbac": {"ok": True, "users": len(users)},
                "audit_log": {"ok": True},
                "encryption": {"ok": enc["roundtrip_ok"],
                               "algorithm": enc["algorithm"]},
                "security_baseline": {"ok": bool(self.baseline.last_report)},
                "compliance": {"ok": True,
                               "reports": len(self.compliance.list_reports())},
            },
        }
