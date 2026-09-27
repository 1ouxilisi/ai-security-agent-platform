#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
identity_dashboard.py — 身份安全运营仪表盘。

覆盖：
    - 身份安全态势：用户/权限/风险账户/异常登录/特权/MFA/孤儿
    - 身份威胁告警：列表/分诊/确认/误报/关联事件/响应动作/趋势/分布
    - 身份风险热力图：按部门/角色/系统/地理位置，颜色编码
    - 身份合规状态：复核完成率/孤儿清理率/MFA/离职回收/特权管理覆盖
    - 身份安全度量：MTTD/异常登录率/权限风险/复核/特权滥用/拦截率/成功率

设计定位：聚合视图，只读分析，不执行任何变更。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from identity_security.identity_governance import IdentityGovernance
from identity_security.permission_audit import PermissionAuditor
from identity_security.identity_threat_detection import IdentityThreatDetector
from identity_security.privileged_access import PrivilegedAccessManager
from identity_security.access_authentication import AccessAuthentication


class IdentityDashboard:
    """身份安全运营仪表盘（聚合器）。"""

    def __init__(self) -> None:
        self.gov = IdentityGovernance()
        self.audit = PermissionAuditor()
        self.threat = IdentityThreatDetector()
        self.pam = PrivilegedAccessManager()
        self.auth = AccessAuthentication()

    # ------------------------------------------------------------------ #
    # 态势
    # ------------------------------------------------------------------ #
    def posture(self) -> Dict[str, Any]:
        q = self.gov.data_quality()
        inv = self.audit.inventory()
        threat = self.threat.anomalous_logins()
        mfa = self.threat.mfa_analysis()
        pam_inv = self.pam.inventory()
        return {
            "users_total": q["summary"]["total_users"],
            "users_active": sum(1 for u in self.gov._users if u["state"] == "active"),
            "roles_total": len({r for u in self.gov._users
                                for r in u.get("roles", [])}),
            "effective_permissions_total": sum(
                row["effective_count"] for row in inv["matrix"]),
            "risky_accounts": q["summary"]["no_mfa_users"]
                              + q["summary"]["orphan_accounts"],
            "anomalous_logins_24h": threat["total"],
            "privileged_accounts": pam_inv["total"],
            "mfa_coverage_pct": mfa["mfa_coverage_pct"],
            "orphan_accounts": q["summary"]["orphan_accounts"],
            "data_quality_score": q["quality_score"],
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 告警
    # ------------------------------------------------------------------ #
    def alerts(self) -> Dict[str, Any]:
        events = self.threat.anomalous_logins()["events"]
        changes = self.audit.changes()["alerts"]
        alerts: List[Dict[str, Any]] = []
        for e in events:
            alerts.append({
                "alert_id": e["event_id"],
                "ts": e["ts"],
                "level": "critical" if e["type"] in ("orphan_login",
                                                      "credential_stuffing")
                         else "high",
                "source": "identity_threat",
                "title": e["type"],
                "desc": e["desc"],
                "status": "open",
                "related_events": [e["event_id"]],
            })
        for c in changes:
            alerts.append({
                "alert_id": c["change_id"],
                "ts": c["ts"],
                "level": c["level"],
                "source": "permission_audit",
                "title": "suspicious_permission_change",
                "desc": c["desc"],
                "status": "open",
                "related_events": [],
            })
        trend = [
            {"day": "2026-09-08", "critical": 2, "high": 5, "medium": 8},
            {"day": "2026-09-09", "critical": 1, "high": 4, "medium": 6},
            {"day": "2026-09-10", "critical": 0, "high": 3, "medium": 9},
            {"day": "2026-09-11", "critical": 3, "high": 7, "medium": 5},
            {"day": "2026-09-12", "critical": 1, "high": 2, "medium": 4},
            {"day": "2026-09-13", "critical": 4, "high": 6, "medium": 7},
        ]
        distribution = {"critical": 0, "high": 0, "medium": 0}
        for a in alerts:
            distribution[a["level"]] = distribution.get(a["level"], 0) + 1
        return {"alerts": alerts, "total": len(alerts),
                "trend": trend, "distribution": distribution}

    # ------------------------------------------------------------------ #
    # 风险热力图
    # ------------------------------------------------------------------ #
    def heatmap(self) -> Dict[str, Any]:
        by_dept = [
            {"dim": "IT", "critical": 2, "high": 3, "medium": 4, "score": 78},
            {"dim": "Engineering", "critical": 1, "high": 4, "medium": 6, "score": 62},
            {"dim": "Finance", "critical": 0, "high": 1, "medium": 2, "score": 28},
            {"dim": "Sales", "critical": 1, "high": 0, "medium": 1, "score": 45},
            {"dim": "HR", "critical": 0, "high": 1, "medium": 0, "score": 22},
        ]
        by_system = [
            {"dim": "AD/Domain", "critical": 2, "high": 2, "medium": 1, "score": 82},
            {"dim": "AWS", "critical": 0, "high": 1, "medium": 2, "score": 35},
            {"dim": "DB-Prod", "critical": 1, "high": 2, "medium": 1, "score": 68},
            {"dim": "Legacy", "critical": 1, "high": 1, "medium": 3, "score": 58},
        ]
        by_geo = [
            {"dim": "昆明", "critical": 0, "high": 1, "medium": 2, "score": 20},
            {"dim": "上海", "critical": 0, "high": 0, "medium": 1, "score": 10},
            {"dim": "境外-VPN", "critical": 1, "high": 2, "medium": 1, "score": 72},
            {"dim": "Tor/匿名", "critical": 1, "high": 1, "medium": 0, "score": 88},
        ]
        return {"by_dept": by_dept, "by_system": by_system, "by_geo": by_geo}

    # ------------------------------------------------------------------ #
    # 合规
    # ------------------------------------------------------------------ #
    def compliance(self) -> Dict[str, Any]:
        return {
            "permission_review_completion_pct": 78,
            "orphan_account_cleanup_pct": 35,
            "mfa_coverage_pct": self.threat.mfa_analysis()["mfa_coverage_pct"],
            "offboarding_recycle_sla_hours": 48,
            "offboarding_recycle_target_hours": 2,
            "pam_coverage_pct": 86,
            "sso_coverage_pct": self.auth.sso_inventory()["sso_coverage_pct"],
            "items": [
                {"name": "权限复核完成率", "value": 78, "target": 90, "ok": False},
                {"name": "孤儿账户清理率", "value": 35, "target": 80, "ok": False},
                {"name": "MFA 覆盖率", "value": 80, "target": 95, "ok": False},
                {"name": "特权账户纳管率", "value": 86, "target": 95, "ok": False},
                {"name": "SSO 覆盖率", "value": 67, "target": 90, "ok": False},
            ],
        }

    # ------------------------------------------------------------------ #
    # 度量
    # ------------------------------------------------------------------ #
    def metrics(self) -> Dict[str, Any]:
        return {
            "mttd_identity_threat_min": 18,
            "anomalous_login_rate_pct": 1.4,
            "permission_risk_distribution": self.audit.risk_assessment()["distribution"],
            "review_completion_pct": 78,
            "privilege_abuse_events_30d": 3,
            "identity_attack_blocked_pct": 92,
            "auth_success_pct_24h": 96.4,
            "history": [
                {"day": "2026-09-08", "mttd": 22, "anomaly_rate": 1.8,
                 "success": 95.8},
                {"day": "2026-09-09", "mttd": 20, "anomaly_rate": 1.6,
                 "success": 96.0},
                {"day": "2026-09-10", "mttd": 19, "anomaly_rate": 1.5,
                 "success": 96.2},
                {"day": "2026-09-11", "mttd": 24, "anomaly_rate": 2.1,
                 "success": 95.5},
                {"day": "2026-09-12", "mttd": 17, "anomaly_rate": 1.2,
                 "success": 96.6},
                {"day": "2026-09-13", "mttd": 18, "anomaly_rate": 1.4,
                 "success": 96.4},
            ],
        }


__all__ = ["IdentityDashboard"]
