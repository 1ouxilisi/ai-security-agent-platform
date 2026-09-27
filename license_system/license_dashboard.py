# -*- coding: utf-8 -*-
"""
license_dashboard.py — License 运营管理控制台聚合。

能力:
    * 总览：总数/激活/在线/即将到期/已过期/异常
    * 分布：按版本/模块/状态
    * 激活统计、设备统计、收入趋势、异常告警
    * 系统设置聚合：密钥/价格/安全策略/审计
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from .license_generator import get_issuer, LICENSE_PLANS, LOCK
from .device_binding import get_activation_server, ACTIVATION_STORE
from .feature_control import get_feature_controller
from .billing_upgrade import get_billing_manager, PRICE_TABLE
from .anti_piracy import get_anti_piracy_guard, BLACKLIST, CRACK_ALERTS


class LicenseDashboard:
    """聚合各子系统为仪表盘视图。"""

    def __init__(self) -> None:
        self.issuer = get_issuer()
        self.act = get_activation_server()
        self.feat = get_feature_controller()
        self.billing = get_billing_manager()
        self.piracy = get_anti_piracy_guard()

    # ---------------- 总览 ---------------- #
    def overview(self) -> Dict[str, Any]:
        lic = self.issuer.licenses
        now = time.time()
        active = expired = expiring = revoked = 0
        plan_dist: Dict[str, int] = {}
        for lid, rec in lic.items():
            p = rec["payload"]
            if lid in self.issuer.revoked:
                revoked += 1
            elif p["expires_at"] < now:
                expired += 1
            elif p["expires_at"] - now < 30 * 86400:
                expiring += 1
            else:
                active += 1
            plan_dist[p["plan"]] = plan_dist.get(p["plan"], 0) + 1
        activated = len(ACTIVATION_STORE["records"])
        return {
            "total_licenses": len(lic),
            "active": active, "expired": expired,
            "expiring_soon": expiring, "revoked": revoked,
            "total_activations": activated,
            "online_estimated": max(0, activated - 3),
            "device_count": len(ACTIVATION_STORE["records"]),
            "blacklist_devices": len(BLACKLIST["devices"]),
            "crack_alerts": len(CRACK_ALERTS),
            "plan_distribution": plan_dist,
            "revenue": self.billing.revenue_summary(),
            "anomalies": self.issuer.anomaly_detection(),
        }

    # ---------------- 模块分布 ---------------- #
    def module_distribution(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for rec in self.issuer.licenses.values():
            for m in rec["payload"]["modules"]:
                out[m] = out.get(m, 0) + 1
        return out

    # ---------------- 激活统计 ---------------- #
    def activation_stats(self) -> Dict[str, Any]:
        recs = list(ACTIVATION_STORE["records"].values())
        by_state: Dict[str, int] = {}
        for r in recs:
            by_state[r["state"]] = by_state.get(r["state"], 0) + 1
        return {"total": len(recs), "by_state": by_state,
                "by_os": {}, "recent": recs[-10:]}

    # ---------------- 异常告警 ---------------- #
    def alerts(self) -> List[Dict[str, Any]]:
        out = list(CRACK_ALERTS)
        out.extend(self.issuer.anomaly_detection())
        out.extend({"type": "renewal_reminder", **r}
                   for r in self.billing.renewal_reminders())
        return out

    # ---------------- 系统设置 ---------------- #
    def system_settings(self) -> Dict[str, Any]:
        return {
            "rsa_key_id": self.issuer and getattr(
                __import__("license_system.license_generator", fromlist=["get_key_manager"]),
                "get_key_manager")().key_id,
            "public_key_pem": __import__(
                "license_system.license_generator", fromlist=["get_key_manager"]
            ).get_key_manager().public_key_pem(),
            "price_config": PRICE_TABLE,
            "blacklist": self.piracy.blacklist_summary(),
            "audit": self.issuer.audit_report(),
            "hardening": self.piracy.hardening_profile(),
        }

    # ---------------- 全量聚合 ---------------- #
    def full_dashboard(self) -> Dict[str, Any]:
        return {
            "overview": self.overview(),
            "module_distribution": self.module_distribution(),
            "activation_stats": self.activation_stats(),
            "alerts": self.alerts(),
            "settings": self.system_settings(),
            "legal_docs": self.piracy.legal_docs(),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


_dash: Optional[LicenseDashboard] = None


def get_dashboard() -> LicenseDashboard:
    global _dash
    with LOCK:
        if _dash is None:
            _dash = LicenseDashboard()
        return _dash
