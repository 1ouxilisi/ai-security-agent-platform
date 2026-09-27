#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
新兴通信安全控制台数据聚合层（emerging_comm_security / emerging_comm_dashboard.py）。

把 5G / V2X / 车载 / OTA / 新兴通信五个子控制器聚合为
统一的控制台总览、健康度、风险评分、最近事件流。
"""

from __future__ import annotations

import importlib
from datetime import datetime
from typing import Any, Dict, List

# 模块名以数字开头（5g_security），无法用常规 from-import，改用 importlib 动态加载
_mod_5g = importlib.import_module(".5g_security", package=__package__)
_mod_v2x = importlib.import_module(".v2x_security", package=__package__)
_mod_veh = importlib.import_module(".vehicle_security", package=__package__)
_mod_ota = importlib.import_module(".ota_security", package=__package__)
_mod_new = importlib.import_module(".emerging_comm", package=__package__)


class EmergingCommDashboard:
    """控制台数据聚合层。"""

    def __init__(self) -> None:
        self.c5g = _mod_5g.get_5g_controller()
        self.cv2x = _mod_v2x.get_v2x_controller()
        self.cveh = _mod_veh.get_vehicle_controller()
        self.cota = _mod_ota.get_ota_controller()
        self.cnew = _mod_new.get_emerging_comm_controller()

    # ------------------------- 总览 -------------------------
    def overview(self) -> Dict[str, Any]:
        return {
            "generated_at": datetime.now().isoformat(),
            "modules": {
                "five_g": self.c5g.overview(),
                "v2x": self.cv2x.overview(),
                "vehicle": self.cveh.overview(),
                "ota": self.cota.stats(),
                "emerging": self.cnew.overview(),
            },
            "health_score": self.health_score(),
            "risk_score": self.risk_score(),
        }

    # ------------------------- 健康度 -------------------------
    def health_score(self) -> Dict[str, Any]:
        """0~100 的模块健康度，越高越好。"""
        s5g = 100 - min(30, len(self.c5g.slice_alerts) * 5)
        sv2x = 100 - min(40, len(self.cv2x.anomaly_events) * 2)
        sveh = 100 - min(50, len(self.cveh.threats) * 3)
        sota = 100 - min(40, len(self.cota.violations) * 4)
        snew = 100 - min(30, len(self.cnew.alerts) * 3)
        avg = (s5g + sv2x + sveh + sota + snew) / 5
        return {
            "five_g": s5g, "v2x": sv2x, "vehicle": sveh,
            "ota": sota, "emerging": snew, "average": round(avg, 1),
        }

    # ------------------------- 风险评分 -------------------------
    def risk_score(self) -> Dict[str, Any]:
        """0~100 的风险评分，越高越危险。"""
        risks = {
            "five_g_slice_cross_attack": min(100, len(self.c5g.slice_alerts) * 10),
            "v2x_anomalies": min(100, len(self.cv2x.anomaly_events) * 5),
            "vehicle_threats": min(100, len(self.cveh.threats) * 6),
            "ota_violations": min(100, len(self.cota.violations) * 8),
            "emerging_alerts": min(100, len(self.cnew.alerts) * 5),
        }
        overall = round(sum(risks.values()) / len(risks), 1)
        level = "LOW"
        if overall >= 70:
            level = "CRITICAL"
        elif overall >= 45:
            level = "HIGH"
        elif overall >= 20:
            level = "MEDIUM"
        return {"score_by_module": risks, "overall": overall, "level": level}

    # ------------------------- 统一事件流 -------------------------
    def unified_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for e in self.c5g.recent_auth_events(limit=limit):
            events.append({"source": "5G", **e})
        for e in self.cv2x.recent_anomalies(limit=limit):
            events.append({"source": "V2X", **e})
        for t in self.cveh.recent_threats(limit=limit):
            events.append({"source": "VEHICLE", **t})
        for v in self.cota.recent_violations(limit=limit):
            events.append({"source": "OTA", **v})
        for a in self.cnew.recent_alerts(limit=limit):
            events.append({"source": "EMERGING", **a})
        events.sort(key=lambda x: x.get("ts", ""), reverse=True)
        return events[:limit]

    # ------------------------- 系统设置 -------------------------
    def settings(self) -> Dict[str, Any]:
        return {
            "replay_window_ms": self.cv2x.REPLAY_WINDOW_MS,
            "pseudonym_rotation_s": self.cv2x.PSEUDONYM_ROTATION_S,
            "can_max_fps": self.cveh.MAX_FRAME_RATE_PER_ID,
            "ota_rollback_grace": self.cota.ROLLBACK_GRACE_VERSIONS,
            "pqc_algorithms": self.cnew.pqc_readiness()["recommended_algorithms"],
            "data_retention": self.cveh.data_inventory(),
            "compliance": [
                "ISO/SAE 21434 道路车辆网络安全",
                "UNECE WP.29 R155/R156 网络安全与软件升级",
                "3GPP TS 33.501 5G 安全架构",
                "ETSI EN 303 609 V2X 安全",
                "GB/T 40861 汽车信息安全指南",
            ],
        }


_dashboard: EmergingCommDashboard | None = None


def get_dashboard() -> EmergingCommDashboard:
    global _dashboard
    if _dashboard is None:
        _dashboard = EmergingCommDashboard()
    return _dashboard
