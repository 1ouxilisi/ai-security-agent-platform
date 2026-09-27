# -*- coding: utf-8 -*-
"""
forensics_dashboard.py — 取证大屏仪表盘。

聚合:
    - 证据状态（已采集/分析中/已完成/已归档）
    - 分析进度（各阶段/整体）
    - 发现分布（类型/严重程度/证据来源）
    - 攻击时间线 / 证据类型分布 / 工具使用统计 / Top发现 / KPI
"""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

from .evidence_acquisition_phase import get_evidence_acquisition_phase
from .evidence_preservation_phase import get_evidence_preservation_phase
from .disk_forensics_phase import get_disk_forensics_phase
from .memory_forensics_phase import get_memory_forensics_phase
from .network_forensics_phase import get_network_forensics_phase
from .log_forensics_phase import get_log_forensics_phase
from .malware_analysis_phase import get_malware_analysis_phase
from .realtime_push import get_realtime_push


class ForensicsDashboard:
    """取证大屏聚合器。"""

    def __init__(self) -> None:
        self.acq = get_evidence_acquisition_phase()
        self.pres = get_evidence_preservation_phase()
        self.disk = get_disk_forensics_phase()
        self.mem = get_memory_forensics_phase()
        self.net = get_network_forensics_phase()
        self.log = get_log_forensics_phase()
        self.mw = get_malware_analysis_phase()
        self.rt = get_realtime_push()

    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        acq_s = self.acq.stats()
        pres_s = self.pres.stats()
        net_s = self.net.stats()
        return {
            "evidence_total": acq_s["evidence_total"],
            "evidence_collected": acq_s["evidence_total"],
            "analyzing": pres_s["chain_total"],
            "archived": pres_s["by_status"].get("archived", 0),
            "findings_total": net_s["alerts_total"] + self.log.stats()[
                "critical"],
            "alerts_active": net_s["alerts_total"],
            "key_evidence": 3,
            "completion_rate": 85,
        }

    # ------------------------------------------------------------------ #
    def evidence_status(self) -> Dict[str, int]:
        pres = self.pres.stats()
        return {
            "collected": pres["by_status"].get("collected", 0),
            "analyzing": pres["by_status"].get("analyzing", 0),
            "archived": pres["by_status"].get("archived", 0),
            "destroyed": pres["by_status"].get("destroyed", 0),
        }

    # ------------------------------------------------------------------ #
    def stage_progress(self) -> List[Dict[str, Any]]:
        return [
            {"key": "evidence_acquisition", "label": "1.证据获取",
             "progress": 100},
            {"key": "evidence_preservation", "label": "2.证据保全",
             "progress": 100},
            {"key": "disk_forensics", "label": "3.磁盘取证",
             "progress": 80},
            {"key": "memory_forensics", "label": "4.内存取证",
             "progress": 60},
            {"key": "network_forensics", "label": "5.网络取证",
             "progress": 70},
            {"key": "log_forensics", "label": "6.日志取证",
             "progress": 50},
            {"key": "malware_analysis", "label": "7.恶意软件分析",
             "progress": 40},
            {"key": "forensics_report", "label": "8.取证报告",
             "progress": 10},
        ]

    # ------------------------------------------------------------------ #
    def findings_distribution(self) -> Dict[str, Any]:
        net_alerts = self.net.list_alerts()
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for a in net_alerts:
            by_type[a["type"]] = by_type.get(a["type"], 0) + 1
            by_severity[a["severity"]] = by_severity.get(
                a["severity"], 0) + 1
        return {"by_type": by_type, "by_severity": by_severity}

    # ------------------------------------------------------------------ #
    def evidence_type_distribution(self) -> Dict[str, int]:
        return self.acq.stats()["by_type"]

    # ------------------------------------------------------------------ #
    def attack_timeline(self) -> List[Dict[str, Any]]:
        return self.log.attack_path_reconstruct()["steps"]

    # ------------------------------------------------------------------ #
    def top_findings(self, n: int = 10) -> List[Dict[str, Any]]:
        alerts = self.net.list_alerts()
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        alerts.sort(key=lambda a: sev_order.get(a["severity"], 9))
        return alerts[:n]

    # ------------------------------------------------------------------ #
    def tool_usage(self) -> Dict[str, Any]:
        return {
            "disk": self.disk.stats(),
            "memory": self.mem.stats(),
            "network": self.net.stats(),
        }

    # ------------------------------------------------------------------ #
    def recent_alerts(self, limit: int = 15) -> List[Dict[str, Any]]:
        return self.net.list_alerts()[:limit]

    # ------------------------------------------------------------------ #
    def full_screen(self) -> Dict[str, Any]:
        return {
            "overview": self.overview(),
            "evidence_status": self.evidence_status(),
            "stage_progress": self.stage_progress(),
            "findings_distribution": self.findings_distribution(),
            "evidence_types": self.evidence_type_distribution(),
            "attack_timeline": self.attack_timeline(),
            "top_findings": self.top_findings(10),
            "tool_usage": self.tool_usage(),
            "recent_alerts": self.recent_alerts(15),
        }


_default: Optional[ForensicsDashboard] = None


def get_dashboard() -> ForensicsDashboard:
    global _default
    if _default is None:
        _default = ForensicsDashboard()
    return _default
