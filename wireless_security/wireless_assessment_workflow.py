# -*- coding: utf-8 -*-
"""
wireless_assessment_workflow.py - 无线网络综合评估工作流（第12轮深化模块）

串行/聚合：WiFi扫描 → WiFi安全评估 → 邪恶孪生检测 → 蓝牙安全 → Zigbee安全 → 频谱分析 → 报告。
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List

from .wifi_scanner import WiFiScanner
from .wifi_security import WiFiSecurityAssessor
from .evil_twin_detector import EvilTwinDetector
from .bluetooth_security import BluetoothSecurityAnalyzer
from .zigbee_security import ZigbeeSecurityAnalyzer
from .spectrum_analyzer import SpectrumAnalyzer


class WirelessAssessmentWorkflow:
    """综合评估工作流。"""

    def __init__(self, parallel: bool = True):
        self.parallel = parallel
        self.scanner = WiFiScanner()
        self.assessor = WiFiSecurityAssessor(self.scanner)
        self.evil = EvilTwinDetector(self.scanner)
        self.bt = BluetoothSecurityAnalyzer()
        self.zig = ZigbeeSecurityAnalyzer()
        self.spec = SpectrumAnalyzer()

    def run(self) -> Dict[str, Any]:
        # 第一步：WiFi 扫描（基础数据）
        aps = self.scanner.scan()

        if self.parallel:
            with ThreadPoolExecutor(max_workers=4) as ex:
                f_sec = ex.submit(self.assessor.assess_all)
                f_evil = ex.submit(self.evil.detect)
                f_bt = ex.submit(self.bt.report)
                f_zig = ex.submit(self.zig.analyze)
                f_spec = ex.submit(self.spec.analyze)
                wifi_sec = f_sec.result()
                evil = f_evil.result()
                bt = f_bt.result()
                zig = f_zig.result()
                spec = f_spec.result()
        else:
            wifi_sec = self.assessor.assess_all()
            evil = self.evil.detect()
            bt = self.bt.report()
            zig = self.zig.analyze()
            spec = self.spec.analyze()

        # 聚合
        overall = self._aggregate(aps, wifi_sec, evil, bt, zig, spec)
        report = self._build_report(aps, wifi_sec, evil, bt, zig, spec, overall)
        return report

    def _aggregate(self, aps, wifi_sec, evil, bt, zig, spec) -> Dict[str, Any]:
        scores = []
        vuln_count = 0
        for r in wifi_sec:
            scores.append(r.get("security_score", 0))
            vuln_count += len(r.get("issues", []))
        scores.append(bt.get("overall_score", 0))
        scores.append(zig.get("overall_score", 0))
        avg = round(sum(scores) / max(1, len(scores)), 1)

        if avg < 40:
            rating = "Critical"
        elif avg < 60:
            rating = "High"
        elif avg < 80:
            rating = "Medium"
        else:
            rating = "Low"

        # 修复优先级
        priorities = []
        for r in wifi_sec:
            if r.get("security_score", 100) < 50:
                priorities.append({"priority": "P0", "target": r.get("ssid") or r.get("bssid"),
                                   "actions": r.get("hardening", [])})
        if evil.get("risk_rating") in ("Critical", "High"):
            priorities.append({"priority": "P0", "target": "恶意AP",
                               "actions": evil.get("recommendations", [])})
        priorities.sort(key=lambda x: x["priority"])
        return {
            "overall_score": avg,
            "risk_rating": rating,
            "total_vulnerabilities": vuln_count,
            "remediation_priorities": priorities,
        }

    def _build_report(self, aps, wifi_sec, evil, bt, zig, spec, overall) -> Dict[str, Any]:
        return {
            "title": "无线网络综合安全评估报告",
            "generated_at": datetime.now().isoformat(),
            "executive_summary": {
                "aps_discovered": len(aps),
                "bluetooth_devices": bt.get("device_count", 0),
                "zigbee_devices": zig.get("device_count", 0),
                "overall_score": overall["overall_score"],
                "risk_rating": overall["risk_rating"],
            },
            "devices": {"wifi_aps": aps, "bluetooth": bt, "zigbee": zig},
            "risk_distribution": self._risk_distribution(wifi_sec, evil, bt, zig),
            "vulnerability_list": [r.get("issues", []) for r in wifi_sec],
            "hardening_recommendations": {
                "wifi": wifi_sec[0].get("hardening", []) if wifi_sec else [],
                "evil_twin": evil.get("recommendations", []),
                "bluetooth": bt.get("recommendations", []),
                "zigbee": zig.get("recommendations", []),
                "spectrum": spec.get("summary", {}).get("overall_recommendation", ""),
            },
            "conclusion": (
                f"综合评分 {overall['overall_score']}，风险等级 {overall['risk_rating']}。"
                "建议按 P0 优先级先修复高危项。"
            ),
            "remediation_priorities": overall["remediation_priorities"],
        }

    def _risk_distribution(self, wifi_sec, evil, bt, zig) -> Dict[str, int]:
        dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for r in wifi_sec:
            s = r.get("security_score", 100)
            if s < 40:
                dist["Critical"] += 1
            elif s < 60:
                dist["High"] += 1
            elif s < 80:
                dist["Medium"] += 1
            else:
                dist["Low"] += 1
        if evil.get("risk_rating") == "Critical":
            dist["Critical"] += 1
        elif evil.get("risk_rating") == "High":
            dist["High"] += 1
        return dist


__all__ = ["WirelessAssessmentWorkflow"]
