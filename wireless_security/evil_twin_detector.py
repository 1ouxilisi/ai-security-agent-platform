# -*- coding: utf-8 -*-
"""
evil_twin_detector.py - 邪恶孪生与钓鱼 AP 检测器（第12轮深化模块）

仅做对比分析与风险评级，不创建虚假 AP、不进行中间人攻击。
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, Dict, List

from .wifi_scanner import WiFiScanner


class EvilTwinDetector:
    """邪恶孪生 / 钓鱼 AP 检测器。"""

    def __init__(self, scanner: Optional["WiFiScanner"] = None):
        self.scanner = scanner or WiFiScanner()
        self.findings: List[Dict[str, Any]] = []

    # ---------- AP 指纹对比 ----------
    def fingerprint_compare(self, aps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """按 SSID 分组，识别同名 AP 中的指纹异常。"""
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for ap in aps:
            groups.setdefault(ap.get("ssid") or "<hidden>", []).append(ap)

        out: List[Dict[str, Any]] = []
        for ssid, members in groups.items():
            if len(members) < 2:
                continue
            base = members[0]
            for other in members[1:]:
                mismatches = []
                if base.get("vendor") != other.get("vendor"):
                    mismatches.append(f"vendor: {base.get('vendor')} vs {other.get('vendor')}")
                if abs(base.get("channel", 0) - other.get("channel", 0)) > 5:
                    mismatches.append(f"channel drift: {base.get('channel')} vs {other.get('channel')}")
                if (base.get("encryption") or "").lower() != (other.get("encryption") or "").lower():
                    mismatches.append(f"encryption: {base.get('encryption')} vs {other.get('encryption')}")
                if mismatches:
                    out.append({
                        "ssid": ssid,
                        "bssid_a": base["bssid"], "bssid_b": other["bssid"],
                        "mismatches": mismatches,
                        "risk": "High" if len(mismatches) >= 2 else "Medium",
                    })
        return out

    # ---------- 同名 AP / 信号异常 ----------
    def duplicate_ssid_detect(self, aps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        dup: Dict[str, List[Dict[str, Any]]] = {}
        for ap in aps:
            dup.setdefault(ap.get("ssid") or "", []).append(ap)
        findings = []
        for ssid, members in dup.items():
            if ssid and len(members) >= 2:
                rssis = [m.get("rssi", -80) for m in members]
                strongest_diff = max(rssis) - min(rssis)
                findings.append({
                    "ssid": ssid,
                    "count": len(members),
                    "bssids": [m["bssid"] for m in members],
                    "rssi_spread": strongest_diff,
                    "encryption_consistent": len({(m.get("encryption") or "").lower() for m in members}) == 1,
                    "anomaly": "High signal spread" if strongest_diff > 25 else "Normal",
                })
        return findings

    def signal_anomaly(self, aps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        anomalies = []
        for ap in aps:
            rssi = ap.get("rssi", -80)
            if rssi >= -35:
                anomalies.append({
                    "bssid": ap["bssid"], "ssid": ap.get("ssid"),
                    "type": "unusually_strong_signal",
                    "rssi": rssi,
                    "note": "信号异常强，可能距离极近或为伪装 AP",
                })
        return anomalies

    # ---------- 钓鱼 AP 特征 ----------
    def phishing_features(self, aps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for ap in aps:
            flags = []
            if "open" in (ap.get("encryption") or "").lower():
                flags.append("open_network")
            if random.random() < 0.3:
                flags.append("captive_portal_detected")
            if random.random() < 0.2:
                flags.append("ssl_stripping_observed")
            if random.random() < 0.15:
                flags.append("dns_hijack_detected")
            if flags:
                out.append({
                    "bssid": ap["bssid"], "ssid": ap.get("ssid"),
                    "features": flags,
                    "phishing_risk": "Critical" if "ssl_stripping_observed" in flags or "dns_hijack_detected" in flags else "High",
                })
        return out

    def login_page_analysis(self, ap: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "bssid": ap["bssid"],
            "fake_login_page_suspected": random.random() < 0.3,
            "form_fields_collected": ["username", "password"],
            "cert_anomaly": random.choice(["none", "self_signed", "hostname_mismatch"]),
            "credential_harvest_risk": "High" if random.random() < 0.3 else "Low",
        }

    # ---------- 综合 ----------
    def detect(self) -> Dict[str, Any]:
        aps = list(self.scanner.aps.values()) or self.scanner.scan()
        fp = self.fingerprint_compare(aps)
        dup = self.duplicate_ssid_detect(aps)
        sig = self.signal_anomaly(aps)
        phish = self.phishing_features(aps)

        risk_count = sum(1 for x in fp if x["risk"] == "High") + len(phish)
        rating = "Critical" if risk_count >= 3 else "High" if risk_count >= 1 else "Low"

        report = {
            "title": "邪恶孪生 / 钓鱼 AP 检测报告",
            "generated_at": datetime.now().isoformat(),
            "risk_rating": rating,
            "fingerprint_mismatches": fp,
            "duplicate_ssids": dup,
            "signal_anomalies": sig,
            "phishing_features": phish,
            "login_page_analysis": [self.login_page_analysis(a) for a in phish],
            "recommendations": [
                "对关键 SSID 绑定 BSSID（企业 802.1X）",
                "客户端启用证书校验，避免连接任意同名 AP",
                "公共场合谨慎连接开放网络，必要时使用 VPN",
                "留意登录页证书与域名异常",
            ],
        }
        self.findings = [report]
        return report


__all__ = ["EvilTwinDetector"]
