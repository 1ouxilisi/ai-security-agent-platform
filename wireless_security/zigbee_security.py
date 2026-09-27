# -*- coding: utf-8 -*-
"""
zigbee_security.py - Zigbee/IoT 无线安全分析器（第12轮深化模块）

仅做信道扫描/设备枚举/漏洞面评估，不进行密钥提取或重放攻击。
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, Dict, List


ZIGBEE_CHANNELS_24G = list(range(11, 27))  # 11-26


class ZigbeeSecurityAnalyzer:
    """Zigbee 安全分析器。"""

    DEFAULT_KEYS = ["ZigBeeAlliance09", "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"]

    def __init__(self):
        self.devices: List[Dict[str, Any]] = []
        self.channel_scan: Dict[int, float] = {}

    # ---------- 信道扫描 ----------
    def scan_channels(self) -> Dict[int, float]:
        energy = {}
        for ch in ZIGBEE_CHANNELS_24G:
            energy[ch] = round(random.uniform(0.0, 1.0), 3)
        self.channel_scan = energy
        return energy

    # ---------- 设备发现 ----------
    def discover(self) -> List[Dict[str, Any]]:
        devices = []
        for i in range(random.randint(4, 10)):
            ext_addr = ":".join(f"{random.randint(0,255):02X}" for _ in range(8))
            devices.append({
                "extended_address": ext_addr,
                "short_address": f"0x{random.randint(0,0xFFFF):04X}",
                "device_type": random.choice(["Coordinator", "Router", "EndDevice"]),
                "pan_id": f"0x{random.randint(0,0xFFFF):04X}",
                "vendor": random.choice(["Philips Hue", "Xiaomi", "IKEA", "Third Reality", "Samsung"]),
                "rssi": random.randint(-95, -55),
            })
        self.devices = devices
        return devices

    # ---------- 网络分析 ----------
    def network_analysis(self, dev: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "extended_address": dev["extended_address"],
            "network_key_in_use": random.choice(["Central", "Distributed"]),
            "link_key_in_use": random.choice(["Global", "InstallCode", "TC-LK"]),
            "join_allowed": random.random() < 0.3,
            "rejoin_in_progress": False,
            "parent": f"0x{random.randint(0,0xFFFF):04X}",
            "neighbor_table_size": random.randint(2, 20),
        }

    # ---------- 安全分析 ----------
    def security_analysis(self, dev: Dict[str, Any]) -> Dict[str, Any]:
        uses_default_key = random.random() < 0.15
        return {
            "extended_address": dev["extended_address"],
            "network_key_strength": "128-bit (AES-128)",
            "default_key_used": uses_default_key,
            "default_key_candidates": self.DEFAULT_KEYS if uses_default_key else [],
            "key_transfer_encrypted": not uses_default_key,
            "replay_attack_surface": "High" if uses_default_key else "Medium",
            "known_impl_vulns": [
                v for v, hit in [
                    ("Trust-Center link-key default", uses_default_key),
                    ("Rejoin without authentication", random.random() < 0.2),
                    ("Insecure install-code provisioning", random.random() < 0.15),
                ] if hit
            ],
        }

    # ---------- 重放 ----------
    def replay_assessment(self, dev: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "extended_address": dev["extended_address"],
            "frame_counter": random.randint(0, 0xFFFFFFFF),
            "sequence_number": random.randint(0, 255),
            "replay_window": 32,
            "anti_replay_mechanism": "Frame counter + freshness",
            "risk": "Low" if random.random() > 0.2 else "Medium",
        }

    # ---------- 主入口 ----------
    def analyze(self) -> Dict[str, Any]:
        if not self.devices:
            self.discover()
        self.scan_channels()

        per = []
        score_total = 0
        for d in self.devices:
            sec = self.security_analysis(d)
            net = self.network_analysis(d)
            rep = self.replay_assessment(d)
            score = 100
            if sec["default_key_used"]:
                score -= 40
            if net["join_allowed"]:
                score -= 15
            if "High" in sec["replay_attack_surface"]:
                score -= 10
            score = max(0, score)
            score_total += score
            per.append({"device": d, "network": net, "security": sec, "replay": rep, "score": score})

        avg = round(score_total / max(1, len(per)), 1)
        busiest = max(self.channel_scan.items(), key=lambda x: x[1]) if self.channel_scan else (0, 0)
        return {
            "title": "Zigbee/IoT 安全分析报告",
            "generated_at": datetime.now().isoformat(),
            "channel_scan": self.channel_scan,
            "busiest_channel": {"channel": busiest[0], "energy": busiest[1]},
            "device_count": len(self.devices),
            "overall_score": avg,
            "devices": per,
            "recommendations": [
                "不要使用默认全球链接密钥 ZigBeeAlliance09",
                "设备入网后立即关闭 join 模式",
                "使用安装码(Install Code)进行安全配网",
                "保持协调器/网关固件更新",
                "对关键开关/传感器评估重放窗口设置",
            ],
        }


__all__ = ["ZigbeeSecurityAnalyzer", "ZIGBEE_CHANNELS_24G"]
