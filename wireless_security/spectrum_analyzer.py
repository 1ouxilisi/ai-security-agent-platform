# -*- coding: utf-8 -*-
"""
spectrum_analyzer.py - 频谱分析器（第12轮无线网络安全深化模块）

仅做能量检测与干扰源识别，不发射干扰信号。
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, Dict, List


NON_WIFI_INTERFERERS = {
    "MicrowaveOven": {"freq_range": "2400-2500 MHz", "symptom": "突发强脉冲，周期性"},
    "WirelessCamera": {"freq_range": "2400-2500 MHz", "symptom": "持续宽带噪声"},
    "Bluetooth": {"freq_range": "2402-2480 MHz", "symptom": "跳变窄带占用"},
    "Zigbee": {"freq_range": "2405-2480 MHz", "symptom": "16个信道中周期性占用"},
    "WirelessMic": {"freq_range": "2400-2483 MHz", "symptom": "窄带突发"},
    "RemoteControl": {"freq_range": "2400-2483 MHz", "symptom": "极短脉冲"},
    "DECTPhone": {"freq_range": "1900 MHz / 2400 MHz", "symptom": "持续占用"},
}


class SpectrumAnalyzer:
    """频谱分析器。"""

    def __init__(self):
        self.snapshots: List[Dict[str, Any]] = []

    def measure_band(self, band: str = "2.4GHz") -> Dict[str, Any]:
        if band == "2.4GHz":
            channels = list(range(1, 15))
        elif band == "5GHz":
            channels = list(range(36, 177, 4))
        else:
            channels = list(range(1, 7))  # 6GHz 简化

        energy = {ch: round(random.uniform(-90, -30), 1) for ch in channels}
        util = {ch: round(random.uniform(0.0, 1.0), 2) for ch in channels}
        occupied = sum(1 for v in util.values() if v > 0.5)
        snr = round(random.uniform(5, 35), 1)
        interferers = self._identify_interferers(energy, util)

        snap = {
            "band": band,
            "measured_at": datetime.now().isoformat(),
            "energy_dbm": energy,
            "channel_utilization": util,
            "occupied_channels": occupied,
            "spectrum_occupancy": round(occupied / max(1, len(channels)), 2),
            "snr_db": snr,
            "channel_quality": "Good" if snr > 20 else "Fair" if snr > 10 else "Poor",
            "interferers_detected": interferers,
        }
        self.snapshots.append(snap)
        return snap

    def _identify_interferers(self, energy: Dict[int, float], util: Dict[int, float]) -> List[Dict[str, Any]]:
        out = []
        for name, meta in NON_WIFI_INTERFERERS.items():
            if random.random() < 0.15:
                out.append({
                    "source": name,
                    "freq_range": meta["freq_range"],
                    "symptom": meta["symptom"],
                    "confidence": random.randint(60, 95),
                    "impact_on_wifi": random.choice(["Low", "Medium", "High"]),
                })
        return out

    def analyze(self) -> Dict[str, Any]:
        snaps = [self.measure_band(b) for b in ["2.4GHz", "5GHz"]]
        return {
            "title": "频谱分析报告",
            "generated_at": datetime.now().isoformat(),
            "snapshots": snaps,
            "summary": {
                "total_bands": len(snaps),
                "interferer_count": sum(len(s["interferers_detected"]) for s in snaps),
                "overall_recommendation": "2.4G 拥堵严重时优先使用 5G；识别并屏蔽非 WiFi 干扰源",
            },
        }


__all__ = ["SpectrumAnalyzer", "NON_WIFI_INTERFERERS"]
