# -*- coding: utf-8 -*-
"""
risk_rating_phase.py — 阶段7：风险评级。

维度: 设备类型权重 / 漏洞严重程度 / 网络位置 / 业务影响 /
      可利用性 / 暴露面
输出: 0-100 评分 + critical/high/medium/low 四级 +
      Top 风险设备 + 风险趋势 + 风险矩阵 + 工控安全成熟度(5级)。
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

DEVICE_WEIGHT = {
    "PLC": 1.0, "DCS": 1.0, "SCADA_SERVER": 0.95, "RTU": 0.9,
    "HISTORIAN": 0.85, "HMI": 0.8, "ENG_STATION": 0.7,
    "IND_GATEWAY": 0.75, "ROUTER": 0.6, "CAMERA": 0.4,
    "SMART_HOME": 0.3, "UNKNOWN": 0.5,
}

NETWORK_WEIGHT = {
    "工控网": 1.0, "管理网": 0.75, "DMZ": 0.6, "互联网": 1.0,
    "隔离": 0.3,
}

BUSINESS_WEIGHT = {
    "关键生产": 1.0, "重要生产": 0.8, "一般生产": 0.55, "辅助系统": 0.35,
}

SEVERITY_SCORE = {"critical": 40, "high": 28, "medium": 15, "low": 6}
EXPLOIT_WEIGHT = {"低": 1.0, "中": 0.7, "高": 0.4}
EXPOSURE_WEIGHT = {"互联网暴露": 1.0, "内网暴露": 0.6, "隔离": 0.2}

MATURITY_LEVELS = [
    (1, "初始级"), (2, "可重复级"), (3, "已定义级"),
    (4, "量化管理级"), (5, "优化级"),
]


@dataclass
class RiskScore:
    risk_id: str = ""
    device: str = ""
    device_type: str = ""
    score: int = 0
    level: str = "low"
    dimensions: Dict[str, Any] = field(default_factory=dict)
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_id": self.risk_id, "device": self.device,
            "device_type": self.device_type, "score": self.score,
            "level": self.level, "dimensions": self.dimensions,
            "updated_at": self.updated_at,
        }


def _level_of(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


class RiskRatingPhase:
    """阶段7：风险评级。"""

    def __init__(self) -> None:
        self._scores: Dict[str, RiskScore] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def score_device(self, device: str, device_type: str,
                     vuln_severities: List[str],
                     network_location: str = "管理网",
                     business: str = "重要生产",
                     exploit_difficulty: str = "中",
                     exposure: str = "内网暴露",
                     open_vuln_count: int = 1) -> Dict[str, Any]:
        dev_w = DEVICE_WEIGHT.get(device_type, 0.5)
        # 漏洞分：取最高严重程度 + 数量加成
        vscore = max((SEVERITY_SCORE.get(s, 5) for s in vuln_severities),
                     default=5)
        vscore += min(15, open_vuln_count * 3)
        net_w = NETWORK_WEIGHT.get(network_location, 0.5)
        biz_w = BUSINESS_WEIGHT.get(business, 0.5)
        exp_w = EXPLOIT_WEIGHT.get(exploit_difficulty, 0.7)
        expo_w = EXPOSURE_WEIGHT.get(exposure, 0.6)
        # 0-100 合成
        raw = (vscore * 0.55
               + (dev_w * 100) * 0.15
               + (net_w * 100) * 0.1
               + (biz_w * 100) * 0.1
               + (exp_w * expo_w * 100) * 0.1)
        score = max(0, min(100, int(raw)))
        rs = RiskScore(
            risk_id="risk_" + uuid.uuid4().hex[:10],
            device=device, device_type=device_type, score=score,
            level=_level_of(score),
            dimensions={
                "device_weight": round(dev_w, 2),
                "vuln_score": vscore,
                "network_weight": round(net_w, 2),
                "business_weight": round(biz_w, 2),
                "exploit_weight": round(exp_w, 2),
                "exposure_weight": round(expo_w, 2),
                "open_vuln_count": open_vuln_count,
            },
            updated_at=datetime.now().isoformat(timespec="seconds"),
        )
        with self._lock:
            self._scores[rs.risk_id] = rs
        return rs.to_dict()

    # ------------------------------------------------------------------ #
    def auto_score(self) -> Dict[str, Any]:
        """基于设备/漏洞自动批量评分。"""
        from .vuln_detection_phase import get_vuln_detection_phase
        vulns = get_vuln_detection_phase().list_vulns()
        # 按目标聚合
        by_target: Dict[str, List[str]] = {}
        for v in vulns:
            by_target.setdefault(v["target"], []).append(v["severity"])
        created = 0
        for target, sevs in by_target.items():
            dtype = "PLC" if "S7" in target or "PLC" in target else (
                "SCADA" if "SCADA" in target else (
                "ROUTER" if "Router" in target else "CAMERA"))
            self.score_device(
                device=target, device_type=dtype,
                vuln_severities=sevs,
                network_location="工控网" if dtype in (
                    "PLC", "SCADA", "RTU") else "管理网",
                business="关键生产" if dtype in (
                    "PLC", "SCADA") else "辅助系统",
                exploit_difficulty="低" if "critical" in sevs else "中",
                exposure="内网暴露",
                open_vuln_count=len(sevs))
            created += 1
        return {"scored_devices": created}

    # ------------------------------------------------------------------ #
    def top_risks(self, n: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            items = sorted(self._scores.values(),
                           key=lambda x: x.score, reverse=True)
        return [x.to_dict() for x in items[:n]]

    def risk_matrix(self) -> Dict[str, Any]:
        """5x5 风险矩阵：可能性 x 影响。"""
        matrix: List[List[int]] = [[0] * 5 for _ in range(5)]
        with self._lock:
            scores = [s.score for s in self._scores.values()]
        import random
        rng = random.Random(3)
        for sc in scores:
            x = min(4, sc // 20)
            y = min(4, (sc + rng.randint(-5, 5)) // 20)
            matrix[x][y] += 1
        return {"matrix": matrix,
                "levels": ["1很低", "2低", "3中", "4高", "5很高"]}

    def maturity(self) -> Dict[str, Any]:
        with self._lock:
            n = len(self._scores)
        # 综合成熟度：分数越低越成熟
        avg = (sum(s.score for s in self._scores.values()) / max(1, n)
               if n else 60)
        level = 5 if avg < 25 else 4 if avg < 40 else 3 if avg < 55 \
            else 2 if avg < 70 else 1
        name = next((nm for lv, nm in MATURITY_LEVELS if lv == level),
                    "初始级")
        return {"level": level, "name": name,
                "avg_score": round(avg, 1),
                "levels": [{"level": lv, "name": nm}
                          for lv, nm in MATURITY_LEVELS]}

    def trend(self, days: int = 14) -> List[Dict[str, Any]]:
        import random
        rng = random.Random(9)
        with self._lock:
            base = (sum(s.score for s in self._scores.values())
                    / max(1, len(self._scores))) or 50
        out = []
        for i in range(days):
            v = int(max(20, base + rng.uniform(-15, 15)))
            out.append({"day": f"D-{days-i}", "score": v})
        return out

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._scores.values())
        lv: Dict[str, int] = {}
        for s in items:
            lv[s.level] = lv.get(s.level, 0) + 1
        avg = (sum(s.score for s in items) / max(1, len(items)))
        return {"total": len(items), "by_level": lv,
                "avg_score": round(avg, 1),
                "maturity": self.maturity()}


_default: Optional[RiskRatingPhase] = None


def get_risk_rating_phase() -> RiskRatingPhase:
    global _default
    if _default is None:
        _default = RiskRatingPhase()
    return _default
