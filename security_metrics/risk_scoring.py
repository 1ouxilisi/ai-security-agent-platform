#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
risk_scoring.py — 风险度量与评分引擎。

覆盖：
    - 综合风险评分（可能性 x 影响 x 暴露，0-100）
    - 风险等级（低/中/高/严重）
    - 风险趋势（近 12 期）、风险分布、风险热力图（资产类别 x 威胁类型）
    - 风险归因（根因贡献度）、风险预测（下一周期预测）
    - 风险处置（接受/转移/规避/缓解）跟踪台账
"""

from __future__ import annotations

import math
import time
from typing import Any, Dict, List, Optional


RISK_LEVELS: Dict[str, Dict[str, Any]] = {
    "critical": {"name": "严重", "range": (80, 100), "color": "#ff4d4f", "action": "立即处置"},
    "high": {"name": "高", "range": (60, 79.99), "color": "#fa8c16", "action": "30 日内处置"},
    "medium": {"name": "中", "range": (35, 59.99), "color": "#fadb14", "action": "90 日内处置"},
    "low": {"name": "低", "range": (0, 34.99), "color": "#52c41a", "action": "接受/监控"},
}

_TREATMENTS = ["accept", "transfer", "avoid", "mitigate"]


class RiskScoringEngine:
    """风险评分与度量引擎（全内存模拟）。"""

    def __init__(self) -> None:
        self._register: List[Dict[str, Any]] = self._seed_register()

    # ------------------------------------------------------------------ #
    # 评分
    # ------------------------------------------------------------------ #
    @staticmethod
    def score(probability: float, impact: float, exposure: float = 1.0) -> Dict[str, Any]:
        """
        probability 0-10, impact 0-10, exposure 0.1-2.0
        综合分 = (probability/10 * impact/10) * 100 * exposure，封顶 100。
        """
        p = max(0.0, min(10.0, float(probability)))
        i = max(0.0, min(10.0, float(impact)))
        e = max(0.1, min(2.0, float(exposure)))
        raw = (p / 10.0) * (i / 10.0) * 100.0 * e
        raw = max(0.0, min(100.0, raw))
        return {
            "probability": p, "impact": i, "exposure_factor": round(e, 2),
            "raw_score": round(raw, 1),
            "level": RiskScoringEngine._level_of(raw),
        }

    @staticmethod
    def _level_of(score: float) -> str:
        for lv, info in RISK_LEVELS.items():
            lo, hi = info["range"]
            if lo <= score <= hi:
                return lv
        return "low"

    # ------------------------------------------------------------------ #
    # 风险登记册
    # ------------------------------------------------------------------ #
    def _seed_register(self) -> List[Dict[str, Any]]:
        seeds = [
            ("R-001", "核心数据库弱口令", "data", "web", 8, 9, 1.2, "mitigate"),
            ("R-002", "公网暴露管理后台", "internet", "web", 7, 8, 1.1, "avoid"),
            ("R-003", "员工钓鱼点击", "people", "phishing", 9, 5, 1.0, "mitigate"),
            ("R-004", "勒索软件横向移动", "endpoint", "malware", 5, 10, 1.3, "transfer"),
            ("R-005", "第三方供应商数据泄露", "supply", "data_breach", 4, 9, 1.0, "transfer"),
            ("R-006", "API 未授权访问", "api", "api", 6, 7, 1.0, "mitigate"),
            ("R-007", "日志缺失导致检测盲区", "siem", "detection", 6, 6, 0.9, "mitigate"),
            ("R-008", "灾备演练未通过", "backup", "availability", 3, 8, 0.8, "mitigate"),
            ("R-009", "开源组件已知漏洞", "software", "vuln", 7, 6, 1.0, "mitigate"),
            ("R-010", "特权账号滥用", "identity", "privilege", 5, 8, 0.9, "mitigate"),
            ("R-011", "云存储桶公网可读", "cloud", "misconfig", 6, 7, 1.0, "avoid"),
            ("R-012", "移动设备失管", "mobile", "device", 5, 5, 0.8, "accept"),
        ]
        out: List[Dict[str, Any]] = []
        for rid, name, asset_cat, threat_type, p, im, e, treat in seeds:
            s = self.score(p, im, e)
            out.append({
                "risk_id": rid, "name": name, "asset_category": asset_cat,
                "threat_type": threat_type, "probability": p, "impact": im,
                "exposure": e, "score": s["raw_score"], "level": s["level"],
                "treatment": treat, "owner": "安全部", "status": "open",
                "due_date": time.strftime("%Y-%m-%d",
                    time.localtime(time.time() + 30 * 86400)),
            })
        return out

    def list_register(self, level: Optional[str] = None,
                      treatment: Optional[str] = None) -> Dict[str, Any]:
        items = self._register
        if level:
            items = [r for r in items if r["level"] == level]
        if treatment:
            items = [r for r in items if r["treatment"] == treatment]
        counts = {lv: sum(1 for r in self._register if r["level"] == lv)
                  for lv in RISK_LEVELS}
        return {
            "total": len(self._register), "returned": len(items),
            "level_distribution": counts,
            "average_score": round(
                sum(r["score"] for r in self._register) / len(self._register), 1),
            "items": items,
        }

    def add_risk(self, name: str, asset_category: str, threat_type: str,
                 probability: float, impact: float, exposure: float = 1.0,
                 treatment: str = "mitigate", owner: str = "安全部") -> Dict[str, Any]:
        s = self.score(probability, impact, exposure)
        rid = f"R-{len(self._register) + 1:03d}"
        item = {
            "risk_id": rid, "name": name, "asset_category": asset_category,
            "threat_type": threat_type, "probability": probability, "impact": impact,
            "exposure": exposure, "score": s["raw_score"], "level": s["level"],
            "treatment": treatment, "owner": owner, "status": "open",
            "due_date": time.strftime("%Y-%m-%d",
                time.localtime(time.time() + 90 * 86400)),
        }
        self._register.append(item)
        return item

    def update_treatment(self, risk_id: str, treatment: str,
                         status: Optional[str] = None,
                         note: str = "") -> Optional[Dict[str, Any]]:
        if treatment not in _TREATMENTS:
            return None
        for r in self._register:
            if r["risk_id"] == risk_id:
                r["treatment"] = treatment
                if status:
                    r["status"] = status
                r["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                if note:
                    r["note"] = note
                return r
        return None

    # ------------------------------------------------------------------ #
    # 综合评分 / 趋势 / 分布 / 热力图
    # ------------------------------------------------------------------ #
    def overall_scorecard(self) -> Dict[str, Any]:
        scores = [r["score"] for r in self._register]
        avg = sum(scores) / len(scores)
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        weighted = sum(weights[r["level"]] * r["score"] for r in self._register) / len(scores)
        return {
            "overall_risk_score": round(avg, 1),
            "weighted_risk_score": round(weighted, 1),
            "max_score": max(scores), "min_score": min(scores),
            "level_distribution": {lv: sum(1 for r in self._register if r["level"] == lv)
                                   for lv in RISK_LEVELS},
            "treatment_distribution": {t: sum(1 for r in self._register if r["treatment"] == t)
                                      for t in _TREATMENTS},
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def risk_trend(self, periods: int = 12) -> Dict[str, Any]:
        """近 N 期综合风险趋势（模拟正弦+趋势）。"""
        now = time.time()
        labels, values = [], []
        base = self.overall_scorecard()["overall_risk_score"]
        for i in range(periods):
            t = now - (periods - i) * 30 * 86400
            month = time.strftime("%Y-%m", time.localtime(t))
            val = round(max(5.0, min(95.0,
                        base + math.sin(i / 2.0) * 6 - i * 0.4)), 1)
            labels.append(month)
            values.append(val)
        return {"periods": labels, "scores": values,
                "direction": "down" if values[-1] < values[0] else "up",
                "change": round(values[-1] - values[0], 1)}

    def risk_distribution(self) -> Dict[str, Any]:
        by_asset: Dict[str, int] = {}
        by_threat: Dict[str, int] = {}
        for r in self._register:
            by_asset[r["asset_category"]] = by_asset.get(r["asset_category"], 0) + 1
            by_threat[r["threat_type"]] = by_threat.get(r["threat_type"], 0) + 1
        return {"by_asset_category": by_asset, "by_threat_type": by_threat}

    def heatmap(self) -> Dict[str, Any]:
        """资产类别 x 威胁类型 风险热力图。"""
        assets = sorted({r["asset_category"] for r in self._register})
        threats = sorted({r["threat_type"] for r in self._register})
        grid: List[List[Dict[str, Any]]] = []
        for a in assets:
            row = []
            for t in threats:
                cell = [r for r in self._register
                        if r["asset_category"] == a and r["threat_type"] == t]
                score = cell[0]["score"] if cell else 0
                row.append({"value": round(score, 1),
                            "level": self._level_of(score) if score else "none",
                            "count": len(cell)})
            grid.append({"asset": a, "cells": row})
        return {"assets": assets, "threats": threats, "grid": grid}

    def attribution(self) -> Dict[str, Any]:
        """风险归因：按资产类别 / 威胁类型 / 处置方式贡献度。"""
        total = sum(r["score"] for r in self._register) or 1
        by_asset: Dict[str, float] = {}
        by_threat: Dict[str, float] = {}
        for r in self._register:
            by_asset[r["asset_category"]] = by_asset.get(r["asset_category"], 0) + r["score"]
            by_threat[r["threat_type"]] = by_threat.get(r["threat_type"], 0) + r["score"]
        top_asset = sorted(by_asset.items(), key=lambda kv: -kv[1])[0]
        top_threat = sorted(by_threat.items(), key=lambda kv: -kv[1])[0]
        return {
            "top_contributing_asset": {"category": top_asset[0],
                                       "share_pct": round(top_asset[1] / total * 100, 1)},
            "top_contributing_threat": {"type": top_threat[0],
                                        "share_pct": round(top_threat[1] / total * 100, 1)},
            "by_asset_pct": {k: round(v / total * 100, 1) for k, v in by_asset.items()},
            "by_threat_pct": {k: round(v / total * 100, 1) for k, v in by_threat.items()},
            "recommendation": "优先治理高贡献资产类别与威胁类型，资源向 Top 风险倾斜。",
        }

    def predict(self, periods_ahead: int = 3) -> Dict[str, Any]:
        """简单线性外推预测下一周期风险。"""
        trend = self.risk_trend(12)
        vals = trend["scores"]
        slope = (vals[-1] - vals[0]) / max(1, len(vals) - 1)
        forecast = []
        last = vals[-1]
        last_time = time.localtime(time.time())
        for k in range(1, periods_ahead + 1):
            next_time = time.localtime(time.time() + k * 30 * 86400)
            last = round(max(5.0, min(95.0, last + slope)), 1)
            forecast.append({"period": time.strftime("%Y-%m", next_time),
                             "predicted_score": last,
                             "level": self._level_of(last)})
        return {"method": "linear_extrapolation", "slope_per_period": round(slope, 2),
                "forecast": forecast}
