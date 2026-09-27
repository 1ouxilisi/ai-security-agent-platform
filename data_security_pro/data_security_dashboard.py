# -*- coding: utf-8 -*-
"""
data_security_dashboard.py — 数据安全大屏仪表盘。

聚合:
    - 敏感数据分布（类型/级别/位置）
    - DLP 告警趋势（24h/7d/30d）
    - 合规状态（GDPR/PIPL）
    - 数据风险热力图
    - 加密覆盖率 / 访问风险 / Top 风险 / 实时 DLP 告警滚动
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .data_discovery_phase import get_data_discovery_phase
from .data_classification_phase import get_data_classification_phase
from .data_asset_phase import get_data_asset_phase
from .dlp_phase import get_dlp_phase
from .privacy_compliance_phase import get_privacy_compliance_phase
from .encryption_key_phase import get_encryption_key_phase
from .access_audit_phase import get_access_audit_phase
from .risk_rating_phase import get_risk_rating_phase


class DataSecurityDashboard:
    """大屏聚合器。"""

    def __init__(self) -> None:
        self.disc = get_data_discovery_phase()
        self.cls = get_data_classification_phase()
        self.asset = get_data_asset_phase()
        self.dlp = get_dlp_phase()
        self.priv = get_privacy_compliance_phase()
        self.enc = get_encryption_key_phase()
        self.acc = get_access_audit_phase()
        self.risk = get_risk_rating_phase()

    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        dlp_s = self.dlp.stats()
        enc_s = self.enc.risk_summary()
        acc_s = self.acc.stats()
        comp_s = self.priv.summary()
        # 分类分级：基于发现结果自动打一次标
        all_hits: List[Dict[str, Any]] = []
        for s in self.disc.list_sources():
            all_hits.extend(s.get("sensitive_hits", []))
        cls_snapshot = self.cls.classify_batch(all_hits) if all_hits \
            else {"by_level": {}}
        # 综合一次风险打分
        risk = self.risk.compute(
            classification=cls_snapshot,
            dlp=dlp_s, compliance=comp_s,
            encryption=enc_s, access=acc_s,
        )
        return {
            "sensitive_distribution": {
                "by_type": self._sensitive_by_type(),
                "by_level": cls_snapshot.get("by_level", {}),
            },
            "dlp": dlp_s,
            "compliance": {
                "framework_scores": comp_s["framework_scores"],
                "overall_score": comp_s["overall_score"],
                "total_items": comp_s["total_items"],
            },
            "encryption": enc_s,
            "access": acc_s,
            "risk": risk,
            "top_risks": risk.get("top_risks", []),
            "maturity": risk.get("maturity"),
        }

    # ------------------------------------------------------------------ #
    def _sensitive_by_type(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for s in self.disc.list_sources():
            for h in s.get("sensitive_hits", []):
                t = h.get("data_type", "unknown")
                out[t] = out.get(t, 0) + 1
        return out

    # ------------------------------------------------------------------ #
    def dlp_alerts_stream(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self.dlp.list_alerts(limit=limit)

    # ------------------------------------------------------------------ #
    def risk_heatmap(self) -> List[Dict[str, Any]]:
        """数据风险热力图：按数据源 x 风险维度。"""
        rows = []
        sources = [s["name"] for s in self.disc.list_sources()] or \
                  ["内置模拟数据源"]
        dims = ["泄露", "合规", "加密", "访问"]
        for src in sources[:6]:
            for d in dims:
                rows.append({
                    "source": src, "dim": d,
                    "value": (hash(src + d) % 60) + 20,
                })
        return rows

    # ------------------------------------------------------------------ #
    def dlp_trend(self) -> Dict[str, List[Dict[str, Any]]]:
        """DLP 告警趋势（演示：24h/7d/30d 三桶）。"""
        import random
        rnd = random.Random(42)
        def series(n: int):
            return [{"x": i, "y": rnd.randint(0, 30)} for i in range(n)]
        return {"h24": series(24), "d7": series(7), "d30": series(30)}


_default_dash: Optional[DataSecurityDashboard] = None


def get_dashboard() -> DataSecurityDashboard:
    global _default_dash
    if _default_dash is None:
        _default_dash = DataSecurityDashboard()
    return _default_dash


__all__ = ["DataSecurityDashboard", "get_dashboard"]
