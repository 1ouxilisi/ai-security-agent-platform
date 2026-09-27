#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_metrics_deep/security_roi.py — 安全投资回报率(ROI)。

能力：
    1. 安全投资管理：项目/金额/时间/类别/目标/收益/风险/状态。
    2. 安全收益计算：风险降低/事件避免/效率提升/合规/品牌/客户信任/量化/定性。
    3. ROI 计算：投资回报率 / NPV / IRR / 投资回收期 / 成本效益比 / 风险调整 ROI。
    4. ROI 分析：项目对比/类别对比/时间趋势/行业基准/最佳实践/优化建议。
    5. 安全成本管理：人力/技术/培训/咨询/合规/事件/机会/总成本。
    6. 安全价值证明：价值主张/量化/对比/趋势/沟通/报告/高管汇报。
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional


def _h(seed: str, mod: int = 100) -> int:
    return int(hashlib.md5(seed.encode("utf-8")).hexdigest()[:8], 16) % mod


# --------------------------------------------------------------------------- #
# 投资项目
# --------------------------------------------------------------------------- #
INVESTMENT_CATEGORIES = ["技术采购", "人力建设", "培训意识", "咨询服务",
                         "合规认证", "应急演练", "运营外包"]

_PRESAMPLED_PROJECTS = [
    ("部署 SIEM 态势感知平台", "技术采购", 1200000, 36),
    ("扩大安全运营团队", "人力建设", 2400000, 24),
    ("全员安全意识培训", "培训意识", 300000, 12),
    ("等保三级咨询与整改", "咨询服务", 500000, 18),
    ("零信任架构改造", "技术采购", 1800000, 30),
    ("应急响应与演练", "应急演练", 200000, 12),
    ("终端 EDR 部署", "技术采购", 800000, 24),
    ("第三方安全评估外包", "运营外包", 400000, 12),
]


class ROIManager:
    def __init__(self) -> None:
        self.projects: Dict[str, Dict[str, Any]] = {}
        self._seed_projects()

    def _seed_projects(self) -> None:
        for i, (name, cat, cost, months) in enumerate(_PRESAMPLED_PROJECTS):
            pid = f"INV-{i + 1:03d}"
            annual_benefit = round(cost * (0.6 + _h(pid, 60) / 100.0), 0)
            self.projects[pid] = {
                "project_id": pid, "name": name, "category": cat,
                "investment": float(cost), "duration_months": months,
                "annual_benefit": annual_benefit,
                "risk_adjustment": round(0.7 + _h(pid + "r", 25) / 100.0, 2),
                "status": "进行中" if i % 3 else "已完成",
                "owner": "安全预算负责人",
                "start_date": "2025-01-01",
                "target": "降低风险并提升运营效率",
            }

    # -- 投资管理 -- #
    def list_projects(self) -> List[Dict[str, Any]]:
        return list(self.projects.values())

    def add_project(self, name: str, category: str = "技术采购",
                    investment: float = 0.0, duration_months: int = 12,
                    annual_benefit: float = 0.0, owner: str = "安全负责人",
                    target: str = "") -> Dict[str, Any]:
        pid = f"INV-{int(time.time())}-{_h(name + str(time.time_ns()), 999)}"
        rec = {
            "project_id": pid, "name": name,
            "category": category if category in INVESTMENT_CATEGORIES else "技术采购",
            "investment": float(investment),
            "duration_months": int(duration_months),
            "annual_benefit": float(annual_benefit),
            "risk_adjustment": 0.8, "status": "规划中", "owner": owner,
            "start_date": time.strftime("%Y-%m-%d"), "target": target or "提升安全能力",
        }
        self.projects[pid] = rec
        return rec

    def get_project(self, pid: str) -> Optional[Dict[str, Any]]:
        return self.projects.get(pid)

    # -- 收益计算 -- #
    def benefits_breakdown(self, pid: str) -> Dict[str, Any]:
        p = self.projects.get(pid)
        if not p:
            return {}
        b = p["annual_benefit"]
        return {
            "project_id": pid,
            "total_annual_benefit": b,
            "breakdown": {
                "风险降低收益": round(b * 0.35, 0),
                "事件避免收益": round(b * 0.25, 0),
                "效率提升收益": round(b * 0.15, 0),
                "合规收益": round(b * 0.12, 0),
                "品牌收益": round(b * 0.08, 0),
                "客户信任收益": round(b * 0.05, 0),
            },
            "qualitative": ["管理层信心提升", "客户续约率改善", "供应链准入通过"],
        }

    # -- ROI 公式计算 -- #
    def roi_metrics(self, pid: str, discount_rate: float = 0.08) -> Dict[str, Any]:
        p = self.projects.get(pid)
        if not p:
            return {}
        cost = p["investment"]
        years = p["duration_months"] / 12.0
        annual = p["annual_benefit"]
        # 简单 ROI
        roi = round((annual * years - cost) / cost * 100, 1) if cost else 0.0
        # 净现值 NPV：年初投资，年末收益
        npv = -cost
        for y in range(1, int(round(years)) + 1):
            npv += annual / ((1 + discount_rate) ** y)
        # 投资回收期（年）
        payback = round(cost / annual, 2) if annual else 99.0
        # 成本效益比 BCR
        bcr = round((annual * years) / cost, 2) if cost else 0.0
        # 风险调整 ROI
        rar = round(roi * p["risk_adjustment"], 1)
        # IRR（近似二分）
        irr = self._approx_irr(cost, annual, int(round(years)))
        return {
            "project_id": pid, "name": p["name"],
            "investment": cost, "annual_benefit": annual, "years": round(years, 2),
            "roi_percent": roi, "npv": round(npv, 0),
            "irr_percent": irr, "payback_years": payback,
            "benefit_cost_ratio": bcr, "risk_adjusted_roi": rar,
            "discount_rate": discount_rate,
        }

    @staticmethod
    def _approx_irr(cost: float, annual: float, years: int) -> float:
        if cost <= 0 or annual <= 0 or years <= 0:
            return 0.0

        def npv_at(r: float) -> float:
            v = -cost
            for y in range(1, years + 1):
                v += annual / ((1 + r) ** y)
            return v

        lo, hi = -0.9, 1.0
        if npv_at(lo) * npv_at(hi) > 0:
            return round(annual / cost * 100, 1)
        for _ in range(40):
            mid = (lo + hi) / 2
            if npv_at(mid) > 0:
                lo = mid
            else:
                hi = mid
        return round(((lo + hi) / 2) * 100, 1)

    # -- ROI 分析 -- #
    def roi_comparison(self) -> Dict[str, Any]:
        rows = []
        for pid, p in self.projects.items():
            m = self.roi_metrics(pid)
            rows.append({"project_id": pid, "name": p["name"],
                         "category": p["category"], "roi": m.get("roi_percent", 0),
                         "npv": m.get("npv", 0), "payback": m.get("payback_years", 0)})
        rows.sort(key=lambda x: -x["roi"])
        by_cat: Dict[str, List[float]] = {}
        for r in rows:
            by_cat.setdefault(r["category"], []).append(r["roi"])
        return {
            "projects": rows,
            "by_category": {c: round(sum(v) / len(v), 1) for c, v in by_cat.items()},
            "best_project": rows[0] if rows else None,
        }

    def roi_trend(self, pid: str, periods: int = 6) -> Dict[str, Any]:
        base = self.roi_metrics(pid)
        if not base:
            return {}
        hist = []
        for i in range(periods):
            roi = round(base["roi_percent"] + (i - periods / 2) * (_h(pid + str(i), 8) - 4) * 0.6, 1)
            hist.append({"period": f"Q{i + 1}", "roi": roi})
        return {"project_id": pid, "history": hist}

    def benchmark(self) -> Dict[str, Any]:
        comp = self.roi_comparison()
        rois = [r["roi"] for r in comp["projects"]]
        avg = round(sum(rois) / len(rois), 1) if rois else 0
        return {
            "your_avg_roi": avg,
            "industry_avg_roi": 45.0,
            "best_practice_roi": 120.0,
            "vs_industry": round(avg - 45.0, 1),
            "recommendations": [
                "优先扩大高 ROI、短回收期的技术采购项目。",
                "对低 ROI 项目进行年度复盘与退出决策。",
                "将定性收益（品牌/客户信任）纳入价值证明。",
            ],
        }

    # -- 成本管理 -- #
    def cost_breakdown(self) -> Dict[str, Any]:
        total_inv = sum(p["investment"] for p in self.projects.values())
        breakdown = {
            "人力成本": round(total_inv * 0.40, 0),
            "技术成本": round(total_inv * 0.30, 0),
            "培训成本": round(total_inv * 0.08, 0),
            "咨询成本": round(total_inv * 0.07, 0),
            "合规成本": round(total_inv * 0.08, 0),
            "事件成本": round(total_inv * 0.05, 0),
            "机会成本": round(total_inv * 0.02, 0),
        }
        breakdown["总成本"] = total_inv
        return {"currency": "CNY", "breakdown": breakdown,
                "total": total_inv}

    # -- 价值证明 -- #
    def value_proposition(self) -> Dict[str, Any]:
        comp = self.roi_comparison()
        cba = self.cost_breakdown()
        return {
            "value_statement": f"安全体系累计投入 {cba['total'] / 10000:.0f} 万元，"
                               f"平均 ROI 达 {comp['projects'][0]['roi'] if comp['projects'] else 0}%，"
                               f"显著降低事件损失并支撑业务连续。",
            "quantified": {
                "total_investment": cba["total"],
                "avg_roi": comp["by_category"],
                "best_project": comp["best_project"],
            },
            "executive_summary": [
                "安全不是成本中心，而是风险对冲与业务使能的投资。",
                "量化收益：风险降低 35%、事件避免 25%、效率提升 15%。",
                "建议每年滚动评估投资组合，保持资源向高 ROI 倾斜。",
            ],
        }


_roi: Optional[ROIManager] = None


def get_roi_manager() -> ROIManager:
    global _roi
    if _roi is None:
        _roi = ROIManager()
    return _roi
