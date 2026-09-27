#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_metrics_deep/maturity_assessment.py — 安全成熟度评估。

能力：
    1. 成熟度模型：CMMI 安全成熟度 / NIST CSF 成熟度 / ISO27001 成熟度 / 等保成熟度 / 自定义；
       5 级模型：初始级(1) / 可重复级(2) / 已定义级(3) / 已管理级(4) / 优化级(5)。
    2. 成熟度评估：控制域评估 / 控制项评估 / 证据收集 / 评分计算 / 等级确定 / 差距分析。
    3. 成熟度路线图：当前/目标/差距/改进计划/优先级/里程碑/时间线/资源需求。
    4. 成熟度趋势：历史评估 / 趋势分析 / 进步速度 / 领域对比 / 行业对比 / 目标达成率。
    5. 成熟度报告：总览/领域详情/控制项详情/证据/差距/建议/路线图/趋势。
    6. 成熟度基准：行业/规模/地区/同行/最佳实践基准与对比。

全部内存字典模拟；评分与等级判定为真实公式计算。
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 成熟度等级与模型定义
# --------------------------------------------------------------------------- #
MATURITY_LEVELS: List[Dict[str, Any]] = [
    {"level": 1, "name": "初始级", "en": "Initial",
     "desc": "过程无序、临时应对，成功依赖个人英雄主义，结果不可预测。",
     "score_range": (0, 20)},
    {"level": 2, "name": "可重复级", "en": "Repeatable",
     "desc": "已建立基本项目管理与过程跟踪，可重复以往类似工作的成功。",
     "score_range": (20, 40)},
    {"level": 3, "name": "已定义级", "en": "Defined",
     "desc": "过程已文档化、标准化，全组织统一执行标准安全过程。",
     "score_range": (40, 60)},
    {"level": 4, "name": "已管理级", "en": "Managed",
     "desc": "过程已被量化度量与统计控制，可预测绩效与质量。",
     "score_range": (60, 80)},
    {"level": 5, "name": "优化级", "en": "Optimizing",
     "desc": "持续过程改进与创新驱动，主动优化与缺陷预防。",
     "score_range": (80, 100)},
]

MATURITY_MODELS: Dict[str, Dict[str, Any]] = {
    "cmmi": {
        "name": "CMMI 安全成熟度",
        "desc": "基于 CMMI 过程域的安全能力成熟度模型。",
        "domains": ["安全策略治理", "风险管理", "安全工程", "安全验证", "过程改进"],
    },
    "nist_csf": {
        "name": "NIST CSF 成熟度",
        "desc": "基于 NIST 网络安全框架五大职能的成熟度评估。",
        "domains": ["识别 Identify", "保护 Protect", "检测 Detect", "响应 Respond", "恢复 Recover"],
    },
    "iso27001": {
        "name": "ISO27001 成熟度",
        "desc": "基于 ISO/IEC 27001 控制域的信息安全管理成熟度。",
        "domains": ["组织控制", "人员控制", "物理控制", "技术控制", "合规与审计"],
    },
    "djcp": {
        "name": "等保成熟度",
        "desc": "基于网络安全等级保护 2.0 控制要求的成熟度。",
        "domains": ["安全物理环境", "安全通信网络", "安全区域边界",
                    "安全计算环境", "安全管理中心", "安全管理制度",
                    "安全管理机构", "安全管理人员", "安全建设管理", "安全运维管理"],
    },
    "custom": {
        "name": "自定义成熟度模型",
        "desc": "由用户自定义控制域与控制项的成熟度模型。",
        "domains": ["战略与治理", "风险管理", "运营安全", "合规审计", "人员文化"],
    },
}


def _stable_int(seed: str, modulo: int = 100) -> int:
    """由字符串生成稳定伪随机整数（0..modulo-1），保证同输入同输出。"""
    h = hashlib.md5(seed.encode("utf-8")).hexdigest()
    return int(h[:8], 16) % modulo


def _level_from_score(score: float) -> Dict[str, Any]:
    for lv in MATURITY_LEVELS:
        lo, hi = lv["score_range"]
        if lo <= score < hi:
            return lv
    return MATURITY_LEVELS[-1]


# --------------------------------------------------------------------------- #
# 控制项库（按模型预置）
# --------------------------------------------------------------------------- #
def _build_controls() -> Dict[str, List[Dict[str, Any]]]:
    """为每个模型的控制域预置控制项。每个控制项：id/name/desc/weight。"""
    controls: Dict[str, List[Dict[str, Any]]] = {}
    for model_key, model in MATURITY_MODELS.items():
        items: List[Dict[str, Any]] = []
        idx = 1
        for dom in model["domains"]:
            for j in range(1, 4):  # 每域 3 个控制项
                cid = f"{model_key}-{idx:03d}"
                items.append({
                    "id": cid,
                    "domain": dom,
                    "name": f"{dom} - 控制项{j}",
                    "desc": f"{model['name']} 下「{dom}」域第 {j} 个控制要求。",
                    "weight": round(0.2 + (_stable_int(cid, 30) / 100.0), 2),
                })
                idx += 1
        controls[model_key] = items
    return controls


CONTROL_ITEMS: Dict[str, List[Dict[str, Any]]] = _build_controls()


# --------------------------------------------------------------------------- #
# 行业/规模/地区基准
# --------------------------------------------------------------------------- #
INDUSTRY_BENCHMARKS: Dict[str, Dict[str, float]] = {
    "金融": {"avg_score": 78.0, "avg_level": 4.0, "top_quartile": 88.0},
    "政务": {"avg_score": 72.0, "avg_level": 3.5, "top_quartile": 84.0},
    "互联网": {"avg_score": 68.0, "avg_level": 3.2, "top_quartile": 82.0},
    "制造": {"avg_score": 55.0, "avg_level": 2.6, "top_quartile": 72.0},
    "医疗": {"avg_score": 60.0, "avg_level": 2.9, "top_quartile": 76.0},
    "教育": {"avg_score": 48.0, "avg_level": 2.2, "top_quartile": 66.0},
}

SCALE_BENCHMARKS: Dict[str, Dict[str, float]] = {
    "大型企业(1000+)": {"avg_score": 74.0, "avg_level": 3.8},
    "中型企业(100-1000)": {"avg_score": 62.0, "avg_level": 3.0},
    "小型企业(10-100)": {"avg_score": 48.0, "avg_level": 2.2},
    "小微企业(<10)": {"avg_score": 35.0, "avg_level": 1.6},
}

REGION_BENCHMARKS: Dict[str, Dict[str, float]] = {
    "华东": {"avg_score": 66.0, "avg_level": 3.1},
    "华北": {"avg_score": 69.0, "avg_level": 3.3},
    "华南": {"avg_score": 64.0, "avg_level": 3.0},
    "西南": {"avg_score": 55.0, "avg_level": 2.6},
    "东北": {"avg_score": 50.0, "avg_level": 2.3},
}


# --------------------------------------------------------------------------- #
# 成熟度评估器
# --------------------------------------------------------------------------- #
class MaturityAssessor:
    def __init__(self) -> None:
        self.assessments: Dict[str, Dict[str, Any]] = {}
        self._seq = 0

    # -- 评估 -- #
    def create_assessment(self, model_key: str = "nist_csf",
                          org_name: str = "默认组织",
                          scope: str = "全组织",
                          assessor: str = "安全团队",
                          evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        model_key = model_key if model_key in MATURITY_MODELS else "nist_csf"
        aid = f"MA-{int(time.time())}-{_stable_int(org_name + str(time.time_ns()), 9999)}"
        evidence = evidence or {}
        # 逐控制项评分：以组织名+控制项id 生成稳定基础分，叠加证据调整
        item_scores: List[Dict[str, Any]] = []
        for ctl in CONTROL_ITEMS[model_key]:
            base = 15 + _stable_int(ctl["id"] + org_name, 75)  # 15..90
            ev = evidence.get(ctl["id"])
            if isinstance(ev, (int, float)):
                raw = float(ev)
            elif ev == "fully_implemented":
                raw = base + 15
            elif ev == "partially_implemented":
                raw = base + 5
            elif ev == "not_implemented":
                raw = max(5, base - 25)
            else:
                raw = base
            raw = max(0.0, min(100.0, raw))
            level = _level_from_score(raw)["level"]
            item_scores.append({
                "control_id": ctl["id"],
                "domain": ctl["domain"],
                "name": ctl["name"],
                "weight": ctl["weight"],
                "score": round(raw, 1),
                "level": level,
                "evidence": ev or "未提供证据",
            })
        # 域聚合
        domains: Dict[str, Dict[str, Any]] = {}
        for it in item_scores:
            d = domains.setdefault(it["domain"],
                                  {"domain": it["domain"], "weighted_sum": 0.0,
                                   "weight_sum": 0.0, "items": 0})
            d["weighted_sum"] += it["score"] * it["weight"]
            d["weight_sum"] += it["weight"]
            d["items"] += 1
        domain_scores: List[Dict[str, Any]] = []
        for d in domains.values():
            ds = d["weighted_sum"] / d["weight_sum"] if d["weight_sum"] else 0.0
            lv = _level_from_score(ds)
            domain_scores.append({
                "domain": d["domain"],
                "score": round(ds, 1),
                "level": lv["level"],
                "level_name": lv["name"],
                "item_count": d["items"],
            })
        total_w = sum(d["weighted_sum"] for d in domains.values())
        total_wt = sum(d["weight_sum"] for d in domains.values())
        overall = total_w / total_wt if total_wt else 0.0
        overall_lv = _level_from_score(overall)

        rec = {
            "assessment_id": aid,
            "model": model_key,
            "model_name": MATURITY_MODELS[model_key]["name"],
            "org_name": org_name,
            "scope": scope,
            "assessor": assessor,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "overall_score": round(overall, 1),
            "overall_level": overall_lv["level"],
            "overall_level_name": overall_lv["name"],
            "domains": domain_scores,
            "items": item_scores,
        }
        self.assessments[aid] = rec
        return rec

    def list_assessments(self) -> List[Dict[str, Any]]:
        return [{"assessment_id": a["assessment_id"], "model": a["model"],
                 "org_name": a["org_name"], "overall_score": a["overall_score"],
                 "overall_level": a["overall_level"],
                 "overall_level_name": a["overall_level_name"],
                 "created_at": a["created_at"]}
                for a in self.assessments.values()]

    def get_assessment(self, aid: str) -> Optional[Dict[str, Any]]:
        return self.assessments.get(aid)

    # -- 差距分析 -- #
    def gap_analysis(self, aid: str, target_level: int = 4) -> Dict[str, Any]:
        rec = self.assessments.get(aid)
        if not rec:
            return {}
        target_level = max(1, min(5, int(target_level)))
        gaps = []
        for d in rec["domains"]:
            deficit = (target_level - d["level"]) * 12.0
            if d["level"] < target_level:
                gaps.append({
                    "domain": d["domain"],
                    "current_level": d["level"],
                    "target_level": target_level,
                    "current_score": d["score"],
                    "gap_score": round(deficit, 1),
                    "priority": "高" if d["level"] <= 2 else ("中" if d["level"] == 3 else "低"),
                    "suggestion": f"在「{d['domain']}」域从 L{d['level']} 提升到 L{target_level}，"
                                  f"需补充过程文档、量化度量与自动化控制。",
                })
        gaps.sort(key=lambda x: x["gap_score"], reverse=True)
        return {
            "assessment_id": aid,
            "current_level": rec["overall_level"],
            "target_level": target_level,
            "gap_domains": gaps,
            "summary": f"当前 L{rec['overall_level']}，目标 L{target_level}，"
                       f"共 {len(gaps)} 个领域存在差距。",
        }

    # -- 路线图 -- #
    def roadmap(self, aid: str, target_level: int = 4,
                horizon_months: int = 18) -> Dict[str, Any]:
        gap = self.gap_analysis(aid, target_level)
        if not gap:
            return {}
        milestones = []
        items = gap["gap_domains"]
        n = len(items) or 1
        per = max(3, horizon_months // (n if n else 1))
        for i, g in enumerate(items):
            milestones.append({
                "milestone": f"M{i + 1} - 提升 {g['domain']}",
                "month": (i + 1) * per,
                "target_level": g["target_level"],
                "actions": [f"梳理并文档化{g['domain']}过程",
                            f"建立{g['domain']}量化度量指标",
                            f"试点自动化{g['domain']}控制"],
                "owner": "安全负责人",
                "resource_estimate": f"约 {g['gap_score'] * 2:.0f} 人时",
                "priority": g["priority"],
            })
        return {
            "assessment_id": aid,
            "current_level": gap["current_level"],
            "target_level": target_level,
            "horizon_months": horizon_months,
            "phases": [
                {"phase": "近期(0-6月)", "focus": "补齐差距最大的高优先级控制域，建立基础过程。"},
                {"phase": "中期(6-12月)", "focus": "标准化与量化度量，达成 L3/L4。"},
                {"phase": "远期(12-18月)", "focus": "持续优化与自动化，逼近 L5。"},
            ],
            "milestones": milestones,
            "resource_total": f"约 {sum(milestone['month'] for milestone in milestones) * 120} 人时",
        }

    # -- 趋势 -- #
    def trend(self, model_key: str = "nist_csf",
              periods: int = 6) -> Dict[str, Any]:
        model_key = model_key if model_key in MATURITY_MODELS else "nist_csf"
        history = []
        base = 40 + _stable_int(model_key, 30)
        for i in range(periods):
            score = min(95.0, base + i * (3 + _stable_int(model_key + str(i), 4) * 0.6))
            lv = _level_from_score(score)
            history.append({
                "period": f"M{i + 1}",
                "score": round(score, 1),
                "level": lv["level"],
                "level_name": lv["name"],
            })
        if len(history) >= 2:
            speed = round((history[-1]["score"] - history[0]["score"]) / max(1, len(history) - 1), 1)
        else:
            speed = 0.0
        return {
            "model": model_key,
            "history": history,
            "progress_speed_per_period": speed,
            "goal_attainment_rate": round(min(1.0, history[-1]["score"] / 90.0), 2),
            "domains_comparison": [
                {"domain": d, "score": round(35 + _stable_int(model_key + d, 55), 1)}
                for d in MATURITY_MODELS[model_key]["domains"]
            ],
        }

    # -- 报告 -- #
    def report(self, aid: str) -> Dict[str, Any]:
        rec = self.assessments.get(aid)
        if not rec:
            return {}
        gap = self.gap_analysis(aid, target_level=4)
        return {
            "report_id": f"RPT-{aid}",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "overview": {
                "org": rec["org_name"], "model": rec["model_name"],
                "score": rec["overall_score"], "level": rec["overall_level_name"],
            },
            "domains": rec["domains"],
            "weakest_domains": sorted(rec["domains"], key=lambda x: x["score"])[:3],
            "strongest_domains": sorted(rec["domains"], key=lambda x: -x["score"])[:3],
            "gaps": gap,
            "recommendations": [
                "优先补齐低成熟度控制域的过程文档与量化度量。",
                "将高频重复的安全操作纳入自动化，提升效率与一致性。",
                "建立季度复评机制，跟踪成熟度提升趋势。",
            ],
        }

    # -- 基准对比 -- #
    def benchmark_compare(self, score: float,
                          industry: str = "互联网",
                          scale: str = "中型企业(100-1000)",
                          region: str = "华东") -> Dict[str, Any]:
        ind = INDUSTRY_BENCHMARKS.get(industry, INDUSTRY_BENCHMARKS["互联网"])
        sca = SCALE_BENCHMARKS.get(scale, SCALE_BENCHMARKS["中型企业(100-1000)"])
        reg = REGION_BENCHMARKS.get(region, REGION_BENCHMARKS["华东"])
        return {
            "your_score": score,
            "industry": {"label": industry, **ind,
                         "vs_industry": round(score - ind["avg_score"], 1)},
            "scale": {"label": scale, **sca,
                      "vs_scale": round(score - sca["avg_score"], 1)},
            "region": {"label": region, **reg,
                       "vs_region": round(score - reg["avg_score"], 1)},
            "peer_percentile": max(1, min(99, int((score - 30) * 1.2))),
            "best_practice_target": 90.0,
        }


_assessor: Optional[MaturityAssessor] = None


def get_maturity_assessor() -> MaturityAssessor:
    global _assessor
    if _assessor is None:
        _assessor = MaturityAssessor()
    return _assessor
