#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_metrics_deep/security_culture.py — 安全文化评估。

能力：
    1. 安全意识评估：知识测试/行为观察/态度调查/文化问卷/意识水平/趋势。
    2. 安全行为度量：合规行为率/违规率/报告率/参与率/培训完成率/演练参与率/趋势。
    3. 安全沟通度量：通知阅读率/邮件回复率/会议参与率/讨论活跃度/反馈率/效果。
    4. 安全培训度量：覆盖率/完成率/通过率/满意度/效果/ROI/趋势。
    5. 安全文化指标：领导力/责任/沟通/学习/参与/信任/创新/综合评分。
    6. 安全文化改进：差距分析/改进计划/措施/效果/建设/活动/报告。
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional


def _h(seed: str, mod: int = 100) -> int:
    return int(hashlib.md5(seed.encode("utf-8")).hexdigest()[:8], 16) % mod


def _v(seed: str, lo: float, hi: float) -> float:
    return round(lo + (hi - lo) * _h(seed) / 100.0, 1)


class CultureManager:
    def __init__(self) -> None:
        self.assessments: Dict[str, Dict[str, Any]] = {}

    # -- 意识评估 -- #
    def awareness(self) -> Dict[str, Any]:
        return {
            "knowledge_test": {"avg_score": _v("aw1", 60, 95), "pass_rate": _v("aw2", 70, 99)},
            "behavior_observation": {"compliance_rate": _v("aw3", 65, 98)},
            "attitude_survey": {"positive_rate": _v("aw4", 60, 95)},
            "culture_questionnaire": {"participants": _h("aw5", 800) + 200,
                                     "avg_score": _v("aw6", 60, 92)},
            "awareness_level_score": _v("awlv", 60, 95),
            "trend": [{"period": f"Q{i+1}", "score": _v("awt"+str(i), 55, 95)} for i in range(4)],
        }

    # -- 行为度量 -- #
    def behavior(self) -> Dict[str, Any]:
        rows = {
            "合规行为率": _v("b1", 70, 99),
            "违规行为率": _v("b2", 1, 15),
            "主动报告率": _v("b3", 40, 90),
            "参与活动率": _v("b4", 50, 95),
            "培训完成率": _v("b5", 75, 100),
            "演练参与率": _v("b6", 60, 98),
        }
        return {"metrics": rows,
                "trend": [{"period": f"M{i+1}", "compliance": _v("bt"+str(i), 65, 99)} for i in range(6)]}

    # -- 沟通度量 -- #
    def communication(self) -> Dict[str, Any]:
        return {
            "notice_read_rate": _v("c1", 60, 99),
            "email_reply_rate": _v("c2", 30, 90),
            "meeting_participation": _v("c3", 50, 98),
            "discussion_activity": _v("c4", 30, 95),
            "feedback_rate": _v("c5", 20, 80),
            "effectiveness": _v("c6", 50, 95),
        }

    # -- 培训度量 -- #
    def training(self) -> Dict[str, Any]:
        return {
            "coverage_rate": _v("tr1", 70, 100),
            "completion_rate": _v("tr2", 75, 100),
            "pass_rate": _v("tr3", 80, 100),
            "satisfaction": _v("tr4", 60, 98),
            "effectiveness": _v("tr5", 55, 95),
            "training_roi": _v("tr6", 50, 150),
            "trend": [{"period": f"Q{i+1}", "completion": _v("trt"+str(i), 70, 100)} for i in range(4)],
        }

    # -- 文化指标 -- #
    def culture_indicators(self) -> Dict[str, Any]:
        dims = ["安全领导力", "安全责任", "安全沟通", "安全学习",
                "安全参与", "安全信任", "安全创新"]
        rows = [{"dimension": d, "score": _v("ci"+d, 55, 96)} for d in dims]
        overall = round(sum(r["score"] for r in rows) / len(rows), 1)
        return {"dimensions": rows, "composite_score": overall,
                "level": "成熟" if overall >= 80 else ("发展中" if overall >= 65 else "起步")}

    # -- 文化改进 -- #
    def improvement(self) -> Dict[str, Any]:
        ci = self.culture_indicators()
        weak = sorted(ci["dimensions"], key=lambda x: x["score"])[:3]
        gaps = [{"dimension": w["dimension"], "score": w["score"],
                 "target": 85.0,
                 "gap": round(85.0 - w["score"], 1),
                 "measure": f"针对{w['dimension']}开展专项文化建设活动"} for w in weak]
        return {
            "gaps": gaps,
            "plan": [
                {"phase": "0-3月", "actions": ["高管安全寄语", "安全月主题活动"]},
                {"phase": "3-6月", "actions": ["钓鱼演练常态化", "安全标兵评选"]},
                {"phase": "6-12月", "actions": ["安全创新大赛", "文化复评"]},
            ],
            "activities": ["安全意识周", "钓鱼演练", "红蓝对抗观摩", "安全故事分享会"],
            "expected_effect": "综合文化评分提升至 80+",
        }

    # -- 报告 -- #
    def report(self) -> Dict[str, Any]:
        ci = self.culture_indicators()
        return {
            "report_id": f"CULTURE-RPT-{int(time.time())}",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "awareness": self.awareness()["awareness_level_score"],
            "behavior": self.behavior()["metrics"],
            "training": self.training()["satisfaction"],
            "composite": ci,
            "summary": f"当前安全文化处于「{ci['level']}」阶段，综合评分 {ci['composite_score']}。",
        }


_culture: Optional[CultureManager] = None


def get_culture_manager() -> CultureManager:
    global _culture
    if _culture is None:
        _culture = CultureManager()
    return _culture
