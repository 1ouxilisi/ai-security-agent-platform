#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_training_deep/competency_assessment.py — 能力评估深度。

覆盖六大子域：
    1. 能力模型：技能维度/等级定义/角色映射/能力图谱
    2. 能力评估：测评工具/自评/他评/考试成绩/综合评估
    3. 能力差距分析：目标vs现状/差距识别/优先级排序
    4. 能力发展：发展计划/学习推荐/导师匹配/实践项目
    5. 能力认证：能力徽章/等级晋升/有效期/复审
    6. 能力报告：个人报告/团队报告/趋势分析/可视化数据
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
SKILL_DOMAINS: Dict[str, str] = {
    "web_hacking": "Web渗透", "network_defense": "网络防御",
    "system_admin": "系统运维", "coding": "安全编码",
    "incident_response": "应急响应", "threat_hunting": "威胁狩猎",
    "compliance": "合规治理", "cloud_security": "云安全",
    "cryptography": "密码学", "forensics": "数字取证",
}

SKILL_LEVELS: Dict[str, str] = {
    "0": "未接触", "1": "了解", "2": "基础", "3": "熟练", "4": "精通", "5": "专家",
}

ROLE_COMPETENCY: Dict[str, Dict[str, int]] = {
    "security_analyst": {"web_hacking": 2, "network_defense": 3, "incident_response": 3,
                         "threat_hunting": 2, "compliance": 2},
    "pentester": {"web_hacking": 4, "network_defense": 2, "coding": 3,
                  "cryptography": 2, "system_admin": 3},
    "soc_manager": {"network_defense": 3, "incident_response": 4,
                    "threat_hunting": 3, "compliance": 4},
    "security_engineer": {"coding": 4, "cloud_security": 3,
                          "system_admin": 3, "compliance": 2},
}


# --------------------------------------------------------------------------- #
# 能力模型
# --------------------------------------------------------------------------- #
class CompetencyModel:
    """能力模型：技能维度/等级/角色映射。"""

    def __init__(self) -> None:
        self.model_version = "2.0"
        self.skill_domains = SKILL_DOMAINS.copy()
        self.skill_levels = SKILL_LEVELS.copy()
        self.role_requirements = ROLE_COMPETENCY.copy()

    def get_skill_tree(self) -> Dict[str, Any]:
        return {
            "version": self.model_version,
            "domains": self.skill_domains,
            "levels": self.skill_levels,
            "total_skills": len(self.skill_domains),
        }

    def get_role_requirements(self, role: str) -> Optional[Dict[str, int]]:
        return self.role_requirements.get(role)

    def list_roles(self) -> List[str]:
        return list(self.role_requirements.keys())


# --------------------------------------------------------------------------- #
# 能力评估
# --------------------------------------------------------------------------- #
class CompetencyAssessor:
    """能力评估：多维度评估/自评/他评/考试成绩综合。"""

    def __init__(self, model: CompetencyModel) -> None:
        self.model = model
        self.assessments: Dict[str, Dict[str, Any]] = {}
        self.user_skills: Dict[str, Dict[str, int]] = {}

    def self_assess(self, user: str, skills: Dict[str, int]) -> Dict[str, Any]:
        aid = f"assess_{uuid.uuid4().hex[:8]}"
        # clamp values
        clamped = {k: max(0, min(5, int(v))) for k, v in skills.items()}
        self.user_skills[user] = clamped
        assessment = {
            "id": aid, "user": user, "type": "self",
            "skills": clamped,
            "overall_level": round(sum(clamped.values()) / max(1, len(clamped)), 1),
            "assessed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.assessments[aid] = assessment
        return assessment

    def assess_from_exam(self, user: str, domain: str, score: float) -> Optional[Dict[str, Any]]:
        if domain not in self.model.skill_domains:
            return None
        # convert score (0-100) to level (0-5)
        level = round(score / 20)
        level = max(0, min(5, level))
        if user not in self.user_skills:
            self.user_skills[user] = {}
        # take max of existing and new
        old = self.user_skills[user].get(domain, 0)
        self.user_skills[user][domain] = max(old, level)
        return {
            "user": user, "domain": domain, "exam_score": score,
            "mapped_level": level, "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def get_user_skills(self, user: str) -> Dict[str, int]:
        return self.user_skills.get(user, {})

    def list_assessments(self, user: str = "") -> List[Dict[str, Any]]:
        results = list(self.assessments.values())
        if user:
            results = [a for a in results if a["user"] == user]
        return results


# --------------------------------------------------------------------------- #
# 能力差距分析
# --------------------------------------------------------------------------- #
class GapAnalyzer:
    """能力差距分析：目标vs现状/优先级。"""

    def __init__(self, model: CompetencyModel, assessor: CompetencyAssessor) -> None:
        self.model = model
        self.assessor = assessor

    def analyze_gap(self, user: str, target_role: str) -> Optional[Dict[str, Any]]:
        requirements = self.model.get_role_requirements(target_role)
        if not requirements:
            return None
        current = self.assessor.get_user_skills(user)
        gaps = []
        total_gap = 0
        for skill, required_level in requirements.items():
            current_level = current.get(skill, 0)
            gap = required_level - current_level
            if gap > 0:
                gaps.append({
                    "skill": skill,
                    "skill_name": self.model.skill_domains.get(skill, skill),
                    "current_level": current_level,
                    "required_level": required_level,
                    "gap": gap,
                    "priority": "high" if gap >= 2 else "medium" if gap == 1 else "low",
                })
                total_gap += gap
        gaps.sort(key=lambda x: x["gap"], reverse=True)
        return {
            "user": user, "target_role": target_role,
            "total_gap_points": total_gap,
            "gap_count": len(gaps),
            "gaps": gaps,
            "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": f"需要提升{len(gaps)}项技能，共{total_gap}个等级点",
        }


# --------------------------------------------------------------------------- #
# 能力发展
# --------------------------------------------------------------------------- #
class CompetencyDevelopment:
    """能力发展：发展计划/学习推荐。"""

    def __init__(self, model: CompetencyModel, assessor: CompetencyAssessor) -> None:
        self.model = model
        self.assessor = assessor
        self.development_plans: Dict[str, Dict[str, Any]] = {}

    def create_plan(self, user: str, gaps: List[Dict[str, Any]],
                     timeline_weeks: int = 12) -> Dict[str, Any]:
        pid = f"devplan_{uuid.uuid4().hex[:8]}"
        plan_items = []
        for g in gaps:
            plan_items.append({
                "skill": g["skill"],
                "target_level": g["required_level"],
                "current_level": g["current_level"],
                "actions": [
                    f"完成{self.model.skill_domains.get(g['skill'], g['skill'])}相关基础课程",
                    f"参与{self.model.skill_domains.get(g['skill'], g['skill'])}实战实验",
                    f"通过{self.model.skill_domains.get(g['skill'], g['skill'])}专项测评",
                ],
                "priority": g["priority"],
            })
        plan = {
            "id": pid, "user": user,
            "timeline_weeks": timeline_weeks,
            "items": plan_items,
            "status": "active",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.development_plans[pid] = plan
        return plan

    def get_plan(self, plan_id: str) -> Optional[Dict[str, Any]]:
        return self.development_plans.get(plan_id)

    def list_plans(self, user: str = "") -> List[Dict[str, Any]]:
        results = list(self.development_plans.values())
        if user:
            results = [p for p in results if p["user"] == user]
        return results


# --------------------------------------------------------------------------- #
# 能力认证（徽章）
# --------------------------------------------------------------------------- #
class CompetencyBadge:
    """能力徽章/等级晋升。"""

    def __init__(self, model: CompetencyModel) -> None:
        self.model = model
        self.badges: Dict[str, Dict[str, Any]] = {}
        self.user_badges: Dict[str, List[str]] = {}

    def award_badge(self, user: str, skill: str, level: int) -> Optional[Dict[str, Any]]:
        if skill not in self.model.skill_domains or level < 1 or level > 5:
            return None
        bid = f"badge_{uuid.uuid4().hex[:8]}"
        badge = {
            "id": bid, "user": user, "skill": skill,
            "skill_name": self.model.skill_domains[skill],
            "level": level, "level_name": self.model.skill_levels[str(level)],
            "awarded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "expires_at": time.strftime("%Y-%m-%d", time.localtime(time.time() + 365 * 86400)),
        }
        self.badges[bid] = badge
        self.user_badges.setdefault(user, []).append(bid)
        return badge

    def get_user_badges(self, user: str) -> List[Dict[str, Any]]:
        ids = self.user_badges.get(user, [])
        return [self.badges[bid] for bid in ids if bid in self.badges]


# --------------------------------------------------------------------------- #
# 能力报告
# --------------------------------------------------------------------------- #
class CompetencyReport:
    """能力报告：个人/团队/趋势。"""

    def __init__(self, model: CompetencyModel, assessor: CompetencyAssessor) -> None:
        self.model = model
        self.assessor = assessor

    def personal_report(self, user: str) -> Dict[str, Any]:
        skills = self.assessor.get_user_skills(user)
        avg_level = round(sum(skills.values()) / max(1, len(skills)), 1) if skills else 0
        strongest = max(skills.items(), key=lambda x: x[1]) if skills else ("无", 0)
        weakest = min(skills.items(), key=lambda x: x[1]) if skills else ("无", 0)
        return {
            "user": user,
            "report_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "overall_avg_level": avg_level,
            "skills_assessed": len(skills),
            "skill_details": [
                {"skill": s, "name": self.model.skill_domains.get(s, s), "level": lv}
                for s, lv in sorted(skills.items(), key=lambda x: x[1], reverse=True)
            ],
            "strongest_skill": {"name": self.model.skill_domains.get(strongest[0], strongest[0]), "level": strongest[1]} if strongest[0] != "无" else None,
            "weakest_skill": {"name": self.model.skill_domains.get(weakest[0], weakest[0]), "level": weakest[1]} if weakest[0] != "无" else None,
        }

    def team_report(self, users: List[str]) -> Dict[str, Any]:
        team_skills: Dict[str, List[int]] = {s: [] for s in self.model.skill_domains}
        for user in users:
            skills = self.assessor.get_user_skills(user)
            for s in self.model.skill_domains:
                if s in skills:
                    team_skills[s].append(skills[s])
        averages = {}
        for s, levels in team_skills.items():
            averages[s] = round(sum(levels) / max(1, len(levels)), 1) if levels else 0
        return {
            "team_size": len(users),
            "report_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "skill_averages": averages,
            "team_strengths": sorted(averages.items(), key=lambda x: x[1], reverse=True)[:3],
            "team_gaps": sorted(averages.items(), key=lambda x: x[1])[:3],
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_model: Optional[CompetencyModel] = None
_assessor: Optional[CompetencyAssessor] = None
_gap_analyzer: Optional[GapAnalyzer] = None
_dev: Optional[CompetencyDevelopment] = None
_badge: Optional[CompetencyBadge] = None
_report: Optional[CompetencyReport] = None


def get_competency_model() -> CompetencyModel:
    global _model
    if _model is None:
        _model = CompetencyModel()
    return _model


def get_assessor() -> CompetencyAssessor:
    global _assessor
    if _assessor is None:
        _assessor = CompetencyAssessor(get_competency_model())
    return _assessor


def get_gap_analyzer() -> GapAnalyzer:
    global _gap_analyzer
    if _gap_analyzer is None:
        _gap_analyzer = GapAnalyzer(get_competency_model(), get_assessor())
    return _gap_analyzer


def get_development() -> CompetencyDevelopment:
    global _dev
    if _dev is None:
        _dev = CompetencyDevelopment(get_competency_model(), get_assessor())
    return _dev


def get_badge() -> CompetencyBadge:
    global _badge
    if _badge is None:
        _badge = CompetencyBadge(get_competency_model())
    return _badge


def get_report() -> CompetencyReport:
    global _report
    if _report is None:
        _report = CompetencyReport(get_competency_model(), get_assessor())
    return _report
