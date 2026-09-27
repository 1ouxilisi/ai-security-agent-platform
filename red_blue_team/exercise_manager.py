# -*- coding: utf-8 -*-
"""
exercise_manager.py — 红蓝对抗管理（第24轮升级方向1）。

职责：
    1. 对抗项目管理（创建/配置/范围/时间/团队/规则/评分标准）
    2. 红队管理（成员/角色/任务/工具/目标/进度/成果）
    3. 蓝队管理（成员/角色/任务/监控/检测/响应/成果）
    4. 对抗过程记录（操作记录/时间线/攻击路径/防御动作/告警/事件/证据）
    5. 对抗评分（攻击评分/防御评分/综合评分/排名/奖项/证书）
    6. 对抗复盘（自动复盘/攻击路径分析/防御缺口/改进建议/知识沉淀）

全部内存字典模拟。
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from red_blue_team.attack_simulator import (
    ATTACK_TACTICS, ATTACK_TECHNIQUES, ATTACK_SCENARIOS,
    get_attack_simulator,
)
from red_blue_team.defense_validator import get_defense_validator


# ============================================================
# 1. 对抗项目管理
# ============================================================

EXERCISES: Dict[str, Dict[str, Any]] = {}


class ExerciseProject:
    """红蓝对抗项目管理。"""

    def create(self, name: str, scope: str, start: str, end: str,
               red_team_name: str, blue_team_name: str,
               rules_of_engagement: Optional[List[str]] = None,
               scoring_criteria: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        eid = f"exercise-{uuid.uuid4().hex[:8]}"
        exercise = {
            "exercise_id": eid,
            "name": name,
            "scope": scope,
            "start_time": start,
            "end_time": end,
            "red_team_name": red_team_name,
            "blue_team_name": blue_team_name,
            "rules_of_engagement": rules_of_engagement or [
                "禁止影响生产系统可用性",
                "禁止数据外泄（仅在隔离环境渗出）",
                "禁止使用破坏性载荷（勒索/擦除）",
                "所有操作需留有日志证据",
            ],
            "scoring_criteria": scoring_criteria or {
                "attack_success_weight": 0.4,
                "detection_rate_weight": 0.3,
                "response_time_weight": 0.2,
                "documentation_weight": 0.1,
            },
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "timeline": [],
            "evidence": [],
        }
        EXERCISES[eid] = exercise
        return exercise

    def get(self, exercise_id: str) -> Optional[Dict[str, Any]]:
        return EXERCISES.get(exercise_id)

    def list(self) -> List[Dict[str, Any]]:
        return list(EXERCISES.values())

    def control(self, exercise_id: str, action: str) -> Dict[str, Any]:
        """对抗控制：start / pause / resume / terminate。"""
        e = EXERCISES.get(exercise_id)
        if not e:
            raise ValueError(f"未知对抗项目: {exercise_id}")
        if action == "start":
            e["status"] = "in_progress"
        elif action == "pause":
            e["status"] = "paused"
        elif action == "resume":
            e["status"] = "in_progress"
        elif action == "terminate":
            e["status"] = "completed"
        e["last_action"] = action
        e["last_action_at"] = datetime.now().isoformat()
        return e


# ============================================================
# 2. 红队 / 蓝队管理
# ============================================================

class TeamManager:
    """红队与蓝队成员/任务管理。"""

    def __init__(self) -> None:
        self.teams: Dict[str, Dict[str, Any]] = {}

    def add_member(self, exercise_id: str, side: str, name: str,
                   role: str) -> Dict[str, Any]:
        key = f"{exercise_id}:{side}"
        self.teams.setdefault(key, {"red": [], "blue": []})
        member = {
            "member_id": f"mem-{uuid.uuid4().hex[:6]}",
            "name": name, "role": role,
            "tasks": [], "progress": 0, "results": [],
        }
        self.teams[key][side].append(member)
        return member

    def assign_task(self, exercise_id: str, side: str,
                    member_id: str, task: str, target: str) -> Dict[str, Any]:
        key = f"{exercise_id}:{side}"
        members = self.teams.get(key, {}).get(side, [])
        member = next((m for m in members if m["member_id"] == member_id), None)
        if not member:
            raise ValueError(f"未知成员: {member_id}")
        task_obj = {
            "task_id": f"task-{uuid.uuid4().hex[:6]}",
            "task": task, "target": target,
            "status": "assigned", "assigned_at": datetime.now().isoformat(),
        }
        member["tasks"].append(task_obj)
        return task_obj

    def get_team(self, exercise_id: str, side: str) -> Dict[str, Any]:
        key = f"{exercise_id}:{side}"
        return self.teams.get(key, {side: []})

    def record_result(self, exercise_id: str, side: str,
                      member_id: str, result: str, score: int) -> Dict[str, Any]:
        key = f"{exercise_id}:{side}"
        members = self.teams.get(key, {}).get(side, [])
        member = next((m for m in members if m["member_id"] == member_id), None)
        if not member:
            raise ValueError(f"未知成员: {member_id}")
        entry = {"result": result, "score": score,
                 "recorded_at": datetime.now().isoformat()}
        member["results"].append(entry)
        member["progress"] = min(100, member["progress"] + score)
        return entry


# ============================================================
# 3. 对抗过程记录
# ============================================================

class ProcessRecorder:
    """操作记录 / 时间线 / 攻击路径 / 防御动作 / 证据。"""

    def __init__(self) -> None:
        self.records: Dict[str, List[Dict[str, Any]]] = {}

    def log(self, exercise_id: str, side: str, action: str,
            detail: str, technique_id: Optional[str] = None) -> Dict[str, Any]:
        entry = {
            "time": datetime.now().isoformat(),
            "side": side, "action": action, "detail": detail,
            "technique_id": technique_id,
            "event_id": f"evt-{uuid.uuid4().hex[:8]}",
        }
        self.records.setdefault(exercise_id, []).append(entry)
        return entry

    def get_timeline(self, exercise_id: str) -> List[Dict[str, Any]]:
        return self.records.get(exercise_id, [])

    def attach_evidence(self, exercise_id: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        e = EXERCISES.get(exercise_id)
        if e:
            ev = {"evidence_id": f"ev-{uuid.uuid4().hex[:8]}",
                  "attached_at": datetime.now().isoformat(), **evidence}
            e["evidence"].append(ev)
            return ev
        raise ValueError(f"未知对抗项目: {exercise_id}")


# ============================================================
# 4. 对抗评分
# ============================================================

class ScoringEngine:
    """攻击评分 / 防御评分 / 综合评分 / 排名 / 奖项。"""

    def score_exercise(self, exercise_id: str,
                        attack_success_rate: float,
                        detection_rate: float,
                        response_time_min: float) -> Dict[str, Any]:
        e = EXERCISES.get(exercise_id)
        if not e:
            raise ValueError(f"未知对抗项目: {exercise_id}")

        criteria = e.get("scoring_criteria", {})
        attack_score = round(attack_success_rate * 100, 1)
        defense_score = round(detection_rate * 100, 1)
        response_score = round(max(0, 100 - response_time_min) * 0.5 + 50, 1)

        composite = round(
            attack_score * criteria.get("attack_success_weight", 0.4) +
            defense_score * criteria.get("detection_rate_weight", 0.3) +
            response_score * criteria.get("response_time_weight", 0.2) +
            90 * criteria.get("documentation_weight", 0.1), 1)

        # 奖项
        if composite >= 85:
            award = "卓越紫队协作奖"
        elif composite >= 70:
            award = "优秀对抗实践奖"
        elif composite >= 55:
            award = "合格对抗完成奖"
        else:
            award = "待提升（需复盘改进）"

        result = {
            "exercise_id": exercise_id,
            "attack_score": attack_score,
            "defense_score": defense_score,
            "response_score": response_score,
            "composite_score": composite,
            "award": award,
            "certificate_id": f"CERT-{exercise_id.upper()}-{uuid.uuid4().hex[:6].upper()}",
            "rankings": self._rank_teams(attack_score, defense_score),
        }
        e["score"] = result
        return result

    def _rank_teams(self, attack_score: float,
                     defense_score: float) -> List[Dict[str, Any]]:
        ranks = [
            {"rank": 1, "team": "红队", "score": attack_score,
             "verdict": "攻击有效" if attack_score >= 60 else "攻击被阻断"},
            {"rank": 2, "team": "蓝队", "score": defense_score,
             "verdict": "检测有效" if defense_score >= 60 else "检测存在盲区"},
        ]
        return ranks


# ============================================================
# 5. 对抗复盘
# ============================================================

class DebriefEngine:
    """自动复盘：攻击路径分析 / 防御缺口 / 改进建议 / 知识沉淀。"""

    def debrief(self, exercise_id: str,
                chain_run: Optional[Dict[str, Any]] = None,
                coverage: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        e = EXERCISES.get(exercise_id)
        if not e:
            raise ValueError(f"未知对抗项目: {exercise_id}")

        # 攻击路径分析
        attack_path: List[str] = []
        if chain_run:
            for s in chain_run.get("stage_results", []):
                if s.get("success"):
                    attack_path.append(
                        f"{s.get('technique_cn')}({s.get('technique_id')}) -> 成功")
                else:
                    attack_path.append(
                        f"{s.get('technique_cn')}({s.get('technique_id')}) -> 阻断")

        # 防御缺口
        gaps: List[str] = []
        if chain_run:
            failed = [s for s in chain_run.get("stage_results", []) if not s.get("success")]
            for f in failed:
                gaps.append(f"攻击 {f.get('technique_cn')} 未成功，"
                            f"需检查是否因防御阻断或技术失误")
        if coverage:
            gaps.append(f"整体检测覆盖率 {coverage.get('coverage_pct')}%，"
                        f"存在 {coverage.get('blind_spot_count')} 个盲区")

        # 改进建议
        improvements = [
            "基于本次攻击路径补齐盲区检测规则",
            "优化告警阈值降低误报",
            "缩短平均响应时间",
            "更新钓鱼培训素材",
        ]

        # 经验沉淀
        knowledge = {
            "key_findings": attack_path[:5] or ["本次对抗无成功攻击路径"],
            "lessons_learned": gaps[:5],
            "recommended_actions": improvements,
        }

        report = {
            "exercise_id": exercise_id,
            "exercise_name": e.get("name"),
            "debrief_time": datetime.now().isoformat(),
            "attack_path_analysis": attack_path,
            "defense_gaps": gaps,
            "improvement_suggestions": improvements,
            "knowledge_sedimentation": knowledge,
            "executive_summary": self._summary(attack_path, gaps),
        }
        e["debrief"] = report
        return report

    def _summary(self, path: List[str], gaps: List[str]) -> str:
        success_count = sum(1 for p in path if "成功" in p)
        return (f"本次对抗共 {len(path)} 个阶段，成功 {success_count} 个，"
                f"识别 {len(gaps)} 个防御缺口，建议按改进建议优化防御体系。")


# ============================================================
# 6. 单例导出
# ============================================================

_project = ExerciseProject()
_teams = TeamManager()
_recorder = ProcessRecorder()
_scoring = ScoringEngine()
_debrief = DebriefEngine()


def get_exercise_manager() -> Dict[str, Any]:
    return {
        "project": _project,
        "teams": _teams,
        "recorder": _recorder,
        "scoring": _scoring,
        "debrief": _debrief,
        "exercises": EXERCISES,
    }


def stats() -> Dict[str, Any]:
    return {
        "exercises_count": len(EXERCISES),
        "teams_count": len(_teams.teams),
        "timeline_records": sum(len(v) for v in _recorder.records.values()),
    }
