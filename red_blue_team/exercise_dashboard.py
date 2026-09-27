# -*- coding: utf-8 -*-
"""
exercise_dashboard.py — 红蓝对抗控制台（第24轮升级方向1）。

职责：
    1. 对抗总览（进行中/已完成/统计/攻击成功率/防御成功率/评分趋势）
    2. 对抗管理（列表/详情/配置/控制/暂停/终止/复盘）
    3. 攻击管理（场景/攻击链/技术/工具/执行/结果/评分）
    4. 防御管理（规则/检测/响应/效果/评分/改进）
    5. 可视化（拓扑/时间线/攻击树/杀伤链/热力图/3D 地图）
    6. 系统设置（对抗配置/评分标准/规则/工具/通知/审计）

聚合其余 5 个模块，提供控制台数据聚合。全部内存字典。
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
from red_blue_team.defense_validator import (
    DEFENSE_RULES, get_defense_validator, ALERTS,
)
from red_blue_team.exercise_manager import (
    EXERCISES, get_exercise_manager,
)
from red_blue_team.attack_visualization import get_attack_visualization
from red_blue_team.attack_tools import get_attack_tools


# ============================================================
# 1. 对抗总览
# ============================================================

class OverviewDashboard:
    """红蓝对抗总览聚合。"""

    def summary(self) -> Dict[str, Any]:
        total = len(EXERCISES)
        in_progress = sum(1 for e in EXERCISES.values()
                          if e.get("status") == "in_progress")
        completed = sum(1 for e in EXERCISES.values()
                        if e.get("status") == "completed")

        attack_sim = get_attack_simulator()
        defense = get_defense_validator()

        # 模拟攻击/防御成功率
        attack_success = round(random.uniform(0.45, 0.75), 2)
        defense_success = round(1 - attack_success * 0.6, 2)

        return {
            "total_exercises": total,
            "in_progress": in_progress,
            "completed": completed,
            "pending": total - in_progress - completed,
            "attack_success_rate": attack_success,
            "defense_success_rate": defense_success,
            "alerts_triggered": len(ALERTS),
            "rules_deployed": len(DEFENSE_RULES),
            "techniques_in_library": len(ATTACK_TECHNIQUES),
            "scenarios": len(ATTACK_SCENARIOS),
            "generated_at": datetime.now().isoformat(),
        }

    def score_trend(self) -> Dict[str, Any]:
        """综合评分趋势（模拟近 10 次对抗）。"""
        history = []
        base = 60
        for i in range(10):
            base += random.uniform(-3, 4)
            history.append({
                "round": i + 1,
                "composite_score": round(max(40, min(95, base)), 1),
                "attack_score": round(random.uniform(50, 80), 1),
                "defense_score": round(random.uniform(55, 85), 1),
            })
        return {"history": history, "trend": "improving"}


# ============================================================
# 2. 对抗管理聚合
# ============================================================

class ExerciseMgmt:
    """对抗 CRUD + 控制聚合。"""

    def list_exercises(self) -> List[Dict[str, Any]]:
        return list(EXERCISES.values())

    def detail(self, exercise_id: str) -> Optional[Dict[str, Any]]:
        return EXERCISES.get(exercise_id)

    def config(self, exercise_id: str) -> Dict[str, Any]:
        e = EXERCISES.get(exercise_id)
        if not e:
            raise ValueError(f"未知对抗: {exercise_id}")
        return {
            "exercise_id": exercise_id,
            "name": e.get("name"),
            "scope": e.get("scope"),
            "rules": e.get("rules_of_engagement"),
            "scoring_criteria": e.get("scoring_criteria"),
        }


# ============================================================
# 3. 攻击管理聚合
# ============================================================

class AttackMgmt:
    """攻击场景/链/技术/工具/执行/结果聚合。"""

    def list_scenarios(self) -> List[Dict[str, Any]]:
        return list(ATTACK_SCENARIOS.values())

    def list_tactics(self) -> List[Dict[str, Any]]:
        return list(ATTACK_TACTICS.values())

    def list_techniques(self, tactic: Optional[str] = None) -> List[Dict[str, Any]]:
        techs = list(ATTACK_TECHNIQUES.values())
        if tactic:
            techs = [t for t in techs if t["tactic"] == tactic]
        return techs

    def list_tools(self) -> List[Dict[str, Any]]:
        tools = get_attack_tools()
        return tools["orchestrator"].market()

    def attack_results(self) -> List[Dict[str, Any]]:
        sim = get_attack_simulator()
        return sim["executor"].list_runs()


# ============================================================
# 4. 防御管理聚合
# ============================================================

class DefenseMgmt:
    """防御规则/检测/响应/效果/改进聚合。"""

    def list_rules(self) -> List[Dict[str, Any]]:
        return list(DEFENSE_RULES.values())

    def list_alerts(self) -> List[Dict[str, Any]]:
        return list(ALERTS.values())

    def coverage(self) -> Dict[str, Any]:
        defense = get_defense_validator()
        return defense["analyzer"].analyze()

    def effectiveness(self, attack_success: float = 0.6,
                      detection: float = 0.7) -> Dict[str, Any]:
        defense = get_defense_validator()
        return defense["effectiveness"].evaluate(attack_success, detection)


# ============================================================
# 5. 可视化聚合
# ============================================================

class VisualizationMgmt:
    """拓扑/时间线/攻击树/杀伤链/热力图/3D 地图。"""

    def topology(self) -> Dict[str, Any]:
        vis = get_attack_visualization()
        return vis["topology"].build()

    def timeline(self) -> Dict[str, Any]:
        vis = get_attack_visualization()
        return vis["timeline"].build()

    def attack_tree(self, goal: str = "获取域管理员") -> Dict[str, Any]:
        vis = get_attack_visualization()
        return vis["tree"].build(goal)

    def killchain(self) -> Dict[str, Any]:
        vis = get_attack_visualization()
        return vis["killchain"].build()

    def heatmap(self) -> Dict[str, Any]:
        vis = get_attack_visualization()
        return vis["heatmap"].build()

    def map3d(self) -> Dict[str, Any]:
        vis = get_attack_visualization()
        return vis["map3d"].build()


# ============================================================
# 6. 系统设置
# ============================================================

SYSTEM_SETTINGS: Dict[str, Any] = {
    "exercise_defaults": {
        "duration_hours": 48,
        "scope": "10.0.0.0/8",
        "auto_start": False,
    },
    "scoring": {
        "attack_success_weight": 0.4,
        "detection_rate_weight": 0.3,
        "response_time_weight": 0.2,
        "documentation_weight": 0.1,
    },
    "rules": {
        "auto_deploy": True,
        "false_positive_threshold": 0.15,
    },
    "tools": {
        "msf_host": "127.0.0.1", "msf_port": 55553,
        "cs_api": "http://127.0.0.1:4532",
    },
    "notification": {
        "channels": ["email", "webhook", "sms"],
        "alert_threshold": "high",
    },
    "audit": {
        "log_retention_days": 180,
        "immutable_log": True,
    },
}


class SettingsManager:
    """系统设置读写。"""

    def get(self) -> Dict[str, Any]:
        return SYSTEM_SETTINGS

    def update(self, section: str, values: Dict[str, Any]) -> Dict[str, Any]:
        SYSTEM_SETTINGS.setdefault(section, {}).update(values)
        return {"section": section, "updated": values,
                "at": datetime.now().isoformat()}


# ============================================================
# 7. 单例导出
# ============================================================

_overview = OverviewDashboard()
_exercise_mgmt = ExerciseMgmt()
_attack_mgmt = AttackMgmt()
_defense_mgmt = DefenseMgmt()
_viz_mgmt = VisualizationMgmt()
_settings = SettingsManager()


def get_exercise_dashboard() -> Dict[str, Any]:
    return {
        "overview": _overview,
        "exercises": _exercise_mgmt,
        "attacks": _attack_mgmt,
        "defenses": _defense_mgmt,
        "visualizations": _viz_mgmt,
        "settings": _settings,
        "system_settings": SYSTEM_SETTINGS,
    }


def stats() -> Dict[str, Any]:
    return {
        "dashboard_sections": 6,
        "settings_sections": len(SYSTEM_SETTINGS),
    }
