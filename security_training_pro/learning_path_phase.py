# -*- coding: utf-8 -*-
"""
learning_path_phase.py — 阶段2：学习路径。

功能:
    - 路径设计（入门→进阶→高级→专家）
    - 知识点关联（前置/后续/相关）
    - 前置课程约束
    - 学习计划（日/周/月）
    - 进度跟踪（进度/完成度/学习时长）
    - 路径模板（Web安全工程师/渗透测试工程师/安全研究员/安全开发）
    - 路径推荐 / 评估 / 优化
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

PATH_LEVELS = ["入门", "进阶", "高级", "专家"]

PATH_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "tpl_web_engineer": {
        "path_id": "tpl_web_engineer",
        "name": "Web 安全工程师",
        "target": "掌握 Web 漏洞全栈攻防",
        "levels": ["入门", "进阶", "高级", "专家"],
        "required_courses": ["c_web_sqli", "c_xss"],
    },
    "tpl_pentester": {
        "path_id": "tpl_pentester",
        "name": "渗透测试工程师",
        "target": "独立完成内外网渗透项目",
        "levels": ["入门", "进阶", "高级", "专家"],
        "required_courses": ["c_web_sqli", "c_ad"],
    },
    "tpl_researcher": {
        "path_id": "tpl_researcher",
        "name": "安全研究员",
        "target": "漏洞挖掘与原理研究",
        "levels": ["进阶", "高级", "专家"],
        "required_courses": ["c_crypto", "c_re"],
    },
    "tpl_sec_dev": {
        "path_id": "tpl_sec_dev",
        "name": "安全开发工程师",
        "target": "安全编码与 DevSecOps",
        "levels": ["入门", "进阶", "高级"],
        "required_courses": [],
    },
}


@dataclass
class LearningPath:
    path_id: str = ""
    name: str = ""
    description: str = ""
    level: str = "入门"
    courses: List[str] = field(default_factory=list)
    prerequisites: Dict[str, List[str]] = field(default_factory=dict)
    progress: float = 0.0
    study_hours: float = 0.0
    template_id: str = ""
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id, "name": self.name,
            "description": self.description, "level": self.level,
            "courses": self.courses,
            "prerequisites": self.prerequisites,
            "progress": round(self.progress, 1),
            "study_hours": round(self.study_hours, 1),
            "template_id": self.template_id,
            "created_at": self.created_at,
        }


class LearningPathPhase:
    """阶段2：学习路径。"""

    def __init__(self) -> None:
        self._paths: Dict[str, LearningPath] = {}
        self._knowledge: Dict[str, Dict[str, List[str]]] = {}
        self._plans: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._seed()

    # ------------------------------------------------------------------ #
    def _seed(self) -> None:
        for tpl in PATH_TEMPLATES.values():
            pid = tpl["path_id"].replace("tpl_", "path_")
            self._paths[pid] = LearningPath(
                path_id=pid, name=tpl["name"],
                description=tpl["target"], level="入门",
                courses=list(tpl["required_courses"]),
                template_id=tpl["path_id"],
                created_at=datetime.now().isoformat(timespec="seconds"),
            )
        # 知识点关联
        self._knowledge["SQL注入"] = {
            "prerequisite": ["HTTP基础", "MySQL语法"],
            "next": ["XSS", "文件上传"],
            "related": ["命令注入", "二次注入"],
        }
        self._knowledge["域渗透"] = {
            "prerequisite": ["内网信息收集", "Windows 认证"],
            "next": ["权限维持", "域控提权"],
            "related": ["横向移动", "票据攻击"],
        }

    # ------------------------------------------------------------------ #
    def list_paths(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [p.to_dict() for p in self._paths.values()]

    def get_path(self, path_id: str) -> Optional[Dict[str, Any]]:
        p = self._paths.get(path_id)
        return p.to_dict() if p else None

    def create_path(self, name: str, description: str = "",
                    level: str = "入门",
                    courses: Optional[List[str]] = None) -> Dict[str, Any]:
        if level not in PATH_LEVELS:
            raise ValueError(f"非法等级: {level}")
        p = LearningPath(
            path_id="path_" + uuid.uuid4().hex[:8], name=name,
            description=description, level=level,
            courses=courses or [],
            created_at=datetime.now().isoformat(timespec="seconds"),
        )
        with self._lock:
            self._paths[p.path_id] = p
        return p.to_dict()

    def set_prerequisite(self, path_id: str,
                         course_id: str,
                         requires: List[str]) -> Optional[Dict[str, Any]]:
        p = self._paths.get(path_id)
        if p is None:
            return None
        with self._lock:
            p.prerequisites[course_id] = requires
        return p.to_dict()

    # ------------------------------------------------------------------ #
    def knowledge_map(self,
                      topic: Optional[str] = None) -> Dict[str, Any]:
        if topic:
            rel = self._knowledge.get(topic)
            if rel is None:
                return {"topic": topic, "found": False}
            return {"topic": topic, "found": True, **rel}
        return {"topics": list(self._knowledge.keys()),
                "relations": self._knowledge}

    def recommend(self, goal: str = "", base: str = "入门",
                  interest: str = "") -> List[Dict[str, Any]]:
        """基于目标/基础/兴趣推荐路径。"""
        scored = []
        for p in self._paths.values():
            score = 0
            if goal and goal in p.name:
                score += 3
            if base == p.level:
                score += 1
            if interest and interest in p.description:
                score += 1
            scored.append((score, p.to_dict()))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [d for _, d in scored[:5]]

    # ------------------------------------------------------------------ #
    def create_plan(self, path_id: str, student: str,
                    period: str = "weekly",
                    minutes_per_day: int = 60) -> Optional[Dict[str, Any]]:
        p = self._paths.get(path_id)
        if p is None:
            return None
        plan = {
            "plan_id": "plan_" + uuid.uuid4().hex[:8],
            "path_id": path_id, "student": student,
            "period": period, "minutes_per_day": minutes_per_day,
            "target_courses": list(p.courses),
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        with self._lock:
            self._plans[plan["plan_id"]] = plan
        return plan

    def update_progress(self, path_id: str, student: str,
                        progress: float,
                        study_hours: float = 0.0) -> Optional[Dict[str, Any]]:
        p = self._paths.get(path_id)
        if p is None:
            return None
        with self._lock:
            p.progress = max(0.0, min(100.0, progress))
            p.study_hours += study_hours
        return {"path_id": path_id, "student": student,
                "progress": p.progress, "study_hours": p.study_hours}

    # ------------------------------------------------------------------ #
    def templates(self) -> List[Dict[str, Any]]:
        return list(PATH_TEMPLATES.values())

    def evaluate(self, path_id: str) -> Dict[str, Any]:
        p = self._paths.get(path_id)
        if p is None:
            return {}
        completion = p.progress
        avg_hours = p.study_hours / max(1, len(p.courses))
        return {
            "path_id": path_id,
            "completion": completion,
            "avg_hours_per_course": round(avg_hours, 1),
            "assess": "优秀" if completion >= 90 else
                      "良好" if completion >= 70 else
                      "一般" if completion >= 50 else "待提升",
            "suggestion": "建议加强前置课程复习" if completion < 60
                          else "可进入下一阶段",
        }

    def optimize(self) -> Dict[str, Any]:
        with self._lock:
            paths = list(self._paths.values())
        slow = [p.to_dict() for p in paths if p.progress < 40]
        return {
            "total_paths": len(paths),
            "avg_progress": round(
                sum(p.progress for p in paths) / max(1, len(paths)), 1),
            "needs_attention": slow,
            "suggestion": "对进度 <40% 的路径拆分里程碑、降低单课难度",
        }

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            paths = list(self._paths.values())
        return {
            "total": len(paths),
            "by_level": {lv: sum(1 for p in paths if p.level == lv)
                         for lv in PATH_LEVELS},
            "avg_progress": round(
                sum(p.progress for p in paths) / max(1, len(paths)), 1),
            "templates": len(PATH_TEMPLATES),
            "knowledge_nodes": len(self._knowledge),
            "plans": len(self._plans),
        }


_default: Optional[LearningPathPhase] = None


def get_learning_path_phase() -> LearningPathPhase:
    global _default
    if _default is None:
        _default = LearningPathPhase()
    return _default
