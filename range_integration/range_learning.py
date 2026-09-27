# -*- coding: utf-8 -*-
"""
range_learning.py - 靶场学习与训练模块

功能：
- 学习路径（入门/进阶/专家/Web/移动/云/工控/红蓝对抗）
- 课程管理（列表/章节/内容/练习/测验/项目/证书）
- 练习模式（引导/自由/挑战/计时/排名/团队/竞赛）
- 考核认证（题目/环境/时间/评分/证书/验证）
- 团队训练（创建/成员/任务/协作/排名/统计/复盘）
- 竞赛管理（创建/题目/环境/时间/排名/奖励/复盘）

全部内存字典模拟。
"""

from __future__ import annotations

import logging
import random
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _clean(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, str):
        return "".join(ch for ch in obj if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return obj


# ----------------------------------------------------------------------
# 学习路径
# ----------------------------------------------------------------------
LEARNING_PATHS: Dict[str, Dict[str, Any]] = {
    "beginner_web": {
        "id": "beginner_web", "name": "Web 安全入门",
        "description": "从零开始学习 Web 安全基础，覆盖 OWASP Top 10 入门内容",
        "level": "入门", "estimated_hours": 40,
        "modules": [
            {"id": "m1", "name": "HTTP 协议基础", "lessons": 8},
            {"id": "m2", "name": "SQL 注入入门", "lessons": 6},
            {"id": "m3", "name": "XSS 跨站脚本", "lessons": 5},
            {"id": "m4", "name": "文件上传漏洞", "lessons": 4},
        ],
        "target_range": "dvwa",
    },
    "advanced_web": {
        "id": "advanced_web", "name": "Web 安全进阶",
        "description": "深入学习高级 Web 漏洞利用与绕过技术",
        "level": "进阶", "estimated_hours": 80,
        "modules": [
            {"id": "m1", "name": "高级 SQL 注入（盲注/二阶）", "lessons": 8},
            {"id": "m2", "name": "CSRF 与 CORS", "lessons": 5},
            {"id": "m3", "name": "SSRF 服务端请求伪造", "lessons": 6},
            {"id": "m4", "name": "反序列化漏洞", "lessons": 7},
        ],
        "target_range": "juice-shop",
    },
    "expert_redteam": {
        "id": "expert_redteam", "name": "红队专家路径",
        "description": "掌握完整的渗透测试流程：信息收集到横向移动",
        "level": "专家", "estimated_hours": 200,
        "modules": [
            {"id": "m1", "name": "OSINT 信息收集", "lessons": 10},
            {"id": "m2", "name": "初始访问", "lessons": 8},
            {"id": "m3", "name": "权限提升", "lessons": 10},
            {"id": "m4", "name": "横向移动", "lessons": 8},
            {"id": "m5", "name": "持久化与防御规避", "lessons": 6},
        ],
        "target_range": "vulhub",
    },
    "mobile_sec": {
        "id": "mobile_sec", "name": "移动安全路径",
        "description": "Android/iOS 应用安全测试与逆向分析",
        "level": "进阶", "estimated_hours": 60,
        "modules": [
            {"id": "m1", "name": "Android 逆向基础", "lessons": 8},
            {"id": "m2", "name": "iOS 安全测试", "lessons": 6},
            {"id": "m3", "name": "移动 API 安全", "lessons": 5},
        ],
        "target_range": "android_diva",
    },
    "cloud_sec": {
        "id": "cloud_sec", "name": "云安全路径",
        "description": "AWS/Azure/阿里云安全配置审计与权限提升",
        "level": "进阶", "estimated_hours": 50,
        "modules": [
            {"id": "m1", "name": "云基础架构", "lessons": 6},
            {"id": "m2", "name": "IAM 权限模型", "lessons": 8},
            {"id": "m3", "name": "云存储安全", "lessons": 4},
        ],
        "target_range": "aws_privesc",
    },
    "ics_sec": {
        "id": "ics_sec", "name": "工控安全路径",
        "description": "工业控制系统安全测试与协议分析",
        "level": "专家", "estimated_hours": 100,
        "modules": [
            {"id": "m1", "name": "工控协议基础", "lessons": 6},
            {"id": "m2", "name": "Modbus/S7 安全", "lessons": 8},
            {"id": "m3", "name": "工控渗透测试", "lessons": 10},
        ],
        "target_range": "modbus_lab",
    },
}

# 课程
COURSES: Dict[str, Dict[str, Any]] = {
    "course_sql_injection": {
        "id": "course_sql_injection", "name": "SQL 注入完全指南",
        "path": "beginner_web",
        "chapters": [
            {"id": "c1", "name": "SQL 注入原理", "duration": "45min"},
            {"id": "c2", "name": "联合查询注入", "duration": "60min"},
            {"id": "c3", "name": "盲注技术", "duration": "90min"},
            {"id": "c4", "name": "防御与修复", "duration": "30min"},
        ],
        "quizzes": 3, "final_project": "在 DVWA 中完成所有难度 SQL 注入",
    },
    "course_xss": {
        "id": "course_xss", "name": "XSS 跨站脚本详解",
        "path": "beginner_web",
        "chapters": [
            {"id": "c1", "name": "XSS 类型与原理", "duration": "30min"},
            {"id": "c2", "name": "反射型 XSS", "duration": "40min"},
            {"id": "c3", "name": "存储型 XSS", "duration": "45min"},
            {"id": "c4", "name": "DOM 型 XSS", "duration": "40min"},
        ],
        "quizzes": 2, "final_project": "在 Juice Shop 中找到 5 个 XSS 漏洞",
    },
}

# 练习模式
PRACTICE_MODES = {
    "guided": {"name": "引导模式", "description": "分步引导，适合新手"},
    "free": {"name": "自由模式", "description": "自由探索靶场"},
    "challenge": {"name": "挑战模式", "description": "限时挑战，考验速度"},
    "timed": {"name": "计时模式", "description": "记录用时，评估效率"},
    "ranking": {"name": "排名模式", "description": "与其他学员比较"},
    "team": {"name": "团队模式", "description": "多人协作"},
    "competition": {"name": "竞赛模式", "description": "正式竞赛环境"},
}


# ======================================================================
# RangeLearningManager
# ======================================================================
class RangeLearningManager:
    """学习与训练管理器。"""

    def __init__(self) -> None:
        self._teams: Dict[str, Dict[str, Any]] = {}
        self._competitions: Dict[str, Dict[str, Any]] = {}
        self._exams: Dict[str, Dict[str, Any]] = {}
        self._user_progress: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # 学习路径
    # ------------------------------------------------------------------
    def list_paths(self) -> List[Dict[str, Any]]:
        return list(LEARNING_PATHS.values())

    def get_path(self, path_id: str) -> Optional[Dict[str, Any]]:
        return LEARNING_PATHS.get(path_id)

    # ------------------------------------------------------------------
    # 课程
    # ------------------------------------------------------------------
    def list_courses(self, path_id: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(COURSES.values())
        if path_id:
            items = [c for c in items if c.get("path") == path_id]
        return items

    def get_course(self, course_id: str) -> Optional[Dict[str, Any]]:
        return COURSES.get(course_id)

    # ------------------------------------------------------------------
    # 练习模式
    # ------------------------------------------------------------------
    def list_practice_modes(self) -> Dict[str, Dict[str, Any]]:
        return PRACTICE_MODES

    def start_practice(self, range_id: str, mode: str,
                       user_id: str = "default") -> Dict[str, Any]:
        if mode not in PRACTICE_MODES:
            return {"success": False, "error": f"不支持的练习模式: {mode}"}
        session_id = f"practice_{uuid.uuid4().hex[:8]}"
        return {
            "success": True,
            "session_id": session_id,
            "range_id": range_id,
            "mode": mode,
            "mode_name": PRACTICE_MODES[mode]["name"],
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "message": f"已进入{PRACTICE_MODES[mode]['name']}",
        }

    # ------------------------------------------------------------------
    # 考核认证
    # ------------------------------------------------------------------
    def create_exam(self, title: str, path_id: str, duration_min: int = 60,
                    question_count: int = 20) -> Dict[str, Any]:
        exam_id = f"exam_{uuid.uuid4().hex[:8]}"
        self._exams[exam_id] = {
            "exam_id": exam_id, "title": title, "path_id": path_id,
            "duration_min": duration_min, "question_count": question_count,
            "status": "created", "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {"success": True, "exam_id": exam_id, "message": "考试创建成功"}

    def grade_exam(self, exam_id: str, answers: List[Dict]) -> Dict[str, Any]:
        exam = self._exams.get(exam_id)
        if not exam:
            return {"success": False, "error": "考试不存在"}
        score = random.randint(60, 98)
        passed = score >= 60
        return {
            "success": True, "exam_id": exam_id, "score": score,
            "passed": passed, "certificate": "已颁发" if passed else "未达标",
        }

    # ------------------------------------------------------------------
    # 团队训练
    # ------------------------------------------------------------------
    def create_team(self, name: str, description: str = "",
                    members: Optional[List[str]] = None) -> Dict[str, Any]:
        team_id = f"team_{uuid.uuid4().hex[:8]}"
        self._teams[team_id] = {
            "team_id": team_id, "name": name, "description": description,
            "members": members or [], "tasks": [],
            "stats": {"completed": 0, "in_progress": 0},
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {"success": True, "team_id": team_id, "message": "团队创建成功"}

    def list_teams(self) -> List[Dict[str, Any]]:
        return list(self._teams.values())

    # ------------------------------------------------------------------
    # 竞赛管理
    # ------------------------------------------------------------------
    def create_competition(self, name: str, start_time: str,
                           end_time: str, range_ids: List[str]) -> Dict[str, Any]:
        comp_id = f"comp_{uuid.uuid4().hex[:8]}"
        self._competitions[comp_id] = {
            "competition_id": comp_id, "name": name,
            "start_time": start_time, "end_time": end_time,
            "ranges": range_ids, "status": "upcoming",
            "participants": [], "ranking": [],
        }
        return {"success": True, "competition_id": comp_id, "message": "竞赛创建成功"}

    def list_competitions(self) -> List[Dict[str, Any]]:
        return list(self._competitions.values())

    def get_competition(self, comp_id: str) -> Dict[str, Any]:
        c = self._competitions.get(comp_id)
        if not c:
            return {"success": False, "error": "竞赛不存在"}
        return {"success": True, "competition": c}

    # ------------------------------------------------------------------
    # 用户进度
    # ------------------------------------------------------------------
    def update_progress(self, user_id: str, path_id: str,
                        completed_modules: List[str]) -> Dict[str, Any]:
        self._user_progress[user_id] = {
            "user_id": user_id, "path_id": path_id,
            "completed_modules": completed_modules,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {"success": True, "message": "进度已更新"}

    def get_progress(self, user_id: str) -> Dict[str, Any]:
        p = self._user_progress.get(user_id)
        if not p:
            return {"success": True, "user_id": user_id, "progress": "尚未开始"}
        return {"success": True, "progress": p}


_learning: Optional[RangeLearningManager] = None


def get_learning_manager() -> RangeLearningManager:
    global _learning
    if _learning is None:
        _learning = RangeLearningManager()
    return _learning
