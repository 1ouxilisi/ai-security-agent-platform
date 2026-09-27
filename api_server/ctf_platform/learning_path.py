# -*- coding: utf-8 -*-
"""ctf_platform.learning_path — 学习路径与课程模块。

入门→进阶→高级→专家，课程、知识点图谱、技能评估、学习统计与社区。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


LEVELS = ["beginner", "intermediate", "advanced", "expert"]


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


class LearningPathManager:
    def __init__(self) -> None:
        self.paths: Dict[str, Dict[str, Any]] = {}
        self.courses: Dict[str, Dict[str, Any]] = {}
        self.knowledge_tree: List[Dict[str, Any]] = []
        self.user_progress: Dict[str, Dict[str, Any]] = {}
        self.badges: List[Dict[str, Any]] = []
        self._seed()

    def _seed(self) -> None:
        self.paths = {
            "p_web": {
                "id": "p_web", "name": "Web 安全成长路径",
                "level": "beginner", "milestones": [
                    {"order": 1, "name": "HTTP 基础", "courses": ["c_http"]},
                    {"order": 2, "name": "SQL 注入", "courses": ["c_sqli"]},
                    {"order": 3, "name": "XSS 与 CSRF", "courses": ["c_xss"]},
                ],
                "description": "从协议到实战",
            },
            "p_pwn": {
                "id": "p_pwn", "name": "Pwn 二进制成长路径",
                "level": "intermediate", "milestones": [
                    {"order": 1, "name": "汇编基础", "courses": ["c_asm"]},
                    {"order": 2, "name": "栈溢出", "courses": ["c_stack"]},
                ],
                "description": "CTF Pwn 入门到精通",
            },
        }
        self.courses = {
            "c_http": {"id": "c_http", "title": "HTTP/HTTPS 协议入门",
                       "type": "video", "level": "beginner",
                       "duration_min": 30, "rating": 4.8, "category": "Web"},
            "c_sqli": {"id": "c_sqli", "title": "SQL 注入原理与利用",
                       "type": "lab", "level": "beginner",
                       "duration_min": 60, "rating": 4.9, "category": "Web"},
            "c_xss": {"id": "c_xss", "title": "XSS 跨站脚本",
                      "type": "doc", "level": "intermediate",
                      "duration_min": 45, "rating": 4.6, "category": "Web"},
            "c_asm": {"id": "c_asm", "title": "x86 汇编速成",
                      "type": "video", "level": "intermediate",
                      "duration_min": 90, "rating": 4.5, "category": "Pwn"},
            "c_stack": {"id": "c_stack", "title": "栈溢出与 ROP",
                        "type": "lab", "level": "advanced",
                        "duration_min": 120, "rating": 4.7, "category": "Pwn"},
        }
        self.knowledge_tree = [
            {"id": "k_web", "name": "Web 安全", "children": [
                {"id": "k_sqli", "name": "SQL 注入", "depends_on": ["k_http"]},
                {"id": "k_xss", "name": "XSS", "depends_on": ["k_http"]},
                {"id": "k_ssrf", "name": "SSRF", "depends_on": ["k_sqli"]},
            ]},
            {"id": "k_pwn", "name": "二进制安全", "children": [
                {"id": "k_overflow", "name": "栈溢出", "depends_on": ["k_asm"]},
            ]},
            {"id": "k_crypto", "name": "密码学", "children": []},
        ]
        self.badges = [
            {"id": "b_first", "name": "初出茅庐", "desc": "首次解题",
             "icon": "star", "threshold": 1},
            {"id": "b_100", "name": "百题斩", "desc": "累计解题 100",
             "icon": "trophy", "threshold": 100},
            {"id": "b_teacher", "name": "分享者", "desc": "提交 5 篇 Writeup",
             "icon": "book", "threshold": 5},
        ]

    # ------------------------------------------------------------------ #
    # 学习路径
    # ------------------------------------------------------------------ #
    def list_paths(self) -> List[Dict[str, Any]]:
        return list(self.paths.values())

    def get_path(self, pid: str) -> Optional[Dict[str, Any]]:
        return self.paths.get(pid)

    # ------------------------------------------------------------------ #
    # 课程
    # ------------------------------------------------------------------ #
    def list_courses(self, category: Optional[str] = None,
                     level: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.courses.values())
        if category:
            items = [c for c in items if c["category"] == category]
        if level:
            items = [c for c in items if c["level"] == level]
        return items

    def enroll(self, user: str, course_id: str) -> Dict[str, Any]:
        prog = self.user_progress.setdefault(user, {})
        enrolled = prog.setdefault("enrolled", {})
        if course_id not in enrolled:
            enrolled[course_id] = {"progress": 0, "status": "learning",
                                   "started_at": _now()}
        return enrolled[course_id]

    def update_progress(self, user: str, course_id: str,
                        progress: int) -> Dict[str, Any]:
        prog = self.user_progress.setdefault(user, {})
        enrolled = prog.setdefault("enrolled", {})
        rec = enrolled.setdefault(course_id, {"progress": 0, "status": "learning"})
        rec["progress"] = max(0, min(100, int(progress)))
        rec["status"] = "done" if rec["progress"] >= 100 else "learning"
        return rec

    # ------------------------------------------------------------------ #
    # 知识点图谱 / 技能评估
    # ------------------------------------------------------------------ #
    def knowledge_graph(self) -> List[Dict[str, Any]]:
        return self.knowledge_tree

    def skill_radar(self, user: str) -> Dict[str, Any]:
        prog = self.user_progress.get(user, {})
        enrolled = prog.get("enrolled", {})
        cat_score: Dict[str, int] = {}
        for cid, rec in enrolled.items():
            c = self.courses.get(cid, {})
            cat = c.get("category", "Misc")
            cat_score[cat] = max(cat_score.get(cat, 0), rec.get("progress", 0))
        radar = [
            {"axis": "Web", "value": cat_score.get("Web", 20)},
            {"axis": "Pwn", "value": cat_score.get("Pwn", 10)},
            {"axis": "Crypto", "value": 15},
            {"axis": "Reverse", "value": 12},
            {"axis": "Forensics", "value": 18},
            {"axis": "Misc", "value": 25},
        ]
        weak = min(radar, key=lambda x: x["value"])
        return {"user": user, "radar": radar,
                "weak_point": weak["axis"],
                "recommended": [c for c in self.courses.values()
                                if c["category"] == weak["axis"]][:3]}

    # ------------------------------------------------------------------ #
    # 学习统计 / 社区
    # ------------------------------------------------------------------ #
    def stats(self, user: str) -> Dict[str, Any]:
        prog = self.user_progress.get(user, {})
        enrolled = prog.get("enrolled", {})
        done = sum(1 for r in enrolled.values() if r["status"] == "done")
        return {
            "user": user,
            "enrolled_courses": len(enrolled),
            "completed_courses": done,
            "learning_hours": round(done * 0.75, 1),
            "badges_earned": self.badges[: max(0, min(2, done // 2))],
            "streak_days": 7,
        }

    def share_moment(self, user: str, text: str) -> Dict[str, Any]:
        return {"id": _uid("moment"), "user": user, "text": text,
                "likes": 0, "at": _now()}


_lp_singleton: Optional[LearningPathManager] = None


def get_learning_manager() -> LearningPathManager:
    global _lp_singleton
    if _lp_singleton is None:
        _lp_singleton = LearningPathManager()
    return _lp_singleton
