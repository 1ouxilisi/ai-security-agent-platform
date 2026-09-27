# -*- coding: utf-8 -*-
"""
learning_path.py — 学习路径与课程。

能力：
  - 学习路径（路径设计/目标/阶段/课程顺序/里程碑/评估/证书/推荐）
  - 课程管理（列表/分类/难度/时长/讲师/评分/报名/进度）
  - 章节管理（列表/顺序/内容/练习/测验/项目/完成条件）
  - 知识点管理（列表/分类/关联/难度/示例/练习/掌握度）
  - 练习与测验（题目类型/答案/解析/评分）
  - 项目实战（目标/需求/步骤/提交/评审/展示）
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _rid(p: str) -> str:
    return f"{p}_{uuid.uuid4().hex[:10]}"


QUESTION_TYPES = ["single_choice", "multiple_choice", "judge", "short_answer", "code"]


class LearningStore:
    def __init__(self) -> None:
        self.paths: Dict[str, Dict[str, Any]] = {}
        self.courses: Dict[str, Dict[str, Any]] = {}
        self.chapters: Dict[str, Dict[str, Any]] = {}
        self.knowledge: Dict[str, Dict[str, Any]] = {}
        self.quiz: Dict[str, Dict[str, Any]] = {}
        self.projects: Dict[str, Dict[str, Any]] = {}
        self.enrollments: Dict[str, Dict[str, Any]] = {}
        self._seed()

    def _seed(self) -> None:
        cid = _rid("course")
        self.courses[cid] = {
            "id": cid, "title": "Web安全实战30讲", "category": "Web安全",
            "difficulty": "进阶", "duration_h": 30, "instructor": "王老师",
            "rating": 4.9, "enrolled": 342, "chapter_ids": [],
            "created_at": _now(),
        }
        kid = _rid("path")
        self.paths[kid] = {
            "id": kid, "name": "渗透工程师成长路线", "goal": "6个月达到中级渗透工程师",
            "stages": [{"stage": "基础", "course_ids": []},
                       {"stage": "实战", "course_ids": [cid]},
                       {"stage": "认证", "course_ids": []}],
            "milestones": ["掌握HTTP", "完成3个靶场", "通过OSCP模拟"],
            "certificate": "渗透工程师结业证书", "recommended_for": ["新人"],
            "created_at": _now(),
        }
        self.knowledge[_rid("kp")] = {
            "id": None, "name": "SQL注入原理", "category": "Web安全",
            "difficulty": "进阶", "related": [], "example": "' OR 1=1--",
            "practice_count": 12,
        }
        self.knowledge[list(self.knowledge.keys())[-1]]["id"] = list(self.knowledge.keys())[-1]


STORE = LearningStore()


# ---------------- 学习路径 ---------------- #
def create_path(payload: Dict[str, Any]) -> Dict[str, Any]:
    pid = _rid("path")
    rec = {
        "id": pid, "name": payload.get("name", "新学习路径"),
        "goal": payload.get("goal", ""),
        "stages": payload.get("stages", []),
        "milestones": payload.get("milestones", []),
        "certificate": payload.get("certificate", ""),
        "recommended_for": payload.get("recommended_for", []),
        "created_at": _now(), "updated_at": _now(),
    }
    STORE.paths[pid] = rec
    return rec


def list_paths() -> List[Dict[str, Any]]:
    return list(STORE.paths.values())


def recommend_path(profile: Dict[str, Any]) -> List[Dict[str, Any]]:
    """根据学员画像（当前技能/目标）推荐路径。"""
    goal = (profile.get("goal") or "").lower()
    out = []
    for p in STORE.paths.values():
        score = 0
        if goal and goal in (p["name"] + p["goal"]).lower():
            score += 2
        for tag in p.get("recommended_for", []):
            if tag.lower() in str(profile).lower():
                score += 1
        out.append({"path": p, "relevance": score})
    out.sort(key=lambda x: x["relevance"], reverse=True)
    return [o["path"] for o in out]


# ---------------- 课程 ---------------- #
def create_course(payload: Dict[str, Any]) -> Dict[str, Any]:
    cid = _rid("course")
    rec = {
        "id": cid, "title": payload.get("title", "新课程"),
        "category": payload.get("category", "Web安全"),
        "difficulty": payload.get("difficulty", "基础"),
        "duration_h": int(payload.get("duration_h", 8)),
        "instructor": payload.get("instructor", ""),
        "rating": 0.0, "enrolled": 0, "chapter_ids": [],
        "created_at": _now(),
    }
    STORE.courses[cid] = rec
    return rec


def list_courses(category: Optional[str] = None,
                 difficulty: Optional[str] = None) -> List[Dict[str, Any]]:
    out = list(STORE.courses.values())
    if category:
        out = [c for c in out if c["category"] == category]
    if difficulty:
        out = [c for c in out if c["difficulty"] == difficulty]
    return out


def enroll(course_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    c = STORE.courses.get(course_id)
    if not c:
        return None
    eid = _rid("enr")
    c["enrolled"] += 1
    rec = {"id": eid, "course_id": course_id, "user_id": user_id,
           "progress": 0, "completed_chapters": [],
           "enrolled_at": _now(), "last_active": _now()}
    STORE.enrollments[eid] = rec
    return rec


# ---------------- 章节 ---------------- #
def add_chapter(course_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    c = STORE.courses.get(course_id)
    if not c:
        return None
    chid = _rid("ch")
    rec = {"id": chid, "course_id": course_id,
           "title": payload.get("title", "新章节"),
           "order": int(payload.get("order", len(c["chapter_ids"]) + 1)),
           "content": payload.get("content", ""),
           "quiz_id": payload.get("quiz_id"),
           "project_id": payload.get("project_id"),
           "complete_condition": payload.get("complete_condition", "完成阅读"),
           "created_at": _now()}
    STORE.chapters[chid] = rec
    c["chapter_ids"].append(chid)
    return rec


def list_course_chapters(course_id: str) -> List[Dict[str, Any]]:
    c = STORE.courses.get(course_id)
    if not c:
        return []
    out = [STORE.chapters[ch] for ch in c["chapter_ids"] if ch in STORE.chapters]
    return sorted(out, key=lambda x: x["order"])


# ---------------- 知识点 ---------------- #
def add_knowledge(payload: Dict[str, Any]) -> Dict[str, Any]:
    kid = _rid("kp")
    rec = {"id": kid, "name": payload.get("name", "新知识点"),
           "category": payload.get("category", ""),
           "difficulty": payload.get("difficulty", "基础"),
           "related": list(payload.get("related", [])),
           "example": payload.get("example", ""),
           "practice_count": 0, "mastery": {}}
    STORE.knowledge[kid] = rec
    return rec


def list_knowledge(category: Optional[str] = None) -> List[Dict[str, Any]]:
    out = list(STORE.knowledge.values())
    if category:
        out = [k for k in out if k["category"] == category]
    return out


# ---------------- 练习与测验 ---------------- #
def create_quiz(payload: Dict[str, Any]) -> Dict[str, Any]:
    qid = _rid("quiz")
    questions = []
    for q in payload.get("questions", []):
        questions.append({
            "id": _rid("q"),
            "type": q.get("type", "single_choice"),
            "content": q.get("content", ""),
            "options": q.get("options", []),
            "answer": q.get("answer", ""),
            "analysis": q.get("analysis", ""),
            "difficulty": q.get("difficulty", "基础"),
            "knowledge_id": q.get("knowledge_id"),
        })
    rec = {"id": qid, "title": payload.get("title", "新测验"),
           "questions": questions, "time_limit_min": payload.get("time_limit_min", 10),
           "created_at": _now()}
    STORE.quiz[qid] = rec
    return rec


def grade_quiz(quiz_id: str, answers: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    q = STORE.quiz.get(quiz_id)
    if not q:
        return None
    correct = 0
    total = len(q["questions"])
    wrong: List[Dict[str, Any]] = []
    for item in q["questions"]:
        ua = answers.get(item["id"])
        if ua is not None and str(ua) == str(item["answer"]):
            correct += 1
        else:
            wrong.append({"question_id": item["id"],
                          "content": item["content"],
                          "your_answer": ua, "correct_answer": item["answer"],
                          "analysis": item["analysis"]})
    score = round(correct / total * 100, 1) if total else 0.0
    return {"quiz_id": quiz_id, "score": score, "correct": correct,
            "total": total, "wrong": wrong, "graded_at": _now()}


# ---------------- 项目实战 ---------------- #
def create_project(payload: Dict[str, Any]) -> Dict[str, Any]:
    pid = _rid("proj")
    rec = {"id": pid, "title": payload.get("title", "新项目实战"),
           "goal": payload.get("goal", ""),
           "requirements": list(payload.get("requirements", [])),
           "steps": list(payload.get("steps", [])),
           "criteria": list(payload.get("criteria", [])),
           "submissions": [], "created_at": _now()}
    STORE.projects[pid] = rec
    return rec


def submit_project(project_id: str, user_id: str,
                   artifact: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    p = STORE.projects.get(project_id)
    if not p:
        return None
    sid = _rid("sub")
    rec = {"id": sid, "user_id": user_id, "artifact": artifact,
           "status": "pending_review", "score": None,
           "submitted_at": _now()}
    p["submissions"].append(rec)
    return rec


def review_project(project_id: str, submission_id: str,
                   score: float, comment: str) -> Optional[Dict[str, Any]]:
    p = STORE.projects.get(project_id)
    if not p:
        return None
    sub = next((s for s in p["submissions"] if s["id"] == submission_id), None)
    if not sub:
        return None
    sub["status"] = "reviewed"
    sub["score"] = score
    sub["comment"] = comment
    sub["reviewed_at"] = _now()
    return sub
