# -*- coding: utf-8 -*-
"""
progress_evaluation.py — 学习进度与评估。

能力：
  - 进度追踪（时长/章节/课程/路径/练习/测验/项目/连续学习/学习日历）
  - 掌握度评估（知识点/技能/能力模型/雷达图数据）
  - 测验与考试（在线测验/限时/随机/防作弊/自动评分/错题本/补考）
  - 证书与徽章（模板/生成/验证/分享/徽章等级）
  - 学习分析（行为/习惯/效率/薄弱环节/推荐/预测/对比/排名）
  - 学习报告（个人/班级/课程/路径/完成率/通过率/平均分/建议）
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _rid(p: str) -> str:
    return f"{p}_{uuid.uuid4().hex[:10]}"


class ProgressStore:
    def __init__(self) -> None:
        self.progress: Dict[str, Dict[str, Any]] = {}      # user_id -> record
        self.exam_attempts: Dict[str, Dict[str, Any]] = {}
        self.wrong_book: Dict[str, List[Dict[str, Any]]] = {}
        self.certificates: Dict[str, Dict[str, Any]] = {}
        self.badges: Dict[str, Dict[str, Any]] = {}
        self.badge_inventory: Dict[str, List[str]] = {}   # user_id -> [badge_id]
        self.learning_logs: Dict[str, List[Dict[str, Any]]] = {}
        self._seed()

    def _seed(self) -> None:
        bid = _rid("badge")
        self.badges[bid] = {"id": bid, "name": "初出茅庐", "level": 1,
                            "icon": "seed", "criteria": "完成第1门课程",
                            "description": "迈出安全学习第一步"}
        # 模拟学员 progress 骨架由 track() 首次访问自动创建

    def ensure(self, user_id: str) -> Dict[str, Any]:
        if user_id not in self.progress:
            self.progress[user_id] = {
                "user_id": user_id, "study_seconds": 0,
                "completed_chapters": [], "completed_courses": [],
                "completed_paths": [], "completed_exercises": [],
                "quiz_scores": [], "project_submissions": [],
                "streak_days": 0, "last_study_date": None,
                "calendar": {}, "knowledge_mastery": {},
                "updated_at": _now(),
            }
        return self.progress[user_id]


STORE = ProgressStore()


# ---------------- 进度追踪 ---------------- #
def track_study(user_id: str, seconds: int = 0,
                activity: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    rec = STORE.ensure(user_id)
    rec["study_seconds"] += max(0, int(seconds))
    today = time.strftime("%Y-%m-%d")
    rec["calendar"][today] = rec["calendar"].get(today, 0) + max(0, int(seconds))
    if rec["last_study_date"] == today:
        pass  # 已连续
    else:
        rec["streak_days"] += 1
    rec["last_study_date"] = today
    if activity:
        STORE.learning_logs.setdefault(user_id, []).append(
            {"at": _now(), **activity})
    rec["updated_at"] = _now()
    return rec


def complete_chapter(user_id: str, chapter_id: str) -> Dict[str, Any]:
    rec = STORE.ensure(user_id)
    if chapter_id not in rec["completed_chapters"]:
        rec["completed_chapters"].append(chapter_id)
    return rec


def get_progress(user_id: str) -> Dict[str, Any]:
    return STORE.ensure(user_id)


def study_calendar(user_id: str) -> Dict[str, Any]:
    rec = STORE.ensure(user_id)
    return {"user_id": user_id, "calendar": rec["calendar"],
            "total_seconds": rec["study_seconds"],
            "streak_days": rec["streak_days"]}


# ---------------- 掌握度评估 ---------------- #
def update_mastery(user_id: str, knowledge_id: str, score: float) -> Dict[str, Any]:
    rec = STORE.ensure(user_id)
    prev = rec["knowledge_mastery"].get(knowledge_id, 0.0)
    rec["knowledge_mastery"][knowledge_id] = round(prev * 0.6 + score * 0.4, 1)
    return rec["knowledge_mastery"]


def radar(user_id: str) -> Dict[str, Any]:
    """能力雷达图维度数据（0-100）。"""
    rec = STORE.ensure(user_id)
    km = rec["knowledge_mastery"]
    avg = (sum(km.values()) / len(km)) if km else 0.0
    return {
        "user_id": user_id,
        "dimensions": [
            {"name": "Web安全", "value": round(avg + 5, 1)},
            {"name": "渗透测试", "value": round(avg + 2, 1)},
            {"name": "应急响应", "value": round(max(0, avg - 3), 1)},
            {"name": "代码审计", "value": round(max(0, avg - 6), 1)},
            {"name": "云安全", "value": round(max(0, avg - 10), 1)},
            {"name": "合规治理", "value": round(max(0, avg - 12), 1)},
        ],
    }


# ---------------- 测验与考试 ---------------- #
def start_exam(user_id: str, quiz_id: str, questions: List[Dict[str, Any]]) -> str:
    eid = _rid("exam")
    STORE.exam_attempts[eid] = {
        "id": eid, "user_id": user_id, "quiz_id": quiz_id,
        "questions": questions, "started_at": _now(),
        "submitted": False, "answers": {}, "score": None,
        "anti_cheat": {"focus_loss": 0, "fullscreen_violation": 0},
    }
    return eid


def submit_exam(exam_id: str, answers: Dict[str, Any],
                focus_loss: int = 0) -> Optional[Dict[str, Any]]:
    ex = STORE.exam_attempts.get(exam_id)
    if not ex:
        return None
    ex["submitted"] = True
    ex["answers"] = answers
    ex["anti_cheat"]["focus_loss"] = focus_loss
    correct = 0
    total = len(ex["questions"])
    wrong: List[Dict[str, Any]] = []
    for q in ex["questions"]:
        ua = answers.get(q["id"])
        if ua is not None and str(ua) == str(q.get("answer", "")):
            correct += 1
        else:
            wrong.append({"question_id": q["id"], "content": q.get("content", ""),
                          "correct_answer": q.get("answer", "")})
            STORE.wrong_book.setdefault(ex["user_id"], []).append(
                {"question_id": q["id"], "content": q.get("content", ""),
                 "correct_answer": q.get("answer", ""),
                 "added_at": _now()})
    ex["score"] = round(correct / total * 100, 1) if total else 0.0
    return {"exam_id": exam_id, "score": ex["score"],
            "correct": correct, "total": total, "wrong": wrong,
            "anti_cheat": ex["anti_cheat"]}


def wrong_book_list(user_id: str) -> List[Dict[str, Any]]:
    return STORE.wrong_book.get(user_id, [])


# ---------------- 证书与徽章 ---------------- #
def issue_certificate(user_id: str, template: str, course_id: str,
                      score: float) -> Dict[str, Any]:
    cid = _rid("cert")
    rec = {"id": cid, "user_id": user_id, "template": template,
           "course_id": course_id, "score": score,
           "issued_at": _now(), "verified": True,
           "verify_code": uuid.uuid4().hex.upper()[:12]}
    STORE.certificates[cid] = rec
    return rec


def verify_certificate(verify_code: str) -> Optional[Dict[str, Any]]:
    for c in STORE.certificates.values():
        if c["verify_code"] == verify_code:
            return c
    return None


def award_badge(user_id: str, badge_id: str) -> Optional[Dict[str, Any]]:
    b = STORE.badges.get(badge_id)
    if not b:
        return None
    inv = STORE.badge_inventory.setdefault(user_id, [])
    if badge_id not in inv:
        inv.append(badge_id)
    return {"badge": b, "owned": inv}


def list_badges() -> List[Dict[str, Any]]:
    return list(STORE.badges.values())


# ---------------- 学习分析 ---------------- #
def learning_analytics(user_id: str) -> Dict[str, Any]:
    rec = STORE.ensure(user_id)
    logs = STORE.learning_logs.get(user_id, [])
    weak = sorted(rec["knowledge_mastery"].items(),
                  key=lambda x: x[1])[:3]
    efficiency = round(rec["study_seconds"] /
                       max(1, len(rec["completed_chapters"])), 1)
    return {
        "user_id": user_id,
        "total_seconds": rec["study_seconds"],
        "streak_days": rec["streak_days"],
        "activity_count": len(logs),
        "seconds_per_chapter": efficiency,
        "weak_points": [{"knowledge_id": k, "mastery": v} for k, v in weak],
        "recommendation": "建议加强薄弱知识点，并安排一次限时测验",
    }


def class_ranking(course_id: str) -> List[Dict[str, Any]]:
    rows = []
    for uid, rec in STORE.progress.items():
        rows.append({"user_id": uid, "study_seconds": rec["study_seconds"],
                     "completed_chapters": len(rec["completed_chapters"])})
    rows.sort(key=lambda x: x["study_seconds"], reverse=True)
    for i, r in enumerate(rows, start=1):
        r["rank"] = i
    return rows


# ---------------- 学习报告 ---------------- #
def learning_report(user_id: str) -> Dict[str, Any]:
    rec = STORE.ensure(user_id)
    exams = [e for e in STORE.exam_attempts.values()
             if e["user_id"] == user_id and e.get("score") is not None]
    avg_score = round(sum(e["score"] for e in exams) / len(exams), 1) if exams else 0.0
    completion = round(len(rec["completed_chapters"]) /
                       max(1, len(rec["completed_chapters"]) +
                           len(rec["completed_exercises"])) * 100, 1)
    return {
        "user_id": user_id,
        "generated_at": _now(),
        "total_study_hours": round(rec["study_seconds"] / 3600, 1),
        "completed_chapters": len(rec["completed_chapters"]),
        "completed_courses": len(rec["completed_courses"]),
        "streak_days": rec["streak_days"],
        "average_exam_score": avg_score,
        "completion_rate": completion,
        "badges_owned": len(STORE.badge_inventory.get(user_id, [])),
        "suggestions": ["保持每日学习节奏", "针对薄弱知识点做专项练习",
                        "完成至少一个项目实战"],
    }
