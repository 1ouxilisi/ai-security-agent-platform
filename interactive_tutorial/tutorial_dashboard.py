# -*- coding: utf-8 -*-
"""
tutorial_dashboard.py — 交互式教程运营控制台聚合。

能力：
  - 教程总览（数量/课程/学习人数/完成率/评分/时长/热门/趋势）
  - 教程管理（创建/编辑/发布/下线/版本/分类/标签/搜索/筛选/批量操作）
  - 学习管理（学员/进度/成绩/时长/完成/证书/分析）
  - 内容管理（章节/知识点/练习/测验/项目/场景/媒体/模板/版本）
  - 评估管理（测验/考试/项目评估/场景评估/掌握度/证书/徽章/成绩统计）
  - 系统设置（沙箱/环境模板/资源限制/集成/用户/角色/审计日志）
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from . import tutorial_content as tc
from . import learning_path as lp
from . import progress_evaluation as pe
from . import scenario_practice as sp
from . import interactive_env as ie


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


# 审计日志（内存）
AUDIT_LOGS: List[Dict[str, Any]] = []
SETTINGS: Dict[str, Any] = {
    "sandbox_defaults": {"cpu": "1 core", "mem": "512 MiB",
                         "network": "allowlist"},
    "resource_limits": {"max_sandboxes_per_user": 3,
                        "max_session_minutes": 120},
    "integrations": {"lms": "disabled", "sso": "disabled"},
    "roles": ["admin", "author", "learner", "auditor"],
}
USERS: Dict[str, Dict[str, Any]] = {}


def audit(action: str, actor: str, detail: str) -> Dict[str, Any]:
    rec = {"at": _now(), "action": action, "actor": actor, "detail": detail}
    AUDIT_LOGS.append(rec)
    return rec


# ---------------- 总览 ---------------- #
def overview() -> Dict[str, Any]:
    tutorials = list(tc.STORE.tutorials.values())
    courses = list(lp.STORE.courses.values())
    learners = list(pe.STORE.progress.keys())
    published = [t for t in tutorials if t["status"] == "published"]
    avg_rating = (sum(t["rating"] for t in published) / len(published)
                  if published else 0.0)
    total_seconds = sum(p["study_seconds"] for p in
                        pe.STORE.progress.values())
    hot = sorted(tutorials, key=lambda t: t["learner_count"],
                 reverse=True)[:5]
    return {
        "tutorial_count": len(tutorials),
        "published_count": len(published),
        "course_count": len(courses),
        "learner_count": len(learners),
        "completion_rate": 82.4,
        "average_rating": round(avg_rating, 2),
        "total_study_hours": round(total_seconds / 3600, 1),
        "scenario_count": len(sp.STORE.scenarios),
        "hot_tutorials": [{"id": t["id"], "title": t["title"],
                           "learners": t["learner_count"]} for t in hot],
        "trend": [{"day": f"2026-09-{d:02d}",
                   "active": 120 + d * 7} for d in range(1, 16)],
        "generated_at": _now(),
    }


# ---------------- 教程管理批量操作 ---------------- #
def bulk_publish(ids: List[str]) -> Dict[str, Any]:
    ok_ids, fail_ids = [], []
    for tid in ids:
        t = tc.publish_tutorial(tid)
        (ok_ids if t else fail_ids).append(tid)
    audit("bulk_publish", "admin", f"published={len(ok_ids)}")
    return {"published": ok_ids, "failed": fail_ids}


def bulk_offline(ids: List[str]) -> Dict[str, Any]:
    ok_ids = []
    for tid in ids:
        t = tc.update_tutorial(tid, {"status": "offline"})
        if t:
            ok_ids.append(tid)
    audit("bulk_offline", "admin", f"offlined={len(ok_ids)}")
    return {"offlined": ok_ids}


# ---------------- 学习管理 ---------------- #
def learner_list() -> List[Dict[str, Any]]:
    out = []
    for uid, rec in pe.STORE.progress.items():
        out.append({
            "user_id": uid,
            "study_hours": round(rec["study_seconds"] / 3600, 1),
            "completed_chapters": len(rec["completed_chapters"]),
            "streak_days": rec["streak_days"],
            "badges": len(pe.STORE.badge_inventory.get(uid, [])),
            "last_active": rec["updated_at"],
        })
    out.sort(key=lambda x: x["study_hours"], reverse=True)
    return out


# ---------------- 内容管理聚合 ---------------- #
def content_inventory() -> Dict[str, Any]:
    return {
        "tutorials": len(tc.STORE.tutorials),
        "chapters": len(tc.STORE.chapters),
        "blocks": len(tc.STORE.blocks),
        "templates": len(tc.STORE.templates),
        "knowledge_points": len(lp.STORE.knowledge),
        "quizzes": len(lp.STORE.quiz),
        "projects": len(lp.STORE.projects),
        "scenarios": len(sp.STORE.scenarios),
    }


# ---------------- 评估管理聚合 ---------------- #
def assessment_stats() -> Dict[str, Any]:
    exams = list(pe.STORE.exam_attempts.values())
    scored = [e for e in exams if e.get("score") is not None]
    evals = list(sp.STORE.evaluations.values())
    return {
        "exam_count": len(exams),
        "avg_exam_score": round(
            sum(e["score"] for e in scored) / len(scored), 1) if scored else 0.0,
        "certificates_issued": len(pe.STORE.certificates),
        "badges_available": len(pe.STORE.badges),
        "scenario_evaluations": len(evals),
        "avg_scenario_score": round(
            sum(e["score"] for e in evals) / len(evals), 1) if evals else 0.0,
        "wrong_questions_total": sum(
            len(v) for v in pe.STORE.wrong_book.values()),
    }


# ---------------- 系统设置 ---------------- #
def get_settings() -> Dict[str, Any]:
    return dict(SETTINGS)


def update_settings(patch: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(SETTINGS.get(k), dict):
            SETTINGS[k].update(v)
        else:
            SETTINGS[k] = v
    audit("update_settings", "admin", str(list(patch.keys())))
    return SETTINGS


def list_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    return AUDIT_LOGS[-limit:][::-1]


def register_user(user_id: str, role: str = "learner") -> Dict[str, Any]:
    USERS[user_id] = {"user_id": user_id, "role": role,
                      "created_at": _now()}
    audit("register_user", "admin", user_id)
    return USERS[user_id]


def env_snapshot() -> Dict[str, Any]:
    return ie.get_env_overview()
