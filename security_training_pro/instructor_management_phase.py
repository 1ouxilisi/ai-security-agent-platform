# -*- coding: utf-8 -*-
"""
instructor_management_phase.py — 阶段7：讲师管理。

功能:
    - 讲师注册 / 资质审核
    - 讲师档案（基本/领域/经验/资质/简介）
    - 课程 / 授课记录 / 学员评价
    - 排名 / 等级 / 收益 / 统计
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

INSTRUCTOR_LEVELS = ["实习讲师", "初级讲师", "中级讲师",
                    "高级讲师", "首席讲师"]


@dataclass
class Instructor:
    iid: str = ""
    name: str = ""
    email: str = ""
    domain: str = "Web安全"
    experience_years: int = 3
    certs: List[str] = field(default_factory=list)
    bio: str = ""
    level: str = "初级讲师"
    status: str = "待审核"
    courses: List[str] = field(default_factory=list)
    records: List[Dict[str, Any]] = field(default_factory=list)
    reviews: List[Dict[str, Any]] = field(default_factory=list)
    rating: float = 0.0
    students: int = 0
    revenue: float = 0.0
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "iid": self.iid, "name": self.name, "email": self.email,
            "domain": self.domain,
            "experience_years": self.experience_years,
            "certs": self.certs, "bio": self.bio, "level": self.level,
            "status": self.status, "courses": self.courses,
            "records": self.records, "reviews": self.reviews,
            "rating": round(self.rating, 2), "students": self.students,
            "revenue": round(self.revenue, 2),
            "created_at": self.created_at,
        }


class InstructorManagementPhase:
    """阶段7：讲师管理。"""

    def __init__(self) -> None:
        self._insts: Dict[str, Instructor] = {}
        self._lock = threading.Lock()
        self._seed()

    # ------------------------------------------------------------------ #
    def _seed(self) -> None:
        self._insts["ins_ai"] = Instructor(
            iid="ins_ai", name="AI 讲师", email="ai@sec.io",
            domain="Web安全", experience_years=10,
            certs=["OSCP", "CISSP"], bio="AI 安全训练官",
            level="首席讲师", status="已通过",
            rating=4.8, students=1200, revenue=88000.0,
            created_at=datetime.now().isoformat(timespec="seconds"))

    # ------------------------------------------------------------------ #
    def register(self, name: str, email: str = "",
                 domain: str = "Web安全", experience_years: int = 3,
                 certs: Optional[List[str]] = None,
                 bio: str = "") -> Dict[str, Any]:
        ins = Instructor(
            iid="ins_" + uuid.uuid4().hex[:8], name=name, email=email,
            domain=domain, experience_years=experience_years,
            certs=certs or [], bio=bio,
            created_at=datetime.now().isoformat(timespec="seconds"))
        with self._lock:
            self._insts[ins.iid] = ins
        return ins.to_dict()

    def approve(self, iid: str, approved: bool = True) -> Optional[Dict[str, Any]]:
        ins = self._insts.get(iid)
        if ins is None:
            return None
        with self._lock:
            ins.status = "已通过" if approved else "已拒绝"
        return ins.to_dict()

    def set_level(self, iid: str, level: str) -> Optional[Dict[str, Any]]:
        ins = self._insts.get(iid)
        if ins is None or level not in INSTRUCTOR_LEVELS:
            return None
        with self._lock:
            ins.level = level
        return ins.to_dict()

    # ------------------------------------------------------------------ #
    def list_instructors(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [i.to_dict() for i in self._insts.values()]

    def get_instructor(self, iid: str) -> Optional[Dict[str, Any]]:
        ins = self._insts.get(iid)
        return ins.to_dict() if ins else None

    def add_course(self, iid: str, course_id: str) -> Optional[Dict[str, Any]]:
        ins = self._insts.get(iid)
        if ins is None:
            return None
        with self._lock:
            if course_id not in ins.courses:
                ins.courses.append(course_id)
        return ins.to_dict()

    def add_record(self, iid: str, content: str,
                   duration_min: int = 60,
                   feedback: str = "") -> Optional[Dict[str, Any]]:
        ins = self._insts.get(iid)
        if ins is None:
            return None
        with self._lock:
            ins.records.append({
                "content": content, "duration_min": duration_min,
                "feedback": feedback,
                "at": datetime.now().isoformat(timespec="seconds")})
        return ins.to_dict()

    def add_review(self, iid: str, student: str, rating: int,
                   comment: str = "") -> Optional[Dict[str, Any]]:
        ins = self._insts.get(iid)
        if ins is None:
            return None
        with self._lock:
            ins.reviews.append({"student": student, "rating": rating,
                                "comment": comment,
                                "at": datetime.now().isoformat(
                                    timespec="seconds")})
            ins.rating = (sum(r["rating"] for r in ins.reviews)
                          / len(ins.reviews))
        return ins.to_dict()

    # ------------------------------------------------------------------ #
    def rank(self, by: str = "rating") -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._insts.values())
        key_map = {"rating": lambda x: x.rating,
                   "students": lambda x: x.students,
                   "revenue": lambda x: x.revenue}
        kf = key_map.get(by, lambda x: x.rating)
        items.sort(key=kf, reverse=True)
        return [{"rank": i + 1, "iid": ins.iid, "name": ins.name,
                 "rating": ins.rating, "students": ins.students,
                 "revenue": ins.revenue, "level": ins.level}
                for i, ins in enumerate(items)]

    def settle(self, iid: str, amount: float) -> Optional[Dict[str, Any]]:
        ins = self._insts.get(iid)
        if ins is None:
            return None
        with self._lock:
            ins.revenue += amount
        return {"iid": iid, "settled": amount,
                "total_revenue": ins.revenue}

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            ins = list(self._insts.values())
        return {
            "total": len(ins),
            "by_level": {lv: sum(1 for i in ins if i.level == lv)
                         for lv in INSTRUCTOR_LEVELS},
            "by_status": {st: sum(1 for i in ins if i.status == st)
                          for st in ("待审核", "已通过", "已拒绝")},
            "avg_rating": round(
                sum(i.rating for i in ins) / max(1, len(ins)), 2),
            "total_revenue": round(sum(i.revenue for i in ins), 2),
        }


_default: Optional[InstructorManagementPhase] = None


def get_instructor_management_phase() -> InstructorManagementPhase:
    global _default
    if _default is None:
        _default = InstructorManagementPhase()
    return _default
