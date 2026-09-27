# -*- coding: utf-8 -*-
"""
student_management_phase.py — 阶段6：学员管理。

功能:
    - 学员注册（个人/企业/邀请/批量导入）
    - 学员档案（基本/学习/考试/证书/能力）
    - 学习进度 / 考试成绩 / 能力评估
    - 证书管理 / 学习行为分析 / 状态机 / 分组
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

STUDENT_STATUS = ["活跃", "休眠", "已结业", "已退学"]
DOMAINS = ["Web安全", "内网渗透", "移动安全", "云安全",
           "密码学", "逆向工程", "社会工程学", "安全开发"]


@dataclass
class Student:
    sid: str = ""
    name: str = ""
    email: str = ""
    org: str = ""
    source: str = "个人注册"
    status: str = "活跃"
    courses: Dict[str, float] = field(default_factory=dict)
    exams: List[Dict[str, Any]] = field(default_factory=list)
    certs: List[str] = field(default_factory=list)
    ability: Dict[str, float] = field(default_factory=dict)
    study_minutes: int = 0
    group: str = ""
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sid": self.sid, "name": self.name, "email": self.email,
            "org": self.org, "source": self.source, "status": self.status,
            "courses": self.courses, "exams": self.exams,
            "certs": self.certs, "ability": self.ability,
            "study_minutes": self.study_minutes, "group": self.group,
            "created_at": self.created_at,
        }


class StudentManagementPhase:
    """阶段6：学员管理。"""

    def __init__(self) -> None:
        self._students: Dict[str, Student] = {}
        self._groups: Dict[str, List[str]] = {}
        self._lock = threading.Lock()
        self._seed()

    # ------------------------------------------------------------------ #
    def _seed(self) -> None:
        for i, nm in enumerate(["张伟", "李娜", "王强", "刘洋"]):
            sid = f"stu_{1000+i}"
            ab = {d: 30.0 + i * 10 for d in DOMAINS}
            self._students[sid] = Student(
                sid=sid, name=nm, email=f"{nm}@corp.com",
                org="安全部", source="企业注册", status="活跃",
                ability=ab, study_minutes=1200 + i * 300,
                group="Web组",
                created_at=datetime.now().isoformat(timespec="seconds"))

    # ------------------------------------------------------------------ #
    def register(self, name: str, email: str = "", org: str = "",
                 source: str = "个人注册") -> Dict[str, Any]:
        s = Student(
            sid="stu_" + uuid.uuid4().hex[:8], name=name, email=email,
            org=org, source=source,
            ability={d: 0.0 for d in DOMAINS},
            created_at=datetime.now().isoformat(timespec="seconds"))
        with self._lock:
            self._students[s.sid] = s
        return s.to_dict()

    def bulk_import(self, names: List[str]) -> Dict[str, Any]:
        created = []
        for nm in names:
            created.append(self.register(nm, source="批量导入")["sid"])
        return {"imported": len(created), "sids": created}

    # ------------------------------------------------------------------ #
    def list_students(self, status: Optional[str] = None,
                      group: Optional[str] = None,
                      keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._students.values())
        out = []
        for s in items:
            if status and s.status != status:
                continue
            if group and s.group != group:
                continue
            if keyword and keyword not in s.name:
                continue
            out.append(s.to_dict())
        return out

    def get_student(self, sid: str) -> Optional[Dict[str, Any]]:
        s = self._students.get(sid)
        return s.to_dict() if s else None

    def update_progress(self, sid: str, course_id: str,
                        progress: float, minutes: int = 0) -> Optional[Dict[str, Any]]:
        s = self._students.get(sid)
        if s is None:
            return None
        with self._lock:
            s.courses[course_id] = max(0.0, min(100.0, progress))
            s.study_minutes += minutes
        return {"sid": sid, "course_id": course_id, "progress": progress,
                "study_minutes": s.study_minutes}

    def add_exam_score(self, sid: str, paper: str,
                       score: float) -> Optional[Dict[str, Any]]:
        s = self._students.get(sid)
        if s is None:
            return None
        with self._lock:
            s.exams.append({"paper": paper, "score": score,
                            "at": datetime.now().isoformat(timespec="seconds")})
        return {"sid": sid, "exams": s.exams}

    def issue_cert(self, sid: str, cert_id: str) -> Optional[Dict[str, Any]]:
        s = self._students.get(sid)
        if s is None:
            return None
        with self._lock:
            if cert_id not in s.certs:
                s.certs.append(cert_id)
        return {"sid": sid, "certs": s.certs}

    def set_status(self, sid: str, status: str) -> Optional[Dict[str, Any]]:
        s = self._students.get(sid)
        if s is None or status not in STUDENT_STATUS:
            return None
        with self._lock:
            s.status = status
        return s.to_dict()

    # ------------------------------------------------------------------ #
    def ability_report(self, sid: str) -> Dict[str, Any]:
        s = self._students.get(sid)
        if s is None:
            return {}
        weak = sorted(s.ability.items(), key=lambda x: x[1])[:3]
        strong = sorted(s.ability.items(), key=lambda x: -x[1])[:3]
        return {
            "sid": sid, "name": s.name,
            "ability": s.ability,
            "weakest": [{"domain": d, "score": v} for d, v in weak],
            "strongest": [{"domain": d, "score": v} for d, v in strong],
            "suggestion": f"建议优先补强 {weak[0][0]}",
        }

    def behavior_analysis(self, sid: str) -> Dict[str, Any]:
        s = self._students.get(sid)
        if s is None:
            return {}
        avg = s.study_minutes / max(1, 90)
        return {"sid": sid, "total_minutes": s.study_minutes,
                "avg_daily": round(avg, 1),
                "habit": "规律" if avg > 20 else "碎片化",
                "completed_courses": sum(
                    1 for v in s.courses.values() if v >= 100)}

    def assign_group(self, sid: str, group: str) -> Optional[Dict[str, Any]]:
        s = self._students.get(sid)
        if s is None:
            return None
        with self._lock:
            s.group = group
            self._groups.setdefault(group, [])
            if sid not in self._groups[group]:
                self._groups[group].append(sid)
        return {"sid": sid, "group": group}

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            ss = list(self._students.values())
        return {
            "total": len(ss),
            "by_status": {st: sum(1 for s in ss if s.status == st)
                          for st in STUDENT_STATUS},
            "by_group": {g: len(v) for g, v in self._groups.items()},
            "total_study_minutes": sum(s.study_minutes for s in ss),
            "total_certs": sum(len(s.certs) for s in ss),
            "domains": DOMAINS,
        }


_default: Optional[StudentManagementPhase] = None


def get_student_management_phase() -> StudentManagementPhase:
    global _default
    if _default is None:
        _default = StudentManagementPhase()
    return _default
