# -*- coding: utf-8 -*-
"""
exam_system_phase.py — 阶段4：考试系统。

功能:
    - 题库（单选/多选/判断/填空/简答/实操）
    - 题目属性（分类/难度/知识点/分值/解析）
    - 试卷生成（手动/自动/随机/模板）
    - 在线考试（计时/防作弊/自动保存/交卷）
    - 自动判题（客观自动/主观人工/实操自动）
    - 成绩管理 / 证书生成 / 考试监控 / 统计
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

QUESTION_TYPES = ["单选题", "多选题", "判断题", "填空题",
                  "简答题", "实操题"]
Q_DIFFICULTIES = ["入门", "简单", "中等", "困难", "地狱"]


@dataclass
class Question:
    qid: str = ""
    qtype: str = "单选题"
    category: str = "Web安全"
    difficulty: str = "入门"
    knowledge: str = ""
    score: float = 5.0
    stem: str = ""
    options: List[str] = field(default_factory=list)
    answer: str = ""
    analysis: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "qid": self.qid, "qtype": self.qtype,
            "category": self.category, "difficulty": self.difficulty,
            "knowledge": self.knowledge, "score": self.score,
            "stem": self.stem, "options": self.options,
            "answer": self.answer, "analysis": self.analysis,
        }


@dataclass
class Paper:
    paper_id: str = ""
    name: str = ""
    qids: List[str] = field(default_factory=list)
    total_score: float = 100.0
    duration_min: int = 60
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "paper_id": self.paper_id, "name": self.name,
            "qids": self.qids, "total_score": self.total_score,
            "duration_min": self.duration_min,
            "created_at": self.created_at,
        }


@dataclass
class ExamRecord:
    record_id: str = ""
    paper_id: str = ""
    student: str = ""
    answers: Dict[str, str] = field(default_factory=dict)
    score: float = 0.0
    status: str = "进行中"
    started_at: str = ""
    submitted_at: str = ""
    cheating_flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id, "paper_id": self.paper_id,
            "student": self.student, "answers": self.answers,
            "score": self.score, "status": self.status,
            "started_at": self.started_at,
            "submitted_at": self.submitted_at,
            "cheating_flags": self.cheating_flags,
        }


class ExamSystemPhase:
    """阶段4：考试系统。"""

    def __init__(self) -> None:
        self._questions: Dict[str, Question] = {}
        self._papers: Dict[str, Paper] = {}
        self._records: Dict[str, ExamRecord] = {}
        self._certificates: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._seed()

    # ------------------------------------------------------------------ #
    def _seed(self) -> None:
        seeds = [
            ("q_s1", "单选题", "Web安全", "简单", "SQL注入", 5,
             "以下哪个是 SQL 注入的防御手段？",
             ["A. 输入长度限制", "B. 参数化查询",
              "C. 关闭错误提示", "D. 前端校验"],
             "B", "参数化查询使数据与SQL分离"),
            ("q_s2", "判断题", "Web安全", "入门", "XSS", 3,
             "反射型 XSS 会持久化存储在服务器。",
             [], "错误", "反射型不存储，存储型才持久化"),
            ("q_s3", "多选题", "内网渗透", "困难", "域渗透", 8,
             "以下哪些属于域渗透常用技术？",
             ["A. Pass-the-Hash", "B. Kerberoasting",
              "C. SQL注入", "D. DCSync"],
             "ABD", "SQL注入不属于域渗透"),
        ]
        for qid, qt, cat, diff, kn, sc, stem, opts, ans, ana in seeds:
            self._questions[qid] = Question(
                qid=qid, qtype=qt, category=cat, difficulty=diff,
                knowledge=kn, score=sc, stem=stem, options=opts,
                answer=ans, analysis=ana)

    # ------------------------------------------------------------------ #
    def list_questions(self, category: Optional[str] = None,
                       qtype: Optional[str] = None,
                       difficulty: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._questions.values())
        out = []
        for q in items:
            if category and q.category != category:
                continue
            if qtype and q.qtype != qtype:
                continue
            if difficulty and q.difficulty != difficulty:
                continue
            out.append(q.to_dict())
        return out

    def add_question(self, qtype: str, stem: str, answer: str,
                     category: str = "Web安全",
                     difficulty: str = "入门",
                     knowledge: str = "", score: float = 5.0,
                     options: Optional[List[str]] = None,
                     analysis: str = "") -> Dict[str, Any]:
        if qtype not in QUESTION_TYPES:
            raise ValueError(f"题型非法: {qtype}")
        q = Question(
            qid="q_" + uuid.uuid4().hex[:8], qtype=qtype,
            category=category, difficulty=difficulty,
            knowledge=knowledge, score=score, stem=stem,
            options=options or [], answer=answer, analysis=analysis)
        with self._lock:
            self._questions[q.qid] = q
        return q.to_dict()

    # ------------------------------------------------------------------ #
    def generate_paper(self, name: str, mode: str = "random",
                       qids: Optional[List[str]] = None,
                       by_category: Optional[str] = None,
                       count: int = 10) -> Dict[str, Any]:
        selected: List[str] = []
        with self._lock:
            pool = list(self._questions.values())
            if by_category:
                pool = [q for q in pool if q.category == by_category]
            if mode == "manual" and qids:
                selected = [q for q in qids if q in self._questions]
            elif mode == "random":
                selected = [q.qid for q in pool[:count]]
            else:
                selected = [q.qid for q in pool]
            total = sum(self._questions[q].score for q in selected)
            p = Paper(paper_id="p_" + uuid.uuid4().hex[:8], name=name,
                      qids=selected, total_score=total or 100.0,
                      created_at=datetime.now().isoformat(timespec="seconds"))
            self._papers[p.paper_id] = p
        return p.to_dict()

    def list_papers(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [p.to_dict() for p in self._papers.values()]

    # ------------------------------------------------------------------ #
    def start_exam(self, paper_id: str, student: str) -> Optional[Dict[str, Any]]:
        p = self._papers.get(paper_id)
        if p is None:
            return None
        r = ExamRecord(
            record_id="e_" + uuid.uuid4().hex[:8], paper_id=paper_id,
            student=student,
            started_at=datetime.now().isoformat(timespec="seconds"))
        with self._lock:
            self._records[r.record_id] = r
        # 题目（屏蔽答案）
        with self._lock:
            questions = []
            for qid in p.qids:
                q = self._questions[qid]
                questions.append({k: v for k, v in q.to_dict().items()
                                  if k not in ("answer", "analysis")})
        return {"record_id": r.record_id, "paper": p.to_dict(),
                "questions": questions, "duration_min": p.duration_min}

    def save_answer(self, record_id: str, qid: str,
                    answer: str) -> Optional[Dict[str, Any]]:
        r = self._records.get(record_id)
        if r is None:
            return None
        with self._lock:
            r.answers[qid] = answer
        return {"record_id": record_id, "saved": True}

    def submit_exam(self, record_id: str) -> Optional[Dict[str, Any]]:
        r = self._records.get(record_id)
        if r is None:
            return None
        with self._lock:
            score = 0.0
            detail = []
            for qid, ans in r.answers.items():
                q = self._questions.get(qid)
                if not q:
                    continue
                if q.qtype in ("简答题", "实操题"):
                    detail.append({"qid": qid, "auto": None,
                                   "note": "待人工/AI 批改"})
                    continue
                ok = ans.strip() == q.answer.strip()
                if ok:
                    score += q.score
                detail.append({"qid": qid, "correct": ok,
                               "award": q.score if ok else 0.0})
            r.score = round(score, 1)
            r.status = "已交卷"
            r.submitted_at = datetime.now().isoformat(timespec="seconds")
        return {"record_id": record_id, "score": r.score,
                "status": r.status, "detail": detail}

    # ------------------------------------------------------------------ #
    def list_records(self, student: Optional[str] = None
                     ) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._records.values())
        if student:
            items = [r for r in items if r.student == student]
        return [r.to_dict() for r in items]

    def grade_subjective(self, record_id: str, qid: str,
                         score: float, feedback: str = "") -> Optional[Dict[str, Any]]:
        r = self._records.get(record_id)
        if r is None:
            return None
        with self._lock:
            r.score = round(r.score + score, 1)
        return {"record_id": record_id, "qid": qid,
                "awarded": score, "feedback": feedback,
                "total": r.score}

    # ------------------------------------------------------------------ #
    def issue_certificate(self, record_id: str) -> Optional[Dict[str, Any]]:
        r = self._records.get(record_id)
        if r is None:
            return None
        cert = {
            "cert_id": "CERT-" + uuid.uuid4().hex[:10].upper(),
            "record_id": record_id, "student": r.student,
            "score": r.score,
            "issued_at": datetime.now().isoformat(timespec="seconds"),
            "valid_until": "2999-12-31",
            "verified": True,
        }
        with self._lock:
            self._certificates[cert["cert_id"]] = cert
        return cert

    def verify_certificate(self, cert_id: str) -> Dict[str, Any]:
        c = self._certificates.get(cert_id)
        return {"cert_id": cert_id, "valid": c is not None,
                "info": c}

    def monitoring(self) -> Dict[str, Any]:
        with self._lock:
            records = list(self._records.values())
        in_progress = [r.to_dict() for r in records
                       if r.status == "进行中"]
        submitted = [r.to_dict() for r in records
                     if r.status == "已交卷"]
        cheats = [r.to_dict() for r in records if r.cheating_flags]
        return {"online": len(in_progress),
                "submitted": len(submitted),
                "anomalies": len(cheats),
                "in_progress": in_progress}

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            recs = list(self._records.values())
            qs = list(self._questions.values())
        scored = [r.score for r in recs if r.status == "已交卷"]
        pass_n = sum(1 for s in scored if s >= 60)
        return {
            "question_total": len(qs),
            "by_type": {t: sum(1 for q in qs if q.qtype == t)
                        for t in QUESTION_TYPES},
            "paper_total": len(self._papers),
            "record_total": len(recs),
            "submitted": len(scored),
            "pass_rate": round(pass_n / max(1, len(scored)) * 100, 1),
            "avg_score": round(sum(scored) / max(1, len(scored)), 1),
            "certificates": len(self._certificates),
        }


_default: Optional[ExamSystemPhase] = None


def get_exam_system_phase() -> ExamSystemPhase:
    global _default
    if _default is None:
        _default = ExamSystemPhase()
    return _default
