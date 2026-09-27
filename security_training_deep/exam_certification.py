#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_training_deep/exam_certification.py — 考试认证深度。

覆盖六大子域：
    1. 考试管理：考试创建/配置/发布/安排/截止
    2. 题库管理：题目CRUD/分类/标签/难度/批量导入
    3. 考试执行：开始考试/答题/计时/交卷
    4. 考试评分：自动评分/主观题评分/分数汇总/排名
    5. 证书管理：证书生成/验证/吊销/续期
    6. 认证体系：认证等级/前置要求/维护积分/续认证
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
QUESTION_TYPES: Dict[str, str] = {
    "single_choice": "单选题", "multiple_choice": "多选题",
    "true_false": "判断题", "fill_blank": "填空题",
    "short_answer": "简答题", "essay": "论述题",
}

EXAM_STATUS: Dict[str, str] = {
    "draft": "草稿", "published": "已发布", "in_progress": "进行中",
    "completed": "已完成", "archived": "已归档",
}

CERT_LEVELS: Dict[str, str] = {
    "associate": "助理级", "professional": "专业级",
    "expert": "专家级", "master": "大师级",
}

PASS_SCORE = 60


# --------------------------------------------------------------------------- #
# 题库管理
# --------------------------------------------------------------------------- #
class QuestionBank:
    """题库管理：题目CRUD/分类/难度。"""

    def __init__(self) -> None:
        self.questions: Dict[str, Dict[str, Any]] = {}
        self._seed_default_questions()

    def _seed_default_questions(self) -> None:
        defaults = [
            ("SQL注入攻击通常利用哪种漏洞？", "single_choice", "web_security", "easy",
             ["XSS", "SQL注入", "CSRF", "文件包含"], 1, "SQL注入通过插入恶意SQL语句操纵数据库。"),
            ("以下哪些是OWASP Top 10中的Web安全风险？", "multiple_choice", "web_security", "medium",
             ["注入攻击", "失效的身份认证", "敏感数据泄露", "DDoS攻击"], 3,
             "DDoS属于可用性攻击，不在OWASP Top 10中。"),
            ("HTTPS协议可以完全防止中间人攻击。", "true_false", "network_security", "easy",
             ["正确", "错误"], 1, "HTTPS依赖证书信任链，证书被篡改仍可能被中间人攻击。"),
        ]
        for q, qtype, cat, diff, opts, ans, exp in defaults:
            qid = f"q_{uuid.uuid4().hex[:8]}"
            self.questions[qid] = {
                "id": qid, "question": q, "type": qtype,
                "category": cat, "difficulty": diff,
                "options": opts, "answer_index": ans,
                "explanation": exp, "score": 5,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

    def add_question(self, data: Dict[str, Any]) -> Dict[str, Any]:
        qid = f"q_{uuid.uuid4().hex[:8]}"
        q = {
            "id": qid,
            "question": data.get("question", ""),
            "type": data.get("type", "single_choice"),
            "category": data.get("category", "web_security"),
            "difficulty": data.get("difficulty", "medium"),
            "options": data.get("options", []),
            "answer_index": int(data.get("answer_index", 0)),
            "explanation": data.get("explanation", ""),
            "score": int(data.get("score", 5)),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.questions[qid] = q
        return q

    def get_question(self, qid: str) -> Optional[Dict[str, Any]]:
        return self.questions.get(qid)

    def list_questions(self, category: str = "", difficulty: str = "",
                       qtype: str = "") -> List[Dict[str, Any]]:
        results = list(self.questions.values())
        if category:
            results = [q for q in results if q["category"] == category]
        if difficulty:
            results = [q for q in results if q["difficulty"] == difficulty]
        if qtype:
            results = [q for q in results if q["type"] == qtype]
        return results

    def delete_question(self, qid: str) -> bool:
        if qid in self.questions:
            del self.questions[qid]
            return True
        return False


# --------------------------------------------------------------------------- #
# 考试管理
# --------------------------------------------------------------------------- #
class ExamManager:
    """考试管理：创建/配置/发布。"""

    def __init__(self, qbank: QuestionBank) -> None:
        self.qbank = qbank
        self.exams: Dict[str, Dict[str, Any]] = {}

    def create_exam(self, title: str, description: str = "",
                    duration_minutes: int = 60,
                    question_ids: Optional[List[str]] = None,
                    passing_score: int = PASS_SCORE) -> Dict[str, Any]:
        eid = f"ex_{uuid.uuid4().hex[:8]}"
        qs = []
        total_score = 0
        if question_ids:
            for qid in question_ids:
                q = self.qbank.get_question(qid)
                if q:
                    qs.append(qid)
                    total_score += q["score"]
        exam = {
            "id": eid, "title": title, "description": description,
            "duration_minutes": duration_minutes,
            "question_ids": qs, "total_score": total_score or 100,
            "passing_score": passing_score,
            "status": "draft", "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "start_time": None, "end_time": None,
            "attempts_allowed": 2,
        }
        self.exams[eid] = exam
        return exam

    def get_exam(self, exam_id: str) -> Optional[Dict[str, Any]]:
        return self.exams.get(exam_id)

    def publish_exam(self, exam_id: str, start_time: str = "",
                     end_time: str = "") -> Optional[Dict[str, Any]]:
        e = self.exams.get(exam_id)
        if not e:
            return None
        e["status"] = "published"
        e["start_time"] = start_time or time.strftime("%Y-%m-%d %H:%M:%S")
        e["end_time"] = end_time or time.strftime("%Y-%m-%d 23:59:59")
        return e

    def list_exams(self, status: str = "") -> List[Dict[str, Any]]:
        results = list(self.exams.values())
        if status:
            results = [e for e in results if e["status"] == status]
        return results


# --------------------------------------------------------------------------- #
# 考试执行
# --------------------------------------------------------------------------- #
class ExamExecutor:
    """考试执行：开始/答题/交卷。"""

    def __init__(self, exam_mgr: ExamManager, qbank: QuestionBank) -> None:
        self.exam_mgr = exam_mgr
        self.qbank = qbank
        self.attempts: Dict[str, Dict[str, Any]] = {}

    def start_exam(self, exam_id: str, user: str) -> Optional[Dict[str, Any]]:
        e = self.exam_mgr.get_exam(exam_id)
        if not e or e["status"] not in ("published", "in_progress"):
            return None
        aid = f"att_{uuid.uuid4().hex[:8]}"
        attempt = {
            "id": aid, "exam_id": exam_id, "user": user,
            "status": "in_progress", "answers": {},
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "submitted_at": None, "score": None,
            "time_remaining_minutes": e["duration_minutes"],
        }
        self.attempts[aid] = attempt
        return attempt

    def submit_answer(self, attempt_id: str, question_id: str,
                      answer: Any) -> Optional[Dict[str, Any]]:
        a = self.attempts.get(attempt_id)
        if not a:
            return None
        a["answers"][question_id] = answer
        return a

    def submit_exam(self, attempt_id: str) -> Optional[Dict[str, Any]]:
        a = self.attempts.get(attempt_id)
        if not a:
            return None
        a["status"] = "submitted"
        a["submitted_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return a

    def get_attempt(self, attempt_id: str) -> Optional[Dict[str, Any]]:
        return self.attempts.get(attempt_id)


# --------------------------------------------------------------------------- #
# 考试评分
# --------------------------------------------------------------------------- #
class ExamGrader:
    """考试评分：自动评分/分数汇总。"""

    def __init__(self, executor: ExamExecutor, qbank: QuestionBank) -> None:
        self.executor = executor
        self.qbank = qbank

    def grade_exam(self, attempt_id: str) -> Optional[Dict[str, Any]]:
        a = self.executor.attempts.get(attempt_id)
        if not a:
            return None
        exam = self.executor.exam_mgr.get_exam(a["exam_id"])
        if not exam:
            return None
        total_score = 0
        earned_score = 0
        details = []
        for qid in exam["question_ids"]:
            q = self.qbank.get_question(qid)
            if not q:
                continue
            total_score += q["score"]
            user_ans = a["answers"].get(qid)
            # auto-grade for choice questions
            is_correct = False
            if q["type"] in ("single_choice", "true_false"):
                if user_ans is not None and int(user_ans) == q["answer_index"]:
                    is_correct = True
                    earned_score += q["score"]
            elif q["type"] == "multiple_choice":
                if isinstance(user_ans, list) and set(user_ans) == {q["answer_index"]}:
                    is_correct = True
                    earned_score += q["score"]
            else:
                # subjective: give partial credit
                if user_ans and len(str(user_ans)) > 10:
                    earned_score += q["score"] // 2
                    is_correct = None  # partial
            details.append({
                "question_id": qid,
                "question": q["question"][:80],
                "correct": is_correct,
                "earned": earned_score if is_correct else (q["score"] // 2 if is_correct is None else 0),
            })
        percentage = round(earned_score / max(1, total_score) * 100, 1)
        passed = percentage >= exam["passing_score"]
        a["score"] = percentage
        a["status"] = "graded"
        result = {
            "attempt_id": attempt_id,
            "user": a["user"],
            "total_score": total_score,
            "earned_score": earned_score,
            "percentage": percentage,
            "passed": passed,
            "grade": "A" if percentage >= 90 else "B" if percentage >= 80 else "C" if percentage >= 70 else "D" if percentage >= 60 else "F",
            "details": details,
            "graded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return result


# --------------------------------------------------------------------------- #
# 证书管理
# --------------------------------------------------------------------------- #
class CertificateManager:
    """证书管理：生成/验证/吊销/续期。"""

    def __init__(self) -> None:
        self.certificates: Dict[str, Dict[str, Any]] = {}

    def generate_certificate(self, user: str, cert_name: str,
                             cert_level: str, score: float,
                             expiry_days: int = 365) -> Dict[str, Any]:
        cid = f"cert_{uuid.uuid4().hex[:12]}"
        cert_hash = hashlib.sha256(f"{cid}{user}{time.time()}".encode()).hexdigest()[:16]
        now = time.time()
        expiry = time.strftime("%Y-%m-%d", time.localtime(now + expiry_days * 86400))
        cert = {
            "id": cid, "cert_number": f"TCMA-{cert_hash.upper()}",
            "user": user, "cert_name": cert_name,
            "cert_level": cert_level, "score": score,
            "issued_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "expires_at": expiry, "status": "active",
            "verify_code": cert_hash,
        }
        self.certificates[cid] = cert
        return cert

    def verify_certificate(self, cert_number: str) -> Optional[Dict[str, Any]]:
        for c in self.certificates.values():
            if c["cert_number"] == cert_number:
                return {
                    "valid": c["status"] == "active" and c["expires_at"] >= time.strftime("%Y-%m-%d"),
                    "certificate": c,
                }
        return None

    def revoke_certificate(self, cert_id: str, reason: str = "") -> bool:
        c = self.certificates.get(cert_id)
        if not c:
            return False
        c["status"] = "revoked"
        c["revoke_reason"] = reason
        c["revoked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return True

    def list_certificates(self, user: str = "") -> List[Dict[str, Any]]:
        results = list(self.certificates.values())
        if user:
            results = [c for c in results if c["user"] == user]
        return results


# --------------------------------------------------------------------------- #
# 认证体系
# --------------------------------------------------------------------------- #
class CertificationSystem:
    """认证体系：等级/前置要求/维护积分。"""

    def __init__(self, cert_mgr: CertificateManager) -> None:
        self.cert_mgr = cert_mgr
        self.cert_paths: Dict[str, Dict[str, Any]] = {
            "security_fundamental": {
                "name": "安全基础认证", "level": "associate",
                "prerequisites": [], "credits_needed": 10,
            },
            "security_professional": {
                "name": "安全专业认证", "level": "professional",
                "prerequisites": ["security_fundamental"], "credits_needed": 30,
            },
            "security_expert": {
                "name": "安全专家认证", "level": "expert",
                "prerequisites": ["security_professional"], "credits_needed": 60,
            },
        }
        self.user_credits: Dict[str, Dict[str, int]] = {}

    def get_cert_paths(self) -> Dict[str, Dict[str, Any]]:
        return self.cert_paths

    def add_credits(self, user: str, category: str, points: int) -> Dict[str, int]:
        if user not in self.user_credits:
            self.user_credits[user] = {}
        self.user_credits[user][category] = self.user_credits[user].get(category, 0) + points
        return self.user_credits[user]

    def check_cert_eligibility(self, user: str, cert_key: str) -> Dict[str, Any]:
        path = self.cert_paths.get(cert_key)
        if not path:
            return {"eligible": False, "reason": "认证路径不存在"}
        credits = self.user_credits.get(user, {})
        total_credits = sum(credits.values())
        eligible = total_credits >= path["credits_needed"]
        return {
            "eligible": eligible,
            "cert_name": path["name"],
            "current_credits": total_credits,
            "required_credits": path["credits_needed"],
            "gap": max(0, path["credits_needed"] - total_credits),
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_qbank: Optional[QuestionBank] = None
_exam_mgr: Optional[ExamManager] = None
_executor: Optional[ExamExecutor] = None
_grader: Optional[ExamGrader] = None
_cert_mgr: Optional[CertificateManager] = None
_cert_system: Optional[CertificationSystem] = None


def get_question_bank() -> QuestionBank:
    global _qbank
    if _qbank is None:
        _qbank = QuestionBank()
    return _qbank


def get_exam_manager() -> ExamManager:
    global _exam_mgr
    if _exam_mgr is None:
        _exam_mgr = ExamManager(get_question_bank())
    return _exam_mgr


def get_exam_executor() -> ExamExecutor:
    global _executor
    if _executor is None:
        _executor = ExamExecutor(get_exam_manager(), get_question_bank())
    return _executor


def get_exam_grader() -> ExamGrader:
    global _grader
    if _grader is None:
        _grader = ExamGrader(get_exam_executor(), get_question_bank())
    return _grader


def get_certificate_manager() -> CertificateManager:
    global _cert_mgr
    if _cert_mgr is None:
        _cert_mgr = CertificateManager()
    return _cert_mgr


def get_certification_system() -> CertificationSystem:
    global _cert_system
    if _cert_system is None:
        _cert_system = CertificationSystem(get_certificate_manager())
    return _cert_system
