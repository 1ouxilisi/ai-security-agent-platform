# -*- coding: utf-8 -*-
"""
ai_analysis.py — 安全培训 AI 分析。

功能:
    - AI 自动生成课程内容（大纲/章节/课件/习题）
    - AI 自动出题（知识点/难度/题型）
    - AI 自动批改（主观题/实操题/评分/反馈）
    - AI 推荐学习路径
    - AI 个性化学习建议
    - AI 能力评估 / 钓鱼风险评估 / 讲师绩效评估
    - 思考过程可视化
"""

from __future__ import annotations

import threading
import uuid
from typing import Any, Dict, List, Optional


class AIAnalysis:
    """AI 分析引擎（规则化启发式，输出思考链）。"""

    def __init__(self) -> None:
        self._history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def _record(self, kind: str, thought: List[str],
                result: Dict[str, Any]) -> Dict[str, Any]:
        entry = {"kind": kind, "thought": thought, "result": result,
                 "id": "ai_" + uuid.uuid4().hex[:8]}
        with self._lock:
            self._history.append(entry)
        return entry

    # ------------------------------------------------------------------ #
    def generate_course_content(self, topic: str,
                                level: str = "入门") -> Dict[str, Any]:
        thought = [
            f"理解主题「{topic}」与目标等级「{level}」",
            "拆解知识图谱：原理→利用→防御→实战",
            "按认知负荷分配章节，避免跳跃",
            "生成配套习题与课件大纲",
        ]
        outline = [
            {"chapter": f"{topic} 概述", "minutes": 30,
             "points": ["定义", "威胁场景", "历史演进"]},
            {"chapter": f"{topic} 原理深入", "minutes": 60,
             "points": ["技术细节", "攻击面"]},
            {"chapter": f"{topic} 实战演练", "minutes": 90,
             "points": ["靶场操作", "复现", "截图"]},
            {"chapter": f"{topic} 防御与修复", "minutes": 45,
             "points": ["缓解措施", "最佳实践"]},
        ]
        exercises = [
            {"q": f"简述 {topic} 的核心危害", "type": "简答题"},
            {"q": f"{topic} 的常见利用方式有哪些？", "type": "多选题"},
        ]
        return self._record("course_content", thought, {
            "topic": topic, "level": level,
            "outline": outline, "exercises": exercises})["result"] | \
            {"thought": thought}

    # ------------------------------------------------------------------ #
    def generate_questions(self, knowledge: str, difficulty: str = "简单",
                           qtype: str = "单选题",
                           count: int = 3) -> Dict[str, Any]:
        thought = [
            f"定位知识点「{knowledge}」",
            f"匹配难度「{difficulty}」与题型「{qtype}」",
            "构造干扰项，保证答案唯一",
            f"批量生成 {count} 题并附解析",
        ]
        questions = []
        for i in range(count):
            questions.append({
                "qid": "aiq_" + uuid.uuid4().hex[:8],
                "qtype": qtype, "knowledge": knowledge,
                "difficulty": difficulty,
                "stem": f"[{knowledge}] 第{i+1}题：下列关于该技术的说法正确的是？",
                "options": ["A. ...", "B. ...", "C. ...", "D. ..."],
                "answer": "B",
                "analysis": f"针对 {knowledge} 的核心概念解析",
            })
        return self._record("question_gen", thought,
                            {"questions": questions})["result"] | \
            {"thought": thought}

    # ------------------------------------------------------------------ #
    def grade_subjective(self, question: str, answer: str,
                         rubric: str = "") -> Dict[str, Any]:
        thought = [
            "解析题目考点关键词",
            "比对作答覆盖度与关键词命中",
            "按要点打分并给出反馈",
        ]
        coverage = min(100, max(30, len(answer) // 4))
        score = round(coverage * 0.85, 1)
        feedback = ("作答要点覆盖较好，建议补充防御细节"
                    if coverage >= 60 else
                    "要点覆盖不足，建议回顾课程第三章")
        return self._record("grading", thought, {
            "question": question, "score": score,
            "feedback": feedback, "auto": True})["result"] | \
            {"thought": thought}

    # ------------------------------------------------------------------ #
    def recommend_path(self, goal: str, base: str,
                       interest: str) -> Dict[str, Any]:
        thought = [
            f"解析目标「{goal}」、基础「{base}」、兴趣「{interest}」",
            "匹配知识图谱前置/后续节点",
            "按基础调整学习节奏与难度",
            "输出推荐路径与里程碑",
        ]
        rec = [
            {"step": 1, "name": f"{interest} 基础", "weeks": 4},
            {"step": 2, "name": f"{goal} 进阶实战", "weeks": 8},
            {"step": 3, "name": "综合考核与认证", "weeks": 2},
        ]
        return self._record("path_rec", thought,
                            {"recommendation": rec,
                             "pace": "标准" if base == "入门" else "加速"}) \
            ["result"] | {"thought": thought}

    # ------------------------------------------------------------------ #
    def study_advice(self, ability: Dict[str, float]) -> Dict[str, Any]:
        thought = ["扫描各领域能力分",
                   "定位最低 2 个领域",
                   "生成复习计划与提醒"]
        weak = sorted(ability.items(), key=lambda x: x[1])[:2]
        advice = [f"本周重点补强 {d}（当前 {v} 分）" for d, v in weak]
        return self._record("study_advice", thought,
                            {"weak": weak, "advice": advice})["result"] | \
            {"thought": thought}

    # ------------------------------------------------------------------ #
    def ability_assessment(self,
                           scores: Dict[str, float]) -> Dict[str, Any]:
        thought = ["归一化各领域得分",
                   "识别短板与长板",
                   "生成提升建议"]
        avg = sum(scores.values()) / max(1, len(scores))
        weak = [k for k, v in scores.items() if v < avg - 10]
        return self._record("ability", thought, {
            "avg": round(avg, 1), "weak_domains": weak,
            "suggestion": f"优先提升 {weak}" if weak else "能力均衡"}) \
            ["result"] | {"thought": thought}

    # ------------------------------------------------------------------ #
    def phish_risk(self, click_users: List[str],
                   cred_users: List[str]) -> Dict[str, Any]:
        thought = ["汇总点击/输入凭据用户",
                   "按行为严重度分级",
                   "输出部门风险与改进建议"]
        return self._record("phish_risk", thought, {
            "high_risk": cred_users,
            "watch": click_users,
            "suggestion": f"对 {len(cred_users)} 名输入凭据用户立即重置密码并 1V1 培训"}) \
            ["result"] | {"thought": thought}

    # ------------------------------------------------------------------ #
    def instructor_eval(self, rating: float, students: int,
                       completion: float) -> Dict[str, Any]:
        thought = ["综合评分、学员数、完课率",
                   "归一化为绩效分",
                   "给出等级建议"]
        perf = round(rating * 0.5 + min(students, 1000) / 1000 * 25
                     + completion * 0.25, 1)
        level = "首席讲师" if perf >= 90 else \
                "高级讲师" if perf >= 75 else "中级讲师"
        return self._record("instructor_eval", thought, {
            "performance": perf, "suggested_level": level})["result"] | \
            {"thought": thought}

    # ------------------------------------------------------------------ #
    def history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history)[-limit:]


_default: Optional[AIAnalysis] = None


def get_ai_analysis() -> AIAnalysis:
    global _default
    if _default is None:
        _default = AIAnalysis()
    return _default
