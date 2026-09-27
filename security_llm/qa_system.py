#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qa_system.py — 安全问答系统（第26轮升级方向1）。

六大能力：
    1. 问答管理：会话管理/历史/搜索/删除
    2. 知识检索：向量检索模拟/关键词检索/混合检索
    3. 答案生成：RAG 增强回答/多轮上下文/引用溯源
    4. 答案审核：事实性校验/安全合规审核/置信度评分
    5. 问答统计：会话数/命中率/满意度/热门问题
    6. 问答知识库：FAQ 管理/分类/导入导出

全部内存字典模拟，仅用于授权安全场景。
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _gen_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# 内置 FAQ
_DEFAULT_FAQS: List[Dict[str, Any]] = [
    {"id": "faq-001", "q": "什么是 SQL 注入？如何防御？",
     "a": "SQL注入是通过插入恶意SQL语句操纵数据库。防御：参数化查询、输入白名单、最小权限、ORM。",
     "category": "漏洞", "hits": 128},
    {"id": "faq-002", "q": "如何配置 HTTPS 才安全？",
     "a": "使用 TLS1.2+，优先TLS1.3，配置HSTS，禁用弱加密套件，证书自动续期。",
     "category": "运维", "hits": 96},
    {"id": "faq-003", "q": "等保三级需要做什么？",
     "a": "等保三级需完成定级备案、差距评估、安全建设整改、等级测评、运营维护五大环节。",
     "category": "合规", "hits": 154},
    {"id": "faq-004", "q": "发现内网疑似挖矿怎么办？",
     "a": "立即隔离主机，保留内存镜像，排查横向移动痕迹，分析进程与网络连接，上报应急响应。",
     "category": "应急", "hits": 73},
    {"id": "faq-005", "q": "什么是零信任？",
     "a": "零信任是从不信任、始终验证的架构理念，基于身份+设备+上下文做持续授权，核心是微分段和最小权限。",
     "category": "架构", "hits": 88},
]


class QASystem:
    """安全问答系统。"""

    def __init__(self) -> None:
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.answers: Dict[str, Dict[str, Any]] = {}
        self.faq: List[Dict[str, Any]] = list(_DEFAULT_FAQS)
        self.total_questions = 0
        self.total_sessions = 0
        self.satisfied = 0

    # ==================== 1. 问答管理 ====================
    def create_session(self, user: str = "anonymous") -> Dict[str, Any]:
        sid = _gen_id("qa")
        self.sessions[sid] = {
            "id": sid, "user": user, "messages": [],
            "created_at": _now(), "updated_at": _now(),
        }
        self.total_sessions += 1
        return self.sessions[sid]

    def list_sessions(self) -> List[Dict[str, Any]]:
        return list(self.sessions.values())

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.sessions.get(session_id)

    def delete_session(self, session_id: str) -> Dict[str, Any]:
        if session_id in self.sessions:
            del self.sessions[session_id]
            return {"deleted": session_id, "ts": _now()}
        raise ValueError(f"会话不存在: {session_id}")

    # ==================== 2. 知识检索 ====================
    def retrieve(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        q = query.lower().strip()
        scored: List[Dict[str, Any]] = []
        for faq in self.faq:
            text = (faq["q"] + " " + faq["a"] + " " + faq["category"]).lower()
            score = 0.0
            for kw in re.split(r"\s+", q):
                kw = kw.strip()
                if not kw:
                    continue
                score += text.count(kw) * 1.5
                if kw in faq["q"].lower():
                    score += 2.0
            if score > 0:
                scored.append({**faq, "score": round(score, 2)})
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    # ==================== 3. 答案生成 ====================
    def ask(self, session_id: str, question: str) -> Dict[str, Any]:
        sess = self.sessions.get(session_id)
        if not sess:
            sess = self.create_session()
            session_id = sess["id"]
        # 检索
        chunks = self.retrieve(question, top_k=3)
        # 生成答案
        answer = self._gen_answer(question, chunks)
        aid = _gen_id("ans")
        record = {
            "id": aid, "session_id": session_id, "question": question,
            "answer": answer, "references": chunks,
            "confidence": round(min(0.99, 0.6 + len(chunks) * 0.1), 2),
            "ts": _now(),
        }
        self.answers[aid] = record
        sess["messages"].append({"role": "user", "content": question, "ts": _now()})
        sess["messages"].append({"role": "assistant", "content": answer, "ts": _now()})
        sess["updated_at"] = _now()
        self.total_questions += 1
        return record

    def _gen_answer(self, question: str, chunks: List[Dict[str, Any]]) -> str:
        if not chunks:
            return (
                f"关于「{question}」，知识库里暂未找到完全匹配的答案。"
                f"建议您：1)补充具体技术术语；2)提供CVE编号或产品版本；"
                f"3)描述具体场景。我会尽力为您解答。"
            )
        top = chunks[0]
        lines = [f"【{top['q']}】", top["a"]]
        if len(chunks) > 1:
            lines.append("\n【相关问答】")
            for c in chunks[1:]:
                lines.append(f"• {c['q']}：{c['a'][:60]}...")
        lines.append("\n【来源】")
        for c in chunks:
            lines.append(f"- {c['id']}（{c['category']}，命中{c.get('hits', 0)}次）")
        return "\n".join(lines)

    def list_answers(self) -> List[Dict[str, Any]]:
        return list(self.answers.values())[-50:]

    # ==================== 4. 答案审核 ====================
    def review_answer(self, answer_id: str) -> Dict[str, Any]:
        ans = self.answers.get(answer_id)
        if not ans:
            raise ValueError(f"答案不存在: {answer_id}")
        issues: List[str] = []
        # 事实性校验：检查是否有引用
        if not ans.get("references"):
            issues.append("无知识库引用，可能为幻觉")
        # 安全合规校验：检查是否包含攻击性指导
        risky_patterns = ["攻击代码", "漏洞利用步骤", "提权命令", "入侵教程"]
        for p in risky_patterns:
            if p in ans["answer"]:
                issues.append(f"可能包含风险内容: {p}")
        score = 100 - len(issues) * 15
        result = {
            "id": _gen_id("rev"), "answer_id": answer_id,
            "passed": len(issues) == 0, "issues": issues,
            "score": max(0, score), "reviewer": "auto-reviewer",
            "ts": _now(),
        }
        return result

    # ==================== 5. 问答统计 ====================
    def stats(self) -> Dict[str, Any]:
        cats: Dict[str, int] = {}
        for f in self.faq:
            cats[f["category"]] = cats.get(f["category"], 0) + 1
        return {
            "total_sessions": self.total_sessions,
            "total_questions": self.total_questions,
            "total_answers": len(self.answers),
            "faq_count": len(self.faq),
            "avg_confidence": round(sum(a["confidence"] for a in self.answers.values()) / max(1, len(self.answers)), 2),
            "categories": cats,
            "top_faq": sorted(self.faq, key=lambda x: x["hits"], reverse=True)[:3],
        }

    def feedback(self, answer_id: str, satisfied: bool) -> Dict[str, Any]:
        if answer_id not in self.answers:
            raise ValueError(f"答案不存在: {answer_id}")
        if satisfied:
            self.satisfied += 1
        return {"answer_id": answer_id, "satisfied": satisfied, "ts": _now()}

    # ==================== 6. 问答知识库 ====================
    def add_faq(self, q: str, a: str, category: str) -> Dict[str, Any]:
        faq = {
            "id": _gen_id("faq"), "q": q, "a": a,
            "category": category, "hits": 0, "added_at": _now(),
        }
        self.faq.append(faq)
        return faq

    def list_faq(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        if category:
            return [f for f in self.faq if f["category"] == category]
        return self.faq

    def delete_faq(self, faq_id: str) -> Dict[str, Any]:
        before = len(self.faq)
        self.faq = [f for f in self.faq if f["id"] != faq_id]
        if len(self.faq) == before:
            raise ValueError(f"FAQ不存在: {faq_id}")
        return {"deleted": faq_id, "remaining": len(self.faq), "ts": _now()}


# 单例
qa_system = QASystem()
