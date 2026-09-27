# -*- coding: utf-8 -*-
"""
kg_qa.py — 安全知识图谱智能问答系统。

真实能力：
    - 知识检索：关键词 / 图谱邻居 / 多跳 / 混合
    - 答案生成：基于图谱事实的模板化回答 + 引用 + 置信度
    - FAQ 库：预置常见问题
    - 答案审核 / 反馈 / 历史
    - 问答统计
"""
from __future__ import annotations

import re
import time
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from security_kg.kg_builder import kg_builder
except Exception:  # pragma: no cover
    kg_builder = None  # type: ignore

try:
    from security_kg.vuln_correlation import vuln_correlation
except Exception:  # pragma: no cover
    vuln_correlation = None  # type: ignore

try:
    from security_kg.reasoning_engine import reasoning_engine
except Exception:  # pragma: no cover
    reasoning_engine = None  # type: ignore


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# 预置 FAQ
DEFAULT_FAQ = [
    {"q": "什么是 Log4j？",
     "a": "Log4j 是 Apache 的 Java 日志库，2021 年披露 CVE-2021-44228 远程代码执行漏洞，"
          "CVSS 10.0，可通过构造日志字段触发 JNDI 注入。",
     "tags": ["漏洞", "CVE"], "category": "漏洞知识"},
    {"q": "什么是 ATT&CK？",
     "a": "MITRE ATT&CK 是攻击战术与技术知识库，覆盖初始访问、执行、持久化、"
          "权限提升、防御规避、凭据访问、发现、横向移动、收集、命令控制、"
          "数据窃取、影响 12 个战术。",
     "tags": ["ATT&CK", "战术"], "category": "框架"},
    {"q": "什么是 SIR 模型？",
     "a": "SIR 是流行病学传播模型，把人群分为易感(S)/感染(I)/恢复(R)三类，"
          "用 beta(传播率) 和 gamma(恢复率) 两个参数刻画传播动力学。",
     "tags": ["传播", "建模"], "category": "建模"},
    {"q": "A* 算法原理？",
     "a": "A* 是启发式图搜索算法，f(n)=g(n)+h(n)，其中 g 是已走代价，h 是到目标的启发估计，"
          "可在攻击图中找到代价最优的攻击路径。",
     "tags": ["算法", "路径"], "category": "算法"},
]


class KGQA:
    """知识图谱问答。"""

    def __init__(self) -> None:
        self.kg = kg_builder
        self.faq: List[Dict[str, Any]] = list(DEFAULT_FAQ)
        self.history: List[Dict[str, Any]] = []
        self.feedback_log: Dict[str, Dict[str, Any]] = {}
        self.stats: Dict[str, int] = {"questions": 0, "answered": 0,
                                       "good": 0, "bad": 0}

    # ---------- FAQ 管理 ----------
    def list_faq(self) -> List[Dict[str, Any]]:
        return self.faq

    def add_faq(self, q: str, a: str,
                category: str = "通用", tags: Optional[List[str]] = None
                ) -> Dict[str, Any]:
        item = {"q": q, "a": a, "category": category,
                "tags": tags or [], "created_at": _now()}
        self.faq.append(item)
        return item

    # ---------- 知识检索 ----------
    def search(self, query: str, top_k: int = 5) -> Dict[str, Any]:
        """混合检索：关键词匹配图谱节点 + FAQ。"""
        if not query:
            return {"nodes": [], "faq": [], "score": 0}
        q = query.lower()
        nodes: List[Dict[str, Any]] = []
        if self.kg:
            for n in self.kg.nodes.values():
                text = (n["name"] + " " + str(n.get("props", {}))).lower()
                if q in text:
                    nodes.append({
                        "id": n["id"], "name": n["name"],
                        "type": n["type"], "type_cn": n["type_cn"],
                        "score": text.count(q) + 1,
                    })
        nodes.sort(key=lambda x: x["score"], reverse=True)
        # FAQ 匹配
        faq_hits = [f for f in self.faq if q in f["q"].lower()]
        return {
            "nodes": nodes[:top_k],
            "faq": faq_hits[:top_k],
            "total": len(nodes) + len(faq_hits),
        }

    # ---------- 多跳检索 ----------
    def multi_hop_search(self, query: str, hops: int = 2) -> Dict[str, Any]:
        # 先定位起点
        s = self.search(query, top_k=1)
        if not s["nodes"] or self.kg is None:
            return {"path": [], "note": "未在图谱中找到起点"}
        start = s["nodes"][0]["id"]
        visited = {start}
        frontier = [(start, [start])]
        paths = []
        for _ in range(hops):
            nxt = []
            for node, path in frontier:
                for nb in self.kg.neighbors(node):
                    child = nb["neighbor"]["id"]
                    if child in visited:
                        continue
                    new_path = path + [child]
                    paths.append({
                        "path": [self.kg.nodes[x]["name"] for x in new_path],
                        "relation": nb["relation_cn"],
                    })
                    visited.add(child)
                    nxt.append((child, new_path))
            frontier = nxt
        return {"start": s["nodes"][0]["name"],
                "hops": hops, "paths": paths[:20]}

    # ---------- 答案生成 ----------
    def ask(self, question: str, user: str = "anonymous") -> Dict[str, Any]:
        t0 = time.time()
        question = (question or "").strip()
        self.stats["questions"] += 1
        if not question:
            return {"error": "问题不能为空"}
        # 1) FAQ 命中
        q_low = question.lower()
        for f in self.faq:
            if f["q"].lower() == q_low or q_low in f["q"].lower():
                answer = f["a"]
                refs = [{"type": "faq", "title": f["q"]}]
                confidence = 0.95
                self.stats["answered"] += 1
                rec = self._record(question, answer, refs, confidence,
                                   "faq", user)
                return rec
        # 2) 图谱检索
        s = self.search(question, top_k=3)
        if s["nodes"]:
            top = s["nodes"][0]
            # 找邻居作为解释
            neighbors = []
            if self.kg:
                for nb in self.kg.neighbors(top["id"])[:5]:
                    neighbors.append(f"{nb['relation_cn']} "
                                     f"{nb['neighbor']['name']}")
            answer = (f"在知识图谱中找到实体「{top['name']}」"
                      f"（类型：{top['type_cn']}）。"
                      f"关联关系：{'; '.join(neighbors) or '无直接关系'}。")
            refs = [{"type": "graph", "id": top["id"],
                     "title": top["name"]}]
            confidence = 0.7
            self.stats["answered"] += 1
            rec = self._record(question, answer, refs, confidence,
                               "graph", user)
            return rec
        # 3) 推理引擎
        if reasoning_engine is not None:
            bc = reasoning_engine.backward_chain(question)
            if bc.get("supported"):
                facts = [f["conclusion"] for f in bc["matched_facts"]]
                answer = "基于推理引擎的结论：" + "；".join(facts[:3]) \
                    if facts else "图谱证据存在，但暂无派生事实。"
                refs = [{"type": "reasoning",
                         "title": "后向链推理结果"}]
                confidence = 0.6
                self.stats["answered"] += 1
                return self._record(question, answer, refs, confidence,
                                    "reasoning", user)
        # 4) 兜底
        answer = (f"未在知识图谱/FAQ 中直接命中「{question}」。"
                  f"建议：1) 尝试用 CVE 编号、资产名、威胁组织名提问；"
                  f"2) 查看知识图谱总览；3) 联系安全运营团队。")
        refs = []
        confidence = 0.2
        self.stats["answered"] += 1
        return self._record(question, answer, refs, confidence,
                            "fallback", user,
                            elapsed_ms=round((time.time() - t0) * 1000, 2))

    def _record(self, question: str, answer: str,
                refs: List[Dict[str, Any]], confidence: float,
                source: str, user: str,
                elapsed_ms: float = 0.0) -> Dict[str, Any]:
        rec = {
            "id": f"qa-{int(time.time() * 1000)}",
            "question": question, "answer": answer,
            "references": refs, "confidence": confidence,
            "source": source, "user": user,
            "created_at": _now(), "elapsed_ms": elapsed_ms,
            "status": "answered",
        }
        self.history.append(rec)
        if len(self.history) > 500:
            self.history = self.history[-500:]
        return rec

    # ---------- 反馈 ----------
    def feedback(self, qa_id: str, rating: int,
                 comment: str = "") -> Dict[str, Any]:
        # rating: 1=bad, 5=good
        self.feedback_log[qa_id] = {"rating": rating, "comment": comment,
                                     "time": _now()}
        if rating >= 4:
            self.stats["good"] += 1
        elif rating <= 2:
            self.stats["bad"] += 1
        return {"ok": True, "qa_id": qa_id, "rating": rating}

    # ---------- 统计 ----------
    def statistics(self) -> Dict[str, Any]:
        total = max(1, self.stats["questions"])
        solved = max(1, self.stats["answered"])
        sources = Counter(r["source"] for r in self.history)
        top_q = Counter(r["question"] for r in self.history)
        return {
            "questions": self.stats["questions"],
            "answered": self.stats["answered"],
            "resolve_rate": round(self.stats["answered"] / total, 3),
            "satisfaction": round(self.stats["good"] /
                                  max(1, self.stats["good"] + self.stats["bad"]),
                                  3),
            "avg_confidence": round(
                sum(r["confidence"] for r in self.history) /
                max(1, len(self.history)), 3),
            "source_distribution": dict(sources),
            "hot_questions": [{"q": q, "count": c}
                              for q, c in top_q.most_common(10)],
            "history_size": len(self.history),
        }

    # ---------- 历史 ----------
    def history_list(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(reversed(self.history[-limit:]))


kg_qa = KGQA()
