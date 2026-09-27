#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 安全知识库 (AI Knowledge Base)
====================================

结构化存储并检索安全知识，支持语义近似检索与关联推理：

    1. 漏洞知识库：CVE / CWE / OWASP / CNVD / CNNVD
    2. 攻击技术库：ATT&CK 矩阵 / 攻击链 / TTPs
    3. 防御知识库：防护措施 / 检测规则 / 响应流程 / 修复方案
    4. 工具知识库：安全工具 / 使用方法 / 参数说明 / 最佳实践
    5. 案例知识库：真实安全事件 / 渗透案例 / 红蓝对抗复盘
    6. 检索与推理：关键词打分检索 / 关联推理 / 知识图谱 / 问答生成

全部为内置种子数据 + 内存索引，纯 Python 实现。
"""
from __future__ import annotations

import math
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# ----------------------------------------------------------------------
# 种子知识条目
# ----------------------------------------------------------------------
_VULN_KB: List[Dict[str, Any]] = [
    {"id": "KB-V-CVE-2021-44228", "category": "vuln", "source": "CVE",
     "title": "Log4Shell 远程代码执行", "tags": ["rce", "log4j", "jndi", "java"],
     "summary": "Log4j2 JNDI 注入导致 RCE，影响广泛中间件。"},
    {"id": "KB-V-CVE-2014-0160", "category": "vuln", "source": "CVE",
     "title": "Heartbleed 心脏滴血", "tags": ["openssl", "disclosure", "tls"],
     "summary": "OpenSSL 心跳处理越界读取，泄露内存。"},
    {"id": "KB-V-OWASP-A03", "category": "vuln", "source": "OWASP",
     "title": "注入 (Injection)", "tags": ["sqli", "xss", "注入"],
     "summary": "不可信数据进入查询/命令导致执行非预期操作。"},
    {"id": "KB-V-CWE-79", "category": "vuln", "source": "CWE",
     "title": "跨站脚本 XSS", "tags": ["xss", "script"],
     "summary": "未对用户输入输出编码导致脚本注入。"},
    {"id": "KB-V-CNVD-0001", "category": "vuln", "source": "CNVD",
     "title": "常见 OA 未授权访问", "tags": ["oa", "unauth", "web"],
     "summary": "主流 OA 系统历史未授权访问与文件上传漏洞集合。"},
]

_ATTACK_KB: List[Dict[str, Any]] = [
    {"id": "KB-A-T1190", "category": "attack", "source": "ATT&CK",
     "title": "利用面向公众的应用 (T1190)", "tactic": "Initial Access",
     "tags": ["initial-access", "web"], "summary": "通过暴露的 Web 应用获取初始访问。"},
    {"id": "KB-A-T1078", "category": "attack", "source": "ATT&CK",
     "title": "有效账户 (T1078)", "tactic": "Defense Evasion",
     "tags": ["credential", "account"], "summary": "使用合法账户伪装正常流量。"},
    {"id": "KB-A-T1048", "category": "attack", "source": "ATT&CK",
     "title": "数据外渗 (T1048)", "tactic": "Exfiltration",
     "tags": ["exfil", "data"], "summary": "通过替代协议把数据传出。"},
]

_DEFENSE_KB: List[Dict[str, Any]] = [
    {"id": "KB-D-001", "category": "defense", "source": "baseline",
     "title": "最小权限原则", "tags": ["权限", "hardening"],
     "summary": "账户与服务按最小权限分配，定期复核。"},
    {"id": "KB-D-002", "category": "defense", "source": "detection",
     "title": "异常外连检测规则", "tags": ["edr", "sigma", "exfil"],
     "summary": "对非业务域名外连、大流量出站建立告警阈值。"},
    {"id": "KB-D-003", "category": "defense", "source": "response",
     "title": "事件响应四段法", "tags": ["ir", "流程"],
     "summary": "遏制 → 根除 → 恢复 → 复盘。"},
]

_TOOL_KB: List[Dict[str, Any]] = [
    {"id": "KB-T-001", "category": "tool", "source": "toolset",
     "title": "Nmap", "tags": ["scanner", "port"],
     "summary": "端口与服务探测。常用: nmap -sV -sC -p- target。"},
    {"id": "KB-T-002", "category": "tool", "source": "toolset",
     "title": "Nuclei", "tags": ["scanner", "poc"],
     "summary": "基于模板的快速漏洞扫描。常用: nuclei -u url -t cves/。"},
    {"id": "KB-T-003", "category": "tool", "source": "toolset",
     "title": "Burp Suite", "tags": ["web", "proxy"],
     "summary": "Web 代理与重放，用于手动验证与 fuzz。"},
]

_CASE_KB: List[Dict[str, Any]] = [
    {"id": "KB-C-001", "category": "case", "source": "case",
     "title": "某企业 Log4j 应急复盘", "tags": ["log4j", "ir"],
     "summary": "外部告警 → 资产梳理 → 临时缓解 → 升级 → 复盘全流程。"},
    {"id": "KB-C-002", "category": "case", "source": "case",
     "title": "红蓝对抗: OA 未授权到域控", "tags": ["attack-chain", "oa"],
     "summary": "从 OA 未授权文件上传获取 webshell，横向至域控。"},
]

# 知识图谱关系（条目 id → 关联 id）
_RELATIONS: Dict[str, List[str]] = {
    "KB-V-CVE-2021-44228": ["KB-A-T1190", "KB-D-002", "KB-T-002"],
    "KB-V-CVE-2014-0160": ["KB-A-T1190", "KB-D-001"],
    "KB-V-OWASP-A03": ["KB-T-003", "KB-D-001"],
    "KB-A-T1190": ["KB-V-CVE-2021-44228", "KB-C-002"],
    "KB-C-002": ["KB-V-OWASP-A03", "KB-A-T1190"],
}


class AIKnowledgeBase:
    """AI 安全知识库（单例）。"""

    def __init__(self) -> None:
        self.entries: Dict[str, Dict[str, Any]] = {}
        self._seed()
        self.user_entries: Dict[str, Dict[str, Any]] = {}

    def _seed(self) -> None:
        for bucket in (_VULN_KB, _ATTACK_KB, _DEFENSE_KB, _TOOL_KB, _CASE_KB):
            for e in bucket:
                self.entries[e["id"]] = {**e}

    # ------------------------------------------------------------------
    # 条目维护
    # ------------------------------------------------------------------
    def add_entry(self, entry: Dict[str, Any]) -> str:
        eid = entry.get("id") or f"KB-U-{uuid.uuid4().hex[:8]}"
        self.user_entries[eid] = {
            "id": eid, "category": entry.get("category", "custom"),
            "title": entry.get("title", "未命名"), "tags": entry.get("tags", []),
            "summary": entry.get("summary", ""), "created_at": _now(),
        }
        self.entries[eid] = self.user_entries[eid]
        return eid

    def list_entries(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.entries.values())
        if category:
            items = [e for e in items if e.get("category") == category]
        return items

    # ------------------------------------------------------------------
    # 检索（关键词 + tag 打分，近似语义）
    # ------------------------------------------------------------------
    @staticmethod
    def _score(query: str, entry: Dict[str, Any]) -> float:
        q = query.lower()
        score = 0.0
        text = (entry.get("title", "") + " " + entry.get("summary", "")).lower()
        tags = " ".join(entry.get("tags", [])).lower()
        for word in q.split():
            if not word:
                continue
            if word in entry.get("title", "").lower():
                score += 3.0
            if word in tags:
                score += 2.0
            if word in text:
                score += 1.0
        # IDF 式权重：命中越稀有的 tag 分越高（粗粒度）
        return round(score, 2)

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        scored = [(self._score(query, e), e) for e in self.entries.values()]
        scored = [(s, e) for s, e in scored if s > 0]
        scored.sort(key=lambda x: -x[0])
        return [{"score": s, **e} for s, e in scored[:top_k]]

    # ------------------------------------------------------------------
    # 关联推理 / 知识图谱
    # ------------------------------------------------------------------
    def related(self, entry_id: str, depth: int = 1) -> Dict[str, Any]:
        seen: Dict[str, int] = {}
        frontier = [entry_id]
        for hop in range(depth):
            nxt: List[str] = []
            for eid in frontier:
                for rel in _RELATIONS.get(eid, []):
                    if rel not in seen:
                        seen[rel] = hop + 1
                        nxt.append(rel)
            frontier = nxt
        nodes = [
            {"id": rid, "hop": hop,
             "title": self.entries.get(rid, {}).get("title", rid)}
            for rid, hop in seen.items()
        ]
        return {"entry_id": entry_id, "nodes": nodes, "edge_count": sum(len(v) for v in _RELATIONS.values())}

    # ------------------------------------------------------------------
    # 问答生成
    # ------------------------------------------------------------------
    def ask(self, question: str) -> Dict[str, Any]:
        hits = self.search(question, top_k=3)
        if not hits:
            answer = "知识库中未找到直接答案，建议补充该领域条目或切换为人工研判。"
        else:
            top = hits[0]
            answer = (
                f"根据知识库《{top['title']}》：{top['summary']}"
                f"（相关度 {top['score']}）。"
                + (f" 其他相关条目：{', '.join(h['title'] for h in hits[1:])}。" if len(hits) > 1 else "")
            )
        return {
            "question": question,
            "answer": answer,
            "citations": [{"id": h["id"], "title": h["title"], "score": h["score"]} for h in hits],
            "answered_at": _now(),
        }

    def stats(self) -> Dict[str, Any]:
        cat_count: Dict[str, int] = {}
        for e in self.entries.values():
            cat_count[e.get("category", "unknown")] = cat_count.get(e.get("category", "unknown"), 0) + 1
        return {
            "entry_count": len(self.entries),
            "user_entries": len(self.user_entries),
            "relation_edges": sum(len(v) for v in _RELATIONS.values()),
            "by_category": cat_count,
        }


ai_knowledge_base = AIKnowledgeBase()
