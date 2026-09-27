#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
super_homepage/global_search.py — 全局模糊搜索。

索引四大类：功能 / 漏洞 / 报告 / 目标。
支持子串 + 子序列（subsequence）模糊匹配，结果按分类聚合，一键直达。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 搜索条目
# --------------------------------------------------------------------------- #
@dataclass
class SearchItem:
    id: str
    category: str          # feature | vuln | report | target
    title: str
    subtitle: str = ""
    route: str = ""
    keywords: List[str] = field(default_factory=list)
    severity: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# 简单模糊打分
# --------------------------------------------------------------------------- #
def _fuzzy_score(query: str, text: str) -> float:
    """子串命中 > 子序列命中；返回 0~1，0 表示不匹配。"""
    if not query:
        return 0.0
    q = query.lower().strip()
    t = text.lower()
    if not q:
        return 0.0
    if q in t:
        # 位置越靠前分越高
        idx = t.find(q)
        return 1.0 - (idx / max(len(t), 1)) * 0.5
    # 子序列匹配（宽松模糊）
    it = iter(t)
    if all(ch in it for ch in q):
        return 0.5
    return 0.0


def _item_score(query: str, item: SearchItem) -> float:
    best = max(
        _fuzzy_score(query, item.title),
        _fuzzy_score(query, item.subtitle),
        max((_fuzzy_score(query, k) for k in item.keywords), default=0.0),
    )
    # 关键词额外加权
    if best > 0 and any(query.lower() in k.lower() for k in item.keywords):
        best = min(1.0, best + 0.2)
    return best


# --------------------------------------------------------------------------- #
# 全局搜索管理器
# --------------------------------------------------------------------------- #
class GlobalSearch:
    """全局搜索索引。"""

    def __init__(self) -> None:
        self._items: List[SearchItem] = []
        self._history: List[Dict[str, Any]] = []
        self._seed_index()

    def _seed_index(self) -> None:
        items: List[SearchItem] = [
            # ---- 功能 ----
            SearchItem("f_web", "feature", "Web 渗透", "指纹/目录/漏洞/利用",
                       "/web-pentest-full", ["web", "渗透", "扫描", "pentest", "xss", "sqli"]),
            SearchItem("f_internal", "feature", "内网渗透", "横向移动/权限维持",
                       "/internal-pentest", ["内网", "横向", "域", "lateral", "kerberos"]),
            SearchItem("f_src", "feature", "SRC 挖洞", "资产测绘/漏洞提交",
                       "/src-workbench", ["src", "挖洞", "众测", "bounty", "资产"]),
            SearchItem("f_report", "feature", "报告中心", "生成/对比/导出",
                       "/report-pro", ["报告", "report", "pdf", "导出"]),
            SearchItem("f_scanner", "feature", "漏洞扫描器", "主机/Web/移动",
                       "/scanner", ["扫描", "scanner", "漏洞"]),
            SearchItem("f_nuclei", "feature", "Nuclei 引擎", "POC 模板批量",
                       "/nuclei-engine", ["nuclei", "poc", "模板"]),
            SearchItem("f_soc", "feature", "SOC 安全运营", "告警/事件/响应",
                       "/soc", ["soc", "告警", "运营"]),
            SearchItem("f_osint", "feature", "OSINT 情报", "公开情报收集",
                       "/osint", ["osint", "情报", "信息收集"]),
            # ---- 漏洞 ----
            SearchItem("v_sqli", "vuln", "SQL 注入", "CWE-89 / CVSS 9.8",
                       "/vuln-management", ["sql", "sqli", "注入", "cve"], severity="critical"),
            SearchItem("v_xss", "vuln", "存储型 XSS", "CWE-79 / CVSS 6.1",
                       "/vuln-management", ["xss", "跨站", "脚本"], severity="medium"),
            SearchItem("v_rce", "vuln", "远程代码执行 RCE", "CWE-78 / CVSS 9.8",
                       "/vuln-management", ["rce", "代码执行", "命令执行"], severity="critical"),
            SearchItem("v_ssrf", "vuln", "SSRF 服务端请求伪造", "CWE-918",
                       "/vuln-management", ["ssrf", "伪造"], severity="high"),
            SearchItem("v_deser", "vuln", "Java 反序列化", "CWE-502",
                       "/vuln-management", ["反序列化", "deserialization"], severity="high"),
            # ---- 报告 ----
            SearchItem("r_2026_09", "report", "Q3 季度渗透报告", "2026-09-12",
                       "/report-pro", ["季度", "q3", "渗透报告"]),
            SearchItem("r_src_0911", "report", "SRC 挖洞月报 0911", "2026-09-11",
                       "/report-pro", ["src", "月报"]),
            SearchItem("r_redteam", "report", "红队演练复盘", "2026-09-08",
                       "/report-pro", ["红队", "演练", "复盘"]),
            # ---- 目标 ----
            SearchItem("t_shop", "target", "shop.example.com", "电商主站",
                       "/web-pentest-full", ["电商", "shop", "主站"]),
            SearchItem("t_admin", "target", "admin.internal.corp", "管理后台",
                       "/internal-pentest", ["admin", "后台", "internal"]),
            SearchItem("t_api", "target", "api.example.com", "开放 API 网关",
                       "/web-pentest-full", ["api", "网关"]),
        ]
        self._items = items

    # ---- 索引维护 ----
    def add(self, item: SearchItem) -> None:
        self._items.append(item)

    def index_size(self) -> int:
        return len(self._items)

    # ---- 搜索 ----
    def search(self, query: str, limit: int = 20) -> Dict[str, Any]:
        q = (query or "").strip()
        scored: List[tuple[float, SearchItem]] = []
        for it in self._items:
            s = _item_score(q, it)
            if s > 0:
                scored.append((s, it))
        scored.sort(key=lambda x: x[0], reverse=True)

        grouped: Dict[str, List[Dict[str, Any]]] = {
            "feature": [], "vuln": [], "report": [], "target": [],
        }
        for s, it in scored:
            grouped.setdefault(it.category, []).append({
                "id": it.id, "category": it.category, "title": it.title,
                "subtitle": it.subtitle, "route": it.route,
                "severity": it.severity, "score": round(s, 3), "meta": it.meta,
            })

        # 每类取 top N
        out: Dict[str, List[Dict[str, Any]]] = {}
        for cat, lst in grouped.items():
            if lst:
                out[cat] = lst[:max(1, limit // 3)]

        total = sum(len(v) for v in out.values())
        if q:
            self._history.append({
                "id": uuid.uuid4().hex[:8], "query": q,
                "results": total, "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            if len(self._history) > 100:
                self._history = self._history[-100:]

        return {
            "query": q,
            "total": total,
            "categories": list(out.keys()),
            "results": out,
            "took_ms": 0,
        }

    def history(self, limit: int = 15) -> List[Dict[str, Any]]:
        return list(reversed(self._history))[:limit]

    def clear_history(self) -> Dict[str, Any]:
        n = len(self._history)
        self._history.clear()
        return {"cleared": n}

    def stats(self) -> Dict[str, Any]:
        cats: Dict[str, int] = {}
        for it in self._items:
            cats[it.category] = cats.get(it.category, 0) + 1
        return {
            "index_size": len(self._items),
            "by_category": cats,
            "history_size": len(self._history),
        }


_manager: GlobalSearch | None = None


def get_global_search() -> GlobalSearch:
    global _manager
    if _manager is None:
        _manager = GlobalSearch()
    return _manager
