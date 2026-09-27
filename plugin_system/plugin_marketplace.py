# -*- coding: utf-8 -*-
"""
plugin_marketplace.py - 插件市场

提供浏览/搜索/分类/详情/一键安装/更新/评分/评论/推荐/统计。
"""

from __future__ import annotations

import time
import math
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


CATEGORIES: Dict[str, Any] = {
    "scanner": {"label": "扫描器", "children": ["vuln", "port", "web", "host", "mobile"]},
    "analyzer": {"label": "分析器", "children": ["malware", "log", "traffic", "memory", "code"]},
    "connector": {"label": "连接器", "children": ["asset", "identity", "ticket", "cloud", "siem"]},
    "visualization": {"label": "可视化", "children": ["dashboard", "graph", "timeline", "map"]},
    "workflow": {"label": "工作流", "children": ["soar", "playbook", "scheduler", "etl"]},
    "notification": {"label": "通知", "children": ["alert", "webhook", "email", "im"]},
    "ai": {"label": "AI 插件", "children": ["llm", "ml", "triage", "report"]},
    "other": {"label": "其他", "children": ["utility", "report", "misc"]},
}


class PluginMarketplace:
    """插件市场：内存字典，内置 10+ 示例插件。"""

    def __init__(self) -> None:
        self.items: Dict[str, Dict[str, Any]] = {}
        self.reviews: Dict[str, List[Dict[str, Any]]] = {}
        self.ratings: Dict[str, List[int]] = {}
        self.search_history: List[str] = []
        self.hot_searches: List[str] = ["nuclei", "llm", "soar", "slack", "ldap", "malware"]
        self._seed()

    def _seed(self) -> None:
        seeds = [
            ("mp-nuclei", "Nuclei 漏洞模板集", "scanner", "vuln", "Nuclei 社区维护的高可信模板", 4.8, 12500),
            ("mp-masscan", "Masscan 高速端口扫描", "scanner", "port", "百万级端口并发扫描", 4.6, 8900),
            ("mp-yara", "YARA 规则引擎", "analyzer", "malware", "基于特征的恶意样本识别", 4.9, 20300),
            ("mp-suricata", "Suricata 流量分析", "analyzer", "traffic", "IDS/IPS 规则与告警", 4.5, 7600),
            ("mp-es-connector", "Elasticsearch 连接器", "connector", "siem", "对接 ES 索引查询", 4.3, 5400),
            ("mp-jira", "Jira 工单连接器", "connector", "ticket", "自动创建/更新工单", 4.4, 6100),
            ("mp-killchain-viz", "KillChain 图谱", "visualization", "graph", "攻击链关系图谱", 4.7, 3300),
            ("mp-soar-book", "SOAR 剧本库", "workflow", "soar", "20+ 内置处置剧本", 4.6, 4200),
            ("mp-feishu", "飞书通知", "notification", "im", "推送到飞书群", 4.5, 5800),
            ("mp-gpt-triage", "GPT 告警分诊", "ai", "triage", "LLM 自动分诊与摘要", 4.2, 2900),
            ("mp-mitre-attack", "MITRE ATT&CK 映射", "ai", "triage", "告警自动映射技术", 4.8, 8700),
            ("mp-pdf-report", "PDF 报告生成", "other", "report", "一键生成合规报告", 4.1, 1900),
        ]
        for pid, name, ptype, cat, desc, score, installs in seeds:
            self.items[pid] = {
                "id": pid, "name": name, "type": ptype, "category": cat,
                "description": desc, "author": "Marketplace Bot", "version": "1.0.0",
                "tags": [cat, ptype], "icon": "🧩", "license": "MIT",
                "homepage": f"https://mp.example.com/{pid}",
                "documentation": f"https://docs.example.com/{pid}",
                "screenshots": [f"https://cdn.example.com/{pid}/shot1.png"],
                "rating_avg": score, "installs": installs,
                "version_history": [{"version": "1.0.0", "released_at": _now(), "notes": "初始版本"}],
            }
            self.reviews[pid] = [
                {"id": f"{pid}-r1", "user": "user_001", "rating": 5,
                 "content": "非常好用，节省大量时间", "created_at": _now(),
                 "likes": 12, "reply": ""},
            ]
            self.ratings[pid] = [5, 4, 5, 5, 4]

    # ---------- 浏览 ----------
    def browse(self, category: Optional[str] = None, plugin_type: Optional[str] = None,
               tag: Optional[str] = None, q: Optional[str] = None,
               sort: str = "installs", page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        items = list(self.items.values())
        if category:
            items = [x for x in items if x["category"] == category]
        if plugin_type:
            items = [x for x in items if x["type"] == plugin_type]
        if tag:
            items = [x for x in items if tag in x.get("tags", [])]
        if q:
            ql = q.lower()
            items = [x for x in items if ql in x["name"].lower() or ql in x["description"].lower()]
        key_map = {"installs": "installs", "rating": "rating_avg", "name": "name"}
        items.sort(key=lambda x: x.get(key_map.get(sort, "installs"), 0), reverse=(sort != "name"))
        total = len(items)
        total_pages = max(1, math.ceil(total / page_size))
        start = (page - 1) * page_size
        return {
            "items": items[start:start + page_size],
            "total": total, "page": page, "page_size": page_size, "total_pages": total_pages,
        }

    def search(self, q: str, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        if q:
            self.search_history.append(q)
            self.search_history = self.search_history[-20:]
        res = self.browse(q=q, page=page, page_size=page_size)
        res["suggestions"] = self._suggest(q)
        res["search_history"] = self.search_history[-10:]
        res["hot_searches"] = self.hot_searches
        return res

    def _suggest(self, q: str) -> List[str]:
        if not q:
            return self.hot_searches[:5]
        ql = q.lower()
        out = []
        for it in self.items.values():
            if ql in it["name"].lower() or any(ql in t for t in it.get("tags", [])):
                out.append(it["name"])
        return out[:6]

    def categories(self) -> Dict[str, Any]:
        return CATEGORIES

    def detail(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        it = self.items.get(plugin_id)
        if not it:
            return None
        out = dict(it)
        out["reviews"] = self.reviews.get(plugin_id, [])
        out["rating_distribution"] = self._rating_distribution(plugin_id)
        return out

    def _rating_distribution(self, plugin_id: str) -> Dict[int, int]:
        dist = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        for r in self.ratings.get(plugin_id, []):
            dist[r] = dist.get(r, 0) + 1
        return dist

    # ---------- 一键安装 ----------
    def install(self, plugin_id: str, target_manager: Any = None) -> Dict[str, Any]:
        it = self.items.get(plugin_id)
        if not it:
            return {"ok": False, "error": "市场插件不存在"}
        installed_now = int(time.time())
        it["installs"] = it.get("installs", 0) + 1
        result = {
            "ok": True, "id": plugin_id, "installed_at": _now(),
            "message": "市场一键安装成功（已模拟依赖自动解析与配置）",
            "auto_configured": True, "dependencies_installed": [],
        }
        return result

    # ---------- 更新 ----------
    def check_updates(self, installed: Dict[str, str]) -> List[Dict[str, Any]]:
        out = []
        for pid, ver in installed.items():
            it = self.items.get(pid)
            if it and it["version"] != ver:
                out.append({"id": pid, "current": ver, "latest": it["version"]})
        return out

    # ---------- 评分 / 评论 ----------
    def rate(self, plugin_id: str, score: int, reviewer: str = "anonymous") -> Dict[str, Any]:
        if plugin_id not in self.items:
            return {"ok": False, "error": "插件不存在"}
        if score < 1 or score > 5:
            return {"ok": False, "error": "评分必须为 1-5"}
        self.ratings.setdefault(plugin_id, []).append(score)
        arr = self.ratings[plugin_id]
        avg = round(sum(arr) / len(arr), 2)
        self.items[plugin_id]["rating_avg"] = avg
        self.items[plugin_id]["rating_count"] = len(arr)
        return {"ok": True, "rating_avg": avg, "count": len(arr)}

    def list_reviews(self, plugin_id: str, sort: str = "likes",
                     page: int = 1, page_size: int = 10) -> Dict[str, Any]:
        rs = list(self.reviews.get(plugin_id, []))
        rs.sort(key=lambda r: r.get(sort, 0), reverse=True)
        total = len(rs)
        total_pages = max(1, math.ceil(total / page_size))
        start = (page - 1) * page_size
        return {"items": rs[start:start + page_size], "total": total,
                "page": page, "page_size": page_size, "total_pages": total_pages}

    def add_review(self, plugin_id: str, user: str, rating: int, content: str) -> Dict[str, Any]:
        if plugin_id not in self.items:
            return {"ok": False, "error": "插件不存在"}
        if not content:
            return {"ok": False, "error": "评论内容不能为空"}
        rid = f"{plugin_id}-r{int(time.time())}"
        self.reviews.setdefault(plugin_id, []).append({
            "id": rid, "user": user, "rating": rating, "content": content,
            "created_at": _now(), "likes": 0, "reply": "",
        })
        return {"ok": True, "id": rid}

    def reply_review(self, plugin_id: str, review_id: str, reply: str) -> Dict[str, Any]:
        for r in self.reviews.get(plugin_id, []):
            if r["id"] == review_id:
                r["reply"] = reply
                return {"ok": True}
        return {"ok": False, "error": "评论不存在"}

    def like_review(self, plugin_id: str, review_id: str) -> Dict[str, Any]:
        for r in self.reviews.get(plugin_id, []):
            if r["id"] == review_id:
                r["likes"] = r.get("likes", 0) + 1
                return {"ok": True, "likes": r["likes"]}
        return {"ok": False, "error": "评论不存在"}

    # ---------- 推荐 ----------
    def recommendations(self, kind: str = "hot", limit: int = 6) -> List[Dict[str, Any]]:
        if kind == "new":
            items = sorted(self.items.values(), key=lambda x: x.get("version_history", [{}])[-1].get("released_at", ""), reverse=True)
        elif kind == "related":
            items = list(self.items.values())
        else:
            items = sorted(self.items.values(), key=lambda x: x.get("installs", 0), reverse=True)
        return items[:limit]

    # ---------- 统计 ----------
    def stats(self) -> Dict[str, Any]:
        total_installs = sum(it.get("installs", 0) for it in self.items.values())
        by_type: Dict[str, int] = {}
        for it in self.items.values():
            by_type[it["type"]] = by_type.get(it["type"], 0) + 1
        avg_rating = round(sum(it.get("rating_avg", 0) for it in self.items.values()) / max(1, len(self.items)), 2)
        return {
            "plugin_count": len(self.items),
            "total_installs": total_installs,
            "avg_rating": avg_rating,
            "by_type": by_type,
            "hot_searches": self.hot_searches,
        }


_default_market: Optional[PluginMarketplace] = None


def get_marketplace() -> PluginMarketplace:
    global _default_market
    if _default_market is None:
        _default_market = PluginMarketplace()
    return _default_market
