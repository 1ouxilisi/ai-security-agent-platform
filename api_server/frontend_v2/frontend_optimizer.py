# -*- coding: utf-8 -*-
"""
frontend_optimizer.py — 前端性能与体验优化后端。

分页 / 虚拟滚动 / 骨架屏 / 搜索建议 / 性能指标上报 / 缓存管理。
"""
from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional

from .common import now_str, new_id


# 全局性能指标
METRICS: List[Dict[str, Any]] = []
CACHE: Dict[str, Dict[str, Any]] = {
    "assets_list": {"hit": 1280, "miss": 42, "ttl_s": 60},
    "vulns_list": {"hit": 860, "miss": 95, "ttl_s": 60},
    "reports_list": {"hit": 430, "miss": 30, "ttl_s": 120},
    "nav_menu": {"hit": 5200, "miss": 0, "ttl_s": 3600},
}

# 虚拟滚动演示数据集（模拟大列表）
_VIRTUAL_POOL: List[Dict[str, Any]] = [
    {"id": f"row_{i:05d}", "index": i,
     "name": f"扫描记录 #{i}",
     "status": random.choice(["done", "running", "failed"]),
     "duration_s": round(random.uniform(2, 120), 1),
     "created_at": now_str()}
    for i in range(5000)
]

# 搜索建议索引
SUGGEST_INDEX: List[Dict[str, str]] = [
    {"type": "page", "label": "任务执行面板", "route": "#/tasks"},
    {"type": "page", "label": "交互式报告查看器", "route": "#/reports"},
    {"type": "page", "label": "数据管理 CRUD", "route": "#/data"},
    {"type": "page", "label": "通知中心", "route": "#/notifications"},
    {"type": "page", "label": "性能与体验", "route": "#/perf"},
    {"type": "vuln", "label": "SQL 注入(登录接口)", "route": "#/reports?focus=vuln"},
    {"type": "vuln", "label": "反射型 XSS", "route": "#/reports?focus=vuln"},
    {"type": "asset", "label": "api.example.com", "route": "#/data?tab=assets"},
    {"type": "asset", "label": "db-master-01", "route": "#/data?tab=assets"},
    {"type": "kb", "label": "如何修复 SQL 注入", "route": "#/data?tab=kb"},
    {"type": "report", "label": "2026-Q3 Web 安全报告", "route": "#/reports"},
]


def paginate_data(rows: List[Dict[str, Any]], page: int, page_size: int) -> Dict[str, Any]:
    total = len(rows)
    page = max(1, page)
    page_size = max(1, min(500, page_size))
    s = (page - 1) * page_size
    return {"items": rows[s:s + page_size], "total": total, "page": page,
            "page_size": page_size, "has_more": s + page_size < total}


def virtual_list(offset: int = 0, limit: int = 50) -> Dict[str, Any]:
    rows = _VIRTUAL_POOL[offset:offset + limit]
    return {"items": rows, "total": len(_VIRTUAL_POOL),
            "offset": offset, "returned": len(rows)}


def skeleton(module: str) -> Dict[str, Any]:
    demos = {
        "tasks": {"task_id": "skeleton", "scenario_name": "加载中…",
                  "target": "…", "status": "pending", "progress": 0},
        "reports": {"report_id": "skeleton", "title": "加载中…",
                    "risk_score": 0, "findings_count": 0},
        "vulns": {"vuln_id": "skeleton", "title": "加载中…", "severity": "low",
                  "cvss": 0, "status": "open"},
    }
    return {"module": module, "data": demos.get(module, {"placeholder": True}),
            "note": "骨架屏：首屏最小数据，等待真实接口返回后替换。"}


def search_suggest(q: str, limit: int = 10) -> List[Dict[str, str]]:
    if not q:
        return []
    ql = q.lower()
    hits = [s for s in SUGGEST_INDEX if ql in s["label"].lower()]
    return hits[:limit]


def report_metric(page: str, load_ms: float, api_ms: float,
                  error: bool = False) -> Dict[str, Any]:
    m = {"id": new_id("met"), "page": page, "load_ms": load_ms,
         "api_ms": api_ms, "error": error, "ts": time.time(),
         "time": now_str()}
    METRICS.append(m)
    if len(METRICS) > 2000:
        del METRICS[:500]
    return m


def perf_summary() -> Dict[str, Any]:
    if not METRICS:
        # 给一份演示基线
        loads = [420, 510, 680, 390, 720, 810, 460, 530, 610, 580]
        apis = [80, 120, 200, 60, 150, 300, 90, 110, 130, 170]
        errors = 1
        total = len(loads)
    else:
        loads = sorted(m["load_ms"] for m in METRICS)
        apis = sorted(m["api_ms"] for m in METRICS)
        errors = sum(1 for m in METRICS if m["error"])
        total = len(METRICS)

    def pct(arr: List[float], p: float) -> float:
        if not arr:
            return 0.0
        idx = min(len(arr) - 1, int(len(arr) * p))
        return float(arr[idx])

    slow = sorted(
        [{"page": m["page"], "load_ms": m["load_ms"],
          "api_ms": m["api_ms"], "time": m["time"]} for m in METRICS],
        key=lambda x: x["api_ms"], reverse=True)[:10] if METRICS else []

    return {
        "load_p50_ms": round(pct(loads, 0.5), 1),
        "load_p95_ms": round(pct(loads, 0.95), 1),
        "api_p50_ms": round(pct(apis, 0.5), 1),
        "api_p95_ms": round(pct(apis, 0.95), 1),
        "error_rate": round(errors / max(1, total), 4),
        "samples": total,
        "slow_apis": slow,
        "cache": cache_stats(),
        "suggestions": [
            "对 /tasks 列表接口增加服务端缓存（TTL 60s）",
            "漏洞详情抽屉采用懒加载，首屏只渲染表格",
            "全局搜索使用防抖(300ms) + 后端 Top10 建议",
            "大列表启用虚拟滚动，DOM 节点控制在 30 以内",
        ],
    }


def cache_stats() -> Dict[str, Any]:
    rows = []
    total_hit = total_miss = 0
    for name, c in CACHE.items():
        total_hit += c["hit"]
        total_miss += c["miss"]
        total = c["hit"] + c["miss"]
        rows.append({"key": name, "hit": c["hit"], "miss": c["miss"],
                     "hit_rate": round(c["hit"] / max(1, total), 3),
                     "ttl_s": c["ttl_s"]})
    overall = total_hit / max(1, total_hit + total_miss)
    return {"overall_hit_rate": round(overall, 3), "keys": rows}


def cache_invalidate(key: str = "") -> Dict[str, Any]:
    if key and key in CACHE:
        CACHE[key]["miss"] += CACHE[key]["hit"]
        CACHE[key]["hit"] = 0
        return {"invalidated": [key]}
    invalidated = []
    for k in CACHE:
        CACHE[k]["miss"] += CACHE[k]["hit"]
        CACHE[k]["hit"] = 0
        invalidated.append(k)
    return {"invalidated": invalidated}


def cache_warmup() -> Dict[str, Any]:
    for k, c in CACHE.items():
        c["hit"] += 50
    return {"warmed": list(CACHE.keys()), "time": now_str()}
