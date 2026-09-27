#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_pro/db_optimizer_v2.py — 数据库优化 V2。

- 索引优化（推荐缺失索引）
- 查询优化（EXPLAIN 模拟：判断是否命中索引）
- 缓存层（查询结果缓存 + 命中率统计）
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List


# 模拟表结构 + 已有索引
SCHEMA: Dict[str, Dict[str, Any]] = {
    "scan_tasks": {
        "columns": ["id", "customer_id", "target", "status", "created_at"],
        "indexes": ["PRIMARY(id)", "idx_status(created_at)"],
        "rows": 1_200_000,
    },
    "vuln_findings": {
        "columns": ["id", "task_id", "severity", "cve", "is_fixed"],
        "indexes": ["PRIMARY(id)", "idx_task(task_id)"],
        "rows": 8_600_000,
    },
    "reports": {
        "columns": ["id", "customer_id", "project_id", "format", "generated_at"],
        "indexes": ["PRIMARY(id)"],
        "rows": 340_000,
    },
}

# 推荐索引（缺失）
RECOMMENDED_INDEXES: List[Dict[str, Any]] = [
    {"table": "vuln_findings", "column": "severity", "reason": "按严重级别过滤慢查询",
     "est_speedup": "8x"},
    {"table": "vuln_findings", "column": "cve", "reason": "按 CVE 检索缺索引",
     "est_speedup": "12x"},
    {"table": "reports", "column": "customer_id", "reason": "客户门户按客户查报告全表扫描",
     "est_speedup": "20x"},
    {"table": "reports", "column": "project_id", "reason": "项目列表关联查询缺索引",
     "est_speedup": "15x"},
]


class DBOptimizerV2:
    """数据库优化器 V2。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cache: Dict[str, Any] = {}
        self._hits = 0
        self._misses = 0
        self._saved_ms = 0

    def schema(self) -> Dict[str, Any]:
        return SCHEMA

    def recommend_indexes(self) -> List[Dict[str, Any]]:
        return RECOMMENDED_INDEXES

    def analyze_query(self, sql: str) -> Dict[str, Any]:
        """模拟 EXPLAIN：简单解析 SQL 谓词，判断是否命中索引。"""
        s = sql.lower()
        hit_cols = []
        for table, meta in SCHEMA.items():
            if table in s:
                existing_cols = [ix.split("(")[1].split(")")[0]
                                 for ix in meta["indexes"] if "(" in ix]
                for col in meta["columns"]:
                    if col in s and col in existing_cols:
                        hit_cols.append(f"{table}.{col}")
        full_scan = not hit_cols
        est_ms = 1200 if full_scan else 18
        return {
            "sql": sql, "hit_indexes": hit_cols,
            "type": "ALL(全表扫描)" if full_scan else "ref(命中索引)",
            "est_cost_ms": est_ms,
            "rows_examined": "8.6M" if full_scan else "120",
            "suggestion": "添加索引 " + RECOMMENDED_INDEXES[0]["column"]
                          if full_scan else "已优化",
        }

    def cache_layer_demo(self) -> Dict[str, Any]:
        """演示：同一查询走缓存层第二次命中。"""
        key = "q:reports_by_customer:C-1001"
        with self._lock:
            if key in self._cache:
                self._hits += 1
                self._saved_ms += 1200
                return {"cached": True, "from_cache": True, "query_ms": 3}
            self._misses += 1
            self._cache[key] = [{"id": "R-1", "title": "demo"}]
            return {"cached": False, "from_cache": False, "query_ms": 1200}

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hits + self._misses
            return {"cache_size": len(self._cache),
                    "hits": self._hits, "misses": self._misses,
                    "hit_rate": round(self._hits / total * 100, 1) if total else 0.0,
                    "saved_ms_total": self._saved_ms,
                    "tables": len(SCHEMA),
                    "recommended_indexes": len(RECOMMENDED_INDEXES)}


_db: DBOptimizerV2 | None = None


def get_db_optimizer_v2() -> DBOptimizerV2:
    global _db
    if _db is None:
        _db = DBOptimizerV2()
    return _db
