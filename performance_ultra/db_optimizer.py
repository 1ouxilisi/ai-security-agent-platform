#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_ultra/db_optimizer.py — 数据库优化（索引 / 查询计划 / LRU 缓存层）。

全部用内存字典模拟：演示索引命中、慢查询、缓存层收益。
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional


# 模拟的表与索引
_SAMPLE_SCHEMA: Dict[str, Any] = {
    "targets": {
        "columns": ["id", "url", "owner", "status", "created_at"],
        "indexes": [
            {"name": "idx_target_url", "col": "url", "type": "btree"},
            {"name": "idx_target_owner", "col": "owner", "type": "btree"},
            {"name": "idx_target_status", "col": "status", "type": "hash"},
        ],
        "rows": 1286,
    },
    "vulns": {
        "columns": ["id", "target_id", "severity", "cve", "status", "cvss"],
        "indexes": [
            {"name": "idx_vuln_target", "col": "target_id", "type": "btree"},
            {"name": "idx_vuln_severity", "col": "severity", "type": "hash"},
            {"name": "idx_vuln_cve", "col": "cve", "type": "btree"},
            {"name": "idx_vuln_status", "col": "status", "type": "hash"},
        ],
        "rows": 4523,
    },
    "reports": {
        "columns": ["id", "title", "author", "created_at", "status"],
        "indexes": [
            {"name": "idx_report_author", "col": "author", "type": "btree"},
            {"name": "idx_report_status", "col": "status", "type": "hash"},
        ],
        "rows": 234,
    },
}


class DbOptimizer:
    """数据库优化演示器。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._schema = _SAMPLE_SCHEMA
        self._slow_queries: List[Dict[str, Any]] = []
        self._cache_hits = 0
        self._cache_misses = 0
        self._query_log: List[Dict[str, Any]] = []

    def schema(self) -> Dict[str, Any]:
        return self._schema

    def recommend_indexes(self) -> List[Dict[str, Any]]:
        """基于慢查询给出索引建议。"""
        return [
            {"table": "vulns", "col": "(severity, status)",
             "benefit": "82%", "note": "高频按严重级别+状态过滤，建联合索引"},
            {"table": "targets", "col": "(owner, status)",
             "benefit": "64%", "note": "按负责人+状态筛选资产"},
            {"table": "reports", "col": "created_at DESC",
             "benefit": "55%", "note": "首页最近报告排序避免 filesort"},
        ]

    def analyze_query(self, sql: str) -> Dict[str, Any]:
        """模拟 EXPLAIN：判断是否命中索引。"""
        sql_low = sql.lower()
        used_index = None
        for table, meta in self._schema.items():
            if table in sql_low:
                for idx in meta["indexes"]:
                    if idx["col"] in sql_low:
                        used_index = idx["name"]
                        break
        scanned_rows = 4523 if "vuln" in sql_low else (1286 if "target" in sql_low else 234)
        rows_examined = scanned_rows if not used_index else max(5, scanned_rows // 100)
        plan = {
            "sql": sql,
            "used_index": used_index,
            "rows_examined": rows_examined,
            "estimated_ms": round(rows_examined * 0.02, 2),
            "type": "index" if used_index else "seq_scan",
            "warning": None if used_index else "未命中索引，建议加索引",
        }
        self._query_log.append(plan)
        if rows_examined > 1000:
            self._slow_queries.append(plan)
        return plan

    def cache_layer_demo(self) -> Dict[str, Any]:
        """模拟 LRU 缓存层收益。"""
        hits, misses = 320, 80
        total = hits + misses
        self._cache_hits += hits
        self._cache_misses += misses
        return {
            "queries": total,
            "cache_hits": hits,
            "cache_misses": misses,
            "hit_rate": round(hits / total * 100, 1),
            "avg_ms_without_cache": 120.0,
            "avg_ms_with_cache": 8.0,
            "saved": round((1 - 8.0 / 120.0) * 100, 1),
        }

    def stats(self) -> Dict[str, Any]:
        return {
            "tables": len(self._schema),
            "indexes": sum(len(t["indexes"]) for t in self._schema.values()),
            "total_rows": sum(t["rows"] for t in self._schema.values()),
            "slow_queries": len(self._slow_queries),
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "queries_logged": len(self._query_log),
        }


_opt: DbOptimizer | None = None


def get_db_optimizer() -> DbOptimizer:
    global _opt
    if _opt is None:
        _opt = DbOptimizer()
    return _opt
