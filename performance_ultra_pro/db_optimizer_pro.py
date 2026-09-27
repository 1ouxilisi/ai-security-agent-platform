# -*- coding: utf-8 -*-
"""
performance_ultra_pro/db_optimizer_pro.py — 数据库优化 Pro。

- 所有查询加索引
- 慢查询优化
- 查询缓存
- 连接池
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List


class DBOptimizerPro:
    """数据库优化 Pro（全内存模拟）。"""

    TABLES = {
        "vulns": {"rows": 128000, "indexes": ["idx_severity", "idx_status", "idx_target"]},
        "reports": {"rows": 12400, "indexes": ["idx_customer", "idx_created"]},
        "scans": {"rows": 98200, "indexes": ["idx_project", "idx_finished_at"]},
        "assets": {"rows": 45000, "indexes": ["idx_owner", "idx_ip"]},
    }

    SAMPLE_SLOW = [
        {"sql": "SELECT * FROM vulns WHERE target LIKE '%x%'", "p95": 820,
         "rows_examined": 128000, "suggest": "加 idx_target + 全文索引"},
        {"sql": "SELECT customer,count(*) FROM reports GROUP BY customer", "p95": 430,
         "rows_examined": 12400, "suggest": "加覆盖索引 idx_customer(created_at)"},
    ]

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._query_cache: Dict[str, Any] = {}
        self._slow_log: List[Dict[str, Any]] = list(self.SAMPLE_SLOW)
        self._pool_size = 20
        self._pool_idle = 20
        self._queries_total = 0
        self._cache_hits = 0

    def schema(self) -> Dict[str, Any]:
        return {"tables": self.TABLES,
                "total_rows": sum(t["rows"] for t in self.TABLES.values()),
                "total_indexes": sum(len(t["indexes"]) for t in self.TABLES.values())}

    def index_recommendations(self) -> List[Dict[str, Any]]:
        return [
            {"table": "vulns", "index": "idx_target_severity(target,severity)",
             "gain": "扫描列表查询 -60%"},
            {"table": "scans", "index": "idx_project_finished(project_id,finished_at)",
             "gain": "项目历史 -45%"},
            {"table": "reports", "index": "idx_customer_status(customer_id,status)",
             "gain": "客户报告页 -50%"},
        ]

    def explain(self, sql: str) -> Dict[str, Any]:
        """模拟执行计划。"""
        cost = 0.0
        rows = 1000
        used_index = "PRIMARY"
        if "vulns" in sql:
            rows = 128000
            used_index = "idx_severity"
            cost = 42.0
        elif "reports" in sql:
            rows = 12400
            used_index = "idx_customer"
            cost = 8.0
        if "LIKE '%" in sql:
            used_index = "NONE (全表扫描)"
            cost = 820.0
        return {"sql": sql, "type": "index" if used_index != "NONE (全表扫描)" else "ALL",
                "used_index": used_index, "rows_examined": rows,
                "cost": cost, "recommend": "LIKE 前导通配 → 改全文索引" if "LIKE" in sql else "已走索引"}

    def query(self, key: str, loader):
        """带查询缓存的读。"""
        with self._lock:
            self._queries_total += 1
            if key in self._query_cache:
                self._cache_hits += 1
                return {"value": self._query_cache[key], "cached": True}
        value = loader()
        with self._lock:
            self._query_cache[key] = value
        return {"value": value, "cached": False}

    def cache_layer(self) -> Dict[str, Any]:
        with self._lock:
            rate = round(100.0 * self._cache_hits / self._queries_total, 1) if self._queries_total else 0.0
            return {"cached_queries": len(self._query_cache),
                    "hits": self._cache_hits, "total": self._queries_total,
                    "hit_rate": rate}

    def slow_queries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return sorted(self._slow_log, key=lambda x: x["p95"], reverse=True)

    def connection_pool(self) -> Dict[str, Any]:
        with self._lock:
            return {"size": self._pool_size, "idle": self._pool_idle,
                    "busy": self._pool_size - self._pool_idle,
                    "timeout_ms": 1000, "max_overflow": 10}

    def stats(self) -> Dict[str, Any]:
        s = self.schema()
        return {"tables": len(self.TABLES), "indexes": s["total_indexes"],
                "total_rows": s["total_rows"],
                "query_cache": self.cache_layer(),
                "pool": self.connection_pool()}


_opt: DBOptimizerPro | None = None


def get_db_optimizer_pro() -> DBOptimizerPro:
    global _opt
    if _opt is None:
        _opt = DBOptimizerPro()
    return _opt
