# -*- coding: utf-8 -*-
"""
performance/query_optimizer.py — 查询优化引擎。

能力：
- 慢查询检测（超过阈值的数据库查询/API/外部调用，记录 SQL/耗时/调用栈/频率）
- 查询分析（EXPLAIN 模拟 / 索引使用 / 全表扫描检测 / 连接顺序 / 计划分析）
- 索引管理（盘点 / 缺失索引建议 / 冗余索引检测 / 使用率 / 创建脚本）
- 查询缓存（多级缓存 / 命中率 / 预热 / 失效 / 大小 / 键设计）
- N+1 查询检测（ORM / 手写 SQL 模式检测 / 批量建议）
- 真实扫描项目 data/*.sqlite 与源码中的查询模式

设计：全部内存字典 + 只读扫描，不写库、不建表。
"""

from __future__ import annotations

import glob
import os
import re
import sqlite3
import threading
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")

# --------------------------------------------------------------------------- #
# psutil 可选
# --------------------------------------------------------------------------- #
try:  # pragma: no cover
    import psutil  # type: ignore
    _PSUTIL = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore
    _PSUTIL = False

_SQL_RE = re.compile(
    r"""(SELECT\s.+?FROM\s+['"`]?([a-zA-Z0-9_\.]+)['"`]?
          |INSERT\s+INTO\s+['"`]?([a-zA-Z0-9_\.]+)['"`]?
          |UPDATE\s+['"`]?([a-zA-Z0-9_\.]+)['"`]?
          |DELETE\s+FROM\s+['"`]?([a-zA-Z0-9_\.]+)['"`]?)""",
    re.IGNORECASE | re.VERBOSE,
)
_WHERE_RE = re.compile(r"\bWHERE\b(.+?)(;|$)", re.IGNORECASE | re.DOTALL)
_JOIN_RE = re.compile(r"\b(JOIN|INNER JOIN|LEFT JOIN|RIGHT JOIN)\b", re.IGNORECASE)


class QueryOptimizer:
    """查询优化引擎（线程安全，内存态）。"""

    SLOW_THRESHOLD_MS = 120.0

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._slow: Deque[Dict[str, Any]] = deque(maxlen=500)
        self._freq: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "total_ms": 0.0, "max_ms": 0.0, "last_at": None})
        # 多级缓存：L1 进程内 / L2 持久化（模拟）
        self._cache: Dict[str, Dict[str, Any]] = {"L1": {}, "L2": {}}
        self._cache_stat = {"hits": 0, "misses": 0, "sets": 0, "evicts": 0}
        self._cache_max = {"L1": 2000, "L2": 10000}
        self.started_at = time.time()

    # ------------------------------------------------------------------ #
    # 慢查询检测
    # ------------------------------------------------------------------ #
    def record_query(self, sql: str, elapsed_ms: float, *, kind: str = "sql",
                     endpoint: str = "", stack: str = "") -> Dict[str, Any]:
        sql_norm = re.sub(r"\s+", " ", sql or "").strip()[:500]
        key = f"{kind}:{sql_norm[:120]}"
        with self._lock:
            bucket = self._freq[key]
            bucket["count"] += 1
            bucket["total_ms"] += elapsed_ms
            bucket["max_ms"] = max(bucket["max_ms"], elapsed_ms)
            bucket["last_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            bucket["sample"] = sql_norm
            bucket["endpoint"] = endpoint
            if elapsed_ms >= self.SLOW_THRESHOLD_MS:
                self._slow.appendleft({
                    "sql": sql_norm, "kind": kind, "endpoint": endpoint,
                    "elapsed_ms": round(elapsed_ms, 2),
                    "stack": stack or self._quick_stack(),
                    "at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "freq": bucket["count"],
                })
        return {"recorded": True, "elapsed_ms": round(elapsed_ms, 2),
                "slow": elapsed_ms >= self.SLOW_THRESHOLD_MS}

    @staticmethod
    def _quick_stack(limit: int = 4) -> str:
        import traceback
        frames = traceback.extract_stack(limit=limit + 3)[:-1]
        return " <- ".join(f"{os.path.basename(f.filename)}:{f.lineno}"
                            for f in frames[-limit:])

    def list_slow(self, limit: int = 50,
                  min_ms: Optional[float] = None) -> Dict[str, Any]:
        with self._lock:
            rows = list(self._slow)
        if min_ms is not None:
            rows = [r for r in rows if r["elapsed_ms"] >= min_ms]
        rows.sort(key=lambda r: r["elapsed_ms"], reverse=True)
        return {"slow_queries": rows[:limit], "total": len(self._slow),
                "threshold_ms": self.SLOW_THRESHOLD_MS}

    def top_queries(self, limit: int = 20) -> Dict[str, Any]:
        with self._lock:
            items = []
            for k, v in self._freq.items():
                items.append({
                    "key": k, "count": v["count"],
                    "avg_ms": round(v["total_ms"] / max(v["count"], 1), 2),
                    "max_ms": round(v["max_ms"], 2),
                    "sample": v.get("sample", ""), "endpoint": v.get("endpoint", ""),
                    "last_at": v["last_at"],
                })
        items.sort(key=lambda x: x["total_ms"] if False else x["count"], reverse=True)
        return {"top_queries": items[:limit], "tracked": len(items)}

    # ------------------------------------------------------------------ #
    # 查询分析（EXPLAIN 模拟）
    # ------------------------------------------------------------------ #
    def analyze_query(self, sql: str, db_path: str = "") -> Dict[str, Any]:
        plan: List[Dict[str, Any]] = []
        full_scan = False
        using_index = False
        joins = len(_JOIN_RE.findall(sql or ""))
        try:
            if db_path and os.path.exists(db_path):
                con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
                cur = con.cursor()
                try:
                    cur.execute("EXPLAIN QUERY PLAN " + (sql or "SELECT 1"))
                    for row in cur.fetchall():
                        detail = str(row[-1] or "")
                        plan.append({"id": row[0], "parent": row[1],
                                     "detail": detail})
                        if "SCAN" in detail.upper() and "USING INDEX" not in detail.upper():
                            if "TABLE" in detail.upper() and "sqlite_autoindex" not in detail:
                                full_scan = True
                        if "USING INDEX" in detail.upper():
                            using_index = True
                finally:
                    con.close()
        except Exception as e:  # noqa: BLE001
            plan.append({"note": f"EXPLAIN 不可用，使用启发式分析: {e}"})
            up = (sql or "").upper()
            full_scan = ("FROM" in up and "WHERE" not in up) or up.count("*") > 0 and "WHERE" not in up
            using_index = False

        heuristics = self._heuristics(sql or "")
        issues: List[str] = []
        if full_scan:
            issues.append("检测到疑似全表扫描（SCAN 且未命中索引）")
        if joins >= 3:
            issues.append(f"多表连接({joins})，注意连接顺序与驱动表选择")
        if re.search(r"SELECT\s+\*", (sql or ""), re.IGNORECASE):
            issues.append("使用 SELECT *，建议字段裁剪")
        if "LIKE '%" in (sql or "").upper() or "LIKE \"%" in (sql or ""):
            issues.append("前导通配符 LIKE '%xxx' 无法使用普通索引")
        if not using_index and not plan:
            issues.append("未观察到索引命中，建议补充覆盖索引")
        return {
            "sql": re.sub(r"\s+", " ", (sql or "")).strip()[:400],
            "query_plan": plan, "uses_index": using_index,
            "likely_full_scan": full_scan, "joins": joins,
            "issues": issues, "heuristics": heuristics,
            "optimization": self._optimization_tips(full_scan, joins, bool(issues)),
        }

    def _heuristics(self, sql: str) -> Dict[str, Any]:
        where = _WHERE_RE.search(sql)
        cond = where.group(1) if where else ""
        cols = re.findall(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\?", cond)
        like_cols = re.findall(r"([a-zA-Z_][a-zA-Z0-9_]*)\s+LIKE", cond, re.IGNORECASE)
        return {"equality_cols": cols, "like_cols": like_cols,
                "where_fragment": cond[:200].strip()}

    @staticmethod
    def _optimization_tips(full_scan: bool, joins: int, has_issue: bool) -> List[str]:
        tips: List[str] = []
        if full_scan:
            tips.append("为 WHERE 过滤列建立 B-Tree 索引，避免全表扫描")
        if joins:
            tips.append("确保连接外键列有索引，并按小结果集驱动大表")
        tips.append("高频只读查询接入多级缓存，降低 DB 往返")
        tips.append("使用 LIMIT + 分页(keyset)替代大结果集一次性拉取")
        if has_issue:
            tips.append("定期 ANALYZE 更新统计信息，帮助查询优化器选择计划")
        return tips

    # ------------------------------------------------------------------ #
    # 索引管理（真实扫描 sqlite_master）
    # ------------------------------------------------------------------ #
    def inventory_indexes(self, db_path: Optional[str] = None) -> Dict[str, Any]:
        targets = [db_path] if db_path else self._list_dbs()
        out: List[Dict[str, Any]] = []
        for db in targets:
            try:
                con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
                cur = con.cursor()
                cur.execute("SELECT name, tbl_name, sql FROM sqlite_master "
                            "WHERE type='index' AND name NOT LIKE 'sqlite_%'")
                for name, tbl, sql in cur.fetchall():
                    out.append({"db": os.path.basename(db), "table": tbl,
                                "index": name, "ddl": (sql or "")[:200]})
                con.close()
            except Exception as e:  # noqa: BLE001
                out.append({"db": os.path.basename(db), "error": str(e)[:120]})
        return {"indexes": out, "total": len(out),
                "databases": [os.path.basename(d) for d in targets]}

    def suggest_indexes(self, db_path: Optional[str] = None) -> Dict[str, Any]:
        targets = [db_path] if db_path else self._list_dbs()
        suggestions: List[Dict[str, Any]] = []
        for db in targets:
            try:
                con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
                cur = con.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' "
                            "AND name NOT LIKE 'sqlite_%'")
                tables = [r[0] for r in cur.fetchall()]
                existing: Dict[str, set] = defaultdict(set)
                cur.execute("SELECT tbl_name, name FROM sqlite_master "
                            "WHERE type='index' AND name NOT LIKE 'sqlite_%'")
                for tbl, idx in cur.fetchall():
                    existing[tbl].add(idx.lower())
                for tbl in tables:
                    cur.execute(f"PRAGMA table_info('{tbl}')")
                    cols = [c[1] for c in cur.fetchall()]
                    common = [c for c in cols if c.lower() in (
                        "id", "status", "created_at", "created_time",
                        "updated_at", "tenant_id", "user_id", "org_id",
                        "type", "level", "severity")]
                    for c in common[:4]:
                        base = f"idx_{tbl}_{c}".lower()
                        if base not in existing[tbl]:
                            suggestions.append({
                                "db": os.path.basename(db), "table": tbl,
                                "column": c,
                                "create_sql": f"CREATE INDEX IF NOT EXISTS "
                                              f"idx_{tbl}_{c} ON {tbl}({c});",
                                "reason": f"{c} 高频过滤/排序列，现有无对应索引",
                            })
                con.close()
            except Exception as e:  # noqa: BLE001
                suggestions.append({"db": os.path.basename(db), "error": str(e)[:120]})
        return {"suggestions": suggestions[:80], "total": len(suggestions),
                "databases": [os.path.basename(d) for d in targets]}

    def detect_redundant_indexes(self) -> Dict[str, Any]:
        # 基于命名与列前缀的启发式冗余检测
        invent = self.inventory_indexes()["indexes"]
        groups: Dict[str, List[str]] = defaultdict(list)
        for it in invent:
            groups[it.get("table", "")].append(it.get("index", ""))
        redundant: List[Dict[str, Any]] = []
        for tbl, names in groups.items():
            lower = [n.lower() for n in names]
            for i, n in enumerate(lower):
                for j, m in enumerate(lower):
                    if i != j and n != m and n.startswith(m + "_"):
                        redundant.append({"table": tbl, "possibly_redundant": names[i],
                                          "covered_by": names[j]})
        return {"redundant": redundant[:60], "total": len(redundant)}

    def index_usage(self) -> Dict[str, Any]:
        inv = self.inventory_indexes()
        # 基于慢查询频率做启发式使用率统计
        with self._lock:
            tracked = sum(v["count"] for v in self._freq.values())
        usage = [{**it, "estimated_scans": max(1, tracked // max(len(inv["indexes"]), 1))}
                 for it in inv["indexes"][:40]]
        return {"indexes": usage, "tracked_queries": tracked,
                "total_indexes": inv["total"]}

    def create_index_script(self) -> Dict[str, Any]:
        sug = self.suggest_indexes()
        lines = [s["create_sql"] for s in sug["suggestions"] if "create_sql" in s]
        return {"script": "\n".join(lines), "count": len(lines),
                "note": "请在低峰期执行，并先在测试库验证"}

    # ------------------------------------------------------------------ #
    # 查询缓存
    # ------------------------------------------------------------------ #
    @staticmethod
    def cache_key(namespace: str, ident: str) -> str:
        return f"{namespace}:{ident}:{hash(ident) & 0xffffffff:08x}"

    def cache_get(self, key: str, level: str = "L1") -> Optional[Any]:
        with self._lock:
            box = self._cache[level]
            hit = box.get(key)
            if hit is not None:
                hit["at"] = time.time()
                self._cache_stat["hits"] += 1
                return hit["value"]
            self._cache_stat["misses"] += 1
            return None

    def cache_set(self, key: str, value: Any, level: str = "L1",
                  ttl: int = 60) -> None:
        with self._lock:
            box = self._cache[level]
            if len(box) >= self._cache_max[level]:
                # LRU 驱逐：移除最旧
                oldest = min(box, key=lambda k: box[k].get("at", 0))
                box.pop(oldest, None)
                self._cache_stat["evicts"] += 1
            box[key] = {"value": value, "at": time.time(), "ttl": ttl}
            self._cache_stat["sets"] += 1

    def cache_stats(self) -> Dict[str, Any]:
        with self._lock:
            h, m = self._cache_stat["hits"], self._cache_stat["misses"]
            total = h + m
            return {
                "hit_rate": round(h / total, 4) if total else 0.0,
                "hits": h, "misses": m, "sets": self._cache_stat["sets"],
                "evicts": self._cache_stat["evicts"],
                "size": {k: len(v) for k, v in self._cache.items()},
                "max_size": dict(self._cache_max),
                "strategy": "L1 进程内(短TTL) + L2 跨请求(长TTL)，写穿 + 主动失效",
                "key_design": "namespace:business_id:hash(ident)",
            }

    def cache_invalidate(self, namespace: str) -> Dict[str, Any]:
        removed = 0
        with self._lock:
            for lvl, box in self._cache.items():
                for k in list(box.keys()):
                    if k.startswith(namespace + ":"):
                        box.pop(k, None)
                        removed += 1
        return {"invalidated": removed, "namespace": namespace}

    def cache_warmup(self) -> Dict[str, Any]:
        namespaces = ["dashboard:overview", "index:list", "lookup:status"]
        for ns in namespaces:
            self.cache_set(ns, {"warmup": True, "ts": time.time()})
        return {"warmed": len(namespaces), "namespaces": namespaces}

    # ------------------------------------------------------------------ #
    # N+1 检测（真实扫描源码）
    # ------------------------------------------------------------------ #
    def detect_n_plus_one(self, sample_size: int = 400) -> Dict[str, Any]:
        """扫描项目源码，检测疑似 N+1 模式：
        循环内执行单条按 id 查询。"""
        findings: List[Dict[str, Any]] = []
        py_files = []
        for ext in ("*.py",):
            py_files.extend(glob.glob(os.path.join(ROOT, "*", "**", ext),
                                      recursive=True))
        py_files = py_files[: sample_size * 3]
        loop_re = re.compile(r"^\s*(for|while)\b")
        q_re = re.compile(r"(execute|fetchone|fetchall|get\(|filter\(|query\()")
        for path in py_files:
            try:
                if os.path.getsize(path) > 400_000:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:  # noqa: BLE001
                continue
            in_loop = False
            loop_indent = ""
            for i, line in enumerate(lines):
                if loop_re.match(line):
                    in_loop = True
                    loop_indent = line[: len(line) - len(line.lstrip())]
                    continue
                if in_loop and q_re.search(line):
                    indent = line[: len(line) - len(line.lstrip())]
                    if indent.startswith(loop_indent) and line.strip():
                        findings.append({
                            "file": os.path.relpath(path, ROOT),
                            "line": i + 1,
                            "loop_snippet": lines[i - 1].strip()[:120],
                            "query_snippet": line.strip()[:120],
                            "suggestion": "批量收集 id 后使用 IN(...) 一次性查询，"
                                          "再在内存中按 id 分组映射",
                        })
                        in_loop = False  # 每个循环块只报一次
                elif in_loop and line.strip() and not line.startswith(loop_indent + " "):
                    in_loop = False
                if len(findings) >= 60:
                    break
            if len(findings) >= 60:
                break
        return {"findings": findings, "total": len(findings),
                "scanned_files": len(py_files),
                "batch_pattern": "ids = [x.id for x in rows];"
                                 " mapped = {r.id: r for r in session.filter(Model.id.in_(ids))}"}

    # ------------------------------------------------------------------ #
    # 工具
    # ------------------------------------------------------------------ #
    def _list_dbs(self) -> List[str]:
        out = []
        if os.path.isdir(DATA_DIR):
            for ext in ("*.db", "*.sqlite", "*.sqlite3"):
                out.extend(glob.glob(os.path.join(DATA_DIR, ext)))
        return sorted(out)

    def project_sql_patterns(self) -> Dict[str, Any]:
        dbs = self._list_dbs()
        table_count = 0
        for db in dbs:
            try:
                con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
                cur = con.cursor()
                cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table'")
                table_count += cur.fetchone()[0]
                con.close()
            except Exception:  # noqa: BLE001
                pass
        return {"databases": [os.path.basename(d) for d in dbs],
                "database_count": len(dbs), "estimated_tables": table_count,
                "data_dir": os.path.relpath(DATA_DIR, ROOT)}


# 单例
query_optimizer = QueryOptimizer()
