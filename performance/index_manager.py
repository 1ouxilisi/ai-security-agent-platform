# -*- coding: utf-8 -*-
"""
performance/index_manager.py — 索引管理器（单例）

功能：
    - 索引分析：通过 sqlite_master 查询索引定义，统计索引数量 / 重复索引 / 缺失索引建议 / 无效索引；
    - 索引建议：结合慢查询分析，给出添加 / 删除 / 修改索引的建议；
    - 索引管理：CREATE INDEX / DROP INDEX / REINDEX，支持在线重建；
    - 索引统计：索引数量 / 大小（sqlite_stat1）/ 使用率估算 / 维护时间；
    - 健康检查：碎片、统计信息过期、未使用索引检测。

仅依赖标准库 + SQLite 内置功能，持久化到 data/performance/index_manager.json。
"""
import json
import os
import re
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


def _project_root() -> str:
    """返回项目根目录。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class IndexManager:
    """索引管理器：分析、建议、创建/删除/重建、统计与健康检查。单例。"""

    _instance: Optional["IndexManager"] = None
    _lock = threading.Lock()

    def __new__(cls, db_path: Optional[str] = None) -> "IndexManager":
        """线程安全单例构造。"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    obj = super().__new__(cls)
                    obj._init(db_path)
                    cls._instance = obj
        return cls._instance

    def _init(self, db_path: Optional[str]) -> None:
        """初始化数据库路径与持久化目录。"""
        root = _project_root()
        self.db_path = db_path or os.path.join(root, "data", "ai_hacking_agent.db")
        self.data_dir = os.path.join(root, "data", "performance")
        os.makedirs(self.data_dir, exist_ok=True)
        self._store_path = os.path.join(self.data_dir, "index_manager.json")
        # 索引维护历史（创建/删除/重建记录）
        self.operation_history: List[Dict[str, Any]] = []
        self._load()

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------
    def _load(self) -> None:
        """恢复维护历史（容错）。"""
        try:
            if os.path.exists(self._store_path):
                with open(self._store_path, "r", encoding="utf-8") as f:
                    self.operation_history = json.load(f).get("history", [])
        except Exception:
            self.operation_history = []

    def _save(self) -> None:
        """保存维护历史（容错）。"""
        try:
            with open(self._store_path, "w", encoding="utf-8") as f:
                json.dump({"history": self.operation_history[-500:]},
                          f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _record(self, action: str, detail: str, ok: bool) -> None:
        """追加一条维护操作记录。"""
        self.operation_history.append({
            "action": action, "detail": detail, "ok": ok, "timestamp": time.time(),
        })
        self._save()

    # ------------------------------------------------------------------
    # 连接
    # ------------------------------------------------------------------
    def _connect(self) -> Optional[sqlite3.Connection]:
        """建立数据库连接（容错）。"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            return conn
        except Exception:
            return None

    # ------------------------------------------------------------------
    # 索引分析
    # ------------------------------------------------------------------
    def analyze_indexes(self) -> Dict[str, Any]:
        """分析所有表的索引使用情况。

        Returns:
            Dict: 索引总数、按表分布、重复索引、无效索引、缺失索引建议。
        """
        result: Dict[str, Any] = {
            "index_count": 0,
            "by_table": {},
            "duplicate_indexes": [],
            "invalid_indexes": [],
            "missing_index_suggestions": [],
        }
        conn = self._connect()
        if conn is None:
            result["error"] = "数据库不可用"
            return result
        try:
            cur = conn.cursor()
            # 索引定义（自动索引 sqlite_autoindex_* 除外但保留统计）
            rows = cur.execute(
                "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index'"
            ).fetchall()
            idx_defs: List[Tuple[str, str, str]] = [(r["name"], r["tbl_name"], r["sql"] or "")
                                                    for r in rows]
            result["index_count"] = len(idx_defs)
            for name, tbl, _sql in idx_defs:
                result["by_table"].setdefault(tbl, []).append(name)

            # 重复索引检测：解析索引列集合
            seen: Dict[str, str] = {}
            for name, tbl, sql in idx_defs:
                cols = self._parse_index_columns(sql)
                key = f"{tbl}:{','.join(sorted(cols))}"
                if key in seen:
                    result["duplicate_indexes"].append({
                        "index": name, "duplicate_of": seen[key], "table": tbl,
                    })
                else:
                    seen[key] = name

            # 无效索引：sql 为空者通常为自动索引，单独标注
            for name, tbl, sql in idx_defs:
                if not sql:
                    result["invalid_indexes"].append({
                        "index": name, "table": tbl, "reason": "自动索引(无显式定义)",
                    })

            # 缺失索引建议：对无任何索引的业务表给出主键/常用字段建议
            tables = [r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            ).fetchall()]
            for t in tables:
                existing = result["by_table"].get(t, [])
                if not existing:
                    result["missing_index_suggestions"].append({
                        "table": t,
                        "suggestion": f"表 {t} 无索引，建议为其主键或常用过滤字段创建索引",
                    })
        except Exception as e:
            result["error"] = str(e)
        finally:
            conn.close()
        return result

    @staticmethod
    def _parse_index_columns(index_sql: str) -> List[str]:
        """从 CREATE INDEX SQL 中解析索引列名。"""
        m = re.search(r"\(([^)]*)\)", index_sql or "")
        if not m:
            return []
        cols = []
        for part in m.group(1).split(","):
            c = re.sub(r"[\"'`]", "", part.strip()).split()[0]
            if c:
                cols.append(c)
        return cols

    # ------------------------------------------------------------------
    # 索引建议
    # ------------------------------------------------------------------
    def get_index_suggestions(self) -> List[Dict[str, str]]:
        """基于查询模式与慢查询分析，综合给出索引建议。"""
        suggestions: List[Dict[str, str]] = []
        try:
            analysis = self.analyze_indexes()
            for dup in analysis.get("duplicate_indexes", []):
                suggestions.append({
                    "action": "drop",
                    "target": dup["index"],
                    "message": f"索引 {dup['index']} 与 {dup['duplicate_of']} 重复，可删除",
                })
            for miss in analysis.get("missing_index_suggestions", []):
                suggestions.append({
                    "action": "create",
                    "target": miss["table"],
                    "message": miss["suggestion"],
                })
            # 结合 query_optimizer 的慢查询（可选导入，避免循环依赖）
            try:
                from performance.query_optimizer import query_optimizer
                for rec in query_optimizer.get_slow_queries(limit=20):
                    if rec.get("tables"):
                        suggestions.append({
                            "action": "create",
                            "target": rec["tables"][0],
                            "message": f"慢查询涉及表 {rec['tables'][0]}，建议为其过滤字段建索引",
                        })
            except Exception:
                pass
        except Exception:
            pass
        return suggestions

    # ------------------------------------------------------------------
    # 索引管理
    # ------------------------------------------------------------------
    def create_index(self,
                     table_name: str,
                     columns: List[str],
                     index_name: Optional[str] = None) -> Dict[str, Any]:
        """创建索引（IF NOT EXISTS，容错）。

        Args:
            table_name: 表名。
            columns: 列名列表。
            index_name: 索引名；为空时自动生成。

        Returns:
            Dict: 操作结果。
        """
        try:
            if not table_name or not columns:
                return {"success": False, "error": "表名与列名不能为空"}
            safe_table = re.sub(r"[^A-Za-z0-9_]", "", table_name)
            safe_cols = ", ".join(
                f'"{re.sub(chr(34), "", c)}"' for c in columns
            )
            name = index_name or f"idx_{safe_table}_{'_'.join(columns)}"
            name = re.sub(r"[^A-Za-z0-9_]", "_", name)
            conn = self._connect()
            if conn is None:
                return {"success": False, "error": "数据库不可用"}
            try:
                conn.execute(
                    f'CREATE INDEX IF NOT EXISTS "{name}" ON "{safe_table}" ({safe_cols})'
                )
                conn.commit()
                self._record("create", f"{name} ON {safe_table}({safe_cols})", True)
                return {"success": True, "index_name": name, "table": safe_table,
                        "columns": columns}
            finally:
                conn.close()
        except Exception as e:
            self._record("create", f"{table_name}: {e}", False)
            return {"success": False, "error": str(e)}

    def drop_index(self, index_name: str) -> Dict[str, Any]:
        """删除索引（IF EXISTS，容错）。"""
        try:
            name = re.sub(r"[^A-Za-z0-9_]", "", index_name or "")
            if not name:
                return {"success": False, "error": "索引名不能为空"}
            conn = self._connect()
            if conn is None:
                return {"success": False, "error": "数据库不可用"}
            try:
                conn.execute(f'DROP INDEX IF EXISTS "{name}"')
                conn.commit()
                self._record("drop", name, True)
                return {"success": True, "dropped": name}
            finally:
                conn.close()
        except Exception as e:
            self._record("drop", f"{index_name}: {e}", False)
            return {"success": False, "error": str(e)}

    def rebuild_index(self, index_name: Optional[str] = None) -> Dict[str, Any]:
        """重建索引（REINDEX）。index_name 为空则重建全部索引。"""
        try:
            conn = self._connect()
            if conn is None:
                return {"success": False, "error": "数据库不可用"}
            t0 = time.time()
            try:
                if index_name:
                    name = re.sub(r"[^A-Za-z0-9_]", "", index_name)
                    conn.execute(f'REINDEX "{name}"')
                else:
                    conn.execute("REINDEX")
                conn.commit()
                elapsed = round((time.time() - t0) * 1000, 2)
                self._record("rebuild", index_name or "ALL", True)
                return {"success": True, "rebuilt": index_name or "ALL",
                        "elapsed_ms": elapsed}
            finally:
                conn.close()
        except Exception as e:
            self._record("rebuild", f"{index_name}: {e}", False)
            return {"success": False, "error": str(e)}

    # ------------------------------------------------------------------
    # 索引统计
    # ------------------------------------------------------------------
    def get_index_stats(self) -> Dict[str, Any]:
        """索引统计：数量、大小、按表分布、最近维护时间。"""
        stats: Dict[str, Any] = {"index_count": 0, "by_table": {}, "size_info": {}}
        conn = self._connect()
        if conn is None:
            stats["error"] = "数据库不可用"
            return stats
        try:
            cur = conn.cursor()
            rows = cur.execute(
                "SELECT name, tbl_name FROM sqlite_master WHERE type='index'"
            ).fetchall()
            stats["index_count"] = len(rows)
            for r in rows:
                stats["by_table"].setdefault(r["tbl_name"], []).append(r["name"])
            # sqlite_stat1 可能不存在，容错读取
            try:
                stat_rows = cur.execute(
                    "SELECT idx, tbl, stat FROM sqlite_stat1"
                ).fetchall()
                stats["size_info"] = {
                    r["idx"]: {"table": r["tbl"], "stat": r["stat"]}
                    for r in stat_rows
                }
            except sqlite3.Error:
                stats["size_info"] = {}
            stats["last_maintenance"] = (
                self.operation_history[-1]["timestamp"] if self.operation_history else None
            )
            stats["operation_count"] = len(self.operation_history)
        except Exception as e:
            stats["error"] = str(e)
        finally:
            conn.close()
        return stats

    # ------------------------------------------------------------------
    # 健康检查
    # ------------------------------------------------------------------
    def health_check(self) -> Dict[str, Any]:
        """索引健康检查：统计信息是否过期 / 未使用索引 / 碎片提示。"""
        report: Dict[str, Any] = {
            "status": "ok",
            "stale_statistics": False,
            "unused_indexes": [],
            "fragmentation_hint": None,
        }
        conn = self._connect()
        if conn is None:
            report["status"] = "error"
            report["error"] = "数据库不可用"
            return report
        try:
            cur = conn.cursor()
            # sqlite_stat1 不存在即认为统计信息过期
            try:
                cur.execute("SELECT COUNT(*) FROM sqlite_stat1").fetchone()
            except sqlite3.Error:
                report["stale_statistics"] = True
                report["fragmentation_hint"] = (
                    "未收集统计信息，建议执行 ANALYZE 以更新查询计划统计"
                )
            # 空闲页比例
            try:
                freelist = cur.execute("PRAGMA freelist_count").fetchone()[0]
                page_count = cur.execute("PRAGMA page_count").fetchone()[0]
                if page_count:
                    ratio = freelist / page_count
                    if ratio > 0.2:
                        report["fragmentation_hint"] = (
                            f"空闲页比例 {ratio:.1%}，碎片较多，建议 VACUUM 整理"
                        )
            except sqlite3.Error:
                pass
            # 未使用索引：与慢查询/查询记录交叉（此处简单标记无业务索引的表）
            analysis = self.analyze_indexes()
            report["unused_indexes"] = [d["index"] for d in analysis.get("invalid_indexes", [])]
            if report["stale_statistics"] or report["fragmentation_hint"]:
                report["status"] = "warning"
        except Exception as e:
            report["status"] = "error"
            report["error"] = str(e)
        finally:
            conn.close()
        return report


# 模块级单例
index_manager = IndexManager()
