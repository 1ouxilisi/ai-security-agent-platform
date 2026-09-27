# -*- coding: utf-8 -*-
"""
performance/database_optimizer.py — SQLite 数据库优化器

提供：常用字段索引、轻量连接池、参数化查询、批量插入、性能统计、VACUUM。
所有索引创建都做容错：表不存在时不抛错（与 SQLite 行为兼容）。
"""
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple


class DatabaseOptimizer:
    """SQLite 优化器：索引 + 连接池 + 批量写 + 统计。"""

    def __init__(self, db_path: str = "data/platform.db",
                 max_connections: int = 5) -> None:
        """初始化：解析 db_path，准备连接池。"""
        # 相对路径按项目根解析
        if not os.path.isabs(db_path):
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(root, db_path)
        self.db_path = db_path
        self.max_connections = max_connections
        self._pool: List[sqlite3.Connection] = []
        self._pool_lock = threading.Lock()
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    # ------------------------------------------------------------------
    # 连接池
    # ------------------------------------------------------------------
    def get_connection(self) -> sqlite3.Connection:
        """获取连接：优先复用空闲连接，否则新建（上限 max_connections）。"""
        with self._pool_lock:
            if self._pool:
                conn = self._pool.pop()
                try:
                    conn.execute("SELECT 1")
                    return conn
                except Exception:
                    # 连接失效，丢弃后重建
                    try:
                        conn.close()
                    except Exception:
                        pass
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        return conn

    def _release(self, conn: sqlite3.Connection) -> None:
        """归还连接到连接池。"""
        with self._pool_lock:
            if len(self._pool) < self.max_connections:
                self._pool.append(conn)
            else:
                try:
                    conn.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # 索引
    # ------------------------------------------------------------------
    def create_indexes(self) -> List[str]:
        """为常用查询字段创建索引（IF NOT EXISTS，表不存在不报错）。"""
        index_defs = [
            ("idx_assessments_target", "assessments", "target"),
            ("idx_assessments_created", "assessments", "created_at"),
            ("idx_assessments_risk", "assessments", "risk_score"),
            ("idx_vulns_assessment", "vulnerabilities", "assessment_id"),
            ("idx_vulns_severity", "vulnerabilities", "severity"),
            ("idx_vulns_status", "vulnerabilities", "status"),
            ("idx_tasks_status", "tasks", "status"),
            ("idx_tasks_created", "tasks", "created_at"),
            ("idx_users_username", "users", "username"),
            ("idx_users_apikey", "users", "api_key"),
        ]
        created: List[str] = []
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            for idx_name, table, column in index_defs:
                sql = f'CREATE INDEX IF NOT EXISTS {idx_name} ON "{table}" ("{column}")'
                try:
                    cur.execute(sql)
                    created.append(idx_name)
                except sqlite3.Error as e:
                    # 表不存在时 SQLite 会报错，按需求忽略
                    created.append(f"{idx_name}(skip: {e})")
            conn.commit()
        finally:
            self._release(conn)
        return created

    # ------------------------------------------------------------------
    # 查询优化
    # ------------------------------------------------------------------
    def optimize_query(self, query: str,
                       params: Optional[Tuple[Any, ...]] = None
                       ) -> List[sqlite3.Row]:
        """参数化查询（预编译），防注入并复用执行计划。"""
        conn = self.get_connection()
        try:
            cur = conn.execute(query, params or ())
            return cur.fetchall()
        finally:
            self._release(conn)

    # ------------------------------------------------------------------
    # 批量插入
    # ------------------------------------------------------------------
    def batch_insert(self, table: str, columns: List[str],
                     rows: List[Tuple[Any, ...]],
                     batch_size: int = 100) -> int:
        """批量插入：executemany 分批执行。返回插入行数。"""
        if not rows:
            return 0
        col_sql = ", ".join(f'"{c}"' for c in columns)
        ph = ", ".join("?" for _ in columns)
        sql = f'INSERT INTO "{table}" ({col_sql}) VALUES ({ph})'

        inserted = 0
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            for i in range(0, len(rows), batch_size):
                chunk = rows[i:i + batch_size]
                cur.executemany(sql, chunk)
                inserted += len(chunk)
            conn.commit()
        except sqlite3.Error:
            # 表不存在等场景回滚并返回已尝试条数
            try:
                conn.rollback()
            except Exception:
                pass
            return 0
        finally:
            self._release(conn)
        return inserted

    # ------------------------------------------------------------------
    # 统计与维护
    # ------------------------------------------------------------------
    def get_performance_stats(self) -> Dict[str, Any]:
        """数据库性能统计：表数、索引数、总记录数、缓存大小。"""
        stats: Dict[str, Any] = {"db_path": self.db_path, "exists": False}
        if not os.path.exists(self.db_path):
            return stats
        stats["exists"] = True
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            tables = [r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()]
            stats["table_count"] = len(tables)
            stats["tables"] = tables

            indexes = [r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()]
            stats["index_count"] = len(indexes)

            total_rows = 0
            for t in tables:
                if t.startswith("sqlite_"):
                    continue
                try:
                    cnt = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                    total_rows += cnt
                except sqlite3.Error:
                    pass
            stats["total_records"] = total_rows

            try:
                stats["cache_size"] = cur.execute("PRAGMA cache_size").fetchone()[0]
            except sqlite3.Error:
                stats["cache_size"] = None
            try:
                stats["page_size"] = cur.execute("PRAGMA page_size").fetchone()[0]
            except sqlite3.Error:
                stats["page_size"] = None
            stats["pool_size"] = len(self._pool)
        finally:
            self._release(conn)
        return stats

    def vacuum(self) -> bool:
        """执行 VACUUM 碎片整理。"""
        if not os.path.exists(self.db_path):
            return False
        conn = self.get_connection()
        try:
            # VACUUM 不能在事务里执行
            conn.isolation_level = None
            conn.execute("VACUUM")
            return True
        except sqlite3.Error:
            return False
        finally:
            try:
                conn.close()
            except Exception:
                pass
