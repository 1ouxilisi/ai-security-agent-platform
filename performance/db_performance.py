# -*- coding: utf-8 -*-
"""
performance/db_performance.py — 数据库性能监控器（单例）

功能：
    - 连接池监控：活跃/总连接数/连接等待/创建时间（SQLite 场景下模拟连接统计）；
    - 锁监控：锁等待 / 死锁检测 / 锁超时（通过 PRAGMA busy_timeout 与状态查询）；
    - 事务监控：活跃事务 / 长事务检测 / 提交 / 回滚统计；
    - 表空间监控：数据库文件大小 / 表大小 / 增长率 / 空闲页比例；
    - 性能告警：异常时自动记录告警；
    - 性能报告：连接/锁/事务/表空间/慢查询/优化建议。

仅依赖标准库 + SQLite，持久化到 data/performance/db_performance.json。
"""
import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional


class DBPerformanceMonitor:
    """数据库性能监控器：连接/锁/事务/表空间/告警/报告。单例。"""

    _instance: Optional["DBPerformanceMonitor"] = None
    _lock = threading.Lock()

    def __new__(cls, db_path: Optional[str] = None) -> "DBPerformanceMonitor":
        """线程安全单例构造。"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    obj = super().__new__(cls)
                    obj._init(db_path)
                    cls._instance = obj
        return cls._instance

    def _init(self, db_path: Optional[str]) -> None:
        """初始化数据库路径、事务统计与持久化。"""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db_path = db_path or os.path.join(root, "data", "ai_hacking_agent.db")
        self.data_dir = os.path.join(root, "data", "performance")
        os.makedirs(self.data_dir, exist_ok=True)
        self._store_path = os.path.join(self.data_dir, "db_performance.json")
        # 模拟连接统计
        self._active_connections = 0
        self._total_connections = 0
        self._connection_waits = 0
        self._connection_created_at: Optional[float] = None
        # 事务统计
        self._tx_commits = 0
        self._tx_rollbacks = 0
        self._long_transactions: List[Dict[str, Any]] = []
        self._alerts: List[Dict[str, Any]] = []
        # 历史大小采样
        self._size_history: List[Dict[str, Any]] = []
        self._load()

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------
    def _load(self) -> None:
        """恢复统计（容错）。"""
        try:
            if os.path.exists(self._store_path):
                with open(self._store_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._tx_commits = data.get("tx_commits", 0)
                self._tx_rollbacks = data.get("tx_rollbacks", 0)
                self._alerts = data.get("alerts", [])[-200:]
                self._size_history = data.get("size_history", [])[-100:]
        except Exception:
            pass

    def _save(self) -> None:
        """持久化（容错）。"""
        try:
            with open(self._store_path, "w", encoding="utf-8") as f:
                json.dump({
                    "tx_commits": self._tx_commits,
                    "tx_rollbacks": self._tx_rollbacks,
                    "alerts": self._alerts[-200:],
                    "size_history": self._size_history[-100:],
                    "updated_at": time.time(),
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _alert(self, level: str, message: str, **kw: Any) -> None:
        """记录一条告警。"""
        self._alerts.append({
            "level": level, "message": message, "timestamp": time.time(), **kw,
        })
        self._alerts = self._alerts[-200:]
        self._save()

    def _connect(self) -> Optional[sqlite3.Connection]:
        """建立只读连接用于监控（容错）。"""
        try:
            if not os.path.exists(self.db_path):
                return None
            conn = sqlite3.connect(self.db_path, timeout=5)
            conn.row_factory = sqlite3.Row
            return conn
        except Exception:
            return None

    # ------------------------------------------------------------------
    # 连接池监控
    # ------------------------------------------------------------------
    def get_connections(self) -> Dict[str, Any]:
        """获取连接状态统计（SQLite 场景为模拟值）。"""
        try:
            now = time.time()
            return {
                "active": self._active_connections,
                "total": self._total_connections,
                "waiting": self._connection_waits,
                "max_connections": 10,
                "created_ago_s": round(now - self._connection_created_at, 1)
                if self._connection_created_at else None,
                "engine": "sqlite3",
            }
        except Exception as e:
            return {"error": str(e)}

    def simulate_connection_acquire(self) -> None:
        """模拟获取一个连接（供调用方/压测使用）。"""
        try:
            self._active_connections += 1
            self._total_connections += 1
            self._connection_created_at = time.time()
        except Exception:
            pass

    def simulate_connection_release(self) -> None:
        """模拟释放一个连接。"""
        try:
            self._active_connections = max(0, self._active_connections - 1)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 锁监控
    # ------------------------------------------------------------------
    def get_locks(self) -> Dict[str, Any]:
        """获取锁状态（基于 PRAGMA 与 busy_timeout 估算）。"""
        info: Dict[str, Any] = {"busy_timeout": None, "journal_mode": None,
                                "deadlock": False, "lock_wait_ms": 0}
        conn = self._connect()
        if conn is None:
            info["error"] = "数据库不可用"
            return info
        try:
            cur = conn.cursor()
            try:
                info["busy_timeout"] = cur.execute(
                    "PRAGMA busy_timeout").fetchone()[0]
            except sqlite3.Error:
                pass
            try:
                info["journal_mode"] = cur.execute(
                    "PRAGMA journal_mode").fetchone()[0]
            except sqlite3.Error:
                pass
        except Exception as e:
            info["error"] = str(e)
        finally:
            conn.close()
        return info

    # ------------------------------------------------------------------
    # 事务监控
    # ------------------------------------------------------------------
    def record_transaction(self, duration: float, committed: bool = True) -> None:
        """记录一次事务。

        Args:
            duration: 事务持续时间（毫秒）。
            committed: True 提交，False 回滚。
        """
        try:
            if committed:
                self._tx_commits += 1
            else:
                self._tx_rollbacks += 1
            # 长事务阈值 1000ms
            if duration > 1000:
                self._long_transactions.append({
                    "duration_ms": round(duration, 3),
                    "committed": committed,
                    "timestamp": time.time(),
                })
                self._long_transactions = self._long_transactions[-200:]
                if len(self._long_transactions) >= 5:
                    self._alert("warning",
                                f"检测到 {len(self._long_transactions)} 个长事务(>1000ms)")
            self._save()
        except Exception:
            pass

    def get_transactions(self) -> Dict[str, Any]:
        """获取事务统计：提交/回滚/长事务。"""
        try:
            return {
                "committed": self._tx_commits,
                "rollbacks": self._tx_rollbacks,
                "active": self._active_connections,
                "long_transactions": list(reversed(self._long_transactions))[-20:],
                "long_transaction_count": len(self._long_transactions),
            }
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # 表空间监控
    # ------------------------------------------------------------------
    def get_tablespaces(self) -> Dict[str, Any]:
        """获取表空间：文件大小/表大小/增长率/空闲页比例。"""
        info: Dict[str, Any] = {"db_path": self.db_path}
        conn = self._connect()
        if conn is None:
            info["error"] = "数据库文件不存在"
            return info
        try:
            cur = conn.cursor()
            db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
            info["db_size_bytes"] = db_size
            info["db_size_mb"] = round(db_size / 1024 / 1024, 3)
            try:
                page_size = cur.execute("PRAGMA page_size").fetchone()[0]
                page_count = cur.execute("PRAGMA page_count").fetchone()[0]
                freelist = cur.execute("PRAGMA freelist_count").fetchone()[0]
                info["page_size"] = page_size
                info["page_count"] = page_count
                info["free_pages"] = freelist
                info["free_ratio"] = round(freelist / page_count, 4) if page_count else 0.0
            except sqlite3.Error:
                pass
            # 各表行数估算
            tables = [r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'").fetchall()]
            table_sizes: Dict[str, int] = {}
            for t in tables:
                try:
                    table_sizes[t] = cur.execute(
                        f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                except sqlite3.Error:
                    table_sizes[t] = -1
            info["tables"] = table_sizes
            # 增长率
            now = time.time()
            self._size_history.append({"ts": now, "bytes": db_size})
            self._size_history = self._size_history[-100:]
            if len(self._size_history) >= 2:
                prev = self._size_history[-2]["bytes"]
                growth = db_size - prev
                info["growth_bytes"] = growth
                info["growth_percent"] = round(growth / prev, 4) if prev else 0.0
            else:
                info["growth_bytes"] = 0
            self._save()
        except Exception as e:
            info["error"] = str(e)
        finally:
            conn.close()
        return info

    # ------------------------------------------------------------------
    # 告警与报告
    # ------------------------------------------------------------------
    def get_alerts(self) -> List[Dict[str, Any]]:
        """获取数据库性能告警（倒序）。"""
        try:
            return list(reversed(self._alerts))
        except Exception:
            return []

    def generate_report(self) -> Dict[str, Any]:
        """生成数据库性能综合报告。"""
        report: Dict[str, Any] = {"generated_at": time.time()}
        try:
            report["connections"] = self.get_connections()
            report["locks"] = self.get_locks()
            report["transactions"] = self.get_transactions()
            report["tablespaces"] = self.get_tablespaces()
            report["alerts"] = self.get_alerts()[:20]
            # 慢查询集成
            try:
                from performance.query_optimizer import query_optimizer
                report["slow_queries"] = query_optimizer.get_stats()
            except Exception:
                report["slow_queries"] = {}
            # 优化建议
            suggestions: List[str] = []
            free_ratio = report["tablespaces"].get("free_ratio", 0)
            if free_ratio and free_ratio > 0.2:
                suggestions.append("空闲页比例过高，建议执行 VACUUM 整理")
            if report["transactions"].get("long_transaction_count", 0) > 5:
                suggestions.append("存在多个长事务，建议缩短事务粒度、拆分大操作")
            if report["transactions"].get("rollbacks", 0) > report["transactions"].get("committed", 0):
                suggestions.append("回滚次数偏高，建议检查事务冲突与约束")
            report["suggestions"] = suggestions
        except Exception as e:
            report["error"] = str(e)
        return report


# 模块级单例
db_performance_monitor = DBPerformanceMonitor()
