"""
db模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import sqlite3
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from contextlib import contextmanager
from utils.logger import log
from config.settings import settings


class Database:
    """SQLite数据库管理"""

    def __init__(self, db_path: Optional[str] = None):
        """初始化Database实例。

        Args:
            self: 类实例。
        """
        self.db_path = db_path or str(Path(settings.project_root) / "data" / "ai_hacking_agent.db")
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()
        log.info(f"数据库初始化: {self.db_path}")

    @contextmanager
    def _get_conn(self):
        """获取数据库连接上下文管理器"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            log.error(f"数据库操作失败: {e}")
            raise
        finally:
            conn.close()

    def _init_tables(self):
        """初始化数据库表"""
        with self._get_conn() as conn:
            cursor = conn.cursor()

            # 任务表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    target TEXT,
                    status TEXT DEFAULT 'initialized',
                    total_steps INTEGER DEFAULT 0,
                    completed_steps INTEGER DEFAULT 0,
                    findings_count INTEGER DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    completed_at REAL,
                    error TEXT,
                    plan_json TEXT,
                    findings_json TEXT,
                    statistics_json TEXT
                )
            """)

            # 漏洞发现表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    task_id TEXT,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT,
                    target TEXT,
                    tool TEXT,
                    recommendations TEXT,
                    timestamp REAL NOT NULL,
                    status TEXT DEFAULT 'open',
                    FOREIGN KEY (task_id) REFERENCES tasks(id)
                )
            """)

            # 工具调用日志表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tool_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT,
                    tool_name TEXT NOT NULL,
                    arguments_json TEXT,
                    result_json TEXT,
                    status TEXT DEFAULT 'success',
                    error TEXT,
                    duration REAL,
                    timestamp REAL NOT NULL,
                    FOREIGN KEY (task_id) REFERENCES tasks(id)
                )
            """)

            # 执行历史表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS execution_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT,
                    step_number INTEGER,
                    step_description TEXT,
                    tool_name TEXT,
                    status TEXT,
                    result_summary TEXT,
                    error TEXT,
                    started_at REAL,
                    completed_at REAL,
                    FOREIGN KEY (task_id) REFERENCES tasks(id)
                )
            """)

            # 插件注册表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS plugins (
                    name TEXT PRIMARY KEY,
                    version TEXT,
                    description TEXT,
                    author TEXT,
                    enabled INTEGER DEFAULT 1,
                    installed_at REAL NOT NULL,
                    config_json TEXT
                )
            """)

            # 创建索引
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_calls_task ON tool_calls(task_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_calls_tool ON tool_calls(tool_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")

    # ===== 任务操作 =====
    def save_task(self, task_data: Dict) -> None:
        """保存任务记录"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO tasks 
                (id, description, target, status, total_steps, completed_steps, 
                 findings_count, created_at, updated_at, completed_at, error,
                 plan_json, findings_json, statistics_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task_data.get("task_id"),
                task_data.get("task_description"),
                task_data.get("target"),
                task_data.get("status"),
                task_data.get("total_steps", 0),
                task_data.get("completed_steps", 0),
                task_data.get("findings_count", 0),
                task_data.get("created_at", time.time()),
                task_data.get("updated_at", time.time()),
                task_data.get("completed_at"),
                task_data.get("error"),
                json.dumps(task_data.get("plan", []), ensure_ascii=False),
                json.dumps(task_data.get("findings", []), ensure_ascii=False),
                json.dumps(task_data.get("statistics", {}), ensure_ascii=False),
            ))
            log.debug(f"任务已保存: {task_data.get('task_id')}")

    def get_task(self, task_id: str) -> Optional[Dict]:
        """获取任务详情"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def list_tasks(self, limit: int = 50, status: Optional[str] = None) -> List[Dict]:
        """列出任务"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute("SELECT * FROM tasks WHERE status = ? ORDER BY created_at DESC LIMIT ?", (status, limit))
            else:
                cursor.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def update_task_status(self, task_id: str, status: str, error: Optional[str] = None) -> None:
        """更新任务状态"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if status == "completed":
                cursor.execute("UPDATE tasks SET status = ?, completed_at = ?, updated_at = ? WHERE id = ?",
                             (status, time.time(), time.time(), task_id))
            else:
                cursor.execute("UPDATE tasks SET status = ?, error = ?, updated_at = ? WHERE id = ?",
                             (status, error, time.time(), task_id))

    # ===== 漏洞发现操作 =====
    def save_finding(self, finding: Dict) -> None:
        """保存漏洞发现"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO findings 
                (id, task_id, type, severity, title, description, evidence, 
                 target, tool, recommendations, timestamp, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.get("finding_id"),
                finding.get("task_id"),
                finding.get("type"),
                finding.get("severity"),
                finding.get("title"),
                finding.get("description"),
                finding.get("evidence"),
                finding.get("target"),
                finding.get("tool"),
                finding.get("recommendations"),
                finding.get("timestamp", time.time()),
                finding.get("status", "open"),
            ))

    def get_findings(self, task_id: Optional[str] = None, severity: Optional[str] = None) -> List[Dict]:
        """获取漏洞发现列表"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM findings WHERE 1=1"
            params = []
            if task_id:
                query += " AND task_id = ?"
                params.append(task_id)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            query += " ORDER BY timestamp DESC"
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> Dict:
        """获取全局统计"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            stats = {}

            cursor.execute("SELECT COUNT(*) as total FROM tasks")
            stats["total_tasks"] = cursor.fetchone()["total"]

            cursor.execute("SELECT status, COUNT(*) as count FROM tasks GROUP BY status")
            stats["tasks_by_status"] = {row["status"]: row["count"] for row in cursor.fetchall()}

            cursor.execute("SELECT COUNT(*) as total FROM findings")
            stats["total_findings"] = cursor.fetchone()["total"]

            cursor.execute("SELECT severity, COUNT(*) as count FROM findings GROUP BY severity")
            stats["findings_by_severity"] = {row["severity"]: row["count"] for row in cursor.fetchall()}

            cursor.execute("SELECT COUNT(*) as total FROM tool_calls")
            stats["total_tool_calls"] = cursor.fetchone()["total"]

            cursor.execute("SELECT tool_name, COUNT(*) as count FROM tool_calls GROUP BY tool_name ORDER BY count DESC LIMIT 10")
            stats["top_tools"] = {row["tool_name"]: row["count"] for row in cursor.fetchall()}

            return stats

    # ===== 工具调用日志 =====
    def log_tool_call(self, task_id: Optional[str], tool_name: str, arguments: Dict,
                      result: Any, status: str = "success", error: Optional[str] = None,
                      duration: float = 0.0) -> None:
        """记录工具调用"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tool_calls 
                (task_id, tool_name, arguments_json, result_json, status, error, duration, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task_id,
                tool_name,
                json.dumps(arguments, ensure_ascii=False),
                json.dumps(result, ensure_ascii=False, default=str)[:5000],
                status,
                error,
                duration,
                time.time(),
            ))


# 全局数据库实例
db = Database()
