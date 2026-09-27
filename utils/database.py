"""
database工具函数模块，提供通用的辅助函数和工具类。

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
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from utils.logger import log


class Database:
    """SQLite数据库管理器"""

    def __init__(self, db_path: Optional[str] = None):
        """初始化Database实例。

        Args:
            self: 类实例。
        """
        if db_path is None:
            db_dir = Path(__file__).parent.parent / "data"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "hacking_agent.db")

        self.db_path = db_path
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        """获取数据库连接"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_database(self):
        """初始化数据库表结构"""
        conn = self._get_connection()
        cursor = conn.cursor()

        # 任务表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                task_type TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending',
                priority INTEGER DEFAULT 5,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                result TEXT,
                error TEXT,
                metadata TEXT
            )
        """)

        # 发现表（漏洞发现）
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                task_id TEXT,
                target TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                cwe_id TEXT,
                cve_id TEXT,
                payload TEXT,
                evidence TEXT,
                status TEXT DEFAULT 'open',
                verified BOOLEAN DEFAULT 0,
                false_positive BOOLEAN DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata TEXT,
                FOREIGN KEY (task_id) REFERENCES tasks(id)
            )
        """)

        # 报告表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                task_id TEXT,
                title TEXT NOT NULL,
                report_type TEXT DEFAULT 'scan',
                summary TEXT,
                findings_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0,
                content TEXT,
                format TEXT DEFAULT 'json',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata TEXT,
                FOREIGN KEY (task_id) REFERENCES tasks(id)
            )
        """)

        # 用户表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                api_key TEXT UNIQUE,
                is_active BOOLEAN DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_login TEXT,
                metadata TEXT
            )
        """)

        # 审计日志表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                username TEXT,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                status TEXT DEFAULT 'success',
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # 索引
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_target ON tasks(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_task ON reports(task_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)")

        conn.commit()
        conn.close()
        log.info(f"✅ 数据库初始化完成: {self.db_path}")

    # ==================== 任务操作 ====================

    def create_task(self, task_id: str, target: str, task_type: str,
                    description: str = "", priority: int = 5, metadata: dict = None) -> bool:
        """创建任务"""
        now = datetime.now().isoformat()
        conn = self._get_connection()
        try:
            conn.execute("""
                INSERT INTO tasks (id, target, task_type, description, priority,
                                  created_at, updated_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (task_id, target, task_type, description, priority, now, now,
                  json.dumps(metadata or {}, ensure_ascii=False)))
            conn.commit()
            return True
        except Exception as e:
            log.error(f"创建任务失败: {e}")
            return False
        finally:
            conn.close()

    def update_task_status(self, task_id: str, status: str, result: dict = None, error: str = None) -> bool:
        """更新任务状态"""
        now = datetime.now().isoformat()
        updates = ["status = ?", "updated_at = ?"]
        params = [status, now]

        if status == "running":
            updates.append("started_at = ?")
            params.append(now)
        elif status in ("completed", "failed"):
            updates.append("completed_at = ?")
            params.append(now)

        if result:
            updates.append("result = ?")
            params.append(json.dumps(result, ensure_ascii=False))
        if error:
            updates.append("error = ?")
            params.append(error)

        params.append(task_id)

        conn = self._get_connection()
        try:
            conn.execute(f"UPDATE tasks SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
            return True
        except Exception as e:
            log.error(f"更新任务状态失败: {e}")
            return False
        finally:
            conn.close()

    def get_task(self, task_id: str) -> Optional[dict]:
        """获取任务详情"""
        conn = self._get_connection()
        try:
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if row:
                task = dict(row)
                if task.get('result'):
                    task['result'] = json.loads(task['result'])
                if task.get('metadata'):
                    task['metadata'] = json.loads(task['metadata'])
                return task
            return None
        finally:
            conn.close()

    def list_tasks(self, status: str = None, limit: int = 50, offset: int = 0) -> List[dict]:
        """列出任务"""
        conn = self._get_connection()
        try:
            query = "SELECT * FROM tasks"
            params = []
            if status:
                query += " WHERE status = ?"
                params.append(status)
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    # ==================== 发现操作 ====================

    def add_finding(self, finding_id: str, task_id: str, target: str,
                    vulnerability_type: str, severity: str, title: str,
                    description: str = "", cvss_score: float = None,
                    cwe_id: str = None, cve_id: str = None,
                    payload: str = None, evidence: str = None,
                    metadata: dict = None) -> bool:
        """添加漏洞发现"""
        now = datetime.now().isoformat()
        conn = self._get_connection()
        try:
            conn.execute("""
                INSERT INTO findings (id, task_id, target, vulnerability_type, severity,
                                     title, description, cvss_score, cwe_id, cve_id,
                                     payload, evidence, created_at, updated_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (finding_id, task_id, target, vulnerability_type, severity,
                  title, description, cvss_score, cwe_id, cve_id,
                  payload, evidence, now, now,
                  json.dumps(metadata or {}, ensure_ascii=False)))
            conn.commit()
            return True
        except Exception as e:
            log.error(f"添加发现失败: {e}")
            return False
        finally:
            conn.close()

    def get_findings(self, task_id: str = None, severity: str = None,
                     target: str = None, limit: int = 100) -> List[dict]:
        """获取漏洞发现列表"""
        conn = self._get_connection()
        try:
            query = "SELECT * FROM findings WHERE 1=1"
            params = []
            if task_id:
                query += " AND task_id = ?"
                params.append(task_id)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if target:
                query += " AND target = ?"
                params.append(target)
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def update_finding_status(self, finding_id: str, status: str,
                              verified: bool = None, false_positive: bool = None) -> bool:
        """更新发现状态"""
        now = datetime.now().isoformat()
        updates = ["status = ?", "updated_at = ?"]
        params = [status, now]

        if verified is not None:
            updates.append("verified = ?")
            params.append(1 if verified else 0)
        if false_positive is not None:
            updates.append("false_positive = ?")
            params.append(1 if false_positive else 0)

        params.append(finding_id)

        conn = self._get_connection()
        try:
            conn.execute(f"UPDATE findings SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
            return True
        except Exception as e:
            log.error(f"更新发现状态失败: {e}")
            return False
        finally:
            conn.close()

    # ==================== 报告操作 ====================

    def create_report(self, report_id: str, task_id: str, title: str,
                      report_type: str = "scan", content: dict = None,
                      summary: str = "", findings_count: int = 0,
                      critical_count: int = 0, high_count: int = 0,
                      medium_count: int = 0, low_count: int = 0,
                      risk_score: float = 0) -> bool:
        """创建报告"""
        now = datetime.now().isoformat()
        conn = self._get_connection()
        try:
            conn.execute("""
                INSERT INTO reports (id, task_id, title, report_type, summary,
                                    findings_count, critical_count, high_count,
                                    medium_count, low_count, risk_score, content,
                                    created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (report_id, task_id, title, report_type, summary,
                  findings_count, critical_count, high_count, medium_count,
                  low_count, risk_score,
                  json.dumps(content or {}, ensure_ascii=False), now, now))
            conn.commit()
            return True
        except Exception as e:
            log.error(f"创建报告失败: {e}")
            return False
        finally:
            conn.close()

    def get_report(self, report_id: str) -> Optional[dict]:
        """获取报告"""
        conn = self._get_connection()
        try:
            row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
            if row:
                report = dict(row)
                if report.get('content'):
                    report['content'] = json.loads(report['content'])
                return report
            return None
        finally:
            conn.close()

    # ==================== 统计操作 ====================

    def get_statistics(self) -> dict:
        """获取数据库统计"""
        conn = self._get_connection()
        try:
            stats = {
                "total_tasks": conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0],
                "completed_tasks": conn.execute("SELECT COUNT(*) FROM tasks WHERE status='completed'").fetchone()[0],
                "total_findings": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                "critical_findings": conn.execute("SELECT COUNT(*) FROM findings WHERE severity='critical'").fetchone()[0],
                "high_findings": conn.execute("SELECT COUNT(*) FROM findings WHERE severity='high'").fetchone()[0],
                "total_reports": conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
                "total_users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                "total_audit_logs": conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0],
            }
            return stats
        finally:
            conn.close()


# 全局数据库实例
db = Database()
