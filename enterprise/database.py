#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
企业级数据库模块 - Enterprise Database Module
SQLite持久化，替代JSON文件存储
表结构：
- users: 用户表（注册/登录/角色权限）
- scan_results: 扫描结果表
- reports: 报告表
- monitor_targets: 监控目标表
- api_keys: API密钥表
- audit_logs: 审计日志表
- tasks: 任务队列表
"""
import sqlite3
import json
import time
import hashlib
import secrets
from typing import Dict, Any, List, Optional
from contextlib import contextmanager
from datetime import datetime


DB_PATH = "data/enterprise.db"


def get_db_path():
    import os
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, DB_PATH)


@contextmanager
def get_db():
    """获取数据库连接上下文管理器"""
    db_path = get_db_path()
    import os
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """初始化数据库表结构"""
    with get_db() as conn:
        # 用户表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                api_key TEXT UNIQUE,
                status TEXT DEFAULT 'active',
                created_at REAL,
                last_login REAL,
                scan_quota INTEGER DEFAULT 100,
                scans_used INTEGER DEFAULT 0
            )
        """)

        # 扫描结果表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT DEFAULT 'running',
                result_json TEXT,
                findings_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                started_at REAL,
                completed_at REAL,
                duration_ms REAL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # 报告表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                scan_id INTEGER,
                title TEXT NOT NULL,
                report_type TEXT DEFAULT 'pentest',
                content_json TEXT,
                format TEXT DEFAULT 'json',
                status TEXT DEFAULT 'draft',
                created_at REAL,
                updated_at REAL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (scan_id) REFERENCES scan_results(id)
            )
        """)

        # 监控目标表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitor_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                target TEXT NOT NULL,
                scan_interval INTEGER DEFAULT 3600,
                ports TEXT DEFAULT '1-1000',
                status TEXT DEFAULT 'active',
                last_scan_at REAL,
                last_result_json TEXT,
                change_count INTEGER DEFAULT 0,
                created_at REAL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # API密钥表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                key TEXT UNIQUE NOT NULL,
                name TEXT,
                permissions TEXT DEFAULT 'read,write',
                status TEXT DEFAULT 'active',
                created_at REAL,
                last_used_at REAL,
                usage_count INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # 审计日志表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT,
                ip_address TEXT,
                created_at REAL
            )
        """)

        # 任务队列表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                task_type TEXT NOT NULL,
                parameters_json TEXT,
                status TEXT DEFAULT 'pending',
                result_json TEXT,
                priority INTEGER DEFAULT 5,
                created_at REAL,
                started_at REAL,
                completed_at REAL,
                error TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # 创建索引
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_user ON scan_results(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_results(target)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_monitor_user ON monitor_targets(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")

    # 创建默认管理员账户
    create_default_admin()


def hash_password(password: str) -> str:
    """密码哈希（SHA256+salt）"""
    salt = "enterprise_security_salt_2024"
    return hashlib.sha256(f"{salt}{password}{salt}".encode()).hexdigest()


def generate_api_key() -> str:
    """生成API密钥"""
    return "sk-" + secrets.token_hex(32)


def create_default_admin():
    """创建默认管理员账户"""
    with get_db() as conn:
        cursor = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",))
        if not cursor.fetchone():
            api_key = generate_api_key()
            conn.execute("""
                INSERT INTO users (username, email, password_hash, role, api_key, status, created_at, scan_quota)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, ("admin", "admin@localhost", hash_password("admin123"), "admin",
                  api_key, "active", time.time(), 999999))
            print(f"默认管理员已创建: admin / admin123")
            print(f"管理员API Key: {api_key}")


# ============================================================
# 用户管理
# ============================================================

def create_user(username: str, password: str, email: str = None, role: str = "user") -> Dict[str, Any]:
    """创建用户"""
    try:
        api_key = generate_api_key()
        with get_db() as conn:
            cursor = conn.execute("""
                INSERT INTO users (username, email, password_hash, role, api_key, status, created_at, scan_quota)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (username, email, hash_password(password), role, api_key, "active", time.time(), 100))
            user_id = cursor.lastrowid
        return {"status": "success", "user_id": user_id, "username": username, "api_key": api_key, "role": role}
    except sqlite3.IntegrityError:
        return {"status": "failed", "error": "用户名或邮箱已存在"}


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """用户认证"""
    with get_db() as conn:
        cursor = conn.execute("""
            SELECT id, username, email, role, api_key, status, scan_quota, scans_used
            FROM users WHERE username = ? AND password_hash = ? AND status = 'active'
        """, (username, hash_password(password)))
        user = cursor.fetchone()
        if user:
            conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), user["id"]))
            return dict(user)
        return None


def get_user_by_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """通过API Key获取用户"""
    with get_db() as conn:
        cursor = conn.execute("""
            SELECT id, username, email, role, status, scan_quota, scans_used
            FROM users WHERE api_key = ? AND status = 'active'
        """, (api_key,))
        user = cursor.fetchone()
        return dict(user) if user else None


def list_users(limit: int = 100) -> List[Dict[str, Any]]:
    """列出所有用户"""
    with get_db() as conn:
        cursor = conn.execute("""
            SELECT id, username, email, role, status, created_at, last_login, scan_quota, scans_used
            FROM users ORDER BY id LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


# ============================================================
# 扫描结果管理
# ============================================================

def save_scan_result(user_id: int, target: str, scan_type: str, result: Dict[str, Any]) -> int:
    """保存扫描结果"""
    findings = result.get("findings", [])
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO scan_results (user_id, target, scan_type, status, result_json,
                findings_count, critical_count, high_count, medium_count, low_count,
                started_at, completed_at, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id, target, scan_type, "completed",
            json.dumps(result, ensure_ascii=False, default=str),
            len(findings),
            sum(1 for f in findings if f.get("severity") == "critical"),
            sum(1 for f in findings if f.get("severity") == "high"),
            sum(1 for f in findings if f.get("severity") == "medium"),
            sum(1 for f in findings if f.get("severity") == "low"),
            result.get("started_at", time.time()),
            time.time(),
            result.get("duration_ms", 0)
        ))
        scan_id = cursor.lastrowid
        # 更新用户扫描计数
        conn.execute("UPDATE users SET scans_used = scans_used + 1 WHERE id = ?", (user_id,))
        return scan_id


def get_scan_history(user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    """获取用户扫描历史"""
    with get_db() as conn:
        cursor = conn.execute("""
            SELECT id, target, scan_type, status, findings_count, critical_count,
                   high_count, medium_count, low_count, started_at, completed_at, duration_ms
            FROM scan_results WHERE user_id = ? ORDER BY id DESC LIMIT ?
        """, (user_id, limit))
        return [dict(row) for row in cursor.fetchall()]


def get_scan_result(scan_id: int) -> Optional[Dict[str, Any]]:
    """获取单个扫描结果详情"""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM scan_results WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if row:
            result = dict(row)
            if result.get("result_json"):
                result["result"] = json.loads(result["result_json"])
            return result
        return None


# ============================================================
# 监控目标管理
# ============================================================

def add_monitor_target(user_id: int, target: str, scan_interval: int = 3600, ports: str = "1-1000") -> int:
    """添加监控目标"""
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO monitor_targets (user_id, target, scan_interval, ports, status, created_at)
            VALUES (?, ?, ?, ?, 'active', ?)
        """, (user_id, target, scan_interval, ports, time.time()))
        return cursor.lastrowid


def get_monitor_targets(user_id: int = None) -> List[Dict[str, Any]]:
    """获取监控目标列表"""
    with get_db() as conn:
        if user_id:
            cursor = conn.execute("SELECT * FROM monitor_targets WHERE user_id = ? ORDER BY id DESC", (user_id,))
        else:
            cursor = conn.execute("SELECT * FROM monitor_targets ORDER BY id DESC")
        return [dict(row) for row in cursor.fetchall()]


def get_due_monitor_targets() -> List[Dict[str, Any]]:
    """获取到期需要扫描的监控目标"""
    now = time.time()
    with get_db() as conn:
        cursor = conn.execute("""
            SELECT * FROM monitor_targets
            WHERE status = 'active' AND (last_scan_at IS NULL OR ? - last_scan_at >= scan_interval)
        """, (now,))
        return [dict(row) for row in cursor.fetchall()]


def update_monitor_scan(target_id: int, result: Dict[str, Any], changes: List = None):
    """更新监控目标扫描结果"""
    with get_db() as conn:
        conn.execute("""
            UPDATE monitor_targets
            SET last_scan_at = ?, last_result_json = ?, change_count = change_count + ?
            WHERE id = ?
        """, (time.time(), json.dumps(result, ensure_ascii=False, default=str),
              len(changes or []), target_id))


# ============================================================
# 审计日志
# ============================================================

def add_audit_log(user_id: int, action: str, target: str = None, details: str = None, ip: str = None):
    """添加审计日志"""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO audit_logs (user_id, action, target, details, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, action, target, details, ip, time.time()))


def get_audit_logs(user_id: int = None, limit: int = 100) -> List[Dict[str, Any]]:
    """获取审计日志"""
    with get_db() as conn:
        if user_id:
            cursor = conn.execute("SELECT * FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit))
        else:
            cursor = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]


# ============================================================
# 任务队列
# ============================================================

def create_task(user_id: int, task_type: str, parameters: Dict[str, Any], priority: int = 5) -> int:
    """创建任务"""
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO tasks (user_id, task_type, parameters_json, priority, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, task_type, json.dumps(parameters, ensure_ascii=False), priority, time.time()))
        return cursor.lastrowid


def get_next_task() -> Optional[Dict[str, Any]]:
    """获取下一个待处理任务"""
    with get_db() as conn:
        cursor = conn.execute("""
            SELECT * FROM tasks WHERE status = 'pending' ORDER BY priority DESC, id ASC LIMIT 1
        """)
        row = cursor.fetchone()
        if row:
            task = dict(row)
            conn.execute("UPDATE tasks SET status = 'running', started_at = ? WHERE id = ?", (time.time(), task["id"]))
            if task.get("parameters_json"):
                task["parameters"] = json.loads(task["parameters_json"])
            return task
        return None


def complete_task(task_id: int, result: Dict[str, Any] = None, error: str = None):
    """完成任务"""
    with get_db() as conn:
        if error:
            conn.execute("UPDATE tasks SET status = 'failed', error = ?, completed_at = ? WHERE id = ?",
                         (error, time.time(), task_id))
        else:
            conn.execute("UPDATE tasks SET status = 'completed', result_json = ?, completed_at = ? WHERE id = ?",
                         (json.dumps(result or {}, ensure_ascii=False, default=str), time.time(), task_id))


# ============================================================
# 统计数据
# ============================================================

def get_statistics() -> Dict[str, Any]:
    """获取系统统计数据"""
    with get_db() as conn:
        stats = {}
        for table in ["users", "scan_results", "reports", "monitor_targets", "audit_logs", "tasks"]:
            cursor = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}")
            stats[f"total_{table}"] = cursor.fetchone()["cnt"]

        cursor = conn.execute("SELECT COUNT(*) as cnt FROM scan_results WHERE status = 'completed'")
        stats["completed_scans"] = cursor.fetchone()["cnt"]

        cursor = conn.execute("SELECT SUM(findings_count) as total FROM scan_results")
        stats["total_findings"] = cursor.fetchone()["total"] or 0

        cursor = conn.execute("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'pending'")
        stats["pending_tasks"] = cursor.fetchone()["cnt"]

        return stats


# 初始化数据库
init_db()
