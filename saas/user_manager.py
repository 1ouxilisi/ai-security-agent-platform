#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
user_manager 模块 — 用户管理器（SaaS 化基础模块 v10）

功能：
    - 用户 CRUD 与状态管理（active/inactive/locked/pending）
    - 角色管理与权限点分配（admin/security_analyst/auditor/user/custom）
    - 用户组管理与权限继承
    - 扩展属性与用户偏好
    - 批量导入导出（CSV/JSON），重复检测与格式校验
    - 用户统计（数量/活跃/角色/部门/状态/增长率）

注意：本模块仅用于授权的安全产品。
"""

import os
import csv
import io
import json
import sqlite3
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

try:
    from loguru import logger
except ImportError:  # pragma: no cover
    import logging
    logger = logging.getLogger(__name__)

from saas.auth_manager import hash_password, check_password_strength  # noqa: E402

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_BASE_DIR, "data", "ai_hacking_agent.db")

# 内置角色及其默认权限点
BUILTIN_ROLES: Dict[str, Dict[str, Any]] = {
    "admin": {"name": "管理员", "permissions": ["*"], "description": "全部权限"},
    "security_analyst": {"name": "安全分析师", "permissions": ["scan:run", "report:view", "vuln:manage"],
                         "description": "扫描与漏洞分析"},
    "auditor": {"name": "审计员", "permissions": ["report:view", "audit:view", "log:view"],
                "description": "只读审计"},
    "user": {"name": "普通用户", "permissions": ["report:view"], "description": "基础查看"},
}


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _get_conn(db_path: str = DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


class UserManager:
    """用户管理器（单例）。"""

    def __init__(self, db_path: str = DB_PATH):
        """初始化用户管理器并建表、写入内置角色。"""
        self.db_path = db_path
        self._init_db()
        self._seed_roles()
        logger.info("UserManager 初始化完成")

    def _init_db(self) -> None:
        conn = _get_conn(self.db_path)
        try:
            c = conn.cursor()
            # saas_users 由 auth_manager 以 IF NOT EXISTS 建立，这里兜底建一张同构表
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE,
                    email TEXT UNIQUE,
                    phone TEXT,
                    password_hash TEXT,
                    salt TEXT,
                    status TEXT DEFAULT 'pending',
                    display_name TEXT DEFAULT '',
                    department TEXT DEFAULT '',
                    position TEXT DEFAULT '',
                    avatar TEXT DEFAULT '',
                    language TEXT DEFAULT 'zh-CN',
                    timezone TEXT DEFAULT 'Asia/Shanghai',
                    tenant_id TEXT DEFAULT 'default',
                    created_at TEXT,
                    updated_at TEXT,
                    last_login_at TEXT,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TEXT DEFAULT '',
                    preferences TEXT DEFAULT '{}',
                    extended_attrs TEXT DEFAULT '{}'
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_roles (
                    role TEXT PRIMARY KEY,
                    name TEXT DEFAULT '',
                    permissions TEXT DEFAULT '[]',
                    description TEXT DEFAULT '',
                    is_builtin INTEGER DEFAULT 0,
                    created_at TEXT
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_user_roles (
                    user_id TEXT,
                    role TEXT,
                    PRIMARY KEY (user_id, role)
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_groups (
                    group_id TEXT PRIMARY KEY,
                    name TEXT UNIQUE,
                    description TEXT DEFAULT '',
                    permissions TEXT DEFAULT '[]',
                    created_at TEXT
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS saas_group_members (
                    group_id TEXT,
                    user_id TEXT,
                    PRIMARY KEY (group_id, user_id)
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _seed_roles(self) -> None:
        conn = self._conn()
        try:
            for role, info in BUILTIN_ROLES.items():
                conn.execute(
                    "INSERT OR IGNORE INTO saas_roles (role, name, permissions, description, is_builtin, created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (role, info["name"], json.dumps(info["permissions"]),
                     info["description"], 1, _now_str()),
                )
            conn.commit()
        finally:
            conn.close()

    def _conn(self) -> sqlite3.Connection:
        return _get_conn(self.db_path)

    # ---------------------------- 用户 CRUD ----------------------------
    def create_user(self, username: str, email: str, password: str, **kwargs: Any) -> Dict[str, Any]:
        """创建用户。

        Args:
            username: 用户名。
            email: 邮箱。
            password: 明文密码。
            **kwargs: display_name/department/position/phone/tenant_id/status 等。

        Returns:
            新建用户字典。
        """
        problems = check_password_strength(password)
        if problems:
            raise ValueError("密码强度不足: " + "; ".join(problems))
        conn = self._conn()
        try:
            cur = conn.execute(
                "SELECT user_id FROM saas_users WHERE username=? OR email=?", (username, email))
            if cur.fetchone():
                raise ValueError("用户名或邮箱已存在")
            ph = hash_password(password)
            user_id = kwargs.get("user_id") or f"user_{secrets.token_hex(10)}"
            now = _now_str()
            conn.execute(
                "INSERT INTO saas_users "
                "(user_id, username, email, phone, password_hash, salt, status, display_name, "
                " department, position, tenant_id, language, timezone, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (user_id, username, email, kwargs.get("phone", ""), ph["hash"], ph["salt"],
                 kwargs.get("status", "active"), kwargs.get("display_name", ""),
                 kwargs.get("department", ""), kwargs.get("position", ""),
                 kwargs.get("tenant_id", "default"),
                 kwargs.get("language", "zh-CN"), kwargs.get("timezone", "Asia/Shanghai"),
                 now, now),
            )
            conn.commit()
            return self.get_user(user_id)
        finally:
            conn.close()

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """按 user_id 获取用户（不含密码哈希）。"""
        conn = self._conn()
        try:
            cur = conn.execute("SELECT * FROM saas_users WHERE user_id=?", (user_id,))
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d.pop("password_hash", None)
            d.pop("salt", None)
            d["roles"] = self.get_user_roles(user_id)
            return d
        finally:
            conn.close()

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        try:
            cur = conn.execute("SELECT user_id FROM saas_users WHERE username=?", (username,))
            row = cur.fetchone()
            return self.get_user(row["user_id"]) if row else None
        finally:
            conn.close()

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        try:
            cur = conn.execute("SELECT user_id FROM saas_users WHERE email=?", (email,))
            row = cur.fetchone()
            return self.get_user(row["user_id"]) if row else None
        finally:
            conn.close()

    def update_user(self, user_id: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
        """更新用户属性（不更新密码，密码走认证模块）。"""
        allowed = {"display_name", "email", "phone", "department", "position",
                   "avatar", "language", "timezone", "status", "tenant_id", "preferences",
                   "extended_attrs"}
        fields = {k: v for k, v in kwargs.items() if k in allowed}
        if not fields:
            return self.get_user(user_id)
        fields["updated_at"] = _now_str()
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [user_id]
        conn = self._conn()
        try:
            cur = conn.execute(f"UPDATE saas_users SET {sets} WHERE user_id=?", vals)
            conn.commit()
            if cur.rowcount == 0:
                return None
            return self.get_user(user_id)
        finally:
            conn.close()

    def delete_user(self, user_id: str) -> bool:
        """删除用户及关联角色/组成员。"""
        conn = self._conn()
        try:
            conn.execute("DELETE FROM saas_users WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM saas_user_roles WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM saas_group_members WHERE user_id=?", (user_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def list_users(self, page: int = 1, page_size: int = 20,
                   **filters: Any) -> Dict[str, Any]:
        """分页列出用户，支持 status/department/keyword 过滤。"""
        where, args = [], []
        if filters.get("status"):
            where.append("status=?")
            args.append(filters["status"])
        if filters.get("department"):
            where.append("department=?")
            args.append(filters["department"])
        if filters.get("keyword"):
            where.append("(username LIKE ? OR email LIKE ? OR display_name LIKE ?)")
            kw = f"%{filters['keyword']}%"
            args.extend([kw, kw, kw])
        sql = "SELECT * FROM saas_users"
        if where:
            sql += " WHERE " + " AND ".join(where)
        conn = self._conn()
        try:
            total = conn.execute(sql.replace("SELECT *", "SELECT COUNT(*)"), args).fetchone()[0]
            offset = (max(1, page) - 1) * page_size
            rows = conn.execute(sql + " ORDER BY created_at DESC LIMIT ? OFFSET ?",
                                args + [page_size, offset]).fetchall()
            items = []
            for r in rows:
                d = dict(r)
                d.pop("password_hash", None)
                d.pop("salt", None)
                items.append(d)
            return {"total": total, "page": page, "page_size": page_size, "items": items}
        finally:
            conn.close()

    # ---------------------------- 用户状态 ----------------------------
    def lock_user(self, user_id: str, reason: Optional[str] = None) -> bool:
        """锁定用户。"""
        conn = self._conn()
        try:
            cur = conn.execute(
                "UPDATE saas_users SET status='locked', locked_until=?, updated_at=? WHERE user_id=?",
                ("", _now_str(), user_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def unlock_user(self, user_id: str) -> bool:
        """解锁用户。"""
        conn = self._conn()
        try:
            cur = conn.execute(
                "UPDATE saas_users SET status='active', failed_attempts=0, locked_until='', updated_at=? WHERE user_id=?",
                (_now_str(), user_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ---------------------------- 角色 ----------------------------
    def get_user_roles(self, user_id: str) -> List[str]:
        conn = self._conn()
        try:
            cur = conn.execute("SELECT role FROM saas_user_roles WHERE user_id=?", (user_id,))
            return [r["role"] for r in cur.fetchall()]
        finally:
            conn.close()

    def assign_role(self, user_id: str, role: str) -> bool:
        """为用户分配角色。"""
        conn = self._conn()
        try:
            conn.execute("INSERT OR IGNORE INTO saas_user_roles (user_id, role) VALUES (?,?)",
                         (user_id, role))
            conn.commit()
            return True
        finally:
            conn.close()

    def remove_role(self, user_id: str, role: str) -> bool:
        """移除用户角色。"""
        conn = self._conn()
        try:
            cur = conn.execute("DELETE FROM saas_user_roles WHERE user_id=? AND role=?",
                               (user_id, role))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def list_roles(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        try:
            cur = conn.execute("SELECT * FROM saas_roles")
            out = []
            for r in cur.fetchall():
                d = dict(r)
                d["permissions"] = json.loads(d["permissions"] or "[]")
                out.append(d)
            return out
        finally:
            conn.close()

    # ---------------------------- 用户组 ----------------------------
    def create_group(self, name: str, **kwargs: Any) -> Dict[str, Any]:
        """创建用户组。"""
        group_id = f"grp_{secrets.token_hex(8)}"
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO saas_groups (group_id, name, description, permissions, created_at) "
                "VALUES (?,?,?,?,?)",
                (group_id, name, kwargs.get("description", ""),
                 json.dumps(kwargs.get("permissions", [])), _now_str()),
            )
            conn.commit()
            return {"group_id": group_id, "name": name}
        finally:
            conn.close()

    def delete_group(self, group_id: str) -> bool:
        conn = self._conn()
        try:
            conn.execute("DELETE FROM saas_group_members WHERE group_id=?", (group_id,))
            cur = conn.execute("DELETE FROM saas_groups WHERE group_id=?", (group_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def add_to_group(self, user_id: str, group_id: str) -> bool:
        conn = self._conn()
        try:
            conn.execute("INSERT OR IGNORE INTO saas_group_members (group_id, user_id) VALUES (?,?)",
                         (group_id, user_id))
            conn.commit()
            return True
        finally:
            conn.close()

    def remove_from_group(self, user_id: str, group_id: str) -> bool:
        conn = self._conn()
        try:
            cur = conn.execute(
                "DELETE FROM saas_group_members WHERE group_id=? AND user_id=?", (group_id, user_id))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ---------------------------- 导入导出 ----------------------------
    def import_users(self, csv_data: str) -> Dict[str, Any]:
        """从 CSV 批量导入用户。

        CSV 表头需含: username,email,password（可选 display_name,department,position,phone）。
        """
        imported, skipped, errors = 0, 0, []
        reader = csv.DictReader(io.StringIO(csv_data))
        required = {"username", "email", "password"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError("CSV 缺少必要列: username,email,password")
        for i, row in enumerate(reader, start=2):
            try:
                self.create_user(
                    username=row["username"].strip(),
                    email=row["email"].strip(),
                    password=row["password"],
                    display_name=row.get("display_name", ""),
                    department=row.get("department", ""),
                    position=row.get("position", ""),
                    phone=row.get("phone", ""),
                )
                imported += 1
            except Exception as e:
                skipped += 1
                errors.append(f"第{i}行: {e}")
        return {"imported": imported, "skipped": skipped, "errors": errors}

    def export_users(self, format: str = "json") -> Any:
        """导出用户列表（json 或 csv）。"""
        res = self.list_users(page=1, page_size=100000)
        items = res["items"]
        if format == "csv":
            buf = io.StringIO()
            cols = ["user_id", "username", "email", "display_name", "department",
                    "position", "status", "created_at", "last_login_at"]
            writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()
            for it in items:
                writer.writerow(it)
            return buf.getvalue()
        return items

    # ---------------------------- 统计 ----------------------------
    def get_stats(self) -> Dict[str, Any]:
        """用户统计。"""
        conn = self._conn()
        try:
            total = conn.execute("SELECT COUNT(*) c FROM saas_users").fetchone()["c"]
            active = conn.execute("SELECT COUNT(*) c FROM saas_users WHERE status='active'").fetchone()["c"]
            locked = conn.execute("SELECT COUNT(*) c FROM saas_users WHERE status='locked'").fetchone()["c"]
            # 近 7 天活跃
            since = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
            week_active = conn.execute(
                "SELECT COUNT(*) c FROM saas_users WHERE last_login_at>=?", (since,)).fetchone()["c"]
            # 按角色
            role_rows = conn.execute(
                "SELECT role, COUNT(*) c FROM saas_user_roles GROUP BY role").fetchall()
            by_role = {r["role"]: r["c"] for r in role_rows}
            # 按部门
            dept_rows = conn.execute(
                "SELECT department, COUNT(*) c FROM saas_users GROUP BY department").fetchall()
            by_dept = {r["department"] or "(未分配)": r["c"] for r in dept_rows}
            # 增长率：本月新增
            month_start = datetime.now().strftime("%Y-%m")
            new_this_month = conn.execute(
                "SELECT COUNT(*) c FROM saas_users WHERE created_at LIKE ?", (month_start + "%",)).fetchone()["c"]
            return {
                "total_users": total,
                "active_users": active,
                "locked_users": locked,
                "week_active_users": week_active,
                "new_this_month": new_this_month,
                "growth_rate": round(new_this_month / total * 100, 2) if total else 0.0,
                "by_role": by_role,
                "by_department": by_dept,
                "groups": conn.execute("SELECT COUNT(*) c FROM saas_groups").fetchone()["c"],
                "roles": conn.execute("SELECT COUNT(*) c FROM saas_roles").fetchone()["c"],
            }
        finally:
            conn.close()


# 模块级单例
user_manager = UserManager()


if __name__ == "__main__":
    print("UserManager 自检")
    u = user_manager.create_user("bob_test", "bob@example.com", "Bob@12345", department="IT")
    print("create:", u["user_id"], u["username"])
    print("stats:", user_manager.get_stats())
