#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auth_system模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import hashlib
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

try:
    import jwt
except ImportError:
    jwt = None
    print("警告: PyJWT未安装，JWT功能不可用。请运行: pip install PyJWT")

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


class UserRole(Enum):
    """用户角色"""
    ADMIN = "admin"
    ANALYST = "analyst"
    SCANNER = "scanner"
    VIEWER = "viewer"
    API = "api"


class Permission(Enum):
    """权限"""
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_EXECUTE = "scan:execute"
    VULN_READ = "vuln:read"
    VULN_UPDATE = "vuln:update"
    VULN_EXPORT = "vuln:export"
    REPORT_CREATE = "report:create"
    REPORT_READ = "report:read"
    REPORT_EXPORT = "report:export"
    SYSTEM_CONFIG = "system:config"
    API_KEY_CREATE = "api_key:create"
    API_KEY_REVOKE = "api_key:revoke"


ROLE_PERMISSIONS = {
    UserRole.ADMIN.value: [p.value for p in Permission],
    UserRole.ANALYST.value: [
        Permission.SCAN_READ.value, Permission.SCAN_EXECUTE.value,
        Permission.VULN_READ.value, Permission.VULN_UPDATE.value,
        Permission.VULN_EXPORT.value, Permission.REPORT_CREATE.value,
        Permission.REPORT_READ.value, Permission.REPORT_EXPORT.value,
    ],
    UserRole.SCANNER.value: [
        Permission.SCAN_CREATE.value, Permission.SCAN_READ.value,
        Permission.SCAN_EXECUTE.value, Permission.VULN_READ.value,
        Permission.REPORT_READ.value,
    ],
    UserRole.VIEWER.value: [
        Permission.SCAN_READ.value, Permission.VULN_READ.value,
        Permission.REPORT_READ.value,
    ],
    UserRole.API.value: [
        Permission.SCAN_CREATE.value, Permission.SCAN_READ.value,
        Permission.SCAN_EXECUTE.value, Permission.VULN_READ.value,
        Permission.VULN_EXPORT.value, Permission.REPORT_READ.value,
        Permission.REPORT_EXPORT.value,
    ],
}


@dataclass
class User:
    """User类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    user_id: str
    username: str
    email: str
    role: str
    status: str = "active"
    last_login_at: str = ""
    created_at: str = ""
    permissions: List[str] = field(default_factory=list)


class AuthSystem:
    """用户认证系统"""

    SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = 30

    def __init__(self, db_path: str = "./data/auth.db"):
        """初始化AuthSystem实例。

        Args:
            self: 类实例。
        """
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()
        self._create_default_admin()
        logger.info(f"用户认证系统初始化完成")

    def _init_db(self):
        """初始化相关组件。

        Returns:
            操作结果。
        """
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                status TEXT NOT NULL DEFAULT 'active',
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                last_login_at TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                permissions TEXT,
                expires_at TEXT,
                last_used_at TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                rate_limit INTEGER DEFAULT 100,
                created_at TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id TEXT PRIMARY KEY,
                user_id TEXT,
                username TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                ip_address TEXT,
                status TEXT NOT NULL,
                details TEXT,
                created_at TEXT
            )
        """)
        self.conn.commit()

    def _create_default_admin(self):
        """创建相关数据。

        Returns:
            操作结果。
        """
        cursor = self.conn.execute("SELECT COUNT(*) as c FROM users WHERE role = 'admin'")
        if cursor.fetchone()["c"] == 0:
            self.register_user("admin", "admin@aihacking.local", "Admin@123456", UserRole.ADMIN.value)
            logger.info("默认管理员已创建: admin / Admin@123456")

    def _hash_password(self, password: str, salt: str = None) -> Tuple[str, str]:
        """计算相关哈希。

        Args:
            password: 相关参数。
            salt: 相关参数。

        Returns:
            操作结果。
        """
        if salt is None:
            salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()
        return password_hash, salt

    def _verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """验证相关数据。

        Args:
            password: 相关参数。
            password_hash: 相关参数。
            salt: 相关参数。

        Returns:
            操作结果。
        """
        computed, _ = self._hash_password(password, salt)
        return secrets.compare_digest(computed, password_hash)

    def register_user(self, username: str, email: str, password: str, role: str = "viewer") -> Optional[User]:
        """注册相关节点。

        Args:
            username: 相关参数。
            email: 相关参数。
            password: 相关参数。
            role: 相关参数。

        Returns:
            操作结果。
        """
        if len(username) < 3 or len(username) > 50:
            raise ValueError("用户名长度3-50字符")
        if len(password) < 8:
            raise ValueError("密码至少8位")

        cursor = self.conn.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            raise ValueError(f"用户名 '{username}' 已存在")

        password_hash, salt = self._hash_password(password)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user_id = f"user_{int(time.time())}_{secrets.token_hex(8)}"

        self.conn.execute("""
            INSERT INTO users (user_id, username, email, password_hash, password_salt, role, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, email, password_hash, salt, role, "active", now, now))
        self.conn.commit()

        self._add_audit_log(user_id, username, "user_register", "user", "", "success", f"角色: {role}")
        return self.get_user(user_id)

    def login(self, username: str, password: str, ip_address: str = "") -> Dict:
        """在...中。

        Args:
            username: 相关参数。
            password: 相关参数。
            ip_address: 相关参数。

        Returns:
            操作结果。
        """
        cursor = self.conn.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, username))
        user_row = cursor.fetchone()

        if not user_row:
            raise ValueError("用户名或密码错误")

        user = dict(user_row)

        if user["status"] == "disabled":
            raise PermissionError("账户已被禁用")

        if user["locked_until"]:
            locked_until = datetime.strptime(user["locked_until"], "%Y-%m-%d %H:%M:%S")
            if datetime.now() < locked_until:
                raise PermissionError("账户已锁定，请稍后重试")

        if not self._verify_password(password, user["password_hash"], user["password_salt"]):
            failed = user["failed_login_attempts"] + 1
            updates = {"failed_login_attempts": failed}
            if failed >= self.MAX_FAILED_ATTEMPTS:
                updates["locked_until"] = (datetime.now() + timedelta(minutes=self.LOCKOUT_DURATION)).strftime("%Y-%m-%d %H:%M:%S")
                updates["failed_login_attempts"] = 0
            updates["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            set_clause = ", ".join([f"{k} = ?" for k in updates])
            self.conn.execute(f"UPDATE users SET {set_clause} WHERE user_id = ?", (*updates.values(), user["user_id"]))
            self.conn.commit()
            raise ValueError("用户名或密码错误")

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.conn.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = ?, updated_at = ? WHERE user_id = ?", (now, now, user["user_id"]))
        self.conn.commit()

        access_token = self._create_access_token(user["user_id"], user["username"], user["role"])
        self._add_audit_log(user["user_id"], user["username"], "login", "auth", ip_address, "success", "登录成功")

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": self.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": {
                "user_id": user["user_id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "permissions": ROLE_PERMISSIONS.get(user["role"], []),
            },
        }

    def _create_access_token(self, user_id: str, username: str, role: str) -> str:
        """创建相关数据。

        Args:
            user_id: 相关参数。
            username: 相关参数。
            role: 相关参数。

        Returns:
            操作结果。
        """
        if jwt is None:
            raise ImportError("PyJWT未安装")
        expire = datetime.utcnow() + timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES)
        payload = {
            "sub": user_id, "username": username, "role": role,
            "permissions": ROLE_PERMISSIONS.get(role, []),
            "type": "access", "exp": expire, "iat": datetime.utcnow(),
        }
        return jwt.encode(payload, self.SECRET_KEY, algorithm=self.ALGORITHM)

    def verify_token(self, token: str) -> Optional[Dict]:
        """验证相关数据。

        Args:
            token: 相关参数。

        Returns:
            操作结果。
        """
        if jwt is None:
            return None
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload.get("type") != "access":
                return None
            user = self.get_user(payload["sub"])
            if not user or user.status != "active":
                return None
            return {"user_id": user.user_id, "username": user.username, "role": user.role, "permissions": payload.get("permissions", [])}
        except:
            return None

    def get_user(self, user_id: str) -> Optional[User]:
        """获取相关数据。

        Args:
            user_id: 相关参数。

        Returns:
            操作结果。
        """
        cursor = self.conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        u = dict(row)
        return User(
            user_id=u["user_id"], username=u["username"], email=u["email"],
            role=u["role"], status=u["status"], last_login_at=u["last_login_at"],
            created_at=u["created_at"], permissions=ROLE_PERMISSIONS.get(u["role"], []),
        )

    def get_user_by_username(self, username: str) -> Optional[User]:
        """获取相关数据。

        Args:
            username: 相关参数。

        Returns:
            操作结果。
        """
        cursor = self.conn.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return self.get_user(row["user_id"]) if row else None

    def list_users(self, page: int = 1, page_size: int = 20) -> Tuple[List[User], int]:
        """列出相关数据。

        Args:
            page: 相关参数。
            page_size: 相关参数。

        Returns:
            操作结果。
        """
        offset = (page - 1) * page_size
        total = self.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        cursor = self.conn.execute("SELECT user_id FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?", (page_size, offset))
        users = [self.get_user(r["user_id"]) for r in cursor.fetchall()]
        return [u for u in users if u], total

    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """或...。

        Args:
            user_id: 相关参数。
            old_password: 相关参数。
            new_password: 相关参数。

        Returns:
            操作结果。
        """
        cursor = self.conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            raise ValueError("用户不存在")
        if not self._verify_password(old_password, user["password_hash"], user["password_salt"]):
            raise ValueError("旧密码错误")
        if len(new_password) < 8:
            raise ValueError("新密码至少8位")
        new_hash, new_salt = self._hash_password(new_password)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.conn.execute("UPDATE users SET password_hash = ?, password_salt = ?, updated_at = ? WHERE user_id = ?", (new_hash, new_salt, now, user_id))
        self.conn.commit()
        self._add_audit_log(user_id, user["username"], "change_password", "user", "", "success", "密码修改成功")
        return True

    def create_api_key(self, user_id: str, name: str, expires_in_days: int = 90, rate_limit: int = 100) -> Dict:
        """创建相关数据。

        Args:
            user_id: 相关参数。
            name: 相关参数。
            expires_in_days: 相关参数。
            rate_limit: 相关参数。

        Returns:
            操作结果。
        """
        user = self.get_user(user_id)
        if not user:
            raise ValueError("用户不存在")
        api_key = f"sk-{secrets.token_hex(32)}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        key_prefix = api_key[:12] + "..."
        key_id = f"key_{int(time.time())}_{secrets.token_hex(8)}"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        expires_at = (datetime.now() + timedelta(days=expires_in_days)).strftime("%Y-%m-%d %H:%M:%S")
        permissions = json.dumps(ROLE_PERMISSIONS.get(user.role, []))

        self.conn.execute("""
            INSERT INTO api_keys (key_id, user_id, name, key_hash, key_prefix, permissions, expires_at, status, rate_limit, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (key_id, user_id, name, key_hash, key_prefix, permissions, expires_at, "active", rate_limit, now))
        self.conn.commit()

        self._add_audit_log(user_id, user.username, "create_api_key", "api_key", "", "success", f"创建: {name}")
        return {"key_id": key_id, "name": name, "api_key": api_key, "key_prefix": key_prefix, "expires_at": expires_at, "rate_limit": rate_limit, "created_at": now}

    def verify_api_key(self, api_key: str) -> Optional[Dict]:
        """验证相关数据。

        Args:
            api_key: 相关参数。

        Returns:
            操作结果。
        """
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        cursor = self.conn.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,))
        key_row = cursor.fetchone()
        if not key_row or key_row["status"] != "active":
            return None
        if key_row["expires_at"]:
            expires_at = datetime.strptime(key_row["expires_at"], "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expires_at:
                return None
        user = self.get_user(key_row["user_id"])
        if not user or user.status != "active":
            return None
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.conn.execute("UPDATE api_keys SET last_used_at = ? WHERE key_id = ?", (now, key_row["key_id"]))
        self.conn.commit()
        return {"key_id": key_row["key_id"], "user_id": user.user_id, "username": user.username, "role": user.role, "permissions": json.loads(key_row["permissions"]), "rate_limit": key_row["rate_limit"]}

    def list_api_keys(self, user_id: str) -> List[Dict]:
        """列出相关数据。

        Args:
            user_id: 相关参数。

        Returns:
            操作结果。
        """
        cursor = self.conn.execute("SELECT key_id, name, key_prefix, expires_at, last_used_at, status, rate_limit, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        return [dict(r) for r in cursor.fetchall()]

    def revoke_api_key(self, key_id: str) -> bool:
        """执行相关操作。

        Args:
            key_id: 相关参数。

        Returns:
            操作结果。
        """
        self.conn.execute("UPDATE api_keys SET status = 'revoked' WHERE key_id = ?", (key_id,))
        self.conn.commit()
        return True

    def check_permission(self, user_id: str, permission: str) -> bool:
        """检查相关状态。

        Args:
            user_id: 相关参数。
            permission: 相关参数。

        Returns:
            操作结果。
        """
        user = self.get_user(user_id)
        if not user:
            return False
        if user.role == UserRole.ADMIN.value:
            return True
        return permission in user.permissions

    def _add_audit_log(self, user_id: str, username: str, action: str, resource: str, ip_address: str, status: str, details: str = ""):
        """添加相关数据。

        Args:
            user_id: 相关参数。
            username: 相关参数。
            action: 相关参数。
            resource: 相关参数。
            ip_address: 相关参数。
            status: 相关参数。
            details: 相关参数。

        Returns:
            操作结果。
        """
        log_id = f"log_{int(time.time())}_{secrets.token_hex(8)}"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.conn.execute("INSERT INTO audit_logs (log_id, user_id, username, action, resource, ip_address, status, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (log_id, user_id, username, action, resource, ip_address, status, details, now))
        self.conn.commit()

    def get_audit_logs(self, page: int = 1, page_size: int = 50) -> Tuple[List[Dict], int]:
        """获取相关数据。

        Args:
            page: 相关参数。
            page_size: 相关参数。

        Returns:
            操作结果。
        """
        offset = (page - 1) * page_size
        total = self.conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
        cursor = self.conn.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?", (page_size, offset))
        return [dict(r) for r in cursor.fetchall()], total

    def get_statistics(self) -> Dict:
        """获取相关数据。

        Returns:
            操作结果。
        """
        stats = {
            "total_users": self.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "active_users": self.conn.execute("SELECT COUNT(*) FROM users WHERE status = 'active'").fetchone()[0],
            "total_api_keys": self.conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0],
            "active_api_keys": self.conn.execute("SELECT COUNT(*) FROM api_keys WHERE status = 'active'").fetchone()[0],
            "total_audit_logs": self.conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0],
            "users_by_role": {},
        }
        for role in UserRole:
            count = self.conn.execute("SELECT COUNT(*) FROM users WHERE role = ?", (role.value,)).fetchone()[0]
            if count > 0:
                stats["users_by_role"][role.value] = count
        return stats

    def close(self):
        """关闭相关资源。

        Returns:
            操作结果。
        """
        self.conn.close()


def main():
    """在...中。

        Returns:
            操作结果。
    """
    print("=" * 60)
    print("  用户认证系统")
    print("=" * 60)
    print()

    auth = AuthSystem()

    # 注册测试用户
    print("[1/4] 注册测试用户...")
    try:
        user = auth.register_user("testuser", "test@example.com", "Test@123456", UserRole.ANALYST.value)
        print(f"  用户注册成功: {user.username}")
        print(f"  角色: {user.role}")
        print(f"  权限数: {len(user.permissions)}")
    except Exception as e:
        print(f"  注册失败（可能已存在）: {e}")
    print()

    # 用户登录
    print("[2/4] 用户登录...")
    try:
        result = auth.login("testuser", "Test@123456", ip_address="127.0.0.1")
        print(f"  登录成功!")
        print(f"  访问令牌: {result['access_token'][:50]}...")
        print(f"  过期时间: {result['expires_in']}秒")
        access_token = result["access_token"]
    except Exception as e:
        print(f"  登录失败: {e}")
        access_token = ""
    print()

    # 验证令牌
    print("[3/4] 验证访问令牌...")
    if access_token:
        user_data = auth.verify_token(access_token)
        if user_data:
            print(f"  令牌验证成功!")
            print(f"  用户: {user_data['username']}")
            print(f"  角色: {user_data['role']}")
    print()

    # 创建API密钥
    print("[4/4] 创建API密钥...")
    try:
        user = auth.get_user_by_username("testuser")
        if user:
            api_key = auth.create_api_key(user.user_id, "测试API密钥", expires_in_days=30)
            print(f"  API密钥创建成功!")
            print(f"  API密钥: {api_key['api_key']}")
            print(f"  过期时间: {api_key['expires_at']}")

            # 验证API密钥
            key_data = auth.verify_api_key(api_key["api_key"])
            if key_data:
                print(f"  API密钥验证成功! 用户: {key_data['username']}")
    except Exception as e:
        print(f"  创建失败: {e}")
    print()

    # 系统统计
    print("系统统计:")
    stats = auth.get_statistics()
    print(f"  总用户数: {stats['total_users']}")
    print(f"  活跃用户: {stats['active_users']}")
    print(f"  API密钥总数: {stats['total_api_keys']}")
    print(f"  审计日志总数: {stats['total_audit_logs']}")
    print()

    # 最近审计日志
    print("最近审计日志:")
    logs, total = auth.get_audit_logs(page_size=5)
    for log in logs[:5]:
        print(f"  [{log['created_at']}] {log['username']} - {log['action']} - {log['status']}")
    print()

    auth.close()
    print("=" * 60)
    print("  完成！默认管理员: admin / Admin@123456")
    print("=" * 60)


if __name__ == "__main__":
    main()
