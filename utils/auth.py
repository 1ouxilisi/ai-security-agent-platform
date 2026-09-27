"""
auth工具函数模块，提供通用的辅助函数和工具类。

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
import secrets
import uuid
from datetime import datetime
from typing import Optional, Dict, List, Any
from utils.database import db
from utils.logger import log


class UserManager:
    """用户管理器"""

    # 角色权限定义
    ROLE_PERMISSIONS = {
        "admin": ["*"],  # 所有权限
        "analyst": [
            "task:create", "task:read", "task:update",
            "finding:read", "finding:update",
            "report:create", "report:read",
            "tool:execute",
        ],
        "user": [
            "task:create", "task:read",
            "finding:read",
            "report:read",
        ],
        "viewer": [
            "task:read", "finding:read", "report:read",
        ],
    }

    def __init__(self):
        """初始化UserManager实例。

        Args:
            self: 类实例。
        """
        self._ensure_admin_user()

    def _hash_password(self, password: str) -> str:
        """密码哈希（SHA256 + salt）"""
        salt = "hacking_agent_2026_secure_salt"
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

    def _generate_api_key(self) -> str:
        """生成API密钥"""
        return "hak-" + secrets.token_hex(24)

    def _ensure_admin_user(self):
        """确保默认管理员用户存在"""
        conn = db._get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) FROM users WHERE username='admin'").fetchone()[0]
            if count == 0:
                now = datetime.now().isoformat()
                admin_id = str(uuid.uuid4())
                api_key = self._generate_api_key()
                conn.execute("""
                    INSERT INTO users (id, username, password_hash, email, role, api_key,
                                      is_active, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """, (admin_id, "admin", self._hash_password("admin123"),
                      "admin@hacking-agent.local", "admin", api_key, now, now))
                conn.commit()
                log.info(f"✅ 默认管理员用户已创建: admin / admin123")
                log.info(f"   API Key: {api_key}")
        except Exception as e:
            log.error(f"创建管理员用户失败: {e}")
        finally:
            conn.close()

    def register_user(self, username: str, password: str, email: str = "",
                      role: str = "user") -> Dict[str, Any]:
        """注册用户"""
        # 验证用户名
        if not username or len(username) < 3:
            return {"success": False, "error": "用户名至少3个字符"}

        # 检查用户名是否已存在
        conn = db._get_connection()
        try:
            existing = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if existing:
                return {"success": False, "error": "用户名已存在"}

            # 创建用户
            now = datetime.now().isoformat()
            user_id = str(uuid.uuid4())
            api_key = self._generate_api_key()
            password_hash = self._hash_password(password)

            conn.execute("""
                INSERT INTO users (id, username, password_hash, email, role, api_key,
                                  is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
            """, (user_id, username, password_hash, email, role, api_key, now, now))
            conn.commit()

            self.log_audit(user_id, username, "user:register", "user", user_id,
                          {"username": username, "role": role})

            return {
                "success": True,
                "user_id": user_id,
                "username": username,
                "role": role,
                "api_key": api_key,
            }
        except Exception as e:
            log.error(f"注册用户失败: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """用户认证"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE username=? AND is_active=1",
                (username,)
            ).fetchone()

            if not row:
                self.log_audit(None, username, "user:login_failed", "user", None,
                              {"reason": "user_not_found"})
                return None

            user = dict(row)
            password_hash = self._hash_password(password)

            if user["password_hash"] != password_hash:
                self.log_audit(user["id"], username, "user:login_failed", "user", user["id"],
                              {"reason": "wrong_password"})
                return None

            # 更新最后登录时间
            now = datetime.now().isoformat()
            conn.execute("UPDATE users SET last_login=?, updated_at=? WHERE id=?",
                        (now, now, user["id"]))
            conn.commit()

            self.log_audit(user["id"], username, "user:login", "user", user["id"])

            return {
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "email": user["email"],
                "api_key": user["api_key"],
            }
        except Exception as e:
            log.error(f"认证失败: {e}")
            return None
        finally:
            conn.close()

    def authenticate_by_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """通过API密钥认证"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE api_key=? AND is_active=1",
                (api_key,)
            ).fetchone()

            if not row:
                return None

            user = dict(row)
            return {
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "email": user["email"],
            }
        except Exception as e:
            log.error(f"API密钥认证失败: {e}")
            return None
        finally:
            conn.close()

    def has_permission(self, user_id: str, permission: str) -> bool:
        """检查用户权限"""
        conn = db._get_connection()
        try:
            row = conn.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
            if not row:
                return False

            role = row["role"]
            role_perms = self.ROLE_PERMISSIONS.get(role, [])

            # admin有所有权限
            if "*" in role_perms:
                return True

            return permission in role_perms
        except Exception as e:
            log.error(f"权限检查失败: {e}")
            return False
        finally:
            conn.close()

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """获取用户信息"""
        conn = db._get_connection()
        try:
            row = conn.execute("SELECT id, username, email, role, is_active, created_at, last_login FROM users WHERE id=?", (user_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def list_users(self, limit: int = 50) -> List[Dict[str, Any]]:
        """列出用户"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT id, username, email, role, is_active, created_at, last_login FROM users ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def update_user_role(self, user_id: str, role: str) -> bool:
        """更新用户角色"""
        if role not in self.ROLE_PERMISSIONS:
            return False

        now = datetime.now().isoformat()
        conn = db._get_connection()
        try:
            conn.execute("UPDATE users SET role=?, updated_at=? WHERE id=?", (role, now, user_id))
            conn.commit()
            return True
        except Exception as e:
            log.error(f"更新用户角色失败: {e}")
            return False
        finally:
            conn.close()

    def regenerate_api_key(self, user_id: str) -> Optional[str]:
        """重新生成API密钥"""
        new_key = self._generate_api_key()
        now = datetime.now().isoformat()
        conn = db._get_connection()
        try:
            conn.execute("UPDATE users SET api_key=?, updated_at=? WHERE id=?", (new_key, now, user_id))
            conn.commit()
            return new_key
        except Exception as e:
            log.error(f"重新生成API密钥失败: {e}")
            return None
        finally:
            conn.close()

    def log_audit(self, user_id: Optional[str], username: Optional[str],
                  action: str, resource_type: str = None, resource_id: str = None,
                  details: dict = None, ip_address: str = None,
                  user_agent: str = None, status: str = "success"):
        """记录审计日志"""
        log_id = str(uuid.uuid4())
        now = datetime.now().isoformat()

        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO audit_logs (id, user_id, username, action, resource_type,
                                       resource_id, details, ip_address, user_agent,
                                       status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (log_id, user_id, username, action, resource_type, resource_id,
                  json.dumps(details or {}, ensure_ascii=False) if details else None,
                  ip_address, user_agent, status, now))
            conn.commit()
        except Exception as e:
            log.error(f"记录审计日志失败: {e}")
        finally:
            conn.close()

    def get_audit_logs(self, user_id: str = None, action: str = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
        """获取审计日志"""
        conn = db._get_connection()
        try:
            query = "SELECT * FROM audit_logs WHERE 1=1"
            params = []
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            if action:
                query += " AND action = ?"
                params.append(action)
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()


import json

# 全局用户管理器实例
user_manager = UserManager()
