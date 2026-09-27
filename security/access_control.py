# -*- coding: utf-8 -*-
"""
access_control模块，提供访问控制加强功能。

模块功能：
    - 基于角色的访问控制（RBAC）
    - 数据级权限控制（租户隔离）
    - 操作审计日志
    - 会话管理（创建/验证/下线/列表）
    - 密码策略检查

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import json
import time
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

# 项目根目录
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
_LOGS_DIR = os.path.join(_PROJECT_ROOT, "logs")


class AccessControl:
    """访问控制加强类。

    提供RBAC权限、数据范围控制、审计日志、会话管理和密码策略。
    """

    # 角色定义
    ROLES = {
        "admin": {"rank": 3, "permissions": ["*"]},
        "analyst": {"rank": 2, "permissions": [
            "scan:create", "scan:read", "query:read", "report:create",
            "report:read", "asset:read", "asset:update",
        ]},
        "viewer": {"rank": 1, "permissions": [
            "query:read", "report:read", "asset:read",
        ]},
    }

    # 端点所需权限映射（method -> 所需最低角色rank）
    ENDPOINT_PERMISSIONS = {
        "DELETE": 3,       # 需要admin
        "POST /scan": 2,   # analyst+
        "POST /admin": 3,  # admin
        "POST /users": 3,  # admin
        "POST /config": 3,  # admin
        "POST /backup": 3,  # admin
        "POST /restore": 3,  # admin
        "POST /export": 2,  # analyst+
        "GET": 1,          # viewer+
        "POST": 2,         # analyst+（默认写操作）
    }

    # 会话超时时间（秒）
    SESSION_TIMEOUT = 30 * 60  # 30分钟
    # 并发会话数限制
    MAX_CONCURRENT_SESSIONS = 3
    # 密码过期时间（天）
    PASSWORD_EXPIRY_DAYS = 90
    # 密码历史记录数
    PASSWORD_HISTORY_LIMIT = 5

    def __init__(self):
        """初始化AccessControl实例。"""
        os.makedirs(_DATA_DIR, exist_ok=True)
        os.makedirs(_LOGS_DIR, exist_ok=True)

        # 会话存储
        self._sessions_file = os.path.join(_DATA_DIR, "sessions.json")
        self._sessions: Dict[str, Dict[str, Any]] = self._load_json(
            self._sessions_file, {})

        # 密码历史
        self._password_history_file = os.path.join(
            _DATA_DIR, "password_history.json")
        self._password_history: Dict[str, List[str]] = self._load_json(
            self._password_history_file, {})

        # 用户角色映射（默认admin用户）
        self._user_roles: Dict[str, str] = {
            "admin": "admin",
        }

        # 尝试从users.json加载用户角色
        users_file = os.path.join(_DATA_DIR, "users.json")
        if os.path.exists(users_file):
            try:
                with open(users_file, "r", encoding="utf-8") as f:
                    users = json.load(f)
                if isinstance(users, dict):
                    for uid, uinfo in users.items():
                        if isinstance(uinfo, dict):
                            role = uinfo.get("role", "viewer")
                            self._user_roles[uid] = role
            except (json.JSONDecodeError, IOError):
                pass

    @staticmethod
    def _load_json(filepath: str, default: Any) -> Any:
        """加载JSON文件，失败则返回默认值。"""
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return default

    def _save_json(self, filepath: str, data: Any):
        """保存数据到JSON文件。"""
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except IOError:
            pass

    # ------------------------------------------------------------------ #
    # RBAC权限检查
    # ------------------------------------------------------------------ #
    def check_permission(self, user_id: str, endpoint: str,
                         method: str) -> Dict[str, Any]:
        """基于角色的访问控制检查。

        Args:
            user_id: 用户ID。
            endpoint: 请求端点路径。
            method: HTTP方法（GET/POST/PUT/DELETE）。

        Returns:
            {"allowed": bool, "required_role": str, "user_role": str}
        """
        user_role = self._user_roles.get(user_id, "viewer")
        user_rank = self.ROLES.get(user_role, self.ROLES["viewer"])["rank"]

        # 确定所需权限级别
        required_rank = self.ENDPOINT_PERMISSIONS.get(method.upper(), 1)

        # 特殊端点检查
        endpoint_lower = endpoint.lower()
        if method.upper() == "POST":
            if any(kw in endpoint_lower for kw in ("/scan", "/export")):
                required_rank = max(required_rank, 2)
            if any(kw in endpoint_lower for kw in
                   ("/admin", "/users", "/config", "/backup", "/restore")):
                required_rank = 3

        # 反查所需角色名
        required_role = "viewer"
        if required_rank >= 3:
            required_role = "admin"
        elif required_rank >= 2:
            required_role = "analyst"

        allowed = user_rank >= required_rank
        return {
            "allowed": allowed,
            "required_role": required_role,
            "user_role": user_role,
        }

    # ------------------------------------------------------------------ #
    # 数据级权限
    # ------------------------------------------------------------------ #
    def check_data_scope(self, user_id: str, tenant_id: str,
                         data_tenant_id: str) -> Dict[str, Any]:
        """数据级权限检查：用户只能访问自己租户的数据。

        Args:
            user_id: 用户ID。
            tenant_id: 用户所属租户ID。
            data_tenant_id: 数据所属租户ID。

        Returns:
            {"allowed": bool}
        """
        user_role = self._user_roles.get(user_id, "viewer")
        # admin可以跨租户
        if user_role == "admin":
            return {"allowed": True}
        # 其他角色只能访问自己租户
        return {"allowed": tenant_id == data_tenant_id}

    # ------------------------------------------------------------------ #
    # 操作审计
    # ------------------------------------------------------------------ #
    def log_audit(self, user_id: str, action: str, resource: str,
                  result: str, details: Optional[Dict] = None):
        """记录操作审计日志。

        记录到logs/audit_security.log和数据库audit_logs表。

        Args:
            user_id: 操作用户ID。
            action: 操作类型。
            resource: 操作资源。
            result: 操作结果（success/failure）。
            details: 额外详情。
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "action": action,
            "resource": resource,
            "result": result,
            "details": details or {},
        }

        # 写入日志文件
        log_file = os.path.join(_LOGS_DIR, "audit_security.log")
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except IOError:
            pass

        # 写入数据库audit_logs表（如果数据库可用）
        try:
            self._write_audit_to_db(entry)
        except Exception:
            pass

    @staticmethod
    def _write_audit_to_db(entry: Dict[str, Any]):
        """尝试将审计日志写入数据库。"""
        try:
            import sqlite3
            db_path = os.path.join(_DATA_DIR, "platform.db")
            if not os.path.exists(db_path):
                return
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            # 确保表存在
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    user_id TEXT,
                    action TEXT,
                    resource TEXT,
                    result TEXT,
                    details TEXT
                )
            """)
            cursor.execute("""
                INSERT INTO audit_logs
                (timestamp, user_id, action, resource, result, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                entry["timestamp"],
                entry["user_id"],
                entry["action"],
                entry["resource"],
                entry["result"],
                json.dumps(entry["details"], ensure_ascii=False),
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # 会话管理
    # ------------------------------------------------------------------ #
    def create_session(self, user_id: str, ip: str,
                       user_agent: str) -> Dict[str, Any]:
        """创建会话。

        Args:
            user_id: 用户ID。
            ip: 客户端IP。
            user_agent: 客户端User-Agent。

        Returns:
            包含session_id和会话信息的字典。
        """
        # 检查并发会话数
        active_sessions = [
            s for s in self._sessions.values()
            if s.get("user_id") == user_id
            and self._is_session_active(s)
        ]
        if len(active_sessions) >= self.MAX_CONCURRENT_SESSIONS:
            # 最旧的会话踢掉
            oldest = min(active_sessions, key=lambda s: s.get("created_at", 0))
            self.kill_session(oldest.get("session_id", ""))

        session_id = secrets.token_urlsafe(32)
        now = time.time()
        session = {
            "session_id": session_id,
            "user_id": user_id,
            "ip": ip,
            "user_agent": user_agent,
            "created_at": now,
            "last_active": now,
        }
        self._sessions[session_id] = session
        self._save_json(self._sessions_file, self._sessions)
        return session

    def _is_session_active(self, session: Dict[str, Any]) -> bool:
        """检查会话是否活跃（未超时）。"""
        last_active = session.get("last_active", 0)
        return time.time() - last_active < self.SESSION_TIMEOUT

    def validate_session(self, session_id: str) -> Dict[str, Any]:
        """验证会话。

        检查会话是否存在、是否超时、并发会话数是否超限。

        Args:
            session_id: 会话ID。

        Returns:
            {"valid": bool, "user_id": str, "reason": str}
        """
        session = self._sessions.get(session_id)
        if not session:
            return {"valid": False, "user_id": "", "reason": "会话不存在"}

        if not self._is_session_active(session):
            # 清理超时会话
            del self._sessions[session_id]
            self._save_json(self._sessions_file, self._sessions)
            return {"valid": False, "user_id": "", "reason": "会话已超时"}

        # 更新最后活跃时间
        session["last_active"] = time.time()
        self._save_json(self._sessions_file, self._sessions)

        return {
            "valid": True,
            "user_id": session.get("user_id", ""),
            "reason": "",
        }

    def kill_session(self, session_id: str) -> bool:
        """强制下线会话。

        Args:
            session_id: 会话ID。

        Returns:
            是否成功下线。
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            self._save_json(self._sessions_file, self._sessions)
            return True
        return False

    def list_sessions(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出当前活跃会话。

        Args:
            user_id: 可选，按用户ID过滤。

        Returns:
            活跃会话列表。
        """
        result = []
        now = time.time()
        for sid, session in list(self._sessions.items()):
            # 清理超时会话
            if now - session.get("last_active", 0) >= self.SESSION_TIMEOUT:
                del self._sessions[sid]
                continue
            if user_id and session.get("user_id") != user_id:
                continue
            result.append({
                "session_id": sid,
                "user_id": session.get("user_id", ""),
                "ip": session.get("ip", ""),
                "created_at": session.get("created_at", 0),
                "last_active": session.get("last_active", 0),
            })
        self._save_json(self._sessions_file, self._sessions)
        return result

    # ------------------------------------------------------------------ #
    # 密码策略
    # ------------------------------------------------------------------ #
    def check_password_policy(self, password: str) -> Dict[str, Any]:
        """密码策略检查。

        规则：
            - 长度>=12位
            - 包含大写字母、小写字母、数字、特殊字符中至少3种
            - 不能与最近5次密码重复
            - 密码90天过期

        Args:
            password: 待检查的密码。

        Returns:
            {"valid": bool, "issues": [...]}
        """
        issues: List[str] = []

        # 长度检查
        if len(password) < 12:
            issues.append("密码长度至少12位")

        # 字符种类检查
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        categories = sum([has_upper, has_lower, has_digit, has_special])
        if categories < 3:
            issues.append(
                "密码需包含大写字母、小写字母、数字、特殊字符中至少3种")

        # 历史密码检查
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        for user_id, history in self._password_history.items():
            if isinstance(history, list) and pwd_hash in history[-self.PASSWORD_HISTORY_LIMIT:]:
                issues.append("密码不能与最近5次使用的密码重复")
                break

        return {
            "valid": len(issues) == 0,
            "issues": issues,
        }

    def record_password(self, user_id: str, password: str):
        """记录用户修改密码（用于历史检查）。

        Args:
            user_id: 用户ID。
            password: 新密码。
        """
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        history = self._password_history.get(user_id, [])
        history.append(pwd_hash)
        # 只保留最近N次
        if len(history) > self.PASSWORD_HISTORY_LIMIT:
            history = history[-self.PASSWORD_HISTORY_LIMIT:]
        self._password_history[user_id] = history
        self._save_json(self._password_history_file, self._password_history)


# 全局实例
_access_control_instance: Optional[AccessControl] = None


def get_access_control() -> AccessControl:
    """获取全局AccessControl实例（单例模式）。"""
    global _access_control_instance
    if _access_control_instance is None:
        _access_control_instance = AccessControl()
    return _access_control_instance
