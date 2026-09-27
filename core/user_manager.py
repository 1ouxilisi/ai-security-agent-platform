#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用户权限系统
User Permission System

功能：用户管理、角色权限、会话管理、审计日志
"""

import os
import json
import time
import uuid
import hashlib
import secrets
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Set
from enum import Enum
from loguru import logger


class UserRole(str, Enum):
    """用户角色"""
    ADMIN = "admin"           # 管理员（全部权限）
    OPERATOR = "operator"     # 操作员（扫描/测试权限）
    VIEWER = "viewer"         # 查看者（只读权限）
    API = "api"               # API用户（API调用权限）


class Permission(str, Enum):
    """权限"""
    # 系统管理
    SYSTEM_CONFIG = "system:config"
    SYSTEM_USERS = "system:users"
    SYSTEM_LOGS = "system:logs"

    # 扫描任务
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_UPDATE = "scan:update"
    SCAN_DELETE = "scan:delete"
    SCAN_EXECUTE = "scan:execute"

    # 实战能力
    COMBAT_USE = "combat:use"
    COMBAT_CONFIG = "combat:config"

    # 报告
    REPORT_CREATE = "report:create"
    REPORT_READ = "report:read"
    REPORT_EXPORT = "report:export"

    # 知识库
    KNOWLEDGE_READ = "knowledge:read"
    KNOWLEDGE_WRITE = "knowledge:write"

    # API
    API_ACCESS = "api:access"


# 角色权限映射
ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.ADMIN: set(Permission),  # 全部权限
    UserRole.OPERATOR: {
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_UPDATE,
        Permission.SCAN_EXECUTE, Permission.COMBAT_USE,
        Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_EXPORT,
        Permission.KNOWLEDGE_READ, Permission.KNOWLEDGE_WRITE,
        Permission.API_ACCESS,
    },
    UserRole.VIEWER: {
        Permission.SCAN_READ, Permission.REPORT_READ,
        Permission.KNOWLEDGE_READ, Permission.API_ACCESS,
    },
    UserRole.API: {
        Permission.SCAN_READ, Permission.SCAN_EXECUTE,
        Permission.API_ACCESS,
    },
}


@dataclass
class User:
    """用户"""
    user_id: str
    username: str
    password_hash: str
    salt: str
    role: UserRole = UserRole.VIEWER
    email: Optional[str] = None
    full_name: Optional[str] = None
    is_active: bool = True
    created_at: float = field(default_factory=time.time)
    last_login: Optional[float] = None
    failed_login_attempts: int = 0
    locked_until: Optional[float] = None
    api_key: Optional[str] = None
    permissions: List[str] = field(default_factory=list)  # 额外权限

    def to_dict(self) -> Dict[str, Any]:
        return {
            'user_id': self.user_id,
            'username': self.username,
            'role': self.role.value,
            'email': self.email,
            'full_name': self.full_name,
            'is_active': self.is_active,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'failed_login_attempts': self.failed_login_attempts,
            'permissions': self.permissions,
            'has_api_key': self.api_key is not None,
        }

    def has_permission(self, permission: Permission) -> bool:
        """检查用户是否有权限"""
        # 角色权限
        role_perms = ROLE_PERMISSIONS.get(self.role, set())
        if permission in role_perms:
            return True
        # 额外权限
        return permission.value in self.permissions


@dataclass
class Session:
    """会话"""
    session_id: str
    user_id: str
    username: str
    role: str
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0
    last_activity: float = field(default_factory=time.time)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_active: bool = True

    def __post_init__(self):
        if self.expires_at == 0:
            self.expires_at = self.created_at + 86400  # 默认24小时

    def to_dict(self) -> Dict[str, Any]:
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'username': self.username,
            'role': self.role,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'last_activity': self.last_activity,
            'ip_address': self.ip_address,
            'is_active': self.is_active,
        }


@dataclass
class AuditLog:
    """审计日志"""
    log_id: str
    user_id: Optional[str]
    username: Optional[str]
    action: str
    resource: str
    resource_id: Optional[str]
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    success: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            'log_id': self.log_id,
            'user_id': self.user_id,
            'username': self.username,
            'action': self.action,
            'resource': self.resource,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp,
            'success': self.success,
        }


class UserManager:
    """用户管理器"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.users_file = os.path.join(data_dir, "users.json")
        self.sessions_file = os.path.join(data_dir, "sessions.json")
        self.audit_log_file = os.path.join(data_dir, "audit_logs.json")

        self._users: Dict[str, User] = {}
        self._sessions: Dict[str, Session] = {}
        self._audit_logs: List[AuditLog] = []

        os.makedirs(data_dir, exist_ok=True)
        self._load()

        # 如果没有用户，创建默认管理员
        if not self._users:
            self._create_default_admin()

        logger.info("用户管理器初始化完成")

    def _hash_password(self, password: str, salt: str) -> str:
        """哈希密码"""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

    def _generate_salt(self) -> str:
        """生成盐"""
        return secrets.token_hex(16)

    def create_user(self, username: str, password: str, role: UserRole = UserRole.VIEWER,
                    email: str = None, full_name: str = None) -> User:
        """创建用户"""
        # 检查用户名是否存在
        if any(u.username == username for u in self._users.values()):
            raise ValueError(f"用户名已存在: {username}")

        user_id = str(uuid.uuid4())
        salt = self._generate_salt()
        password_hash = self._hash_password(password, salt)
        api_key = secrets.token_hex(32)

        user = User(
            user_id=user_id,
            username=username,
            password_hash=password_hash,
            salt=salt,
            role=role,
            email=email,
            full_name=full_name,
            api_key=api_key,
        )

        self._users[user_id] = user
        self._save()
        self._log_audit(user_id, username, "create_user", "user", user_id, {'role': role.value})

        logger.info(f"用户创建成功: {username} ({role.value})")
        return user

    def authenticate(self, username: str, password: str, ip_address: str = None,
                     user_agent: str = None) -> Optional[Session]:
        """用户认证"""
        user = next((u for u in self._users.values() if u.username == username), None)

        if not user:
            return None

        # 检查账户是否锁定
        if user.locked_until and time.time() < user.locked_until:
            raise PermissionError(f"账户已锁定，请在 {user.locked_until - time.time():.0f} 秒后重试")

        # 验证密码
        password_hash = self._hash_password(password, user.salt)
        if password_hash != user.password_hash:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = time.time() + 300  # 锁定5分钟
                user.failed_login_attempts = 0
            self._save()
            self._log_audit(user.user_id, username, "login_failed", "auth", None,
                          {'ip_address': ip_address}, success=False)
            return None

        # 登录成功
        user.failed_login_attempts = 0
        user.last_login = time.time()
        self._save()

        # 创建会话
        session_id = secrets.token_hex(32)
        session = Session(
            session_id=session_id,
            user_id=user.user_id,
            username=user.username,
            role=user.role.value,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self._sessions[session_id] = session
        self._save_sessions()

        self._log_audit(user.user_id, username, "login", "auth", session_id, {'ip_address': ip_address})

        logger.info(f"用户登录成功: {username}")
        return session

    def logout(self, session_id: str) -> bool:
        """登出"""
        session = self._sessions.get(session_id)
        if session:
            session.is_active = False
            self._save_sessions()
            self._log_audit(session.user_id, session.username, "logout", "auth", session_id)
            return True
        return False

    def get_session(self, session_id: str) -> Optional[Session]:
        """获取会话"""
        session = self._sessions.get(session_id)
        if session and session.is_active:
            # 检查是否过期
            if time.time() > session.expires_at:
                session.is_active = False
                self._save_sessions()
                return None
            # 更新最后活动时间
            session.last_activity = time.time()
            return session
        return None

    def get_user(self, user_id: str) -> Optional[User]:
        """获取用户"""
        return self._users.get(user_id)

    def get_user_by_username(self, username: str) -> Optional[User]:
        """根据用户名获取用户"""
        return next((u for u in self._users.values() if u.username == username), None)

    def list_users(self) -> List[User]:
        """列出所有用户"""
        return list(self._users.values())

    def update_user(self, user_id: str, **kwargs) -> Optional[User]:
        """更新用户"""
        user = self._users.get(user_id)
        if not user:
            return None

        allowed_fields = ['email', 'full_name', 'is_active', 'role', 'permissions']
        for key, value in kwargs.items():
            if key in allowed_fields and hasattr(user, key):
                setattr(user, key, value)

        self._save()
        self._log_audit(user_id, user.username, "update_user", "user", user_id, kwargs)
        return user

    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """修改密码"""
        user = self._users.get(user_id)
        if not user:
            return False

        # 验证旧密码
        old_hash = self._hash_password(old_password, user.salt)
        if old_hash != user.password_hash:
            return False

        # 更新密码
        user.salt = self._generate_salt()
        user.password_hash = self._hash_password(new_password, user.salt)
        self._save()
        self._log_audit(user_id, user.username, "change_password", "user", user_id)
        return True

    def delete_user(self, user_id: str) -> bool:
        """删除用户"""
        if user_id in self._users:
            user = self._users.pop(user_id)
            self._save()
            self._log_audit(user_id, user.username, "delete_user", "user", user_id)
            return True
        return False

    def verify_api_key(self, api_key: str) -> Optional[User]:
        """验证API Key"""
        return next((u for u in self._users.values() if u.api_key == api_key and u.is_active), None)

    def check_permission(self, user_id: str, permission: Permission) -> bool:
        """检查用户权限"""
        user = self._users.get(user_id)
        if not user or not user.is_active:
            return False
        return user.has_permission(permission)

    def get_audit_logs(self, limit: int = 100, offset: int = 0,
                       user_id: str = None, action: str = None) -> List[AuditLog]:
        """获取审计日志"""
        logs = self._audit_logs
        if user_id:
            logs = [l for l in logs if l.user_id == user_id]
        if action:
            logs = [l for l in logs if l.action == action]
        logs.sort(key=lambda l: l.timestamp, reverse=True)
        return logs[offset:offset + limit]

    def _log_audit(self, user_id: str, username: str, action: str, resource: str,
                   resource_id: str = None, details: Dict = None, success: bool = True,
                   ip_address: str = None):
        """记录审计日志"""
        log = AuditLog(
            log_id=str(uuid.uuid4()),
            user_id=user_id,
            username=username,
            action=action,
            resource=resource,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
            success=success,
        )
        self._audit_logs.append(log)
        # 只保留最近10000条
        if len(self._audit_logs) > 10000:
            self._audit_logs = self._audit_logs[-10000:]
        self._save_audit_logs()

    def _create_default_admin(self):
        """创建默认管理员"""
        admin_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")
        admin = self.create_user(
            username="admin",
            password=admin_password,
            role=UserRole.ADMIN,
            email="admin@localhost",
            full_name="System Administrator",
        )
        logger.warning(f"已创建默认管理员: admin / {admin_password} (请立即修改密码!)")

    def _load(self):
        """加载数据"""
        # 加载用户
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    users_data = json.load(f)
                for data in users_data:
                    user = User(**{k: v for k, v in data.items() if k in User.__dataclass_fields__})
                    if isinstance(user.role, str):
                        user.role = UserRole(user.role)
                    self._users[user.user_id] = user
            except Exception as e:
                logger.error(f"加载用户数据失败: {e}")

        # 加载会话
        if os.path.exists(self.sessions_file):
            try:
                with open(self.sessions_file, 'r', encoding='utf-8') as f:
                    sessions_data = json.load(f)
                for data in sessions_data:
                    session = Session(**{k: v for k, v in data.items() if k in Session.__dataclass_fields__})
                    self._sessions[session.session_id] = session
            except Exception as e:
                logger.error(f"加载会话数据失败: {e}")

        # 加载审计日志
        if os.path.exists(self.audit_log_file):
            try:
                with open(self.audit_log_file, 'r', encoding='utf-8') as f:
                    logs_data = json.load(f)
                for data in logs_data:
                    log = AuditLog(**{k: v for k, v in data.items() if k in AuditLog.__dataclass_fields__})
                    self._audit_logs.append(log)
            except Exception as e:
                logger.error(f"加载审计日志失败: {e}")

    def _save(self):
        """保存用户数据"""
        try:
            users_data = [u.to_dict() for u in self._users.values()]
            # 重新添加password_hash和salt（to_dict不包含）
            for i, (user_id, user) in enumerate(self._users.items()):
                users_data[i]['password_hash'] = user.password_hash
                users_data[i]['salt'] = user.salt
                users_data[i]['api_key'] = user.api_key
                users_data[i]['locked_until'] = user.locked_until
            with open(self.users_file, 'w', encoding='utf-8') as f:
                json.dump(users_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存用户数据失败: {e}")

    def _save_sessions(self):
        """保存会话数据"""
        try:
            sessions_data = [s.to_dict() for s in self._sessions.values()]
            with open(self.sessions_file, 'w', encoding='utf-8') as f:
                json.dump(sessions_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存会话数据失败: {e}")

    def _save_audit_logs(self):
        """保存审计日志"""
        try:
            logs_data = [l.to_dict() for l in self._audit_logs[-1000:]]  # 只保存最近1000条
            with open(self.audit_log_file, 'w', encoding='utf-8') as f:
                json.dump(logs_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存审计日志失败: {e}")


# 全局用户管理器实例
_global_user_manager: Optional[UserManager] = None


def get_user_manager() -> UserManager:
    """获取全局用户管理器实例"""
    global _global_user_manager
    if _global_user_manager is None:
        _global_user_manager = UserManager()
    return _global_user_manager
