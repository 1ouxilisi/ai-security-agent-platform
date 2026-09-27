#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
enterprise_manager_v2安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger


class Role(Enum):
    """角色枚举"""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    SECURITY_ENGINEER = "security_engineer"
    AUDITOR = "auditor"
    VIEWER = "viewer"
    GUEST = "guest"


class Permission(Enum):
    """权限枚举"""
    # 系统管理
    SYSTEM_CONFIG = "system:config"
    SYSTEM_MONITOR = "system:monitor"
    SYSTEM_BACKUP = "system:backup"

    # 用户管理
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"

    # 角色管理
    ROLE_CREATE = "role:create"
    ROLE_READ = "role:read"
    ROLE_UPDATE = "role:update"
    ROLE_DELETE = "role:delete"

    # 租户管理
    TENANT_CREATE = "tenant:create"
    TENANT_READ = "tenant:read"
    TENANT_UPDATE = "tenant:update"
    TENANT_DELETE = "tenant:delete"

    # 扫描管理
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_UPDATE = "scan:update"
    SCAN_DELETE = "scan:delete"
    SCAN_EXECUTE = "scan:execute"

    # 报告管理
    REPORT_CREATE = "report:create"
    REPORT_READ = "report:read"
    REPORT_UPDATE = "report:update"
    REPORT_DELETE = "report:delete"
    REPORT_EXPORT = "report:export"

    # 漏洞管理
    VULN_READ = "vuln:read"
    VULN_UPDATE = "vuln:update"
    VULN_DELETE = "vuln:delete"
    VULN_ACKNOWLEDGE = "vuln:acknowledge"

    # 审计日志
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"

    # API管理
    API_KEY_CREATE = "api_key:create"
    API_KEY_READ = "api_key:read"
    API_KEY_REVOKE = "api_key:revoke"


@dataclass
class Tenant:
    """租户"""
    id: str
    name: str
    description: str = ""
    status: str = "active"  # active/suspended/deleted
    max_users: int = 100
    max_scans: int = 1000
    max_storage: int = 10  # GB
    created_at: str = ""
    updated_at: str = ""
    settings: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)


@dataclass
class User:
    """用户"""
    id: str
    username: str
    email: str
    password_hash: str = ""
    password_salt: str = ""
    full_name: str = ""
    role: str = Role.VIEWER.value
    tenant_id: str = ""
    department: str = ""
    title: str = ""
    phone: str = ""
    status: str = "active"  # active/suspended/locked/deleted
    failed_login_attempts: int = 0
    last_login_at: str = ""
    last_login_ip: str = ""
    password_changed_at: str = ""
    must_change_password: bool = False
    two_factor_enabled: bool = False
    two_factor_secret: str = ""
    api_keys: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    metadata: Dict = field(default_factory=dict)


@dataclass
class RoleDefinition:
    """角色定义"""
    id: str
    name: str
    description: str = ""
    permissions: List[str] = field(default_factory=list)
    is_system: bool = False
    created_at: str = ""
    updated_at: str = ""


@dataclass
class AuditLog:
    """审计日志"""
    id: str
    timestamp: str
    user_id: str
    username: str
    tenant_id: str
    action: str
    resource_type: str
    resource_id: str
    resource_name: str
    ip_address: str
    user_agent: str
    status: str  # success/failure/denied
    details: Dict = field(default_factory=dict)
    risk_level: str = "low"  # low/medium/high/critical
    session_id: str = ""


@dataclass
class APIToken:
    """API令牌"""
    id: str
    name: str
    token_hash: str
    user_id: str
    tenant_id: str
    permissions: List[str] = field(default_factory=list)
    expires_at: str = ""
    last_used_at: str = ""
    status: str = "active"  # active/revoked/expired
    created_at: str = ""
    revoked_at: str = ""
    revoked_by: str = ""


@dataclass
class Session:
    """会话"""
    id: str
    user_id: str
    username: str
    tenant_id: str
    ip_address: str
    user_agent: str
    created_at: str
    expires_at: str
    last_activity_at: str
    is_active: bool = True
    device_info: Dict = field(default_factory=dict)


@dataclass
class EnterpriseConfig:
    """企业级配置"""
    # 认证配置
    password_min_length: int = 12
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digits: bool = True
    password_require_special: bool = True
    password_expiry_days: int = 90
    password_history_count: int = 5
    max_failed_login_attempts: int = 5
    account_lockout_duration: int = 30  # 分钟
    session_timeout: int = 30  # 分钟
    max_sessions_per_user: int = 3

    # SSO配置
    sso_enabled: bool = False
    sso_provider: str = ""  # saml/oidc/ldap
    sso_config: Dict = field(default_factory=dict)

    # 审计配置
    audit_log_enabled: bool = True
    audit_log_retention_days: int = 365
    audit_log_alert_enabled: bool = True

    # 数据安全
    data_encryption_enabled: bool = True
    data_backup_enabled: bool = True
    data_backup_frequency: str = "daily"  # daily/weekly/monthly

    # 通知配置
    notification_email_enabled: bool = True
    notification_webhook_enabled: bool = False
    notification_webhook_url: str = ""


class EnterpriseManager:
    """企业级管理器"""

    def __init__(self, config: Optional[Dict] = None):
        """初始化EnterpriseManager实例。

        Args:
            self: 类实例。
        """
        self.config = config or {}
        self.workspace = self.config.get("workspace", "./enterprise_workspace")
        self._ensure_workspace()
        self.tenants: Dict[str, Tenant] = {}
        self.users: Dict[str, User] = {}
        self.roles: Dict[str, RoleDefinition] = {}
        self.audit_logs: List[AuditLog] = []
        self.api_tokens: Dict[str, APIToken] = {}
        self.sessions: Dict[str, Session] = {}
        self.enterprise_config = EnterpriseConfig()
        self._init_system_roles()
        self._init_default_tenant()
        logger.info("企业级管理模块初始化完成")

    def _ensure_workspace(self):
        """确保工作目录存在"""
        os.makedirs(self.workspace, exist_ok=True)
        os.makedirs(f"{self.workspace}/tenants", exist_ok=True)
        os.makedirs(f"{self.workspace}/users", exist_ok=True)
        os.makedirs(f"{self.workspace}/audit", exist_ok=True)
        os.makedirs(f"{self.workspace}/sessions", exist_ok=True)

    def _init_system_roles(self):
        """初始化系统角色"""
        system_roles = [
            RoleDefinition(
                id="super_admin",
                name="超级管理员",
                description="拥有所有权限，可管理系统、租户、用户、角色",
                permissions=[p.value for p in Permission],
                is_system=True,
                created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
            RoleDefinition(
                id="admin",
                name="管理员",
                description="可管理用户、角色、扫描、报告",
                permissions=[
                    Permission.USER_CREATE.value, Permission.USER_READ.value,
                    Permission.USER_UPDATE.value, Permission.USER_DELETE.value,
                    Permission.ROLE_READ.value,
                    Permission.SCAN_CREATE.value, Permission.SCAN_READ.value,
                    Permission.SCAN_EXECUTE.value,
                    Permission.REPORT_CREATE.value, Permission.REPORT_READ.value,
                    Permission.REPORT_EXPORT.value,
                    Permission.VULN_READ.value, Permission.VULN_UPDATE.value,
                    Permission.AUDIT_READ.value,
                ],
                is_system=True,
                created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
            RoleDefinition(
                id="security_analyst",
                name="安全分析师",
                description="可执行扫描、查看报告、管理漏洞",
                permissions=[
                    Permission.SCAN_CREATE.value, Permission.SCAN_READ.value,
                    Permission.SCAN_EXECUTE.value,
                    Permission.REPORT_READ.value, Permission.REPORT_EXPORT.value,
                    Permission.VULN_READ.value, Permission.VULN_UPDATE.value,
                    Permission.VULN_ACKNOWLEDGE.value,
                ],
                is_system=True,
                created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
            RoleDefinition(
                id="auditor",
                name="审计员",
                description="可查看审计日志、报告，只读权限",
                permissions=[
                    Permission.AUDIT_READ.value, Permission.AUDIT_EXPORT.value,
                    Permission.REPORT_READ.value, Permission.REPORT_EXPORT.value,
                    Permission.SCAN_READ.value, Permission.VULN_READ.value,
                    Permission.USER_READ.value, Permission.ROLE_READ.value,
                ],
                is_system=True,
                created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
            RoleDefinition(
                id="viewer",
                name="查看者",
                description="只读权限，可查看扫描结果和报告",
                permissions=[
                    Permission.SCAN_READ.value, Permission.REPORT_READ.value,
                    Permission.VULN_READ.value,
                ],
                is_system=True,
                created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        ]

        for role in system_roles:
            self.roles[role.id] = role

    def _init_default_tenant(self):
        """初始化默认租户"""
        default_tenant = Tenant(
            id="default",
            name="默认租户",
            description="系统默认租户",
            max_users=1000,
            max_scans=10000,
            max_storage=100,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            updated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.tenants["default"] = default_tenant

    # ==================== 租户管理 ====================

    def create_tenant(
        self,
        name: str,
        description: str = "",
        max_users: int = 100,
        max_scans: int = 1000,
        max_storage: int = 10,
    ) -> Tenant:
        """创建租户"""
        tenant_id = f"tenant_{uuid.uuid4().hex[:12]}"
        tenant = Tenant(
            id=tenant_id,
            name=name,
            description=description,
            max_users=max_users,
            max_scans=max_scans,
            max_storage=max_storage,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            updated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.tenants[tenant_id] = tenant
        logger.info(f"创建租户: {name} ({tenant_id})")
        return tenant

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """获取租户"""
        return self.tenants.get(tenant_id)

    def list_tenants(self) -> List[Tenant]:
        """列出所有租户"""
        return list(self.tenants.values())

    def update_tenant(self, tenant_id: str, **kwargs) -> Optional[Tenant]:
        """更新租户"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return None

        for key, value in kwargs.items():
            if hasattr(tenant, key):
                setattr(tenant, key, value)

        tenant.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"更新租户: {tenant_id}")
        return tenant

    def suspend_tenant(self, tenant_id: str) -> bool:
        """暂停租户"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False
        tenant.status = "suspended"
        tenant.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"暂停租户: {tenant_id}")
        return True

    def delete_tenant(self, tenant_id: str) -> bool:
        """删除租户"""
        if tenant_id == "default":
            logger.warning("不能删除默认租户")
            return False
        if tenant_id in self.tenants:
            del self.tenants[tenant_id]
            logger.info(f"删除租户: {tenant_id}")
            return True
        return False

    # ==================== 用户管理 ====================

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: str = "",
        role: str = Role.VIEWER.value,
        tenant_id: str = "default",
        department: str = "",
        title: str = "",
    ) -> User:
        """创建用户"""
        # 检查用户名是否已存在
        for user in self.users.values():
            if user.username == username:
                raise ValueError(f"用户名已存在: {username}")

        # 密码强度检查
        self._validate_password(password)

        # 生成密码哈希
        salt = secrets.token_hex(16)
        password_hash = self._hash_password(password, salt)

        user_id = f"user_{uuid.uuid4().hex[:12]}"
        user = User(
            id=user_id,
            username=username,
            email=email,
            password_hash=password_hash,
            password_salt=salt,
            full_name=full_name or username,
            role=role,
            tenant_id=tenant_id,
            department=department,
            title=title,
            status="active",
            must_change_password=True,
            password_changed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            updated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        # 获取角色权限
        role_def = self.roles.get(role)
        if role_def:
            user.permissions = role_def.permissions.copy()

        self.users[user_id] = user
        logger.info(f"创建用户: {username} ({user_id}), 角色: {role}")
        return user

    def _validate_password(self, password: str):
        """验证密码强度"""
        config = self.enterprise_config
        errors = []

        if len(password) < config.password_min_length:
            errors.append(f"密码长度至少{config.password_min_length}位")
        if config.password_require_uppercase and not any(c.isupper() for c in password):
            errors.append("密码必须包含大写字母")
        if config.password_require_lowercase and not any(c.islower() for c in password):
            errors.append("密码必须包含小写字母")
        if config.password_require_digits and not any(c.isdigit() for c in password):
            errors.append("密码必须包含数字")
        if config.password_require_special and not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password):
            errors.append("密码必须包含特殊字符")

        if errors:
            raise ValueError("密码强度不足: " + "; ".join(errors))

    def _hash_password(self, password: str, salt: str) -> str:
        """哈希密码"""
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000
        ).hex()

    def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str = "",
        user_agent: str = "",
    ) -> Tuple[bool, Optional[User], str]:
        """用户认证"""
        user = None
        for u in self.users.values():
            if u.username == username or u.email == username:
                user = u
                break

        if not user:
            self._log_audit(
                user_id="", username=username, tenant_id="",
                action="login_failed", resource_type="user",
                resource_id="", resource_name=username,
                ip_address=ip_address, user_agent=user_agent,
                status="failure", details={"reason": "用户不存在"},
                risk_level="medium",
            )
            return False, None, "用户不存在"

        if user.status != "active":
            return False, None, f"账户状态异常: {user.status}"

        if user.failed_login_attempts >= self.enterprise_config.max_failed_login_attempts:
            user.status = "locked"
            self._log_audit(
                user_id=user.id, username=user.username, tenant_id=user.tenant_id,
                action="account_locked", resource_type="user",
                resource_id=user.id, resource_name=user.username,
                ip_address=ip_address, user_agent=user_agent,
                status="success", details={"reason": "登录失败次数过多"},
                risk_level="high",
            )
            return False, None, "账户已锁定，请联系管理员"

        # 验证密码
        password_hash = self._hash_password(password, user.password_salt)
        if password_hash != user.password_hash:
            user.failed_login_attempts += 1
            self._log_audit(
                user_id=user.id, username=user.username, tenant_id=user.tenant_id,
                action="login_failed", resource_type="user",
                resource_id=user.id, resource_name=user.username,
                ip_address=ip_address, user_agent=user_agent,
                status="failure", details={"reason": "密码错误", "attempts": user.failed_login_attempts},
                risk_level="medium",
            )
            return False, None, "密码错误"

        # 认证成功
        user.failed_login_attempts = 0
        user.last_login_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user.last_login_ip = ip_address

        # 创建会话
        session = self._create_session(user, ip_address, user_agent)

        self._log_audit(
            user_id=user.id, username=user.username, tenant_id=user.tenant_id,
            action="login_success", resource_type="user",
            resource_id=user.id, resource_name=user.username,
            ip_address=ip_address, user_agent=user_agent,
            status="success", details={"session_id": session.id},
            risk_level="low",
        )

        return True, user, session.id

    def _create_session(self, user: User, ip_address: str, user_agent: str) -> Session:
        """创建会话"""
        session_id = secrets.token_hex(32)
        now = datetime.now()
        expires_at = now + timedelta(minutes=self.enterprise_config.session_timeout)

        session = Session(
            id=session_id,
            user_id=user.id,
            username=user.username,
            tenant_id=user.tenant_id,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=now.strftime("%Y-%m-%d %H:%M:%S"),
            expires_at=expires_at.strftime("%Y-%m-%d %H:%M:%S"),
            last_activity_at=now.strftime("%Y-%m-%d %H:%M:%S"),
            is_active=True,
        )

        self.sessions[session_id] = session
        return session

    def validate_session(self, session_id: str) -> Tuple[bool, Optional[User]]:
        """验证会话"""
        session = self.sessions.get(session_id)
        if not session or not session.is_active:
            return False, None

        # 检查是否过期
        now = datetime.now()
        expires_at = datetime.strptime(session.expires_at, "%Y-%m-%d %H:%M:%S")
        if now > expires_at:
            session.is_active = False
            return False, None

        # 更新最后活动时间
        session.last_activity_at = now.strftime("%Y-%m-%d %H:%M:%S")

        user = self.users.get(session.user_id)
        return True, user

    def logout(self, session_id: str) -> bool:
        """登出"""
        session = self.sessions.get(session_id)
        if session:
            session.is_active = False
            self._log_audit(
                user_id=session.user_id, username=session.username,
                tenant_id=session.tenant_id, action="logout",
                resource_type="session", resource_id=session.id,
                resource_name=session.username, ip_address=session.ip_address,
                user_agent=session.user_agent, status="success",
                risk_level="low",
            )
            return True
        return False

    def get_user(self, user_id: str) -> Optional[User]:
        """获取用户"""
        return self.users.get(user_id)

    def list_users(self, tenant_id: str = "") -> List[User]:
        """列出用户"""
        if tenant_id:
            return [u for u in self.users.values() if u.tenant_id == tenant_id]
        return list(self.users.values())

    def update_user(self, user_id: str, **kwargs) -> Optional[User]:
        """更新用户"""
        user = self.users.get(user_id)
        if not user:
            return None

        for key, value in kwargs.items():
            if hasattr(user, key) and key not in ["id", "password_hash", "password_salt"]:
                setattr(user, key, value)

        user.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return user

    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """修改密码"""
        user = self.users.get(user_id)
        if not user:
            return False

        # 验证旧密码
        old_hash = self._hash_password(old_password, user.password_salt)
        if old_hash != user.password_hash:
            return False

        # 验证新密码强度
        self._validate_password(new_password)

        # 更新密码
        new_salt = secrets.token_hex(16)
        user.password_hash = self._hash_password(new_password, new_salt)
        user.password_salt = new_salt
        user.password_changed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user.must_change_password = False
        user.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return True

    def reset_password(self, user_id: str, new_password: str) -> bool:
        """重置密码（管理员）"""
        user = self.users.get(user_id)
        if not user:
            return False

        self._validate_password(new_password)

        new_salt = secrets.token_hex(16)
        user.password_hash = self._hash_password(new_password, new_salt)
        user.password_salt = new_salt
        user.password_changed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user.must_change_password = True
        user.failed_login_attempts = 0
        user.status = "active"
        user.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return True

    def suspend_user(self, user_id: str) -> bool:
        """暂停用户"""
        user = self.users.get(user_id)
        if not user:
            return False
        user.status = "suspended"
        user.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return True

    def delete_user(self, user_id: str) -> bool:
        """删除用户"""
        if user_id in self.users:
            del self.users[user_id]
            return True
        return False

    # ==================== 角色与权限管理 ====================

    def create_role(
        self,
        name: str,
        description: str = "",
        permissions: Optional[List[str]] = None,
    ) -> RoleDefinition:
        """创建角色"""
        role_id = f"role_{uuid.uuid4().hex[:12]}"
        role = RoleDefinition(
            id=role_id,
            name=name,
            description=description,
            permissions=permissions or [],
            is_system=False,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            updated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.roles[role_id] = role
        return role

    def get_role(self, role_id: str) -> Optional[RoleDefinition]:
        """获取角色"""
        return self.roles.get(role_id)

    def list_roles(self) -> List[RoleDefinition]:
        """列出所有角色"""
        return list(self.roles.values())

    def update_role(self, role_id: str, **kwargs) -> Optional[RoleDefinition]:
        """更新角色"""
        role = self.roles.get(role_id)
        if not role or role.is_system:
            return None

        for key, value in kwargs.items():
            if hasattr(role, key):
                setattr(role, key, value)

        role.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return role

    def delete_role(self, role_id: str) -> bool:
        """删除角色"""
        role = self.roles.get(role_id)
        if not role or role.is_system:
            return False

        # 检查是否有用户使用此角色
        for user in self.users.values():
            if user.role == role_id:
                logger.warning(f"角色{role_id}仍有用户使用，不能删除")
                return False

        del self.roles[role_id]
        return True

    def check_permission(self, user: User, permission: str) -> bool:
        """检查用户权限"""
        if user.role == Role.SUPER_ADMIN.value:
            return True
        return permission in user.permissions

    def assign_role(self, user_id: str, role_id: str) -> bool:
        """分配角色"""
        user = self.users.get(user_id)
        role = self.roles.get(role_id)
        if not user or not role:
            return False

        user.role = role_id
        user.permissions = role.permissions.copy()
        user.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return True

    # ==================== API令牌管理 ====================

    def create_api_token(
        self,
        user_id: str,
        name: str,
        permissions: Optional[List[str]] = None,
        expires_in_days: int = 30,
    ) -> Tuple[Optional[APIToken], str]:
        """创建API令牌"""
        user = self.users.get(user_id)
        if not user:
            return None, ""

        token = secrets.token_hex(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        token_id = f"token_{uuid.uuid4().hex[:12]}"
        expires_at = (datetime.now() + timedelta(days=expires_in_days)).strftime("%Y-%m-%d %H:%M:%S")

        api_token = APIToken(
            id=token_id,
            name=name,
            token_hash=token_hash,
            user_id=user_id,
            tenant_id=user.tenant_id,
            permissions=permissions or user.permissions,
            expires_at=expires_at,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        self.api_tokens[token_id] = api_token
        return api_token, token

    def validate_api_token(self, token: str) -> Tuple[bool, Optional[User], Optional[APIToken]]:
        """验证API令牌"""
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        for api_token in self.api_tokens.values():
            if api_token.token_hash == token_hash:
                if api_token.status != "active":
                    return False, None, None

                # 检查是否过期
                expires_at = datetime.strptime(api_token.expires_at, "%Y-%m-%d %H:%M:%S")
                if datetime.now() > expires_at:
                    api_token.status = "expired"
                    return False, None, None

                api_token.last_used_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                user = self.users.get(api_token.user_id)
                return True, user, api_token

        return False, None, None

    def revoke_api_token(self, token_id: str, revoked_by: str = "") -> bool:
        """撤销API令牌"""
        api_token = self.api_tokens.get(token_id)
        if not api_token:
            return False

        api_token.status = "revoked"
        api_token.revoked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        api_token.revoked_by = revoked_by
        return True

    def list_api_tokens(self, user_id: str = "") -> List[APIToken]:
        """列出API令牌"""
        if user_id:
            return [t for t in self.api_tokens.values() if t.user_id == user_id]
        return list(self.api_tokens.values())

    # ==================== 审计日志 ====================

    def _log_audit(
        self,
        user_id: str,
        username: str,
        tenant_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        resource_name: str,
        ip_address: str,
        user_agent: str,
        status: str,
        details: Optional[Dict] = None,
        risk_level: str = "low",
        session_id: str = "",
    ):
        """记录审计日志"""
        if not self.enterprise_config.audit_log_enabled:
            return

        audit_log = AuditLog(
            id=f"audit_{uuid.uuid4().hex[:16]}",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            user_id=user_id,
            username=username,
            tenant_id=tenant_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            details=details or {},
            risk_level=risk_level,
            session_id=session_id,
        )

        self.audit_logs.append(audit_log)

        # 高风险操作告警
        if risk_level in ["high", "critical"] and self.enterprise_config.audit_log_alert_enabled:
            logger.warning(f"高风险审计事件: {action} - {username} - {resource_name}")

    def query_audit_logs(
        self,
        user_id: str = "",
        action: str = "",
        resource_type: str = "",
        status: str = "",
        risk_level: str = "",
        start_time: str = "",
        end_time: str = "",
        limit: int = 100,
    ) -> List[AuditLog]:
        """查询审计日志"""
        results = self.audit_logs

        if user_id:
            results = [log for log in results if log.user_id == user_id]
        if action:
            results = [log for log in results if action in log.action]
        if resource_type:
            results = [log for log in results if log.resource_type == resource_type]
        if status:
            results = [log for log in results if log.status == status]
        if risk_level:
            results = [log for log in results if log.risk_level == risk_level]
        if start_time:
            results = [log for log in results if log.timestamp >= start_time]
        if end_time:
            results = [log for log in results if log.timestamp <= end_time]

        return results[-limit:]

    def get_audit_statistics(self) -> Dict:
        """获取审计统计"""
        total = len(self.audit_logs)
        success = len([log for log in self.audit_logs if log.status == "success"])
        failure = len([log for log in self.audit_logs if log.status == "failure"])
        denied = len([log for log in self.audit_logs if log.status == "denied"])
        high_risk = len([log for log in self.audit_logs if log.risk_level in ["high", "critical"]])

        # 按操作类型统计
        action_stats = {}
        for log in self.audit_logs:
            action_stats[log.action] = action_stats.get(log.action, 0) + 1

        return {
            "total": total,
            "success": success,
            "failure": failure,
            "denied": denied,
            "high_risk_events": high_risk,
            "success_rate": success / total if total > 0 else 0,
            "action_statistics": action_stats,
        }

    # ==================== SSO配置 ====================

    def configure_sso(
        self,
        provider: str,
        config: Dict,
        enabled: bool = True,
    ) -> bool:
        """配置SSO"""
        if provider not in ["saml", "oidc", "ldap"]:
            return False

        self.enterprise_config.sso_enabled = enabled
        self.enterprise_config.sso_provider = provider
        self.enterprise_config.sso_config = config
        return True

    def get_sso_config(self) -> Dict:
        """获取SSO配置"""
        return {
            "enabled": self.enterprise_config.sso_enabled,
            "provider": self.enterprise_config.sso_provider,
            "config": self.enterprise_config.sso_config,
        }

    def authenticate_with_sso(self, sso_token: str) -> Tuple[bool, Optional[User], str]:
        """SSO认证（简化版）"""
        # 实际需要根据SAML/OIDC/LDAP协议进行验证
        # 这里只是模拟
        if not self.enterprise_config.sso_enabled:
            return False, None, "SSO未启用"

        # 模拟SSO验证
        # 实际实现需要解析SAML断言/OIDC令牌/LDAP绑定
        return False, None, "SSO认证需要实际配置"

    # ==================== 企业配置 ====================

    def update_enterprise_config(self, **kwargs) -> EnterpriseConfig:
        """更新企业配置"""
        for key, value in kwargs.items():
            if hasattr(self.enterprise_config, key):
                setattr(self.enterprise_config, key, value)
        return self.enterprise_config

    def get_enterprise_config(self) -> Dict:
        """获取企业配置"""
        return asdict(self.enterprise_config)

    # ==================== 数据导出 ====================

    def export_audit_logs(self, output_path: str, filters: Optional[Dict] = None) -> str:
        """导出审计日志"""
        logs = self.query_audit_logs(**(filters or {}))
        data = [asdict(log) for log in logs]

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        return output_path

    def export_users(self, output_path: str) -> str:
        """导出用户列表"""
        users = []
        for user in self.users.values():
            user_data = asdict(user)
            # 移除敏感信息
            user_data.pop("password_hash", None)
            user_data.pop("password_salt", None)
            user_data.pop("two_factor_secret", None)
            users.append(user_data)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(users, f, ensure_ascii=False, indent=2)

        return output_path

    def generate_enterprise_report(self, output_path: str) -> str:
        """生成企业级管理报告"""
        report = {
            "title": "企业级安全管理报告",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_tenants": len(self.tenants),
                "total_users": len(self.users),
                "active_users": len([u for u in self.users.values() if u.status == "active"]),
                "total_roles": len(self.roles),
                "total_api_tokens": len(self.api_tokens),
                "active_sessions": len([s for s in self.sessions.values() if s.is_active]),
                "total_audit_logs": len(self.audit_logs),
            },
            "audit_statistics": self.get_audit_statistics(),
            "enterprise_config": self.get_enterprise_config(),
            "tenant_list": [asdict(t) for t in self.tenants.values()],
            "role_list": [asdict(r) for r in self.roles.values()],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        logger.info(f"企业级管理报告已生成: {output_path}")
        return output_path


# 便捷函数
def create_enterprise_manager() -> EnterpriseManager:
    """创建企业级管理器"""
    return EnterpriseManager()


def init_enterprise_system() -> EnterpriseManager:
    """初始化企业级系统"""
    manager = EnterpriseManager()

    # 创建默认管理员
    try:
        admin = manager.create_user(
            username="admin",
            email="admin@example.com",
            password=os.environ.get("DEFAULT_ADMIN_PASSWORD", "Admin@123456"),
            full_name="系统管理员",
            role=Role.SUPER_ADMIN.value,
            tenant_id="default",
        )
        admin.must_change_password = True
        logger.info("默认管理员创建成功: admin / Admin@123456")
    except Exception as e:
        logger.warning(f"默认管理员创建失败: {e}")

    return manager


if __name__ == "__main__":
    # 测试
    print("=== 企业级管理模块 ===")
    print()

    manager = init_enterprise_system()

    # 租户统计
    print(f"租户数量: {len(manager.tenants)}")
    print(f"用户数量: {len(manager.users)}")
    print(f"角色数量: {len(manager.roles)}")
    print()

    # 列出角色
    print("系统角色:")
    for role in manager.list_roles():
        print(f"  - {role.name} ({role.id}): {len(role.permissions)}个权限")
    print()

    # 创建测试用户
    try:
        user = manager.create_user(
            username="testuser",
            email="test@example.com",
            password=os.environ.get("DEFAULT_TEST_PASSWORD", "Test@123456"),
            full_name="测试用户",
            role=Role.SECURITY_ANALYST.value,
        )
        print(f"创建测试用户: {user.username} ({user.id})")
        print(f"角色: {user.role}")
        print(f"权限数量: {len(user.permissions)}")
    except Exception as e:
        print(f"创建测试用户失败: {e}")
    print()

    # 认证测试
    success, user, session_id = manager.authenticate_user(
        "admin", "Admin@123456",
        ip_address="127.0.0.1",
        user_agent="TestAgent",
    )
    print(f"管理员认证: {'成功' if success else '失败'}")
    if success:
        print(f"会话ID: {session_id[:16]}...")
    print()

    # 审计统计
    stats = manager.get_audit_statistics()
    print(f"审计日志统计:")
    print(f"  总数: {stats['total']}")
    print(f"  成功: {stats['success']}")
    print(f"  失败: {stats['failure']}")
    print(f"  高风险事件: {stats['high_risk_events']}")
    print()

    # 企业配置
    config = manager.get_enterprise_config()
    print(f"企业配置:")
    print(f"  密码最小长度: {config['password_min_length']}")
    print(f"  会话超时: {config['session_timeout']}分钟")
    print(f"  审计日志: {'启用' if config['audit_log_enabled'] else '禁用'}")
    print(f"  SSO: {'启用' if config['sso_enabled'] else '禁用'}")
