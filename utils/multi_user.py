"""多用户基础框架模块。

包含：用户管理、角色权限、会话管理、API密钥管理、
操作审计、多租户支持等多用户系统基础功能。
"""
import os
import json
import time
import hashlib
import secrets
import threading
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from utils.logger import log


# ============== 数据模型 ==============

@dataclass
class Role:
    """角色"""
    name: str
    description: str = ""
    permissions: List[str] = field(default_factory=list)
    is_system: bool = False


@dataclass
class User:
    """用户"""
    username: str
    email: str = ""
    password_hash: str = ""
    salt: str = ""
    role: str = "user"
    api_keys: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_login: float = 0
    is_active: bool = True
    is_locked: bool = False
    failed_login_attempts: int = 0
    tenant_id: str = "default"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Session:
    """会话"""
    session_id: str
    username: str
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0
    ip_address: str = ""
    user_agent: str = ""
    is_active: bool = True


@dataclass
class APIKey:
    """API密钥"""
    key_id: str
    key_hash: str
    username: str
    name: str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0
    last_used: float = 0
    is_active: bool = True
    permissions: List[str] = field(default_factory=list)
    rate_limit: int = 100  # 每分钟请求数


@dataclass
class AuditLog:
    """审计日志"""
    log_id: str
    timestamp: float = field(default_factory=time.time)
    username: str = ""
    action: str = ""
    resource: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: str = ""
    success: bool = True


@dataclass
class Tenant:
    """租户"""
    tenant_id: str
    name: str
    description: str = ""
    created_at: float = field(default_factory=time.time)
    is_active: bool = True
    max_users: int = 100
    max_api_keys: int = 10
    settings: Dict[str, Any] = field(default_factory=dict)


# ============== 权限常量 ==============

PERMISSIONS = {
    # 扫描相关
    "scan:read": "查看扫描结果",
    "scan:create": "创建扫描任务",
    "scan:delete": "删除扫描任务",
    "scan:export": "导出扫描报告",
    
    # 漏洞管理
    "vuln:read": "查看漏洞",
    "vuln:update": "更新漏洞状态",
    "vuln:assign": "分配漏洞",
    "vuln:delete": "删除漏洞",
    
    # 工具使用
    "tool:use": "使用安全工具",
    "tool:admin": "管理工具配置",
    
    # 报告
    "report:read": "查看报告",
    "report:create": "生成报告",
    "report:export": "导出报告",
    
    # 管理
    "admin:users": "管理用户",
    "admin:roles": "管理角色",
    "admin:settings": "系统设置",
    "admin:audit": "查看审计日志",
    "admin:tenants": "管理租户",
    
    # API
    "api:use": "使用API",
    "api:admin": "管理API密钥",

    # 租户管理员
    "tenant:admin": "管理本租户",
    "tenant:users": "管理本租户用户",
    "tenant:config": "管理本租户配置",
    "tenant:quota": "查看/调整本租户配额",
    "tenant:billing": "查看本租户计费",
}

# 预设角色
DEFAULT_ROLES = {
    "admin": Role(
        name="admin",
        description="系统管理员，拥有所有权限",
        permissions=list(PERMISSIONS.keys()),
        is_system=True
    ),
    "security_analyst": Role(
        name="security_analyst",
        description="安全分析师，可进行扫描和查看结果",
        permissions=["scan:read", "scan:create", "scan:export", 
                    "vuln:read", "vuln:update", "tool:use",
                    "report:read", "report:create", "report:export", "api:use"],
        is_system=True
    ),
    "auditor": Role(
        name="auditor",
        description="审计员，只读权限",
        permissions=["scan:read", "vuln:read", "report:read", "report:export"],
        is_system=True
    ),
    "user": Role(
        name="user",
        description="普通用户，基础权限",
        permissions=["scan:read", "vuln:read", "report:read", "api:use"],
        is_system=True
    ),
    "tenant_admin": Role(
        name="tenant_admin",
        description="租户管理员，管理本租户用户/配置/查看审计",
        permissions=["scan:read", "scan:create", "scan:export",
                    "vuln:read", "vuln:update", "tool:use",
                    "report:read", "report:create", "report:export", "api:use",
                    "tenant:admin", "tenant:users", "tenant:config",
                    "tenant:quota", "tenant:billing", "admin:audit"],
        is_system=True
    ),
    "read_only": Role(
        name="read_only",
        description="只读用户，仅查看结果和报告",
        permissions=["scan:read", "vuln:read", "report:read", "report:export"],
        is_system=True
    ),
}


# ============== 用户管理器 ==============

class UserManager:
    """用户管理器"""

    # 并发会话限制（可配置）
    MAX_CONCURRENT_SESSIONS = 3
    # 会话默认有效期（秒），24 小时
    SESSION_TTL = 86400

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.users_file = os.path.join(data_dir, "users.json")
        self.sessions_file = os.path.join(data_dir, "sessions.json")
        self.api_keys_file = os.path.join(data_dir, "api_keys.json")
        self.audit_log_file = os.path.join(data_dir, "audit_log.json")
        self.tenants_file = os.path.join(data_dir, "tenants.json")
        
        self._users: Dict[str, User] = {}
        self._sessions: Dict[str, Session] = {}
        self._api_keys: Dict[str, APIKey] = {}
        self._audit_logs: List[AuditLog] = []
        self._tenants: Dict[str, Tenant] = {}
        self._roles: Dict[str, Role] = dict(DEFAULT_ROLES)
        
        self._lock = threading.Lock()
        
        # 确保数据目录存在
        os.makedirs(data_dir, exist_ok=True)
        
        # 加载数据
        self._load_all()
        
        # 初始化默认管理员
        self._init_default_admin()
    
    def _load_all(self):
        """加载所有数据"""
        self._users = self._load_json(self.users_file, User)
        self._sessions = self._load_json(self.sessions_file, Session)
        self._api_keys = self._load_json(self.api_keys_file, APIKey)
        self._audit_logs = self._load_json_list(self.audit_log_file, AuditLog)
        self._tenants = self._load_json(self.tenants_file, Tenant)
    
    def _load_json(self, filepath: str, cls) -> Dict:
        """加载JSON文件为字典"""
        if not os.path.exists(filepath):
            return {}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            result = {}
            # 处理字典格式
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        result[key] = cls(**value)
            # 处理列表格式（转换为字典，使用第一个字符串字段作为key）
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        # 尝试使用常见的ID字段作为key
                        key = item.get('username') or item.get('session_id') or item.get('key_id') or item.get('tenant_id') or str(len(result))
                        result[key] = cls(**item)
            return result
        except Exception as e:
            log.warning(f"加载 {filepath} 失败: {e}")
            return {}
    
    def _load_json_list(self, filepath: str, cls) -> List:
        """加载JSON文件为列表"""
        if not os.path.exists(filepath):
            return []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [cls(**item) for item in data if isinstance(item, dict)]
        except Exception as e:
            log.warning(f"加载 {filepath} 失败: {e}")
            return []
    
    def _save_all(self):
        """保存所有数据"""
        self._save_json(self.users_file, self._users)
        self._save_json(self.sessions_file, self._sessions)
        self._save_json(self.api_keys_file, self._api_keys)
        self._save_json_list(self.audit_log_file, self._audit_logs)
        self._save_json(self.tenants_file, self._tenants)
    
    def _save_json(self, filepath: str, data: Dict):
        """保存字典为JSON"""
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump({k: asdict(v) for k, v in data.items()}, f, 
                         ensure_ascii=False, indent=2)
        except Exception as e:
            log.warning(f"保存 {filepath} 失败: {e}")
    
    def _save_json_list(self, filepath: str, data: List):
        """保存列表为JSON"""
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump([asdict(item) for item in data], f, 
                         ensure_ascii=False, indent=2)
        except Exception as e:
            log.warning(f"保存 {filepath} 失败: {e}")
    
    def _init_default_admin(self):
        """初始化默认管理员"""
        if "admin" not in self._users:
            admin = User(
                username="admin",
                email="admin@localhost",
                role="admin",
                is_active=True
            )
            # 默认密码 admin123（首次登录后应修改）
            admin.salt = secrets.token_hex(16)
            admin.password_hash = self._hash_password("admin123", admin.salt)
            self._users["admin"] = admin
            self._save_all()
            log.info("默认管理员已创建 (admin/admin123)，请尽快修改密码")
    
    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        """哈希密码"""
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 100000
        ).hex()
    
    # ============== 用户管理 ==============
    
    def create_user(self, username: str, password: str, email: str = "", 
                    role: str = "user", tenant_id: str = "default") -> Optional[User]:
        """创建用户"""
        with self._lock:
            if username in self._users:
                log.warning(f"用户 {username} 已存在")
                return None
            
            if role not in self._roles:
                log.warning(f"角色 {role} 不存在")
                return None
            
            salt = secrets.token_hex(16)
            user = User(
                username=username,
                email=email,
                password_hash=self._hash_password(password, salt),
                salt=salt,
                role=role,
                tenant_id=tenant_id
            )
            self._users[username] = user
            self._save_all()
            self._add_audit_log(username, "user:create", username, {"role": role})
            log.info(f"用户 {username} 已创建")
            return user
    
    def authenticate(self, username: str, password: str, ip_address: str = "", 
                     user_agent: str = "") -> Optional[Session]:
        """用户认证"""
        with self._lock:
            user = self._users.get(username)
            if not user:
                return None
            
            if not user.is_active or user.is_locked:
                log.warning(f"用户 {username} 被禁用或锁定")
                return None
            
            # 验证密码
            password_hash = self._hash_password(password, user.salt)
            if password_hash != user.password_hash:
                user.failed_login_attempts += 1
                # 5次失败后锁定
                if user.failed_login_attempts >= 5:
                    user.is_locked = True
                    log.warning(f"用户 {username} 因多次登录失败被锁定")
                self._save_all()
                return None
            
            # 登录成功
            user.failed_login_attempts = 0
            user.last_login = time.time()
            
            # 创建会话
            session_id = secrets.token_hex(32)
            session = Session(
                session_id=session_id,
                username=username,
                expires_at=time.time() + 86400,  # 24小时
                ip_address=ip_address,
                user_agent=user_agent
            )
            self._sessions[session_id] = session
            self._save_all()
            
            self._add_audit_log(username, "auth:login", username, {"ip": ip_address})
            log.info(f"用户 {username} 登录成功")
            return session
    
    def logout(self, session_id: str):
        """用户登出"""
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session:
                session.is_active = False
                self._add_audit_log(session.username, "auth:logout", session.username)
            self._save_all()
    
    def get_user(self, username: str) -> Optional[User]:
        """获取用户"""
        return self._users.get(username)
    
    def list_users(self, tenant_id: str = None) -> List[User]:
        """列出用户"""
        users = list(self._users.values())
        if tenant_id:
            users = [u for u in users if u.tenant_id == tenant_id]
        return users
    
    def update_user(self, username: str, **kwargs) -> Optional[User]:
        """更新用户"""
        with self._lock:
            user = self._users.get(username)
            if not user:
                return None
            
            for key, value in kwargs.items():
                if hasattr(user, key) and key not in ["username", "password_hash", "salt"]:
                    setattr(user, key, value)
            
            self._save_all()
            return user
    
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """修改密码"""
        with self._lock:
            user = self._users.get(username)
            if not user:
                return False
            
            old_hash = self._hash_password(old_password, user.salt)
            if old_hash != user.password_hash:
                return False
            
            user.salt = secrets.token_hex(16)
            user.password_hash = self._hash_password(new_password, user.salt)
            self._save_all()
            self._add_audit_log(username, "user:change_password", username)
            return True
    
    def delete_user(self, username: str) -> bool:
        """删除用户"""
        with self._lock:
            if username not in self._users:
                return False
            if username == "admin":
                log.warning("不能删除默认管理员")
                return False
            
            del self._users[username]
            # 删除相关会话和API密钥
            self._sessions = {k: v for k, v in self._sessions.items() if v.username != username}
            self._api_keys = {k: v for k, v in self._api_keys.items() if v.username != username}
            self._save_all()
            self._add_audit_log("system", "user:delete", username)
            return True
    
    # ============== 会话管理 ==============
    
    def validate_session(self, session_id: str) -> Optional[User]:
        """验证会话"""
        session = self._sessions.get(session_id)
        if not session or not session.is_active:
            return None
        
        if time.time() > session.expires_at:
            session.is_active = False
            self._save_all()
            return None
        
        return self._users.get(session.username)
    
    # ============== API密钥管理 ==============
    
    def create_api_key(self, username: str, name: str = "", 
                       permissions: List[str] = None, expires_days: int = 365) -> Optional[str]:
        """创建API密钥"""
        with self._lock:
            user = self._users.get(username)
            if not user:
                return None
            
            key_id = secrets.token_hex(8)
            api_key = f"sk-{secrets.token_hex(32)}"
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            api_key_obj = APIKey(
                key_id=key_id,
                key_hash=key_hash,
                username=username,
                name=name,
                expires_at=time.time() + expires_days * 86400,
                permissions=permissions or ["api:use"]
            )
            
            self._api_keys[key_id] = api_key_obj
            user.api_keys.append(key_id)
            self._save_all()
            self._add_audit_log(username, "api_key:create", key_id, {"name": name})
            
            return api_key  # 只返回一次明文
    
    def validate_api_key(self, api_key: str) -> Optional[APIKey]:
        """验证API密钥"""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        for key_obj in self._api_keys.values():
            if key_obj.key_hash == key_hash:
                if not key_obj.is_active:
                    return None
                if key_obj.expires_at and time.time() > key_obj.expires_at:
                    return None
                key_obj.last_used = time.time()
                return key_obj
        
        return None
    
    def revoke_api_key(self, username: str, key_id: str) -> bool:
        """撤销API密钥"""
        with self._lock:
            api_key = self._api_keys.get(key_id)
            if not api_key or api_key.username != username:
                return False
            
            api_key.is_active = False
            self._save_all()
            self._add_audit_log(username, "api_key:revoke", key_id)
            return True
    
    def list_api_keys(self, username: str) -> List[APIKey]:
        """列出用户的API密钥"""
        return [k for k in self._api_keys.values() if k.username == username]
    
    # ============== 权限检查 ==============
    
    def has_permission(self, username: str, permission: str,
                       tenant_id: str = None) -> bool:
        """检查用户权限。

        若传入 tenant_id，额外校验用户归属于该租户。
        """
        user = self._users.get(username)
        if not user:
            return False

        if tenant_id is not None and user.tenant_id != tenant_id:
            return False

        role = self._roles.get(user.role)
        if not role:
            return False

        return permission in role.permissions
    
    def get_user_permissions(self, username: str) -> List[str]:
        """获取用户权限列表"""
        user = self._users.get(username)
        if not user:
            return []
        
        role = self._roles.get(user.role)
        return role.permissions if role else []
    
    # ============== 角色管理 ==============
    
    def create_role(self, name: str, description: str = "", 
                    permissions: List[str] = None) -> Optional[Role]:
        """创建角色"""
        with self._lock:
            if name in self._roles:
                return None
            
            role = Role(name=name, description=description, 
                       permissions=permissions or [])
            self._roles[name] = role
            return role
    
    def list_roles(self) -> List[Role]:
        """列出角色"""
        return list(self._roles.values())
    
    # ============== 审计日志 ==============
    
    def _add_audit_log(self, username: str, action: str, resource: str, 
                       details: Dict = None, ip_address: str = "", success: bool = True):
        """添加审计日志"""
        log_entry = AuditLog(
            log_id=secrets.token_hex(8),
            username=username,
            action=action,
            resource=resource,
            details=details or {},
            ip_address=ip_address,
            success=success
        )
        self._audit_logs.append(log_entry)
        
        # 只保留最近10000条
        if len(self._audit_logs) > 10000:
            self._audit_logs = self._audit_logs[-10000:]
    
    def get_audit_logs(self, username: str = None, action: str = None,
                       limit: int = 100, tenant_id: str = None) -> List[AuditLog]:
        """获取审计日志。

        兼容旧签名(username/action)；新增 tenant_id 按租户过滤。
        """
        logs = self._audit_logs

        if tenant_id is not None:
            # 通过用户名反查其租户
            logs = [l for l in logs
                    if self._users.get(l.username)
                    and self._users[l.username].tenant_id == tenant_id]
        if username:
            logs = [l for l in logs if l.username == username]
        if action:
            logs = [l for l in logs if l.action == action]

        return logs[-limit:]

    # ============== 商业化扩展：登录/并发会话/审计 ==============

    def login(self, username: str, password: str, ip: str = "",
              user_agent: str = "") -> Optional[str]:
        """登录，返回 session_token。

        在 authenticate 基础上增加并发会话限制：超过
        ``MAX_CONCURRENT_SESSIONS`` 时踢掉该用户最旧的会话。
        """
        session = self.authenticate(username, password,
                                    ip_address=ip, user_agent=user_agent)
        if session is None:
            return None

        # 并发会话限制：只统计该用户的活跃会话
        user_sessions = sorted(
            [s for s in self._sessions.values()
             if s.username == username and s.is_active],
            key=lambda s: s.created_at)
        with self._lock:
            while len(user_sessions) > self.MAX_CONCURRENT_SESSIONS:
                oldest = user_sessions.pop(0)
                oldest.is_active = False
                self._sessions.pop(oldest.session_id, None)
                self._add_audit_log(
                    username, "auth:session_evicted", username,
                    {"reason": "max_concurrent_sessions"})
            self._save_all()
        return session.session_id

    def get_user_by_tenant(self, username: str,
                           tenant_id: str) -> Optional[User]:
        """按租户获取用户。"""
        u = self._users.get(username)
        if u and u.tenant_id == tenant_id:
            return u
        return None

    def log_audit(self, username: str, action: str, resource: str,
                  details: Dict = None, ip: str = "",
                  success: bool = True) -> None:
        """记录操作审计日志（公开接口）。"""
        self._add_audit_log(username, action, resource, details or {},
                            ip_address=ip, success=success)
        self._save_all()

    @staticmethod
    def require_permission(permission: str, tenant_id: str = None):
        """构造一个 FastAPI 依赖：校验当前会话用户是否具备某权限。

        用法::

            @router.get("/x", dependencies=[Depends(user_manager.require_permission("scan:read"))])
        """
        try:
            from fastapi import Depends, HTTPException, Request
        except Exception:  # pragma: no cover
            def _noop():
                return None
            return _noop

        def _dep(request: Request,
                 token: str = Depends(lambda: None)):
            # 从 Authorization: Bearer <token> 读取
            auth = request.headers.get("Authorization", "")
            token_str = ""
            if auth.startswith("Bearer "):
                token_str = auth[7:]
            user = user_manager.validate_session(token_str)
            if user is None:
                raise HTTPException(status_code=401, detail="未登录或会话过期")
            if not user_manager.has_permission(user.username, permission,
                                               tenant_id):
                raise HTTPException(status_code=403,
                                    detail=f"缺少权限: {permission}")
            return user
        return _dep
    
    # ============== 租户管理 ==============
    
    def create_tenant(self, tenant_id: str, name: str, 
                      description: str = "") -> Optional[Tenant]:
        """创建租户"""
        with self._lock:
            if tenant_id in self._tenants:
                return None
            
            tenant = Tenant(tenant_id=tenant_id, name=name, description=description)
            self._tenants[tenant_id] = tenant
            self._save_all()
            return tenant
    
    def get_stats(self) -> Dict[str, Any]:
        """获取系统统计"""
        return {
            "total_users": len(self._users),
            "active_users": sum(1 for u in self._users.values() if u.is_active),
            "total_sessions": len(self._sessions),
            "active_sessions": sum(1 for s in self._sessions.values() if s.is_active),
            "total_api_keys": len(self._api_keys),
            "active_api_keys": sum(1 for k in self._api_keys.values() if k.is_active),
            "total_roles": len(self._roles),
            "total_tenants": len(self._tenants),
            "total_audit_logs": len(self._audit_logs),
        }


# 全局用户管理器实例
user_manager = UserManager()
