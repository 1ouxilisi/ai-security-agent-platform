"""
auth企业级功能模块，提供相关企业级安全管理和认证功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import time
import hmac
import hashlib
import base64
import json
import secrets
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from utils.logger import log


class Role(Enum):
    """用户角色"""
    ADMIN = "admin"  # 超级管理员，全部权限
    AUDITOR = "auditor"  # 审计员，只读+报告
    OPERATOR = "operator"  # 操作员，可执行任务
    VIEWER = "viewer"  # 只读用户


# 角色权限映射
ROLE_PERMISSIONS = {
    Role.ADMIN: {"*"},  # 全部权限
    Role.AUDITOR: {"task:read", "report:read", "report:export", "system:read", "log:read"},
    Role.OPERATOR: {"task:read", "task:create", "task:execute", "tool:read", "tool:execute",
                     "report:read", "system:read"},
    Role.VIEWER: {"task:read", "tool:read", "report:read", "system:read"},
}


@dataclass
class User:
    """用户"""
    user_id: str
    username: str
    email: str
    password_hash: str
    role: Role = Role.VIEWER
    tenant_id: str = "default"
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    last_login: Optional[float] = None
    api_keys: List[str] = field(default_factory=list)
    permissions: Set[str] = field(default_factory=set)  # 额外权限


@dataclass
class Tenant:
    """租户"""
    tenant_id: str
    name: str
    plan: str = "free"  # free/pro/enterprise
    max_users: int = 5
    max_tasks: int = 100
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    settings: Dict[str, Any] = field(default_factory=dict)


@dataclass
class JWTPayload:
    """JWT载荷"""
    sub: str  # 用户ID
    username: str
    role: str
    tenant_id: str
    exp: float  # 过期时间
    iat: float  # 签发时间
    jti: str  # 令牌ID
    permissions: List[str] = field(default_factory=list)


class EnterpriseAuth:
    """企业级认证管理器"""

    def __init__(self, secret_key: str = None, token_expiry: int = 3600):
        """初始化EnterpriseAuth实例。

        Args:
            self: 类实例。
        """
        self.secret_key = secret_key or secrets.token_hex(32)
        self.token_expiry = token_expiry  # JWT过期时间（秒）
        self.users: Dict[str, User] = {}
        self.tenants: Dict[str, Tenant] = {}
        self.revoked_tokens: Set[str] = set()  # 已撤销的令牌ID
        self._init_default_tenant()
        self._init_default_admin()
        log.info(f"企业级认证系统初始化，令牌过期: {token_expiry}s")

    def _init_default_tenant(self):
        """初始化默认租户"""
        tenant = Tenant(tenant_id="default", name="Default Organization", plan="enterprise", max_users=100, max_tasks=10000)
        self.tenants["default"] = tenant

    def _init_default_admin(self):
        """初始化默认管理员"""
        admin = User(
            user_id="admin", username="admin", email="admin@localhost",
            password_hash=self._hash_password("admin123"),
            role=Role.ADMIN, tenant_id="default",
        )
        self.users["admin"] = admin
        log.info("默认管理员已创建: admin/admin123 (生产环境请立即修改密码)")

    def _hash_password(self, password: str) -> str:
        """密码哈希（PBKDF2）"""
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
        return f"{salt}${base64.b64encode(dk).decode()}"

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """验证密码"""
        try:
            salt, hash_val = password_hash.split("$", 1)
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
            return hmac.compare_digest(base64.b64encode(dk).decode(), hash_val)
        except Exception:
            return False

    def _base64url_encode(self, data: bytes) -> str:
        """Base64URL编码"""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _base64url_decode(self, data: str) -> bytes:
        """Base64URL解码"""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    def create_jwt(self, user: User) -> str:
        """创建JWT令牌"""
        now = time.time()
        payload = JWTPayload(
            sub=user.user_id, username=user.username, role=user.role.value,
            tenant_id=user.tenant_id, exp=now + self.token_expiry, iat=now,
            jti=secrets.token_hex(16),
            permissions=list(self.get_user_permissions(user)),
        )

        # 编码Header和Payload
        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = self._base64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = self._base64url_encode(json.dumps(payload.__dict__, separators=(",", ":")).encode())

        # 签名
        signing_input = f"{header_b64}.{payload_b64}"
        signature = hmac.new(self.secret_key.encode(), signing_input.encode(), hashlib.sha256).digest()
        signature_b64 = self._base64url_encode(signature)

        token = f"{header_b64}.{payload_b64}.{signature_b64}"
        log.debug(f"JWT已创建: {user.username}, 过期: {self.token_expiry}s")
        return token

    def verify_jwt(self, token: str) -> Optional[JWTPayload]:
        """验证JWT令牌"""
        try:
            header_b64, payload_b64, signature_b64 = token.split(".")

            # 验证签名
            signing_input = f"{header_b64}.{payload_b64}"
            expected_signature = hmac.new(self.secret_key.encode(), signing_input.encode(), hashlib.sha256).digest()
            actual_signature = self._base64url_decode(signature_b64)
            if not hmac.compare_digest(expected_signature, actual_signature):
                log.warning("JWT签名验证失败")
                return None

            # 解码载荷
            payload_data = json.loads(self._base64url_decode(payload_b64))
            payload = JWTPayload(**payload_data)

            # 检查过期
            if time.time() > payload.exp:
                log.warning(f"JWT已过期: {payload.sub}")
                return None

            # 检查是否已撤销
            if payload.jti in self.revoked_tokens:
                log.warning(f"JWT已撤销: {payload.jti}")
                return None

            return payload

        except Exception as e:
            log.error(f"JWT验证错误: {e}")
            return None

    def revoke_token(self, jti: str):
        """撤销令牌"""
        self.revoked_tokens.add(jti)
        log.info(f"JWT已撤销: {jti}")

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """用户认证，返回JWT令牌"""
        user = self.users.get(username)
        if not user or not user.enabled:
            log.warning(f"认证失败: 用户不存在或已禁用 - {username}")
            return None

        if not self._verify_password(password, user.password_hash):
            log.warning(f"认证失败: 密码错误 - {username}")
            return None

        user.last_login = time.time()
        token = self.create_jwt(user)
        log.info(f"用户认证成功: {username}")
        return token

    def create_user(self, username: str, password: str, email: str,
                    role: Role = Role.VIEWER, tenant_id: str = "default") -> Optional[str]:
        """创建用户"""
        if username in self.users:
            log.warning(f"用户已存在: {username}")
            return None

        user = User(
            user_id=username, username=username, email=email,
            password_hash=self._hash_password(password),
            role=role, tenant_id=tenant_id,
        )
        self.users[username] = user
        log.info(f"用户已创建: {username} (角色: {role.value})")
        return username

    def get_user_permissions(self, user: User) -> Set[str]:
        """获取用户权限（角色权限 + 额外权限）"""
        permissions = set(ROLE_PERMISSIONS.get(user.role, set()))
        permissions.update(user.permissions)
        return permissions

    def check_permission(self, user: User, permission: str) -> bool:
        """检查用户权限"""
        permissions = self.get_user_permissions(user)
        return "*" in permissions or permission in permissions

    def create_api_key(self, user: User, name: str, permissions: List[str] = None) -> str:
        """创建API密钥"""
        api_key = f"aha-{secrets.token_hex(24)}"
        user.api_keys.append(api_key)
        log.info(f"API密钥已创建: {name} for {user.username}")
        return api_key

    def create_tenant(self, name: str, plan: str = "pro", max_users: int = 20) -> str:
        """创建租户"""
        tenant_id = f"tenant-{secrets.token_hex(6)}"
        tenant = Tenant(tenant_id=tenant_id, name=name, plan=plan, max_users=max_users)
        self.tenants[tenant_id] = tenant
        log.info(f"租户已创建: {name} ({tenant_id})")
        return tenant_id

    def get_stats(self) -> Dict:
        """获取认证系统统计"""
        return {
            "total_users": len(self.users),
            "active_users": sum(1 for u in self.users.values() if u.enabled),
            "total_tenants": len(self.tenants),
            "revoked_tokens": len(self.revoked_tokens),
            "roles": {role.value: sum(1 for u in self.users.values() if u.role == role) for role in Role},
        }


# 权限装饰器
def require_permission(permission: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 从kwargs或args中获取用户
            user = kwargs.get("user") or (args[0] if args else None)
            if not user or not isinstance(user, User):
                raise PermissionError("未认证用户")
            if not enterprise_auth.check_permission(user, permission):
                raise PermissionError(f"权限不足: 需要 {permission}")
            return func(*args, **kwargs)
        return wrapper
    return decorator


# 全局企业级认证实例
enterprise_auth = EnterpriseAuth()
