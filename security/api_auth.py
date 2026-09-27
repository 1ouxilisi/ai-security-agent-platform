"""
api_auth模块，提供相关安全测试功能。

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
import hashlib
import secrets
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict, deque
from utils.logger import log


@dataclass
class APIKey:
    """API密钥"""
    key: str
    name: str
    created_at: float
    expires_at: Optional[float] = None
    rate_limit: int = 100  # 每分钟请求数
    daily_limit: int = 10000  # 每日请求数
    enabled: bool = True
    permissions: List[str] = field(default_factory=lambda: ["*"])  # 允许的端点
    ip_whitelist: List[str] = field(default_factory=list)
    usage_today: int = 0
    last_used: Optional[float] = None


@dataclass
class RateLimitState:
    """限流状态"""
    requests: deque = field(default_factory=deque)  # 滑动窗口请求时间戳
    token_bucket: float = 0.0  # 令牌桶当前令牌数
    last_refill: float = field(default_factory=time.time)


class APISecurityManager:
    """API安全管理器"""

    def __init__(self):
        """初始化APISecurityManager实例。

        Args:
            self: 类实例。
        """
        self.api_keys: Dict[str, APIKey] = {}
        self.rate_limits: Dict[str, RateLimitState] = defaultdict(RateLimitState)
        self.ip_blacklist: Set[str] = set()
        self.audit_log: List[Dict] = []
        self._default_rate_limit = 100  # 每分钟
        self._window_size = 60  # 滑动窗口大小（秒）
        log.info("API安全管理器初始化")

    def generate_api_key(self, name: str, rate_limit: int = 100,
                         daily_limit: int = 10000, expires_days: Optional[int] = None,
                         permissions: Optional[List[str]] = None,
                         ip_whitelist: Optional[List[str]] = None) -> str:
        """生成API密钥"""
        # 生成安全的API密钥
        raw_key = secrets.token_hex(32)
        api_key = f"aha-{raw_key[:16]}{hashlib.sha256(raw_key.encode()).hexdigest()[:16]}"

        expires_at = None
        if expires_days:
            expires_at = time.time() + expires_days * 86400

        key_obj = APIKey(
            key=api_key,
            name=name,
            created_at=time.time(),
            expires_at=expires_at,
            rate_limit=rate_limit,
            daily_limit=daily_limit,
            permissions=permissions or ["*"],
            ip_whitelist=ip_whitelist or [],
        )

        self.api_keys[api_key] = key_obj
        log.info(f"API密钥已生成: {name} ({api_key[:12]}...)")
        return api_key

    def validate_api_key(self, api_key: str, client_ip: str = "", endpoint: str = "") -> tuple[bool, str]:
        """
        验证API密钥
        返回: (是否有效, 错误信息)
        """
        # 检查IP黑名单
        if client_ip in self.ip_blacklist:
            return False, "IP地址已被封禁"

        # 检查密钥是否存在
        if api_key not in self.api_keys:
            return False, "无效的API密钥"

        key_obj = self.api_keys[api_key]

        # 检查是否启用
        if not key_obj.enabled:
            return False, "API密钥已被禁用"

        # 检查是否过期
        if key_obj.expires_at and time.time() > key_obj.expires_at:
            return False, "API密钥已过期"

        # 检查IP白名单
        if key_obj.ip_whitelist and client_ip not in key_obj.ip_whitelist:
            return False, "IP地址不在白名单中"

        # 检查权限
        if "*" not in key_obj.permissions and endpoint not in key_obj.permissions:
            return False, "无权限访问该端点"

        # 检查每日限额
        today_start = time.time() - (time.time() % 86400)
        if key_obj.last_used and key_obj.last_used < today_start:
            key_obj.usage_today = 0  # 重置每日计数
        if key_obj.usage_today >= key_obj.daily_limit:
            return False, "已超出每日请求限额"

        # 检查限流
        if not self._check_rate_limit(api_key, key_obj.rate_limit):
            return False, "请求过于频繁，请稍后再试"

        # 更新使用统计
        key_obj.usage_today += 1
        key_obj.last_used = time.time()

        # 记录审计日志
        self._add_audit_log(api_key, client_ip, endpoint, "success")

        return True, ""

    def _check_rate_limit(self, api_key: str, limit: int) -> bool:
        """检查限流（滑动窗口算法）"""
        state = self.rate_limits[api_key]
        now = time.time()

        # 清理过期的请求记录
        while state.requests and now - state.requests[0] > self._window_size:
            state.requests.popleft()

        # 检查是否超限
        if len(state.requests) >= limit:
            return False

        # 记录当前请求
        state.requests.append(now)
        return True

    def _add_audit_log(self, api_key: str, client_ip: str, endpoint: str, status: str):
        """添加审计日志"""
        self.audit_log.append({
            "timestamp": time.time(),
            "api_key": api_key[:12] + "..." if len(api_key) > 12 else api_key,
            "client_ip": client_ip,
            "endpoint": endpoint,
            "status": status,
        })
        # 只保留最近10000条
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-10000:]

    def revoke_api_key(self, api_key: str) -> bool:
        """撤销API密钥"""
        if api_key in self.api_keys:
            self.api_keys[api_key].enabled = False
            log.info(f"API密钥已撤销: {api_key[:12]}...")
            return True
        return False

    def block_ip(self, ip: str):
        """封禁IP"""
        self.ip_blacklist.add(ip)
        log.info(f"IP已封禁: {ip}")

    def unblock_ip(self, ip: str):
        """解封IP"""
        self.ip_blacklist.discard(ip)
        log.info(f"IP已解封: {ip}")

    def get_api_key_info(self, api_key: str) -> Optional[Dict]:
        """获取API密钥信息"""
        if api_key not in self.api_keys:
            return None
        key = self.api_keys[api_key]
        return {
            "name": key.name,
            "created_at": key.created_at,
            "expires_at": key.expires_at,
            "rate_limit": key.rate_limit,
            "daily_limit": key.daily_limit,
            "enabled": key.enabled,
            "permissions": key.permissions,
            "usage_today": key.usage_today,
            "last_used": key.last_used,
        }

    def get_usage_stats(self) -> Dict:
        """获取使用统计"""
        total_requests = sum(k.usage_today for k in self.api_keys.values())
        active_keys = sum(1 for k in self.api_keys.values() if k.enabled)
        return {
            "total_api_keys": len(self.api_keys),
            "active_keys": active_keys,
            "total_requests_today": total_requests,
            "blocked_ips": len(self.ip_blacklist),
            "audit_log_entries": len(self.audit_log),
        }

    def list_api_keys(self) -> List[Dict]:
        """列出所有API密钥"""
        return [
            {
                "key": k.key[:12] + "...",
                "name": k.name,
                "enabled": k.enabled,
                "usage_today": k.usage_today,
                "rate_limit": k.rate_limit,
            }
            for k in self.api_keys.values()
        ]


# 全局API安全管理器实例
api_security = APISecurityManager()
