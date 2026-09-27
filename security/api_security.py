# -*- coding: utf-8 -*-
"""
api_security模块，提供API安全防护功能。

模块功能：
    - API密钥认证（X-API-Key）
    - 请求签名验证（HMAC-SHA256，防重放）
    - 令牌桶速率限制
    - IP白名单/黑名单
    - 请求日志记录
    - 异常请求检测

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import json
import time
import hmac
import hashlib
import secrets
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

# 项目根目录
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
_CONFIG_DIR = os.path.join(_PROJECT_ROOT, "config")
_LOGS_DIR = os.path.join(_PROJECT_ROOT, "logs")


class APISecurity:
    """API安全防护类。

    提供API密钥认证、请求签名验证、速率限制、IP访问控制、
    请求日志和异常检测等功能。
    """

    # 时间戳有效期（秒）
    TIMESTAMP_TTL = 300  # 5分钟
    # nonce缓存大小
    NONCE_CACHE_SIZE = 1000
    # 默认速率限制
    DEFAULT_RATE_LIMIT = 100
    DEFAULT_RATE_WINDOW = 60

    def __init__(self):
        """初始化APISecurity实例。"""
        # 确保目录存在
        os.makedirs(_DATA_DIR, exist_ok=True)
        os.makedirs(_CONFIG_DIR, exist_ok=True)
        os.makedirs(_LOGS_DIR, exist_ok=True)

        # 加载API密钥
        self._api_keys: Dict[str, Dict[str, Any]] = {}
        self._load_api_keys()

        # 加载IP访问配置
        self._ip_config: Dict[str, Any] = {}
        self._load_ip_config()

        # nonce缓存（防重放）
        self._nonce_cache: deque = deque(maxlen=self.NONCE_CACHE_SIZE)
        self._nonce_set: Set[str] = set()

        # 令牌桶状态
        self._rate_buckets: Dict[str, Dict[str, Any]] = {}

        # 失败请求追踪（用于异常检测）
        self._recent_failures: deque = deque(maxlen=5000)

    # ------------------------------------------------------------------ #
    # 数据加载
    # ------------------------------------------------------------------ #
    def _load_api_keys(self):
        """从环境变量和data/api_keys.json加载API密钥。"""
        # 默认密钥
        default_key = os.environ.get("DEFAULT_API_KEY", "")
        if default_key:
            self._api_keys[default_key] = {
                "key": default_key,
                "user_id": "default",
                "scopes": ["*"],
                "secret": default_key,
                "created_at": time.time(),
                "expires_at": None,
            }

        # 用户创建的密钥
        keys_file = os.path.join(_DATA_DIR, "api_keys.json")
        if os.path.exists(keys_file):
            try:
                with open(keys_file, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                if isinstance(saved, dict):
                    for kid, info in saved.items():
                        if isinstance(info, dict):
                            self._api_keys[info.get("key", kid)] = info
            except (json.JSONDecodeError, IOError):
                pass

    def _load_ip_config(self):
        """加载IP访问配置，不存在则创建默认配置。"""
        config_file = os.path.join(_CONFIG_DIR, "ip_access.json")
        if os.path.exists(config_file):
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    self._ip_config = json.load(f)
                return
            except (json.JSONDecodeError, IOError):
                pass

        # 默认配置：白名单空=不限制，黑名单包含常见恶意IP
        self._ip_config = {
            "whitelist": [],
            "blacklist": [
                "0.0.0.0",
                "255.255.255.255",
                "10.255.255.1",
                "172.16.0.1",
            ],
        }
        try:
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(self._ip_config, f, indent=2, ensure_ascii=False)
        except IOError:
            pass

    # ------------------------------------------------------------------ #
    # API密钥认证
    # ------------------------------------------------------------------ #
    def verify_api_key(self, api_key: str) -> Dict[str, Any]:
        """验证API密钥。

        Args:
            api_key: X-API-Key请求头中的密钥。

        Returns:
            {"valid": bool, "user_id": str, "scopes": [...]}
        """
        if not api_key or not isinstance(api_key, str):
            return {"valid": False, "user_id": "", "scopes": []}

        key_info = self._api_keys.get(api_key)
        if not key_info:
            return {"valid": False, "user_id": "", "scopes": []}

        # 检查过期
        expires_at = key_info.get("expires_at")
        if expires_at and time.time() > expires_at:
            return {"valid": False, "user_id": "", "scopes": []}

        return {
            "valid": True,
            "user_id": key_info.get("user_id", "unknown"),
            "scopes": key_info.get("scopes", []),
        }

    # ------------------------------------------------------------------ #
    # 请求签名验证
    # ------------------------------------------------------------------ #
    def verify_request_signature(self, api_key: str, timestamp: str,
                                 nonce: str, signature: str,
                                 body: str = "") -> Dict[str, Any]:
        """验证HMAC-SHA256请求签名（防重放）。

        签名方法：HMAC-SHA256(secret, timestamp + nonce + body)
        时间戳有效期5分钟，nonce去重。

        Args:
            api_key: API密钥。
            timestamp: 请求时间戳（字符串）。
            nonce: 随机数。
            signature: 客户端计算的签名。
            body: 请求体字符串。

        Returns:
            {"valid": bool, "reason": str}
        """
        # 验证时间戳
        try:
            ts = float(timestamp)
        except (ValueError, TypeError):
            return {"valid": False, "reason": "时间戳格式无效"}

        now = time.time()
        if abs(now - ts) > self.TIMESTAMP_TTL:
            return {"valid": False, "reason": "时间戳已过期或不在有效期内"}

        # 验证nonce唯一性
        if nonce in self._nonce_set:
            return {"valid": False, "reason": "请求重放检测：nonce重复"}

        # 获取密钥对应的secret
        key_info = self._api_keys.get(api_key)
        if not key_info:
            return {"valid": False, "reason": "API密钥无效"}

        secret = key_info.get("secret", api_key)

        # 计算签名
        sign_content = f"{timestamp}{nonce}{body}"
        expected_sig = hmac.new(
            secret.encode("utf-8"),
            sign_content.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, signature):
            return {"valid": False, "reason": "签名验证失败"}

        # 记录nonce
        self._nonce_cache.append(nonce)
        self._nonce_set.add(nonce)
        # 清理超出缓存的旧nonce
        while len(self._nonce_cache) > self.NONCE_CACHE_SIZE:
            old = self._nonce_cache.popleft()
            self._nonce_set.discard(old)

        return {"valid": True, "reason": ""}

    # ------------------------------------------------------------------ #
    # 速率限制（令牌桶）
    # ------------------------------------------------------------------ #
    def check_rate_limit(self, api_key: str, ip: str, endpoint: str,
                         limit: int = 100, window: int = 60) -> Dict[str, Any]:
        """令牌桶速率限制。

        按API密钥+IP+端点限制请求速率。

        Args:
            api_key: API密钥。
            ip: 客户端IP。
            endpoint: 请求端点。
            limit: 时间窗口内最大请求数。
            window: 时间窗口（秒）。

        Returns:
            {"allowed": bool, "retry_after": seconds}
        """
        bucket_key = f"{api_key}:{ip}:{endpoint}"
        now = time.time()

        bucket = self._rate_buckets.get(bucket_key)
        if bucket is None:
            bucket = {
                "tokens": float(limit),
                "last_refill": now,
                "requests": deque(),
            }
            self._rate_buckets[bucket_key] = bucket

        # 清理过期请求记录
        while bucket["requests"] and now - bucket["requests"][0] > window:
            bucket["requests"].popleft()

        # 检查是否超限
        if len(bucket["requests"]) >= limit:
            oldest = bucket["requests"][0]
            retry_after = max(1, int(window - (now - oldest)))
            return {"allowed": False, "retry_after": retry_after}

        bucket["requests"].append(now)
        return {"allowed": True, "retry_after": 0}

    # ------------------------------------------------------------------ #
    # IP白名单/黑名单
    # ------------------------------------------------------------------ #
    def check_ip_whitelist(self, ip: str) -> bool:
        """检查IP是否在白名单中。

        白名单为空时不限制（返回True）。

        Args:
            ip: 客户端IP。

        Returns:
            True表示允许访问。
        """
        whitelist = self._ip_config.get("whitelist", [])
        if not whitelist:
            return True  # 白名单为空=不限制
        return ip in whitelist

    def check_ip_blacklist(self, ip: str) -> bool:
        """检查IP是否在黑名单中。

        Args:
            ip: 客户端IP。

        Returns:
            True表示在黑名单中（应拒绝）。
        """
        blacklist = self._ip_config.get("blacklist", [])
        return ip in blacklist

    # ------------------------------------------------------------------ #
    # 请求日志
    # ------------------------------------------------------------------ #
    def log_request(self, request_info: Dict[str, Any]):
        """记录API请求日志到logs/api_requests.log。

        Args:
            request_info: 包含timestamp, ip, api_key, endpoint, method,
                          status_code, response_time_ms, user_agent等字段。
        """
        log_file = os.path.join(_LOGS_DIR, "api_requests.log")
        try:
            ts = request_info.get("timestamp", time.time())
            if isinstance(ts, (int, float)):
                ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            else:
                ts_str = str(ts)

            line = (
                f"{ts_str} | "
                f"IP={request_info.get('ip', '-')} | "
                f"KEY={request_info.get('api_key', '-')} | "
                f"{request_info.get('method', '-')} "
                f"{request_info.get('endpoint', '-')} | "
                f"STATUS={request_info.get('status_code', '-')} | "
                f"TIME={request_info.get('response_time_ms', '-')}ms | "
                f"UA={request_info.get('user_agent', '-')}"
            )
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except IOError:
            pass

    # ------------------------------------------------------------------ #
    # 异常检测
    # ------------------------------------------------------------------ #
    def detect_anomaly(self, request_info: Dict[str, Any]) -> Dict[str, Any]:
        """检测异常请求模式。

        检测规则：
            1. 1分钟内>10次4xx失败请求
            2. 异常User-Agent（sqlmap/nmap/python-requests）
            3. 凌晨2-5点大量请求

        Args:
            request_info: 请求信息字典。

        Returns:
            {"anomaly": bool, "type": str, "severity": str, "details": {...}}
        """
        details: Dict[str, Any] = {}
        anomaly_types: List[str] = []

        now = time.time()
        ip = request_info.get("ip", "")
        status_code = request_info.get("status_code", 200)
        user_agent = request_info.get("user_agent", "")

        # 记录失败请求
        if isinstance(status_code, int) and 400 <= status_code < 500:
            self._recent_failures.append({"ip": ip, "time": now})

        # 规则1：短时间大量失败请求
        one_min_ago = now - 60
        recent_failures = [
            f for f in self._recent_failures
            if f["ip"] == ip and f["time"] > one_min_ago
        ]
        if len(recent_failures) > 10:
            anomaly_types.append("excessive_failures")
            details["failure_count"] = len(recent_failures)
            details["window_seconds"] = 60

        # 规则2：异常User-Agent
        suspicious_uas = ["sqlmap", "nmap", "python-requests", "curl/", "wget"]
        ua_lower = user_agent.lower() if user_agent else ""
        matched_ua = [ua for ua in suspicious_uas if ua in ua_lower]
        if matched_ua:
            anomaly_types.append("suspicious_user_agent")
            details["matched_ua"] = matched_ua

        # 规则3：凌晨2-5点大量请求
        hour = datetime.fromtimestamp(now).hour
        if 2 <= hour <= 5:
            # 统计该IP在最近10分钟的请求数（简单追踪）
            details["night_hour"] = hour
            # 这里只标记时间段，不单独触发anomaly，除非同时有其他异常
            # 为了使检测有意义，凌晨时段的请求直接标记
            if not anomaly_types:
                anomaly_types.append("unusual_time_access")
                details["note"] = "凌晨2-5点访问"

        if anomaly_types:
            # 严重程度判断
            severity = "medium"
            if "excessive_failures" in anomaly_types:
                severity = "high"
            elif "suspicious_user_agent" in anomaly_types:
                severity = "high"

            return {
                "anomaly": True,
                "type": ",".join(anomaly_types),
                "severity": severity,
                "details": details,
            }

        return {"anomaly": False, "type": "", "severity": "", "details": {}}


# 全局实例
_api_security_instance: Optional[APISecurity] = None


def get_api_security() -> APISecurity:
    """获取全局APISecurity实例（单例模式）。"""
    global _api_security_instance
    if _api_security_instance is None:
        _api_security_instance = APISecurity()
    return _api_security_instance
