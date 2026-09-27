# -*- coding: utf-8 -*-
"""API 网关中间件。

提供：
- API Key 管理（sk_ 前缀，仅创建时返回明文）
- 三级限流：租户级 / 用户级 / 端点级（令牌桶算法）
- 每日/每月 API 调用配额
- 调用计量（jsonl 追加日志）
- FastAPI 中间件适配函数
"""
import os
import json
import time
import hmac
import hashlib
import secrets
import threading
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Tuple

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging
    log = logging.getLogger("commercial.api_gateway")


# ============== 令牌桶 ==============

class TokenBucket:
    """令牌桶限流器。

    capacity: 桶容量（最大突发请求数）
    rate: 每秒补充令牌数
    """

    def __init__(self, capacity: int, rate: float):
        self.capacity = float(capacity)
        self.rate = float(rate)
        self.tokens = float(capacity)
        self.last = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        with self.lock:
            now = time.time()
            elapsed = now - self.last
            self.last = now
            # 按时间补充令牌
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


# ============== API 网关 ==============

class APIGateway:
    """API 网关。"""

    def __init__(self, base_dir: str = "data/tenants", tenant_manager=None):
        self.meta_dir = os.path.join(base_dir, "_meta")
        self.keys_file = os.path.join(self.meta_dir, "api_keys.json")
        self.calls_file = os.path.join(self.meta_dir, "api_calls.jsonl")

        # key_id -> {key_id, key_hash, tenant_id, username, name, permissions,
        #            rate_limit, created_at, is_active, last_used, call_count}
        self._keys: Dict[str, Dict[str, Any]] = {}
        # key_hash -> key_id 索引
        self._hash_index: Dict[str, str] = {}

        # 三级限流桶
        self._tenant_buckets: Dict[str, TokenBucket] = {}
        self._user_buckets: Dict[str, TokenBucket] = {}
        self._endpoint_buckets: Dict[str, TokenBucket] = {}

        # 端点级默认配置: endpoint -> (capacity, rate_per_sec)
        self.endpoint_limits: Dict[str, Tuple[int, float]] = {}

        self._lock = threading.RLock()
        self._tm = tenant_manager

        os.makedirs(self.meta_dir, exist_ok=True)
        self._load()

    # ---------------- 持久化 ----------------

    def _load(self):
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, "r", encoding="utf-8") as f:
                    self._keys = json.load(f)
            except Exception as e:
                log.warning(f"[api_gateway] 加载 api_keys.json 失败: {e}")
                self._keys = {}
        self._hash_index = {}
        for kid, k in self._keys.items():
            self._hash_index[k["key_hash"]] = kid

    def _save(self):
        with open(self.keys_file, "w", encoding="utf-8") as f:
            json.dump(self._keys, f, ensure_ascii=False, indent=2)

    @staticmethod
    def _hash_key(api_key: str) -> str:
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    # ---------------- API Key 管理 ----------------

    def create_api_key(self, tenant_id: str, username: str, name: str = "",
                       permissions: Optional[List[str]] = None,
                       rate_limit: Optional[int] = None
                       ) -> Tuple[str, str]:
        """创建 API Key。返回 (明文key, key_id)。明文仅此时返回。"""
        with self._lock:
            key_id = secrets.token_hex(8)
            plain = "sk_" + secrets.token_urlsafe(32)
            key_hash = self._hash_key(plain)
            self._keys[key_id] = {
                "key_id": key_id,
                "key_hash": key_hash,
                "key_prefix": plain[:10] + "...",
                "tenant_id": tenant_id,
                "username": username,
                "name": name,
                "permissions": permissions or ["api:use"],
                "rate_limit": rate_limit or 100,  # 默认 100 req/min
                "created_at": time.time(),
                "is_active": True,
                "last_used": 0,
                "call_count": 0,
            }
            self._hash_index[key_hash] = key_id
            self._save()
            log.info(f"[api_gateway] 为租户 {tenant_id} 用户 {username} 创建 Key {key_id}")
            return plain, key_id

    def revoke_api_key(self, key_id: str) -> bool:
        with self._lock:
            k = self._keys.get(key_id)
            if not k:
                return False
            k["is_active"] = False
            self._save()
            return True

    def validate_api_key(self, api_key: str
                         ) -> Optional[Tuple[str, str, List[str], int]]:
        """验证 API Key。返回 (tenant_id, username, permissions, rate_limit)。"""
        if not api_key or not api_key.startswith("sk_"):
            return None
        h = self._hash_key(api_key)
        kid = self._hash_index.get(h)
        if not kid:
            return None
        k = self._keys[kid]
        if not k["is_active"]:
            return None
        k["last_used"] = time.time()
        return (k["tenant_id"], k["username"],
                k.get("permissions", ["api:use"]), int(k.get("rate_limit", 100)))

    def list_api_keys(self, tenant_id: str) -> List[Dict[str, Any]]:
        """列出 Key（不返回明文，只返回前缀+元信息）。"""
        with self._lock:
            out = []
            for k in self._keys.values():
                if k["tenant_id"] != tenant_id:
                    continue
                out.append({
                    "key_id": k["key_id"],
                    "key_prefix": k.get("key_prefix", "sk_..."),
                    "name": k["name"],
                    "username": k["username"],
                    "permissions": k.get("permissions", []),
                    "rate_limit": k.get("rate_limit", 100),
                    "created_at": k.get("created_at", 0),
                    "is_active": k.get("is_active", True),
                    "last_used": k.get("last_used", 0),
                    "call_count": k.get("call_count", 0),
                })
            return out

    def get_api_key_stats(self, key_id: str) -> Optional[Dict[str, Any]]:
        k = self._keys.get(key_id)
        if not k:
            return None
        return {
            "key_id": key_id,
            "key_prefix": k.get("key_prefix"),
            "username": k["username"],
            "tenant_id": k["tenant_id"],
            "is_active": k["is_active"],
            "call_count": k.get("call_count", 0),
            "last_used": k.get("last_used", 0),
        }

    # ---------------- 三级限流 ----------------

    @staticmethod
    def _get_bucket(store: Dict[str, TokenBucket], key: str,
                    capacity: int, rate: float) -> TokenBucket:
        b = store.get(key)
        if b is None:
            b = TokenBucket(capacity, rate)
            store[key] = b
        return b

    def check_rate_limit(self, tenant_id: str, username: str,
                         endpoint: str) -> Tuple[bool, str]:
        """三级限流。返回 (allowed, reason)。

        默认：租户级 100 req/min（capacity=100, rate=100/60），
              用户级 30 req/min（capacity=30, rate=30/60）。
        """
        # 租户级
        tb = self._get_bucket(self._tenant_buckets, "t:" + tenant_id, 100, 100 / 60)
        if not tb.consume(1):
            return False, "tenant_rate_limited"
        # 用户级
        ub = self._get_bucket(self._user_buckets,
                              f"u:{tenant_id}:{username}", 30, 30 / 60)
        if not ub.consume(1):
            return False, "user_rate_limited"
        # 端点级（可选配置）
        if endpoint in self.endpoint_limits:
            cap, rate = self.endpoint_limits[endpoint]
            eb = self._get_bucket(self._endpoint_buckets,
                                  f"e:{endpoint}", cap, rate)
            if not eb.consume(1):
                return False, "endpoint_rate_limited"
        return True, "ok"

    # ---------------- 配额 ----------------

    def check_quota(self, tenant_id: str) -> Tuple[bool, int, int]:
        """检查每日 API 调用配额。返回 (allowed, remaining, limit)。"""
        if self._tm is None:
            return True, -1, -1
        return self._tm.check_quota(tenant_id, "api_calls_daily", 1)

    # ---------------- 调用计量 ----------------

    def record_call(self, tenant_id: str, username: str, key_id: str,
                    endpoint: str, method: str, status_code: int,
                    duration_ms: float) -> None:
        rec = {
            "ts": time.time(),
            "tenant_id": tenant_id,
            "username": username,
            "key_id": key_id,
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "duration_ms": duration_ms,
        }
        try:
            with open(self.calls_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception as e:
            log.warning(f"[api_gateway] 写入调用日志失败: {e}")

        with self._lock:
            k = self._keys.get(key_id)
            if k:
                k["call_count"] = k.get("call_count", 0) + 1
                k["last_used"] = time.time()
                self._save()
            if self._tm is not None:
                self._tm.record_usage(tenant_id, "api_calls_daily", 1)

    def get_call_stats(self, tenant_id: str,
                        period: Optional[str] = None) -> Dict[str, Any]:
        """统计调用：按端点 / 按状态码 / 按时间分布。"""
        if not os.path.exists(self.calls_file):
            return {"tenant_id": tenant_id, "total": 0, "by_endpoint": {},
                    "by_status": {}, "recent": []}
        cutoff = 0
        now = time.time()
        if period == "hour":
            cutoff = now - 3600
        elif period == "day":
            cutoff = now - 86400

        by_endpoint: Dict[str, int] = defaultdict(int)
        by_status: Dict[str, int] = defaultdict(int)
        total = 0
        recent: Deque[Dict[str, Any]] = deque(maxlen=20)
        try:
            with open(self.calls_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if rec.get("tenant_id") != tenant_id:
                        continue
                    if cutoff and rec.get("ts", 0) < cutoff:
                        continue
                    total += 1
                    by_endpoint[rec.get("endpoint", "?")] += 1
                    by_status[str(rec.get("status_code", 0))] += 1
                    recent.append(rec)
        except Exception as e:
            log.warning(f"[api_gateway] 读取调用日志失败: {e}")
        return {
            "tenant_id": tenant_id,
            "period": period or "all",
            "total": total,
            "by_endpoint": dict(by_endpoint),
            "by_status": dict(by_status),
            "recent": list(recent),
        }


# ============== FastAPI 中间件适配 ==============

def make_api_gateway_middleware(gateway: APIGateway):
    """构造一个 FastAPI 中间件函数。

    从请求头 ``X-API-Key`` 读取密钥 -> 验证 -> 三级限流 -> 配额 -> 计量。
    失败时直接返回 401/429 JSON，不调用下游。
    """
    async def api_gateway_middleware(request, call_next):
        # 只保护 /api/ 前缀的请求，且排除商业化自身的管理端点（避免自举失败）
        path = request.url.path
        if not path.startswith("/api/"):
            return await call_next(request)
        if path.startswith("/api/v1/commercial"):
            return await call_next(request)

        api_key = request.headers.get("X-API-Key", "")
        start = time.time()

        if not api_key:
            return _json_error(401, "missing_api_key", "缺少 X-API-Key 请求头")

        validated = gateway.validate_api_key(api_key)
        if validated is None:
            gateway.record_call("anonymous", "-", "-", path,
                                request.method, 401,
                                (time.time() - start) * 1000)
            return _json_error(401, "invalid_api_key", "API Key 无效或已吊销")

        tenant_id, username, permissions, rate_limit = validated

        # 配额检查
        allowed, remaining, limit = gateway.check_quota(tenant_id)
        if not allowed:
            gateway.record_call(tenant_id, username, "-", path,
                                request.method, 429,
                                (time.time() - start) * 1000)
            return _json_error(429, "quota_exceeded",
                               f"API 调用配额已用尽 (剩余 {remaining}/{limit})")

        # 三级限流
        ok, reason = gateway.check_rate_limit(tenant_id, username, path)
        if not ok:
            gateway.record_call(tenant_id, username, "-", path,
                                request.method, 429,
                                (time.time() - start) * 1000)
            return _json_error(429, reason, "触发限流，请降低调用频率")

        response = await call_next(request)
        gateway.record_call(tenant_id, username, "-", path,
                            request.method, response.status_code,
                            (time.time() - start) * 1000)
        return response

    return api_gateway_middleware


def _json_error(status_code: int, error: str, message: str):
    """构造 JSON 错误响应（延迟导入 fastapi 以避免硬依赖）。"""
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "message": message},
    )


# 模块级单例
_default_gw: Optional[APIGateway] = None


def get_api_gateway(base_dir: str = "data/tenants",
                    tenant_manager=None) -> APIGateway:
    global _default_gw
    if _default_gw is None:
        _default_gw = APIGateway(base_dir, tenant_manager)
    return _default_gw
