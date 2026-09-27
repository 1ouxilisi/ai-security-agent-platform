#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_gateway模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import json
import os
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps

try:
    from fastapi import FastAPI, Request, HTTPException, Depends, Header
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
except ImportError:
    FastAPI = None

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


class APIKeyStatus(Enum):
    """API密钥状态"""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class APIKey:
    """API密钥"""
    key_id: str
    key: str
    name: str
    owner: str
    permissions: List[str] = field(default_factory=lambda: ["read"])
    rate_limit: int = 100  # 每分钟请求数
    status: str = "active"
    created_at: str = ""
    expires_at: str = ""
    last_used: str = ""
    total_requests: int = 0


@dataclass
class RateLimit:
    """限流记录"""
    key_id: str
    requests: List[float] = field(default_factory=list)
    blocked_until: float = 0.0


@dataclass
class Route:
    """路由配置"""
    path: str
    methods: List[str]
    handler: Optional[Callable] = None
    auth_required: bool = True
    permissions: List[str] = field(default_factory=list)
    rate_limit: int = 100
    cache_ttl: int = 0  # 0表示不缓存


class APIGateway:
    """API网关"""

    def __init__(self, db_path: str = "./data/api_gateway.db"):
        """初始化APIGateway实例。

        Args:
            self: 类实例。
        """
        self.db_path = db_path
        self.api_keys: Dict[str, APIKey] = {}
        self.rate_limits: Dict[str, RateLimit] = {}
        self.routes: Dict[str, Route] = {}
        self.request_log: List[Dict] = []
        self.cache: Dict[str, tuple] = {}  # key -> (value, expire_time)
        self._load_keys()
        self._register_default_routes()
        logger.info("API网关初始化完成")

    def _load_keys(self):
        """加载API密钥"""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for key_data in data.get("api_keys", []):
                        key = APIKey(**key_data)
                        self.api_keys[key.key] = key
            except Exception as e:
                logger.error(f"加载API密钥失败: {e}")

    def _save_keys(self):
        """保存API密钥"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        data = {
            "api_keys": [
                {
                    "key_id": k.key_id,
                    "key": k.key,
                    "name": k.name,
                    "owner": k.owner,
                    "permissions": k.permissions,
                    "rate_limit": k.rate_limit,
                    "status": k.status,
                    "created_at": k.created_at,
                    "expires_at": k.expires_at,
                    "last_used": k.last_used,
                    "total_requests": k.total_requests,
                }
                for k in self.api_keys.values()
            ]
        }
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _register_default_routes(self):
        """注册默认路由"""
        default_routes = [
            Route(path="/api/v1/health", methods=["GET"], auth_required=False, rate_limit=60),
            Route(path="/api/v1/scans", methods=["GET", "POST"], auth_required=True, permissions=["scan:read", "scan:write"]),
            Route(path="/api/v1/vulnerabilities", methods=["GET"], auth_required=True, permissions=["vuln:read"]),
            Route(path="/api/v1/tasks", methods=["GET", "POST"], auth_required=True, permissions=["task:read", "task:write"]),
            Route(path="/api/v1/reports", methods=["GET", "POST"], auth_required=True, permissions=["report:read", "report:write"]),
            Route(path="/api/v1/users", methods=["GET"], auth_required=True, permissions=["admin"]),
            Route(path="/api/v1/api-keys", methods=["GET", "POST", "DELETE"], auth_required=True, permissions=["admin"]),
        ]
        for route in default_routes:
            self.routes[route.path] = route

    def create_api_key(self, name: str, owner: str, permissions: List[str] = None,
                       rate_limit: int = 100, expires_days: int = 365) -> APIKey:
        """创建API密钥"""
        key_id = f"key_{secrets.token_hex(8)}"
        key = f"sk-{secrets.token_hex(24)}"

        api_key = APIKey(
            key_id=key_id,
            key=key,
            name=name,
            owner=owner,
            permissions=permissions or ["read"],
            rate_limit=rate_limit,
            status="active",
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            expires_at=(datetime.now() + timedelta(days=expires_days)).strftime("%Y-%m-%d %H:%M:%S"),
        )

        self.api_keys[key] = api_key
        self._save_keys()
        logger.info(f"创建API密钥: {name} ({key_id})")
        return api_key

    def revoke_api_key(self, key: str) -> bool:
        """撤销API密钥"""
        if key in self.api_keys:
            self.api_keys[key].status = "revoked"
            self._save_keys()
            logger.info(f"撤销API密钥: {self.api_keys[key].name}")
            return True
        return False

    def validate_api_key(self, key: str, required_permissions: List[str] = None) -> Dict:
        """验证API密钥"""
        if key not in self.api_keys:
            return {"valid": False, "error": "无效的API密钥"}

        api_key = self.api_keys[key]

        # 检查状态
        if api_key.status != "active":
            return {"valid": False, "error": f"API密钥已{api_key.status}"}

        # 检查过期
        if api_key.expires_at:
            try:
                expire_time = datetime.strptime(api_key.expires_at, "%Y-%m-%d %H:%M:%S")
                if datetime.now() > expire_time:
                    api_key.status = "expired"
                    self._save_keys()
                    return {"valid": False, "error": "API密钥已过期"}
            except:
                pass

        # 检查权限
        if required_permissions:
            for perm in required_permissions:
                if perm not in api_key.permissions and "admin" not in api_key.permissions:
                    return {"valid": False, "error": f"缺少权限: {perm}"}

        # 检查限流
        if not self._check_rate_limit(api_key):
            return {"valid": False, "error": "请求频率超限，请稍后再试"}

        # 更新使用记录
        api_key.last_used = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        api_key.total_requests += 1
        self._save_keys()

        return {"valid": True, "api_key": api_key}

    def _check_rate_limit(self, api_key: APIKey) -> bool:
        """检查限流"""
        key_id = api_key.key_id
        now = time.time()

        if key_id not in self.rate_limits:
            self.rate_limits[key_id] = RateLimit(key_id=key_id)

        rl = self.rate_limits[key_id]

        # 检查是否被封禁
        if now < rl.blocked_until:
            return False

        # 清理过期请求记录
        rl.requests = [t for t in rl.requests if now - t < 60]

        # 检查是否超限
        if len(rl.requests) >= api_key.rate_limit:
            rl.blocked_until = now + 60  # 封禁1分钟
            logger.warning(f"API密钥 {api_key.name} 触发限流")
            return False

        rl.requests.append(now)
        return True

    def log_request(self, method: str, path: str, api_key: str = "",
                    status_code: int = 200, duration: float = 0.0,
                    client_ip: str = ""):
        """记录请求日志"""
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "method": method,
            "path": path,
            "api_key": api_key[:16] + "..." if api_key else "",
            "status_code": status_code,
            "duration_ms": round(duration * 1000, 2),
            "client_ip": client_ip,
        }
        self.request_log.append(log_entry)

        # 只保留最近10000条
        if len(self.request_log) > 10000:
            self.request_log = self.request_log[-10000:]

    def get_cache(self, key: str) -> Optional[Any]:
        """获取缓存"""
        if key in self.cache:
            value, expire_time = self.cache[key]
            if time.time() < expire_time:
                return value
            else:
                del self.cache[key]
        return None

    def set_cache(self, key: str, value: Any, ttl: int = 60):
        """设置缓存"""
        self.cache[key] = (value, time.time() + ttl)

    def get_stats(self) -> Dict:
        """获取网关统计"""
        return {
            "total_api_keys": len(self.api_keys),
            "active_keys": len([k for k in self.api_keys.values() if k.status == "active"]),
            "revoked_keys": len([k for k in self.api_keys.values() if k.status == "revoked"]),
            "total_requests": sum(k.total_requests for k in self.api_keys.values()),
            "registered_routes": len(self.routes),
            "cache_entries": len(self.cache),
            "request_log_entries": len(self.request_log),
        }

    def get_request_log(self, limit: int = 100, api_key: str = "") -> List[Dict]:
        """获取请求日志"""
        logs = self.request_log[::-1]
        if api_key:
            logs = [l for l in logs if l["api_key"].startswith(api_key[:16])]
        return logs[:limit]

    def create_fastapi_app(self) -> Any:
        """创建FastAPI应用（如果已安装FastAPI）"""
        if FastAPI is None:
            raise ImportError("FastAPI未安装，请运行: pip install fastapi uvicorn")

        app = FastAPI(title="AI Hacking Agent API Gateway", version="2.0.0")

        # CORS中间件
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        gateway = self

        @app.middleware("http")
        async def api_gateway_middleware(request: Request, call_next):
            """API网关中间件"""
            start_time = time.time()
            path = request.url.path
            method = request.method

            # 跳过健康检查和文档
            if path in ["/health", "/docs", "/openapi.json", "/redoc"]:
                response = await call_next(request)
                return response

            # 查找路由
            route = None
            for r in gateway.routes.values():
                if path.startswith(r.path) and method in r.methods:
                    route = r
                    break

            if route and route.auth_required:
                # 验证API密钥
                api_key = request.headers.get("X-API-Key", "")
                if not api_key:
                    auth_header = request.headers.get("Authorization", "")
                    if auth_header.startswith("Bearer "):
                        api_key = auth_header[7:]

                if not api_key:
                    return JSONResponse(
                        status_code=401,
                        content={"error": "缺少API密钥", "detail": "请在X-API-Key头或Authorization: Bearer中提供API密钥"}
                    )

                result = gateway.validate_api_key(api_key, route.permissions)
                if not result["valid"]:
                    return JSONResponse(
                        status_code=403,
                        content={"error": result["error"]}
                    )

            # 处理请求
            response = await call_next(request)
            duration = time.time() - start_time

            # 记录日志
            api_key = request.headers.get("X-API-Key", "")
            gateway.log_request(method, path, api_key, response.status_code, duration)

            # 添加网关头
            response.headers["X-Gateway"] = "AI-Hacking-Agent-Gateway/2.0"
            response.headers["X-Request-Duration"] = f"{duration*1000:.2f}ms"

            return response

        @app.get("/health")
        async def health():
            return {"status": "healthy", "gateway": "AI Hacking Agent API Gateway v2.0"}

        @app.get("/api/v1/gateway/stats")
        async def gateway_stats():
            return gateway.get_stats()

        return app


def main():
    """演示用法"""
    print("=" * 60)
    print("  API网关")
    print("=" * 60)
    print()

    gateway = APIGateway()

    # 创建API密钥
    print("[1/4] 创建API密钥...")
    key1 = gateway.create_api_key(
        name="生产环境API",
        owner="admin",
        permissions=["read", "write", "scan:read", "scan:write", "vuln:read", "report:read", "report:write"],
        rate_limit=1000,
    )
    print(f"  密钥名称: {key1.name}")
    print(f"  API密钥: {key1.key}")
    print(f"  权限: {key1.permissions}")
    print(f"  限流: {key1.rate_limit}/分钟")
    print()

    key2 = gateway.create_api_key(
        name="只读API",
        owner="analyst",
        permissions=["read", "scan:read", "vuln:read"],
        rate_limit=100,
    )
    print(f"  密钥名称: {key2.name}")
    print(f"  API密钥: {key2.key}")
    print(f"  权限: {key2.permissions}")
    print()

    # 验证API密钥
    print("[2/4] 验证API密钥...")
    result = gateway.validate_api_key(key1.key, ["scan:write"])
    print(f"  有效: {result['valid']}")
    if result["valid"]:
        print(f"  所有者: {result['api_key'].owner}")
        print(f"  剩余请求: {key1.rate_limit - len(gateway.rate_limits[key1.key_id].requests)}/分钟")
    print()

    # 测试无效密钥
    result = gateway.validate_api_key("invalid-key")
    print(f"  无效密钥测试: {result['valid']} - {result['error']}")
    print()

    # 统计
    print("[3/4] 网关统计:")
    stats = gateway.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    print()

    # FastAPI集成
    print("[4/4] FastAPI集成:")
    print("  # 创建FastAPI应用")
    print("  app = gateway.create_fastapi_app()")
    print()
    print("  # 启动服务")
    print("  uvicorn main:app --host 0.0.0.0 --port 8000")
    print()
    print("  # API调用示例")
    print("  curl -H 'X-API-Key: sk-xxx' http://localhost:8000/api/v1/scans")
    print()

    print("=" * 60)
    print("  API网关功能:")
    print("  - ✅ API密钥管理（创建/撤销/过期）")
    print("  - ✅ 细粒度权限控制")
    print("  - ✅ 请求限流（每分钟）")
    print("  - ✅ 请求日志记录")
    print("  - ✅ 响应缓存")
    print("  - ✅ 路由管理")
    print("  - ✅ CORS支持")
    print("  - ✅ FastAPI中间件集成")
    print("=" * 60)


if __name__ == "__main__":
    main()
