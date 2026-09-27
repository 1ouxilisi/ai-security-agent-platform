"""API安全中间件模块。

包含：输入验证、审计日志、速率限制。
"""
import time
import json
import hashlib
from collections import defaultdict
from typing import Dict, Optional
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class InputValidationMiddleware(BaseHTTPMiddleware):
    """输入验证中间件。
    
    对API请求进行基本的输入验证和消毒，防止注入攻击。
    """
    
    # 危险字符模式
    DANGEROUS_PATTERNS = [
        "../", "..\\",  # 路径遍历
        "<script", "javascript:",  # XSS
        "union select", "drop table", "insert into",  # SQL注入（基础）
        "\x00",  # 空字节
    ]
    
    # 最大请求体大小（10MB）
    MAX_BODY_SIZE = 10 * 1024 * 1024
    
    async def dispatch(self, request: Request, call_next):
        # 只检查API端点
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        
        # 检查请求体大小
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.MAX_BODY_SIZE:
            return JSONResponse(
                status_code=413,
                content={"detail": "请求体过大，最大支持10MB"}
            )
        
        # 检查URL路径中的危险字符
        path = request.url.path.lower()
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern in path:
                return JSONResponse(
                    status_code=400,
                    content={"detail": f"请求路径包含非法字符: {pattern}"}
                )
        
        # 检查查询参数
        query_string = request.url.query.lower()
        for pattern in self.DANGEROUS_PATTERNS[:3]:  # 只检查前3种常见的
            if pattern in query_string:
                return JSONResponse(
                    status_code=400,
                    content={"detail": f"查询参数包含非法字符: {pattern}"}
                )
        
        return await call_next(request)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """审计日志中间件。
    
    记录关键操作的审计日志，包括请求时间、客户端IP、端点、方法、响应状态码。
    """
    
    def __init__(self, app, log_file: str = "logs/audit.log"):
        super().__init__(app)
        self.log_file = log_file
        self._ensure_log_dir()
    
    def _ensure_log_dir(self):
        import os
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        
        # 只记录API端点的操作
        if request.url.path.startswith("/api/"):
            client_ip = request.client.host if request.client else "unknown"
            api_key = request.headers.get("X-API-Key", "anonymous")
            # 对API密钥做哈希，不记录明文
            api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16] if api_key != "anonymous" else "anonymous"
            
            log_entry = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": client_ip,
                "api_key_hash": api_key_hash,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration * 1000, 2),
                "user_agent": request.headers.get("user-agent", "unknown")[:100]
            }
            
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
            except Exception:
                pass  # 审计日志写入失败不影响正常请求
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """速率限制中间件。
    
    基于客户端IP和API密钥进行速率限制，防止API滥用。
    """
    
    def __init__(self, app, requests_per_minute: int = 60, requests_per_hour: int = 1000):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self._minute_buckets: Dict[str, list] = defaultdict(list)
        self._hour_buckets: Dict[str, list] = defaultdict(list)
    
    def _get_client_key(self, request: Request) -> str:
        """获取客户端标识（IP + API密钥哈希）"""
        client_ip = request.client.host if request.client else "unknown"
        api_key = request.headers.get("X-API-Key", "")
        if api_key:
            api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
            return f"{client_ip}:{api_key_hash}"
        return client_ip
    
    def _clean_old_requests(self, buckets: Dict[str, list], key: str, window_seconds: int):
        """清理过期的请求记录"""
        now = time.time()
        buckets[key] = [t for t in buckets[key] if now - t < window_seconds]
    
    async def dispatch(self, request: Request, call_next):
        # 只限制API端点
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        
        # 健康检查端点不限制
        if request.url.path == "/api/v1/health":
            return await call_next(request)
        
        client_key = self._get_client_key(request)
        now = time.time()
        
        # 检查每分钟限制
        self._clean_old_requests(self._minute_buckets, client_key, 60)
        if len(self._minute_buckets[client_key]) >= self.requests_per_minute:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "请求过于频繁，请稍后再试",
                    "retry_after": 60,
                    "limit": f"{self.requests_per_minute} requests/minute"
                },
                headers={"Retry-After": "60"}
            )
        
        # 检查每小时限制
        self._clean_old_requests(self._hour_buckets, client_key, 3600)
        if len(self._hour_buckets[client_key]) >= self.requests_per_hour:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "已达到每小时请求上限",
                    "retry_after": 3600,
                    "limit": f"{self.requests_per_hour} requests/hour"
                },
                headers={"Retry-After": "3600"}
            )
        
        # 记录请求
        self._minute_buckets[client_key].append(now)
        self._hour_buckets[client_key].append(now)
        
        return await call_next(request)


class SecurityMiddleware(BaseHTTPMiddleware):
    """统一安全中间件。
    
    组合：输入验证、审计日志、速率限制、安全头、IP过滤。
    与app.py中的注册方式兼容（接受enabled参数）。
    """
    
    def __init__(self, app, enabled: bool = True, requests_per_minute: int = 120, requests_per_hour: int = 2000):
        super().__init__(app)
        self.enabled = enabled
        self.input_validator = InputValidationMiddleware(app)
        self.audit_logger = AuditLogMiddleware(app)
        self.rate_limiter = RateLimitMiddleware(app, requests_per_minute, requests_per_hour)
    
    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        
        # 1. 输入验证
        validation_response = await self._validate_input(request)
        if validation_response:
            return validation_response
        
        # 2. 速率限制
        rate_response = await self._check_rate_limit(request)
        if rate_response:
            return rate_response
        
        # 3. 执行请求并记录审计日志
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        
        # 4. 添加安全头
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # 5. 记录审计日志
        if request.url.path.startswith("/api/"):
            self._write_audit_log(request, response, duration)
        
        return response
    
    async def _validate_input(self, request: Request):
        """输入验证"""
        if not request.url.path.startswith("/api/"):
            return None
        
        path = request.url.path.lower()
        for pattern in InputValidationMiddleware.DANGEROUS_PATTERNS:
            if pattern in path:
                return JSONResponse(status_code=400, content={"detail": f"请求路径包含非法字符"})
        
        query_string = request.url.query.lower()
        for pattern in ["../", "<script", "union select"]:
            if pattern in query_string:
                return JSONResponse(status_code=400, content={"detail": f"查询参数包含非法字符"})
        
        return None
    
    async def _check_rate_limit(self, request: Request):
        """速率限制检查"""
        if not request.url.path.startswith("/api/") or request.url.path == "/api/v1/health":
            return None
        
        client_key = self.rate_limiter._get_client_key(request)
        now = time.time()
        
        self.rate_limiter._clean_old_requests(self.rate_limiter._minute_buckets, client_key, 60)
        if len(self.rate_limiter._minute_buckets[client_key]) >= self.rate_limiter.requests_per_minute:
            return JSONResponse(status_code=429, content={"detail": "请求过于频繁", "retry_after": 60}, headers={"Retry-After": "60"})
        
        self.rate_limiter._minute_buckets[client_key].append(now)
        self.rate_limiter._hour_buckets[client_key].append(now)
        return None
    
    def _write_audit_log(self, request: Request, response, duration: float):
        """写入审计日志"""
        import os
        log_file = "logs/audit.log"
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        client_ip = request.client.host if request.client else "unknown"
        api_key = request.headers.get("X-API-Key", "anonymous")
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16] if api_key != "anonymous" else "anonymous"
        
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "client_ip": client_ip,
            "api_key_hash": api_key_hash,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": round(duration * 1000, 2),
        }
        
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        except Exception:
            pass
