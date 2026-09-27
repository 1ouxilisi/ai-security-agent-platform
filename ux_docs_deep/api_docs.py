#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ux_docs_deep/api_docs.py — API 文档管理。

覆盖四大分册：
    1. API概览：API介绍/认证方式/请求格式/响应格式/错误码/限流/版本/SDK
    2. 接口文档：接口列表/分类/详情/参数/示例/错误示例
    3. 认证授权：API Key/OAuth2.0/JWT/签名/IP白名单/权限/角色/Token管理
    4. SDK文档：Python/JavaScript/Java/Go/PHP/Ruby SDK 安装与示例
    5. 最佳实践：性能优化/错误处理/重试/幂等/分页/批量/缓存/安全
    6. API变更：版本变更/废弃/新增/变更日志/迁移指南/兼容性/通知
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 元数据
# --------------------------------------------------------------------------- #
AUTH_METHODS: Dict[str, Dict[str, str]] = {
    "api_key":  {"name": "API Key", "header": "X-API-Key", "security": "中"},
    "bearer":   {"name": "Bearer Token", "header": "Authorization: Bearer <JWT>", "security": "高"},
    "oauth2":   {"name": "OAuth 2.0", "flow": "authorization_code / client_credentials", "security": "高"},
    "hmac":     {"name": "HMAC 签名", "header": "X-Signature", "security": "高"},
    "ip_whitelist": {"name": "IP 白名单", "config": "allowlist.yaml", "security": "中"},
}

ERROR_CODE_TABLE: Dict[int, str] = {
    200: "成功",
    400: "请求参数错误",
    401: "未认证",
    403: "无权限",
    404: "资源不存在",
    409: "资源冲突",
    422: "参数校验失败",
    429: "请求过于频繁",
    500: "服务器内部错误",
    502: "网关错误",
    503: "服务不可用",
    504: "网关超时",
}

SDK_REGISTRY: Dict[str, Dict[str, str]] = {
    "python": {"package": "aihacking-sdk", "install": "pip install aihacking-sdk",
               "doc": "python.md", "maintainer": "devrel"},
    "javascript": {"package": "@aihacking/sdk", "install": "npm install @aihacking/sdk",
                   "doc": "js.md", "maintainer": "frontend"},
    "java": {"package": "com.aihacking:sdk", "install": "maven dependency",
             "doc": "java.md", "maintainer": "java-team"},
    "go": {"package": "github.com/aihacking/sdk-go", "install": "go get ...",
           "doc": "go.md", "maintainer": "go-team"},
    "php": {"package": "aihacking/sdk-php", "install": "composer require ...",
            "doc": "php.md", "maintainer": "php-team"},
    "ruby": {"package": "aihacking-sdk", "install": "gem install aihacking-sdk",
             "doc": "ruby.md", "maintainer": "ruby-team"},
}


# --------------------------------------------------------------------------- #
# API 端点对象
# --------------------------------------------------------------------------- #
class ApiEndpoint:
    """API 接口文档对象。"""

    def __init__(self, method: str, path: str, summary: str, category: str,
                 description: str = "", params: Optional[List[Dict[str, Any]]] = None,
                 response: Optional[Dict[str, Any]] = None,
                 auth_required: bool = True, deprecated: bool = False) -> None:
        self.id = f"ep_{uuid.uuid4().hex[:10]}"
        self.method = method.upper()
        self.path = path
        self.summary = summary
        self.category = category
        self.description = description
        self.params: List[Dict[str, Any]] = params or []
        self.response: Dict[str, Any] = response or {}
        self.auth_required = auth_required
        self.deprecated = deprecated
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.calls = 0
        self.error_rate = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "method": self.method, "path": self.path,
            "summary": self.summary, "category": self.category,
            "description": self.description, "params": self.params,
            "response": self.response, "auth_required": self.auth_required,
            "deprecated": self.deprecated, "created_at": self.created_at,
            "calls": self.calls, "error_rate": self.error_rate,
        }


# --------------------------------------------------------------------------- #
# API 变更记录
# --------------------------------------------------------------------------- #
class ApiChange:
    """API 变更日志条目。"""

    def __init__(self, version: str, change_type: str, endpoint: str,
                 description: str, deprecated_from: Optional[str] = None) -> None:
        self.id = f"ch_{uuid.uuid4().hex[:10]}"
        self.version = version
        self.change_type = change_type  # added / changed / deprecated / removed
        self.endpoint = endpoint
        self.description = description
        self.deprecated_from = deprecated_from
        self.date = time.strftime("%Y-%m-%d")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "version": self.version, "change_type": self.change_type,
            "endpoint": self.endpoint, "description": self.description,
            "deprecated_from": self.deprecated_from, "date": self.date,
        }


# --------------------------------------------------------------------------- #
# API 文档管理器
# --------------------------------------------------------------------------- #
class ApiDocsManager:
    """API 文档管理器（内存字典模拟）。"""

    def __init__(self) -> None:
        self.endpoints: Dict[str, ApiEndpoint] = {}
        self.changes: List[ApiChange] = []
        self.tokens: Dict[str, Dict[str, Any]] = {}
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        seeds = [
            ("GET", "/api/v1/health", "健康检查", "system", "无需认证",
             [], {"status": "ok"}, False),
            ("POST", "/api/v1/auth/login", "用户登录", "auth", "返回JWT",
             [{"name": "username", "in": "body", "type": "string", "required": True},
              {"name": "password", "in": "body", "type": "string", "required": True}],
             {"token": "string"}, True),
            ("GET", "/api/v1/assets", "资产列表", "asset", "分页查询资产",
             [{"name": "page", "in": "query", "type": "int", "required": False}],
             {"items": [], "total": 0}, True),
            ("POST", "/api/v1/scan/start", "启动扫描", "scan", "异步任务",
             [{"name": "target", "in": "body", "type": "string", "required": True}],
             {"task_id": "string"}, True),
            ("GET", "/api/v1/vulns", "漏洞列表", "vuln", "支持过滤",
             [{"name": "severity", "in": "query", "type": "string", "required": False}],
             {"items": []}, True),
            ("GET", "/api/v1/reports/{id}", "下载报告", "report", "PDF/HTML",
             [{"name": "id", "in": "path", "type": "string", "required": True}],
             {"file_url": "string"}, True),
        ]
        for method, path, summary, cat, desc, params, resp, auth in seeds:
            ep = ApiEndpoint(method, path, summary, cat, desc, params, resp, auth)
            self.endpoints[ep.id] = ep

        self.changes.append(ApiChange("v28.4.0", "added", "/api/v1/ux-docs-deep/*",
                                       "新增文档与UX优化API套件"))

    # ---- 端点 CRUD ----
    def create_endpoint(self, method: str, path: str, summary: str,
                        category: str, description: str = "",
                        params: Optional[List[Dict[str, Any]]] = None,
                        response: Optional[Dict[str, Any]] = None,
                        auth_required: bool = True) -> Dict[str, Any]:
        ep = ApiEndpoint(method, path, summary, category, description,
                         params, response, auth_required)
        self.endpoints[ep.id] = ep
        return ep.to_dict()

    def get_endpoint(self, ep_id: str) -> Optional[Dict[str, Any]]:
        ep = self.endpoints.get(ep_id)
        if ep is None:
            return None
        ep.calls += 1
        return ep.to_dict()

    def deprecate_endpoint(self, ep_id: str, sunset_version: str) -> Optional[Dict[str, Any]]:
        ep = self.endpoints.get(ep_id)
        if ep is None:
            return None
        ep.deprecated = True
        self.changes.append(ApiChange(sunset_version, "deprecated",
                                       f"{ep.method} {ep.path}",
                                       f"接口已废弃，请迁移至新版"))
        return ep.to_dict()

    def list_endpoints(self, category: Optional[str] = None,
                       method: Optional[str] = None,
                       include_deprecated: bool = False) -> List[Dict[str, Any]]:
        items = list(self.endpoints.values())
        if category:
            items = [e for e in items if e.category == category]
        if method:
            items = [e for e in items if e.method == method.upper()]
        if not include_deprecated:
            items = [e for e in items if not e.deprecated]
        return [e.to_dict() for e in items]

    # ---- 认证 Token ----
    def issue_token(self, client: str, scope: str = "read",
                    ttl_hours: int = 24) -> Dict[str, Any]:
        token_id = f"tk_{uuid.uuid4().hex[:16]}"
        token = {
            "token_id": token_id,
            "client": client, "scope": scope,
            "ttl_hours": ttl_hours,
            "issued_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "active",
        }
        self.tokens[token_id] = token
        return token

    def revoke_token(self, token_id: str) -> bool:
        t = self.tokens.get(token_id)
        if t:
            t["status"] = "revoked"
            return True
        return False

    def list_tokens(self) -> List[Dict[str, Any]]:
        return list(self.tokens.values())

    # ---- 变更日志 ----
    def add_change(self, version: str, change_type: str, endpoint: str,
                   description: str) -> Dict[str, Any]:
        ch = ApiChange(version, change_type, endpoint, description)
        self.changes.append(ch)
        return ch.to_dict()

    def list_changes(self, version: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.changes)
        if version:
            items = [c for c in items if c.version == version]
        return [c.to_dict() for c in reversed(items)]

    # ---- 元数据 ----
    def overview(self) -> Dict[str, Any]:
        return {
            "title": "AI Hacking Agent Open API",
            "version": "v28.4.0",
            "base_url": "https://api.aihacking.local",
            "auth_methods": AUTH_METHODS,
            "error_codes": ERROR_CODE_TABLE,
            "sdk_registry": SDK_REGISTRY,
            "rate_limit": "1000 req/min per token",
            "content_type": "application/json; charset=utf-8",
        }

    def stats(self) -> Dict[str, Any]:
        items = list(self.endpoints.values())
        by_cat: Dict[str, int] = {}
        for e in items:
            by_cat[e.category] = by_cat.get(e.category, 0) + 1
        return {
            "total_endpoints": len(items),
            "by_category": by_cat,
            "deprecated": len([e for e in items if e.deprecated]),
            "tokens_active": len([t for t in self.tokens.values()
                                  if t["status"] == "active"]),
            "changes": len(self.changes),
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_manager: Optional[ApiDocsManager] = None


def get_api_docs_manager() -> ApiDocsManager:
    global _manager
    if _manager is None:
        _manager = ApiDocsManager()
    return _manager
