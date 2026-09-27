# -*- coding: utf-8 -*-
"""api_docs.py — API 文档中心。

能力：
- 自动汇总 OpenAPI 3.0 规范（基于内存中的接口清单）
- 接口分类、全文搜索、版本管理
- 变更日志（changelog）、示例代码、错误码文档、SDK 文档索引
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 接口清单（模拟 OpenAPI paths）
# --------------------------------------------------------------------------- #
API_ENDPOINTS: List[Dict[str, Any]] = [
    {
        "id": "ep_auth_login",
        "method": "POST",
        "path": "/api/v1/auth/login",
        "category": "认证",
        "title": "用户登录",
        "version": "v1",
        "description": "使用账号密码或 OAuth 凭证换取访问令牌。",
        "auth_required": False,
        "rate_limit": "60/min",
        "parameters": [
            {"name": "username", "in": "body", "type": "string", "required": True},
            {"name": "password", "in": "body", "type": "string", "required": True},
        ],
        "response_example": {"access_token": "eyJ...", "expires_in": 3600},
        "errors": ["401 凭证错误", "429 触发限流"],
    },
    {
        "id": "ep_scan_start",
        "method": "POST",
        "path": "/api/v1/scanner/start",
        "category": "扫描",
        "title": "启动安全扫描",
        "version": "v1",
        "description": "对目标资产发起漏洞/配置/组件扫描。",
        "auth_required": True,
        "rate_limit": "30/min",
        "parameters": [
            {"name": "target", "in": "body", "type": "string", "required": True},
            {"name": "modules", "in": "body", "type": "array", "required": False},
        ],
        "response_example": {"task_id": "tsk_xxx", "status": "pending"},
        "errors": ["400 目标非法", "403 权限不足", "429 限流"],
    },
    {
        "id": "ep_scan_status",
        "method": "GET",
        "path": "/api/v1/scanner/{task_id}/status",
        "category": "扫描",
        "title": "查询扫描状态",
        "version": "v1",
        "description": "按 task_id 查询扫描任务进度与结果。",
        "auth_required": True,
        "rate_limit": "120/min",
        "parameters": [
            {"name": "task_id", "in": "path", "type": "string", "required": True},
        ],
        "response_example": {"task_id": "tsk_xxx", "status": "done", "progress": 100},
        "errors": ["404 任务不存在"],
    },
    {
        "id": "ep_report_list",
        "method": "GET",
        "path": "/api/v1/reports",
        "category": "报告",
        "title": "报告列表",
        "version": "v1",
        "description": "分页查询历史报告。",
        "auth_required": True,
        "rate_limit": "60/min",
        "parameters": [
            {"name": "page", "in": "query", "type": "integer", "required": False},
            {"name": "size", "in": "query", "type": "integer", "required": False},
        ],
        "response_example": {"items": [], "total": 0},
        "errors": [],
    },
    {
        "id": "ep_ioc_query",
        "method": "GET",
        "path": "/api/v1/intel/ioc",
        "category": "情报",
        "title": "IOC 情报查询",
        "version": "v1",
        "description": "根据 Hash / IP / 域名查询威胁情报。",
        "auth_required": True,
        "rate_limit": "60/min",
        "parameters": [
            {"name": "indicator", "in": "query", "type": "string", "required": True},
        ],
        "response_example": {"indicator": "x.x.x.x", "verdict": "malicious"},
        "errors": ["400 参数缺失"],
    },
    {
        "id": "ep_asset_create",
        "method": "POST",
        "path": "/api/v1/assets",
        "category": "资产",
        "title": "注册资产",
        "version": "v1",
        "description": "新增一条受管资产记录。",
        "auth_required": True,
        "rate_limit": "60/min",
        "parameters": [
            {"name": "name", "in": "body", "type": "string", "required": True},
            {"name": "type", "in": "body", "type": "string", "required": True},
        ],
        "response_example": {"asset_id": "ast_xxx"},
        "errors": ["400 参数错误"],
    },
]


CHANGELOG: List[Dict[str, Any]] = [
    {
        "version": "v1.4.0",
        "date": "2026-09-10",
        "items": [
            "新增 /api/v1/intel/ioc 情报查询接口",
            "扫描接口新增 modules 字段，支持按模块启用",
            "废弃旧版 /api/v1/scan/legacy（6 个月后下线）",
        ],
    },
    {
        "version": "v1.3.0",
        "date": "2026-08-15",
        "items": [
            "报告接口支持分页 page/size",
            "统一错误码为 4xxxx 段",
        ],
    },
    {
        "version": "v1.0.0",
        "date": "2026-06-01",
        "items": ["首个稳定版本发布"],
    },
]


ERROR_CODES: List[Dict[str, Any]] = [
    {"code": 40001, "name": "INVALID_PARAMS", "http": 400, "message": "请求参数不合法"},
    {"code": 40101, "name": "UNAUTHORIZED", "http": 401, "message": "未提供或访问令牌无效"},
    {"code": 40301, "name": "FORBIDDEN", "http": 403, "message": "无权限访问该资源"},
    {"code": 40401, "name": "NOT_FOUND", "http": 404, "message": "资源不存在"},
    {"code": 42901, "name": "RATE_LIMITED", "http": 429, "message": "触发限流，请稍后重试"},
    {"code": 50001, "name": "INTERNAL_ERROR", "http": 500, "message": "服务器内部错误"},
]


CATEGORIES: List[str] = ["认证", "扫描", "报告", "情报", "资产", "全部"]


class APIDocsCenter:
    """API 文档中心：聚合接口、搜索、版本、示例代码。"""

    def __init__(self) -> None:
        self.endpoints: List[Dict[str, Any]] = [dict(e) for e in API_ENDPOINTS]
        self.changelog: List[Dict[str, Any]] = [dict(c) for c in CHANGELOG]
        self.error_codes: List[Dict[str, Any]] = [dict(c) for c in ERROR_CODES]
        self.versions: List[Dict[str, Any]] = [
            {"version": "v1", "status": "stable", "released": "2026-06-01"},
            {"version": "v2-beta", "status": "beta", "released": "2026-10-01"},
        ]

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def list_endpoints(self, category: str = "全部", keyword: str = "") -> List[Dict[str, Any]]:
        out = []
        for ep in self.endpoints:
            if category and category != "全部" and ep.get("category") != category:
                continue
            if keyword:
                blob = " ".join(str(v) for v in ep.values()).lower()
                if keyword.lower() not in blob:
                    continue
            out.append(ep)
        return out

    def get_endpoint(self, ep_id: str) -> Optional[Dict[str, Any]]:
        for ep in self.endpoints:
            if ep.get("id") == ep_id:
                return ep
        return None

    # ------------------------------------------------------------------ #
    # OpenAPI 3.0 生成
    # ------------------------------------------------------------------ #
    def to_openapi(self, version: str = "v1") -> Dict[str, Any]:
        paths: Dict[str, Any] = {}
        for ep in self.endpoints:
            if version != "全部" and ep.get("version") != version:
                continue
            path = ep["path"]
            method = ep["method"].lower()
            paths.setdefault(path, {})[method] = {
                "summary": ep.get("title"),
                "description": ep.get("description"),
                "tags": [ep.get("category", "")],
                "parameters": [
                    {
                        "name": p["name"],
                        "in": p["in"],
                        "required": p.get("required", False),
                        "schema": {"type": p.get("type", "string")},
                    }
                    for p in ep.get("parameters", [])
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "example": ep.get("response_example", {})
                            }
                        },
                    }
                },
                "security": [{"ApiKeyAuth": []}] if ep.get("auth_required") else [],
            }
        return {
            "openapi": "3.0.3",
            "info": {
                "title": "AI Hacking Agent Open API",
                "version": version,
                "description": "开放 API 平台自动生成的 OpenAPI 3.0 规范",
            },
            "servers": [{"url": "https://api.example.com", "description": "生产"}],
            "paths": paths,
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
                }
            },
        }

    # ------------------------------------------------------------------ #
    # 示例代码
    # ------------------------------------------------------------------ #
    def example_code(self, ep_id: str, language: str = "python") -> str:
        ep = self.get_endpoint(ep_id)
        if not ep:
            return "# 接口不存在"
        method = ep["method"].lower()
        path = ep["path"]
        if language == "python":
            return (
                "import requests\n\n"
                f"url = 'https://api.example.com{path}'\n"
                "headers = {'X-API-Key': 'YOUR_KEY'}\n"
                f"resp = requests.{method}(url, headers=headers, json={{}})\n"
                "print(resp.json())\n"
            )
        if language == "javascript":
            return (
                f"const resp = await fetch('https://api.example.com{path}', {{\n"
                f"  method: '{ep['method']}',\n"
                "  headers: {'X-API-Key': 'YOUR_KEY'}\n"
                "});\n"
                "console.log(await resp.json());\n"
            )
        if language == "curl":
            return (
                f"curl -X {ep['method']} 'https://api.example.com{path}' \\\n"
                "  -H 'X-API-Key: YOUR_KEY'\n"
            )
        return f"// TODO: {language} example for {ep_id}"

    # ------------------------------------------------------------------ #
    # 版本 / 变更 / 错误码
    # ------------------------------------------------------------------ #
    def list_versions(self) -> List[Dict[str, Any]]:
        return self.versions

    def list_changelog(self, version: Optional[str] = None) -> List[Dict[str, Any]]:
        if version:
            return [c for c in self.changelog if c.get("version") == version]
        return self.changelog

    def list_error_codes(self) -> List[Dict[str, Any]]:
        return self.error_codes

    def categories(self) -> List[str]:
        return CATEGORIES


# 单例
_docs_center: Optional[APIDocsCenter] = None


def get_docs_center() -> APIDocsCenter:
    global _docs_center
    if _docs_center is None:
        _docs_center = APIDocsCenter()
    return _docs_center
