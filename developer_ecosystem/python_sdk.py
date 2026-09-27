# -*- coding: utf-8 -*-
"""
python_sdk.py — Python SDK 与 API 文档（第24轮升级方向4 / 模块4）。

包含：
  - SDK 核心：客户端初始化 / 认证管理 / 请求处理 / 响应解析 / 错误处理 / 重试 / 超时 / 日志
  - API 封装：资产 / 扫描任务 / 漏洞 / 报告 / 威胁情报 / 用户 / 系统管理
  - 高级功能：异步支持 / 批量操作 / 流式响应 / 分页处理 / 缓存 / 数据导入导出
  - 示例与教程：快速开始 / 基础示例 / 高级示例 / 最佳实践 / FAQ / 故障排查
  - API 文档：自动生成 / 交互式文档 / 代码示例 / 参数说明 / 响应说明 / 错误码 / 版本说明
  - SDK 版本管理：版本列表 / 对比 / 升级指南 / 弃用说明 / 兼容性矩阵 / 发布说明

全部内存字典模拟。
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, Generator, List, Optional

# 第三方 try-import
try:
    import httpx  # type: ignore
    _HAS_HTTPX = True
except Exception:
    httpx = None  # type: ignore
    _HAS_HTTPX = False

try:
    import requests  # type: ignore
    _HAS_REQUESTS = True
except Exception:
    requests = None  # type: ignore
    _HAS_REQUESTS = False


# ==================== SDK 核心 ====================

class SDKError(Exception):
    """SDK 统一异常"""
    def __init__(self, message: str, code: str = "UNKNOWN", status_code: int = 0):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


class AuthenticationError(SDKError):
    """认证失败"""
    def __init__(self, msg: str = "API 认证失败"):
        super().__init__(msg, "AUTH_ERROR", 401)


class RateLimitError(SDKError):
    """限流"""
    def __init__(self, msg: str = "请求过于频繁"):
        super().__init__(msg, "RATE_LIMITED", 429)


class NotFoundError(SDKError):
    """资源不存在"""
    def __init__(self, msg: str = "资源不存在"):
        super().__init__(msg, "NOT_FOUND", 404)


@dataclass
class RetryConfig:
    """重试配置"""
    max_retries: int = 3
    backoff_factor: float = 0.5
    retry_on_status: List[int] = field(default_factory=lambda: [429, 500, 502, 503, 504])


@dataclass
class SDKConfig:
    """SDK 客户端配置"""
    api_endpoint: str = "http://127.0.0.1:8000"
    api_key: str = ""
    timeout: float = 30.0
    max_retries: int = 3
    retry_backoff: float = 0.5
    verify_ssl: bool = True
    proxy: str = ""
    log_level: str = "WARNING"
    user_agent: str = "aha-python-sdk/24.4.0"


class ResponseParser:
    """响应解析器"""

    @staticmethod
    def parse(raw: Dict[str, Any]) -> Dict[str, Any]:
        success = raw.get("success", False)
        data = raw.get("data")
        error = raw.get("error")
        if not success:
            code = "API_ERROR"
            if error and "auth" in str(error).lower():
                raise AuthenticationError(str(error))
            if error and "not found" in str(error).lower():
                raise NotFoundError(str(error))
            raise SDKError(str(error) or "未知错误", code)
        return data or {}


class AhaClient:
    """AHA Python SDK 同步客户端"""

    def __init__(self, api_endpoint: str = "", api_key: str = "", **kwargs: Any):
        self.config = SDKConfig(
            api_endpoint=api_endpoint or SDKConfig.api_endpoint,
            api_key=api_key or SDKConfig.api_key,
            **{k: v for k, v in kwargs.items() if k in SDKConfig.__dataclass_fields__},
        )
        self.logger = logging.getLogger("aha-sdk")
        self.logger.setLevel(getattr(logging, self.config.log_level, logging.WARNING))
        self.cache: Dict[str, Any] = {}
        self.cache_ttl: Dict[str, float] = {}
        self._request_count: int = 0
        self._total_latency_ms: float = 0.0

        # 子模块 API
        self.assets = AssetAPI(self)
        self.scans = ScanTaskAPI(self)
        self.vulns = VulnerabilityAPI(self)
        self.reports = ReportAPI(self)
        self.threats = ThreatIntelAPI(self)
        self.users = UserAPI(self)
        self.system = SystemAPI(self)

    # ---------- 请求核心 ----------
    def _request(self, method: str, path: str, params: Optional[Dict] = None,
                 json_body: Optional[Dict] = None) -> Dict[str, Any]:
        """模拟 HTTP 请求（带重试/超时/缓存）"""
        url = f"{self.config.api_endpoint}{path}"
        cache_key = f"{method}:{path}:{json.dumps(params or {}, sort_keys=True)}"

        # 缓存检查
        if method == "GET" and cache_key in self.cache:
            ttl = self.cache_ttl.get(cache_key, 0)
            if time.time() < ttl:
                self.logger.debug("Cache hit: %s", path)
                return self.cache[cache_key]

        # 重试循环
        last_err: Optional[Exception] = None
        for attempt in range(self.config.max_retries + 1):
            try:
                t0 = time.time()
                # 模拟请求延迟
                result = self._mock_response(method, path, params, json_body)
                elapsed = (time.time() - t0) * 1000
                self._request_count += 1
                self._total_latency_ms += elapsed

                # 缓存写入
                if method == "GET":
                    self.cache[cache_key] = result
                    self.cache_ttl[cache_key] = time.time() + 60

                return ResponseParser.parse(result)
            except SDKError as e:
                last_err = e
                if e.code not in ("RATE_LIMITED", "SERVER_ERROR") or attempt >= self.config.max_retries:
                    raise
                time.sleep(self.config.retry_backoff * (2 ** attempt))
            except Exception as e:
                last_err = e
                if attempt >= self.config.max_retries:
                    raise SDKError(str(e))
                time.sleep(self.config.retry_backoff * (2 ** attempt))

        raise SDKError(str(last_err) if last_err else "请求失败")

    def _mock_response(self, method: str, path: str,
                       params: Optional[Dict], body: Optional[Dict]) -> Dict[str, Any]:
        """根据路径模拟响应数据"""
        mock_db: Dict[str, Dict] = {
            "/api/v1/assets": {"items": [
                {"id": "ast-001", "name": "Web服务器", "type": "host", "address": "10.0.0.1"},
                {"id": "ast-002", "name": "数据库", "type": "host", "address": "10.0.0.2"},
            ], "total": 2},
            "/api/v1/scans": {"items": [
                {"id": "scan-001", "type": "port", "status": "completed", "progress": 100},
            ], "total": 1},
            "/api/v1/vulns": {"items": [
                {"id": "v-001", "cve": "CVE-2024-23334", "severity": "high", "cvss": 7.5},
            ], "total": 1},
            "/api/v1/reports": {"items": [
                {"id": "rpt-001", "title": "安全报告", "status": "generated"},
            ], "total": 1},
        }
        for prefix, data in mock_db.items():
            if path.startswith(prefix):
                return {"success": True, "data": data, "error": None}
        return {"success": True, "data": {"path": path, "method": method, "received": True}, "error": None}

    def get_stats(self) -> Dict[str, Any]:
        return {
            "requests": self._request_count,
            "avg_latency_ms": round(self._total_latency_ms / max(self._request_count, 1), 2),
            "cache_entries": len(self.cache),
            "endpoint": self.config.api_endpoint,
        }


class AsyncAhaClient:
    """异步 SDK 客户端"""

    def __init__(self, api_endpoint: str = "", api_key: str = "", **kwargs: Any):
        self.config = SDKConfig(api_endpoint=api_endpoint, api_key=api_key, **kwargs)
        self._request_count: int = 0

    async def _request(self, method: str, path: str,
                       params: Optional[Dict] = None, body: Optional[Dict] = None) -> Dict[str, Any]:
        """异步模拟请求"""
        await asyncio.sleep(0.01)  # 模拟网络延迟
        self._request_count += 1
        return {"path": path, "method": method, "async": True, "received": True}

    async def get(self, path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        return await self._request("GET", path, params=params)

    async def post(self, path: str, body: Optional[Dict] = None) -> Dict[str, Any]:
        return await self._request("POST", path, body=body)

    async def batch(self, requests_list: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """批量异步请求"""
        tasks = [self._request(r.get("method", "GET"), r.get("path", "/")) for r in requests_list]
        return await asyncio.gather(*tasks)

    async def stream(self, path: str) -> AsyncGenerator[Dict[str, Any], None]:
        """流式响应模拟"""
        for i in range(5):
            await asyncio.sleep(0.05)
            yield {"chunk": i, "data": f"stream_line_{i}", "path": path}


# ==================== API 封装 ====================

class AssetAPI:
    """资产管理 API 封装"""
    def __init__(self, client: AhaClient):
        self.c = client

    def list(self, group: str = "", page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        return self.c._request("GET", "/api/v1/assets", params={"group": group, "page": page, "page_size": page_size})

    def get(self, asset_id: str) -> Dict[str, Any]:
        return self.c._request("GET", f"/api/v1/assets/{asset_id}")

    def create(self, name: str, atype: str = "host", address: str = "") -> Dict[str, Any]:
        return self.c._request("POST", "/api/v1/assets", body={"name": name, "type": atype, "address": address})

    def delete(self, asset_id: str) -> Dict[str, Any]:
        return self.c._request("DELETE", f"/api/v1/assets/{asset_id}")

    def update(self, asset_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return self.c._request("PUT", f"/api/v1/assets/{asset_id}", body=data)


class ScanTaskAPI:
    """扫描任务 API 封装"""
    def __init__(self, client: AhaClient):
        self.c = client

    def list(self, status: str = "") -> Dict[str, Any]:
        return self.c._request("GET", "/api/v1/scans", params={"status": status})

    def create(self, scan_type: str, target: str, config: Optional[Dict] = None) -> Dict[str, Any]:
        return self.c._request("POST", "/api/v1/scans", body={"type": scan_type, "target": target, "config": config or {}})

    def get(self, scan_id: str) -> Dict[str, Any]:
        return self.c._request("GET", f"/api/v1/scans/{scan_id}")

    def cancel(self, scan_id: str) -> Dict[str, Any]:
        return self.c._request("POST", f"/api/v1/scans/{scan_id}/cancel")

    def results(self, scan_id: str) -> Dict[str, Any]:
        return self.c._request("GET", f"/api/v1/scans/{scan_id}/results")


class VulnerabilityAPI:
    """漏洞管理 API 封装"""
    def __init__(self, client: AhaClient):
        self.c = client

    def list(self, severity: str = "", asset_id: str = "") -> Dict[str, Any]:
        return self.c._request("GET", "/api/v1/vulns", params={"severity": severity, "asset_id": asset_id})

    def get(self, vuln_id: str) -> Dict[str, Any]:
        return self.c._request("GET", f"/api/v1/vulns/{vuln_id}")

    def update_status(self, vuln_id: str, status: str) -> Dict[str, Any]:
        return self.c._request("PATCH", f"/api/v1/vulns/{vuln_id}", body={"status": status})

    def stats(self) -> Dict[str, Any]:
        return self.c._request("GET", "/api/v1/vulns/stats")


class ReportAPI:
    """报告生成 API 封装"""
    def __init__(self, client: AhaClient):
        self.c = client

    def list(self) -> Dict[str, Any]:
        return self.c._request("GET", "/api/v1/reports")

    def generate(self, scan_id: str, fmt: str = "pdf") -> Dict[str, Any]:
        return self.c._request("POST", "/api/v1/reports/generate", body={"scan_id": scan_id, "format": fmt})

    def download(self, report_id: str) -> Dict[str, Any]:
        return self.c._request("GET", f"/api/v1/reports/{report_id}/download")


class ThreatIntelAPI:
    """威胁情报 API 封装"""
    def __init__(self, client: AhaClient):
        self.c = client

    def query(self, indicator: str, itype: str = "ip") -> Dict[str, Any]:
        return self.c._request("GET", "/api/v1/threat-intel/query", params={"indicator": indicator, "type": itype})

    def feeds(self) -> Dict[str, Any]:
        return self.c._request("GET", "/api/v1/threat-intel/feeds")


class UserAPI:
    """用户管理 API 封装"""
    def __init__(self, client: AhaClient):
        self.c = client

    def me(self) -> Dict[str, Any]:
        return self.c._request("GET", "/api/v1/users/me")

    def list(self) -> Dict[str, Any]:
        return self.c._request("GET", "/api/v1/users")


class SystemAPI:
    """系统管理 API 封装"""
    def __init__(self, client: AhaClient):
        self.c = client

    def health(self) -> Dict[str, Any]:
        return self.c._request("GET", "/api/v1/system/health")

    def status(self) -> Dict[str, Any]:
        return self.c._request("GET", "/api/v1/system/status")

    def metrics(self) -> Dict[str, Any]:
        return self.c._request("GET", "/api/v1/system/metrics")


# ==================== 高级功能 ====================

class BatchOperations:
    """批量操作工具"""

    def __init__(self, client: AhaClient):
        self.c = client

    def batch_create_assets(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """批量创建资产"""
        results = []
        for item in items:
            results.append(self.c.assets.create(**item))
        return {"total": len(items), "success": len(results), "results": results}

    def batch_scan(self, targets: List[str], scan_type: str = "port") -> Dict[str, Any]:
        """批量发起扫描"""
        results = []
        for target in targets:
            results.append(self.c.scans.create(scan_type, target))
        return {"total": len(targets), "scans_created": len(results), "results": results}


class Paginator:
    """分页处理工具"""

    def __init__(self, client: AhaClient, path: str, params: Optional[Dict] = None):
        self.client = client
        self.path = path
        self.params = params or {}
        self.page = 1
        self.page_size = 20

    def __iter__(self) -> Generator[Dict[str, Any], None, None]:
        while True:
            self.params["page"] = self.page
            self.params["page_size"] = self.page_size
            data = self.client._request("GET", self.path, params=self.params)
            items = data.get("items", [])
            if not items:
                break
            yield from items
            total = data.get("total", 0)
            if self.page * self.page_size >= total:
                break
            self.page += 1


# ==================== 示例与教程 ====================

class SDKExamples:
    """SDK 示例代码"""

    @staticmethod
    def quickstart() -> str:
        return """
# 快速开始
from aha_sdk import AhaClient

client = AhaClient(api_endpoint="http://127.0.0.1:8000", api_key="your-api-key")

# 列出资产
assets = client.assets.list()
print(assets)

# 发起端口扫描
scan = client.scans.create("port", "192.168.1.1")
print(scan)
"""

    @staticmethod
    def basic_examples() -> List[Dict[str, str]]:
        return [
            {"title": "创建资产", "code": 'asset = client.assets.create("Web服务器", "host", "10.0.0.1")'},
            {"title": "查询漏洞", "code": 'vulns = client.vulns.list(severity="high")'},
            {"title": "生成报告", "code": 'report = client.reports.generate("scan-001", "pdf")'},
            {"title": "威胁情报查询", "code": 'result = client.threats.query("8.8.8.8", "ip")'},
        ]

    @staticmethod
    def advanced_examples() -> List[Dict[str, str]]:
        return [
            {"title": "异步批量扫描", "code": """
async with AsyncAhaClient() as ac:
    results = await ac.batch([
        {"method": "POST", "path": "/api/v1/scans"},
        {"method": "POST", "path": "/api/v1/scans"},
    ])
"""},
            {"title": "分页遍历", "code": """
paginator = Paginator(client, "/api/v1/vulns")
for vuln in paginator:
    print(vuln)
"""},
            {"title": "流式结果", "code": """
async for chunk in ac.stream("/api/v1/scans/001/results"):
    print(chunk)
"""},
        ]

    @staticmethod
    def best_practices() -> List[str]:
        return [
            "始终使用环境变量存储 API Key，不要硬编码",
            "生产环境设置合理的超时和重试",
            "利用缓存减少重复请求",
            "批量操作使用 batch 接口减少网络开销",
            "异步场景使用 AsyncAhaClient",
        ]

    @staticmethod
    def faq() -> List[Dict[str, str]]:
        return [
            {"q": "如何获取 API Key？", "a": "登录开发者门户，在 API 密钥页面创建"},
            {"q": "请求被限流怎么办？", "a": "降低请求频率，或使用指数退避重试"},
            {"q": "SDK 支持哪些 Python 版本？", "a": "Python 3.8+"},
        ]

    @staticmethod
    def troubleshooting() -> List[Dict[str, str]]:
        return [
            {"error": "Connection refused", "cause": "API 服务未启动", "solution": "检查服务地址和端口"},
            {"error": "401 Unauthorized", "cause": "API Key 无效", "solution": "重新生成 API Key"},
            {"error": "429 Too Many Requests", "cause": "触发限流", "solution": "降低频率或申请提升配额"},
        ]


# ==================== API 文档自动生成 ====================

class APIDocumentation:
    """自动生成 API 文档"""

    ENDPOINTS: List[Dict[str, Any]] = [
        {"method": "GET", "path": "/api/v1/assets", "summary": "列出资产", "params": ["group", "page", "page_size"], "response": "资产列表"},
        {"method": "POST", "path": "/api/v1/assets", "summary": "创建资产", "params": ["name", "type", "address"], "response": "资产对象"},
        {"method": "GET", "path": "/api/v1/assets/{id}", "summary": "获取资产详情", "params": ["id"], "response": "资产详情"},
        {"method": "DELETE", "path": "/api/v1/assets/{id}", "summary": "删除资产", "params": ["id"], "response": "操作结果"},
        {"method": "POST", "path": "/api/v1/scans", "summary": "创建扫描任务", "params": ["type", "target", "config"], "response": "任务对象"},
        {"method": "GET", "path": "/api/v1/scans", "summary": "列出扫描任务", "params": ["status"], "response": "任务列表"},
        {"method": "GET", "path": "/api/v1/vulns", "summary": "列出漏洞", "params": ["severity", "asset_id"], "response": "漏洞列表"},
        {"method": "GET", "path": "/api/v1/reports", "summary": "列出报告", "params": [], "response": "报告列表"},
    ]

    ERROR_CODES: Dict[str, Dict[str, str]] = {
        "AUTH_ERROR": {"http_status": "401", "description": "认证失败", "solution": "检查 API Key"},
        "NOT_FOUND": {"http_status": "404", "description": "资源不存在", "solution": "检查请求路径"},
        "RATE_LIMITED": {"http_status": "429", "description": "请求超限", "solution": "降低请求频率"},
        "VALIDATION_ERROR": {"http_status": "400", "description": "参数校验失败", "solution": "检查参数格式"},
        "SERVER_ERROR": {"http_status": "500", "description": "服务器错误", "solution": "稍后重试或联系支持"},
    }

    @classmethod
    def generate_markdown(cls) -> str:
        lines = ["# AHA Security API 文档", "", f"版本: 24.4.0", ""]
        for ep in cls.ENDPOINTS:
            lines.append(f"## {ep['method']} {ep['path']}")
            lines.append(f"**摘要**: {ep['summary']}")
            lines.append(f"**参数**: {', '.join(ep['params'])}")
            lines.append(f"**响应**: {ep['response']}")
            lines.append("")
        return "\n".join(lines)

    @classmethod
    def generate_openapi(cls) -> Dict[str, Any]:
        """生成 OpenAPI 3.0 规范"""
        paths: Dict[str, Any] = {}
        for ep in cls.ENDPOINTS:
            path = ep["path"].replace("{id}", "{id}")
            if path not in paths:
                paths[path] = {}
            paths[path][ep["method"].lower()] = {
                "summary": ep["summary"],
                "parameters": [{"name": p, "in": "query", "required": False} for p in ep["params"]],
                "responses": {"200": {"description": "成功"}},
            }
        return {
            "openapi": "3.0.3",
            "info": {"title": "AHA Security API", "version": "24.4.0"},
            "paths": paths,
        }

    @classmethod
    def get_error_codes(cls) -> Dict[str, Dict[str, str]]:
        return cls.ERROR_CODES


# ==================== SDK 版本管理 ====================

class SDKVersionManager:
    """SDK 版本管理"""

    VERSIONS: List[Dict[str, Any]] = [
        {"version": "24.4.0", "released": "2026-09-15", "status": "stable", "changes": ["新增开发者生态模块", "性能优化"]},
        {"version": "24.3.0", "released": "2026-08-01", "status": "stable", "changes": ["新增威胁情报API"]},
        {"version": "24.2.0", "released": "2026-07-01", "status": "stable", "changes": ["修复已知问题"]},
        {"version": "24.1.0", "released": "2026-06-01", "status": "deprecated", "changes": ["初始版本"]},
    ]

    COMPATIBILITY_MATRIX: Dict[str, Dict[str, str]] = {
        "24.4.x": {"python": ">=3.8", "api_version": "v1", "deps": "httpx>=0.24"},
        "24.3.x": {"python": ">=3.8", "api_version": "v1", "deps": "httpx>=0.23"},
        "24.2.x": {"python": ">=3.7", "api_version": "v1", "deps": "requests>=2.28"},
    }

    @classmethod
    def list_versions(cls) -> List[Dict[str, Any]]:
        return cls.VERSIONS

    @classmethod
    def compare_versions(cls, v1: str, v2: str) -> Dict[str, Any]:
        return {"version_a": v1, "version_b": v2, "breaking_changes": False, "new_features": 5, "bug_fixes": 3}

    @classmethod
    def upgrade_guide(cls, from_ver: str, to_ver: str = "24.4.0") -> Dict[str, Any]:
        return {
            "from": from_ver, "to": to_ver,
            "steps": [
                f"pip install --upgrade aha-sdk=={to_ver}",
                "检查 import 兼容性",
                "运行迁移脚本（如有）",
                "测试核心流程",
            ],
            "breaking_changes": [],
        }

    @classmethod
    def deprecations(cls) -> List[Dict[str, str]]:
        return [
            {"api": "client.legacy_scan()", "deprecated_in": "24.3.0", "sunset_in": "25.0.0", "replacement": "client.scans.create()"},
        ]


# ==================== 单例 ====================

sdk_client = AhaClient()
async_sdk_client = AsyncAhaClient()
sdk_examples = SDKExamples()
api_docs = APIDocumentation()
sdk_versions = SDKVersionManager()

__all__ = [
    "AhaClient", "AsyncAhaClient", "SDKConfig", "SDKError",
    "AuthenticationError", "RateLimitError", "NotFoundError", "RetryConfig",
    "AssetAPI", "ScanTaskAPI", "VulnerabilityAPI", "ReportAPI",
    "ThreatIntelAPI", "UserAPI", "SystemAPI",
    "BatchOperations", "Paginator", "SDKExamples", "APIDocumentation",
    "SDKVersionManager", "sdk_client", "async_sdk_client",
]
