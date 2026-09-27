# -*- coding: utf-8 -*-
"""
api_docs_center.py — API文档中心模块。

提供自动API文档、交互式调试、API分类搜索、变更日志、最佳实践，
并支持真实扫描项目中的API路由自动生成端点列表。
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional


_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #
def _safe_read(path: str, max_lines: int = 200) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                lines.append(line.rstrip())
            return "\n".join(lines)
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# 1. 自动API文档（真实扫描路由文件）
# --------------------------------------------------------------------------- #
def get_auto_api_docs() -> Dict[str, Any]:
    """扫描项目所有路由文件，自动生成API文档和端点列表。"""
    endpoints = _scan_all_routes()
    return {
        "title": "AI Hacking Agent — API 文档",
        "openapi_version": "3.0.3",
        "info": {
            "title": "AI Hacking Agent REST API",
            "version": "v19.0",
            "description": (
                "全栈式智能安全评估平台API，覆盖32大安全方向。"
                "所有端点前缀 /api/v1/，统一响应 {success, data, error}。"
            ),
            "contact": "security-team@internal",
        },
        "total_endpoints": len(endpoints),
        "endpoints": endpoints,
        "servers": [
            {"url": "http://localhost:8000", "description": "本地开发"},
        ],
        "scan_info": {
            "scanned_directory": os.path.join(_PROJECT_ROOT, "api_server"),
            "route_files_found": len([
                f for f in os.listdir(os.path.join(_PROJECT_ROOT, "api_server"))
                if f.endswith("_routes.py")
            ]) if os.path.isdir(os.path.join(_PROJECT_ROOT, "api_server")) else 0,
        },
    }


def _scan_all_routes() -> List[Dict[str, Any]]:
    """扫描所有 *_routes.py 文件，提取端点信息。"""
    endpoints = []
    api_server_dir = os.path.join(_PROJECT_ROOT, "api_server")
    if not os.path.isdir(api_server_dir):
        return _get_fallback_endpoints()

    try:
        for fname in sorted(os.listdir(api_server_dir)):
            if not fname.endswith("_routes.py"):
                continue
            fpath = os.path.join(api_server_dir, fname)
            content = _safe_read(fpath, max_lines=500)

            # 提取路由前缀和标签
            prefix_match = re.search(r'prefix\s*=\s*["\']([^"\']+)["\']', content)
            api_prefix = prefix_match.group(1) if prefix_match else "/api/v1/unknown"

            tag_match = re.search(r'tags\s*=\s*\[(.*?)\]', content)
            tag = tag_match.group(1).strip().strip('"').strip("'") if tag_match else fname.replace("_routes.py", "")

            # 提取所有端点
            for match in re.finditer(
                r'@router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']*)["\']',
                content,
            ):
                method = match.group(1).upper()
                path_suffix = match.group(2)
                full_path = api_prefix + path_suffix

                # 尝试提取函数名和docstring
                rest = content[match.end():]
                func_match = re.match(
                    r'\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)',
                    rest,
                )
                func_name = func_match.group(1) if func_match else "unknown"

                # 推断描述
                desc = func_name.replace("_", " ").strip()

                endpoints.append({
                    "method": method,
                    "path": full_path,
                    "function": func_name,
                    "source_file": fname,
                    "tag": tag,
                    "description": desc,
                })
    except Exception:
        return _get_fallback_endpoints()

    return endpoints


def _get_fallback_endpoints() -> List[Dict[str, Any]]:
    """回退端点列表。"""
    sample_domains = [
        ("web-security", "Web安全", [
            ("POST", "/scan", "启动Web漏洞扫描"),
            ("GET", "/scan/{task_id}", "查询扫描任务状态"),
            ("GET", "/results/{task_id}", "获取扫描结果"),
        ]),
        ("vulnerabilities", "漏洞管理", [
            ("GET", "/", "获取漏洞列表"),
            ("GET", "/{vuln_id}", "获取漏洞详情"),
            ("PUT", "/{vuln_id}/status", "更新漏洞状态"),
        ]),
        ("data-security", "数据安全", [
            ("POST", "/classify", "数据分类识别"),
            ("GET", "/policies", "获取DLP策略"),
        ]),
    ]
    endpoints = []
    for prefix, tag, paths in sample_domains:
        for method, suffix, desc in paths:
            endpoints.append({
                "method": method,
                "path": f"/api/v1/{prefix}{suffix}",
                "function": suffix.strip("/").replace("/", "_") or "list",
                "source_file": f"{prefix.replace('-', '_')}_routes.py",
                "tag": tag,
                "description": desc,
            })
    return endpoints


# --------------------------------------------------------------------------- #
# 2. 交互式API调试
# --------------------------------------------------------------------------- #
def get_interactive_debug_info() -> Dict[str, Any]:
    """交互式API调试信息。"""
    return {
        "title": "交互式 API 调试台",
        "features": [
            {
                "name": "Try it out",
                "description": "在线填写参数并发送请求，实时查看响应",
            },
            {
                "name": "cURL 生成",
                "description": "根据填写的参数自动生成cURL命令",
            },
            {
                "name": "代码示例",
                "description": "提供Python/JavaScript/cURL多语言示例",
            },
            {
                "name": "历史记录",
                "description": "自动保存最近50条调试请求",
            },
        ],
        "request_builder": {
            "method_selector": ["GET", "POST", "PUT", "DELETE", "PATCH"],
            "url_input": "完整API路径，如 /api/v1/vulnerabilities",
            "headers": [
                {"key": "Content-Type", "value": "application/json"},
                {"key": "X-API-Key", "value": "<your-api-key>"},
            ],
            "body_editor": "JSON格式请求体编辑器",
            "response_viewer": "格式化JSON响应，支持语法高亮",
        },
        "code_snippets": {
            "python": (
                "import requests\n"
                "resp = requests.get(\n"
                "    'http://localhost:8000/api/v1/vulnerabilities',\n"
                "    headers={'X-API-Key': 'your-key'}\n"
                ")\n"
                "print(resp.json())"
            ),
            "javascript": (
                "const resp = await fetch('/api/v1/vulnerabilities', {\n"
                "  headers: { 'X-API-Key': 'your-key' }\n"
                "});\n"
                "const data = await resp.json();\n"
                "console.log(data);"
            ),
            "curl": (
                "curl -X GET 'http://localhost:8000/api/v1/vulnerabilities' \\\n"
                "  -H 'X-API-Key: your-key'"
            ),
        },
    }


# --------------------------------------------------------------------------- #
# 3. API分类与搜索
# --------------------------------------------------------------------------- #
def get_api_categories() -> Dict[str, Any]:
    """API分类体系。"""
    endpoints = _scan_all_routes()

    # 按tag分类
    by_tag: Dict[str, List[Dict[str, Any]]] = {}
    for ep in endpoints:
        tag = ep.get("tag", "未分类")
        by_tag.setdefault(tag, []).append(ep)

    # 按方法分类
    by_method: Dict[str, int] = {}
    for ep in endpoints:
        m = ep["method"]
        by_method[m] = by_method.get(m, 0) + 1

    return {
        "total_endpoints": len(endpoints),
        "by_tag": {k: len(v) for k, v in sorted(by_tag.items())},
        "by_method": by_method,
        "categories_detail": [
            {"tag": k, "count": len(v), "endpoints": v[:10]}
            for k, v in sorted(by_tag.items())
        ],
        "search_features": [
            "全文搜索：端点路径、描述、函数名",
            "按HTTP方法过滤",
            "按标签/领域过滤",
            "收藏端点：保存常用API",
            "最近访问：自动记录最近查看的端点",
            "搜索建议：输入时自动补全",
        ],
        "search_example": {
            "query": "扫描",
            "filters": {"method": "POST", "tag": "Web安全"},
            "result_count": "自动计算",
        },
    }


# --------------------------------------------------------------------------- #
# 4. API变更日志
# --------------------------------------------------------------------------- #
def get_api_changelog() -> Dict[str, Any]:
    """API变更日志。"""
    return {
        "title": "API 变更日志",
        "versions": [
            {
                "version": "v19.0",
                "date": "2026-09",
                "changes": [
                    {"type": "new", "endpoint": "/api/v1/docs-center/*", "desc": "新增文档体系API（30+端点）"},
                    {"type": "new", "endpoint": "/api/v1/docs-center/architecture/*", "desc": "架构文档体系"},
                    {"type": "new", "endpoint": "/api/v1/docs-center/api-docs/*", "desc": "API文档中心"},
                    {"type": "new", "endpoint": "/api/v1/docs-center/user-guides/*", "desc": "用户手册与指南"},
                    {"type": "new", "endpoint": "/api/v1/docs-center/deployment/*", "desc": "部署运维文档"},
                    {"type": "new", "endpoint": "/api/v1/docs-center/knowledge/*", "desc": "知识库与最佳实践"},
                    {"type": "new", "endpoint": "/api/v1/docs-center/management/*", "desc": "文档管理与运营"},
                ],
            },
            {
                "version": "v18.0",
                "date": "2026-08",
                "changes": [
                    {"type": "new", "endpoint": "/api/v1/data-security/*", "desc": "数据安全与隐私保护模块（35端点）"},
                    {"type": "modified", "endpoint": "/api/v1/vulnerabilities", "desc": "新增severity排序参数"},
                ],
            },
            {
                "version": "v17.0",
                "date": "2026-07",
                "changes": [
                    {"type": "new", "endpoint": "/api/v1/combat/*", "desc": "实战训练模块"},
                    {"type": "deprecation", "endpoint": "/api/v1/legacy/*", "desc": "旧版API标记废弃"},
                ],
            },
        ],
        "change_types": {
            "new": "新增端点，向后兼容",
            "modified": "修改端点，可能有参数变化",
            "deprecated": "标记废弃，将在未来版本移除",
            "breaking": "破坏性变更，需迁移",
        },
        "migration_guide": (
            "1. 阅读变更日志，识别影响范围\n"
            "2. 更新API调用路径和参数\n"
            "3. 运行回归测试\n"
            "4. 确认兼容性后切换流量"
        ),
    }


# --------------------------------------------------------------------------- #
# 5. API最佳实践
# --------------------------------------------------------------------------- #
def get_api_best_practices() -> Dict[str, Any]:
    """API最佳实践库。"""
    return {
        "title": "API 设计最佳实践",
        "practices": [
            {
                "category": "命名规范",
                "items": [
                    {"title": "URL用名词复数", "desc": "/vulnerabilities 而非 /getVulnerabilities"},
                    {"title": "HTTP方法表达操作", "desc": "GET查询、POST创建、PUT更新、DELETE删除"},
                    {"title": "snake_case字段", "desc": "请求/响应JSON字段用snake_case"},
                    {"title": "kebab-case路径", "desc": "URL路径用kebab-case，如 /web-security/scan"},
                ],
            },
            {
                "category": "分页与排序",
                "items": [
                    {"title": "offset分页", "desc": "?page=1&page_size=20，默认page_size=20"},
                    {"title": "最大限制", "desc": "page_size最大100，防止滥用"},
                    {"title": "排序参数", "desc": "?sort_by=created_at&order=desc"},
                ],
            },
            {
                "category": "错误处理",
                "items": [
                    {"title": "统一响应格式", "desc": "{success: bool, data: any, error: string|null}"},
                    {"title": "合适的HTTP状态码", "desc": "400参数错、401未认证、403无权限、404不存在"},
                    {"title": "错误描述清晰", "desc": "error字段提供人类可读的错误描述"},
                    {"title": "try-except兜底", "desc": "所有端点try-except包裹，不抛500"},
                ],
            },
            {
                "category": "认证与限流",
                "items": [
                    {"title": "API Key认证", "desc": "Header: X-API-Key"},
                    {"title": "按用户限流", "desc": "每用户60次/分钟"},
                    {"title": "密钥安全存储", "desc": "环境变量管理，不硬编码"},
                ],
            },
            {
                "category": "幂等性",
                "items": [
                    {"title": "GET天然幂等", "desc": "重复GET不产生副作用"},
                    {"title": "POST幂等Key", "desc": "重要POST请求携带Idempotency-Key头"},
                ],
            },
            {
                "category": "缓存策略",
                "items": [
                    {"title": "GET可缓存", "desc": "查询类端点设置Cache-Control"},
                    {"title": "POST不缓存", "desc": "操作类请求不缓存"},
                ],
            },
            {
                "category": "版本化",
                "items": [
                    {"title": "URL路径版本", "desc": "/api/v1/...，当前版本v1"},
                    {"title": "向后兼容", "desc": "新增字段不破坏现有客户端"},
                    {"title": "废弃流程", "desc": "标记DeprecationWarning → 维护6个月 → 移除"},
                ],
            },
        ],
    }


# --------------------------------------------------------------------------- #
# OpenAPI 3.0 规范生成
# --------------------------------------------------------------------------- #
def get_openapi_spec() -> Dict[str, Any]:
    """生成OpenAPI 3.0规范文档。"""
    endpoints = _scan_all_routes()

    paths: Dict[str, Any] = {}
    for ep in endpoints:
        path = ep["path"]
        method = ep["method"].lower()
        if path not in paths:
            paths[path] = {}
        paths[path][method] = {
            "summary": ep["description"],
            "tags": [ep["tag"]],
            "operationId": ep["function"],
            "responses": {
                "200": {
                    "description": "成功响应",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "success": {"type": "boolean"},
                                    "data": {"type": "object"},
                                    "error": {"type": "string", "nullable": True},
                                },
                            }
                        }
                    },
                },
                "400": {"description": "请求参数错误"},
                "500": {"description": "服务器内部错误（已兜底）"},
            },
        }

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "AI Hacking Agent API",
            "version": "v19.0",
            "description": "全栈式智能安全评估平台OpenAPI规范",
        },
        "servers": [{"url": "http://localhost:8000"}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                }
            }
        },
        "security": [{"ApiKeyAuth": []}],
    }
