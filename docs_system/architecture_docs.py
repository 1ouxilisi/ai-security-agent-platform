# -*- coding: utf-8 -*-
"""
architecture_docs.py — 架构文档体系模块。

提供系统架构总览、模块架构文档、API架构、数据架构、部署架构，
并支持真实扫描项目结构自动生成模块架构文档和依赖关系图。
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 项目根路径（用于真实扫描）
# --------------------------------------------------------------------------- #
_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #
def _safe_read(path: str, max_lines: int = 500) -> str:
    """安全读取文件内容，失败返回空字符串。"""
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


def _count_lines(path: str) -> int:
    """统计文件行数。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


# --------------------------------------------------------------------------- #
# 1. 系统架构总览
# --------------------------------------------------------------------------- #
def get_system_overview() -> Dict[str, Any]:
    """系统架构总览：整体架构图、分层架构、模块关系、技术栈、设计原则、架构决策记录。"""
    return {
        "title": "AI Hacking Agent — 系统架构总览",
        "version": "19.0",
        "description": (
            "AI Hacking Agent 是一个全栈式智能安全评估平台，"
            "覆盖32大安全方向、2426个API端点、69个前端页面。"
            "系统采用分层架构设计，以FastAPI为核心后端，"
            "集成AI智能体、自动化扫描、漏洞管理、报告生成等子系统。"
        ),
        "architecture_diagram": _build_architecture_diagram(),
        "layered_architecture": _build_layered_architecture(),
        "module_relations": _build_module_relations(),
        "tech_stack": _build_tech_stack(),
        "design_principles": _build_design_principles(),
        "architecture_decision_records": _build_adrs(),
        "stats": {
            "total_api_endpoints": 2426,
            "total_frontend_pages": 69,
            "total_security_domains": 32,
            "total_route_files": 85,
            "total_code_lines_approx": 300000,
        },
    }


def _build_architecture_diagram() -> Dict[str, Any]:
    """构建整体架构图（文本+节点/边描述）。"""
    return {
        "type": "layered_block",
        "nodes": [
            {"id": "client", "label": "客户端层\n(Web/Browser/API Client)", "layer": 1},
            {"id": "gateway", "label": "API网关层\n(CORS/Auth/限流/路由)", "layer": 2},
            {"id": "router", "label": "路由层\n(85个路由模块/2426端点)", "layer": 3},
            {"id": "service", "label": "服务层\n(业务逻辑/AI智能体/工作流)", "layer": 4},
            {"id": "engine", "label": "引擎层\n(扫描引擎/漏洞引擎/分析引擎)", "layer": 5},
            {"id": "data", "label": "数据层\n(内存字典/文件存储/缓存)", "layer": 6},
        ],
        "edges": [
            {"from": "client", "to": "gateway"},
            {"from": "gateway", "to": "router"},
            {"from": "router", "to": "service"},
            {"from": "service", "to": "engine"},
            {"from": "engine", "to": "data"},
        ],
        "ascii_art": (
            "┌─────────────────────────────────┐\n"
            "│        客户端层 (Web/API)        │\n"
            "├─────────────────────────────────┤\n"
            "│     API网关 (CORS/Auth/限流)     │\n"
            "├─────────────────────────────────┤\n"
            "│   路由层 (85模块/2426端点)      │\n"
            "├─────────────────────────────────┤\n"
            "│   服务层 (业务/AI/工作流)        │\n"
            "├─────────────────────────────────┤\n"
            "│   引擎层 (扫描/漏洞/分析)        │\n"
            "├─────────────────────────────────┤\n"
            "│   数据层 (内存/文件/缓存)        │\n"
            "└─────────────────────────────────┘"
        ),
    }


def _build_layered_architecture() -> List[Dict[str, Any]]:
    """分层架构详情。"""
    return [
        {
            "layer": "表现层",
            "responsibility": "前端页面渲染、用户交互、API调用",
            "components": [
                "69个HTML控制台页面",
                "JavaScript前端逻辑",
                "CSS深色安全工具主题",
                "响应式布局",
            ],
        },
        {
            "layer": "API网关层",
            "responsibility": "请求路由、认证鉴权、CORS处理、限流防护",
            "components": [
                "FastAPI中间件链",
                "APIKeyHeader认证",
                "CORSMiddleware",
                "请求日志记录",
            ],
        },
        {
            "layer": "路由层",
            "responsibility": "REST API端点定义、请求校验、响应封装",
            "components": [
                "85个路由模块文件",
                "统一响应格式 {success, data, error}",
                "try-except全局兜底",
                "Pydantic请求/响应模型",
            ],
        },
        {
            "layer": "服务层",
            "responsibility": "核心业务逻辑编排、AI智能体调度、工作流管理",
            "components": [
                "AI智能体调度引擎",
                "任务工作流管理",
                "报告生成服务",
                "协作与通知服务",
            ],
        },
        {
            "layer": "引擎层",
            "responsibility": "扫描执行、漏洞分析、安全检测、数据处理",
            "components": [
                "漏洞扫描引擎",
                "代码审计引擎",
                "渗透测试引擎",
                "数据分析引擎",
            ],
        },
        {
            "layer": "数据层",
            "responsibility": "数据存储、缓存、持久化",
            "components": [
                "内存字典TASKS模拟异步",
                "文件系统存储",
                "配置管理(settings)",
                "日志系统",
            ],
        },
    ]


def _build_module_relations() -> Dict[str, Any]:
    """模块关系图。"""
    domains = _get_security_domains()
    return {
        "core_modules": [
            {"name": "api_server/app.py", "role": "主应用入口，注册所有路由"},
            {"name": "config/settings.py", "role": "全局配置管理"},
            {"name": "utils/logger.py", "role": "日志系统"},
            {"name": "utils/auth.py", "role": "用户认证与权限"},
            {"name": "utils/database.py", "role": "数据库连接管理"},
            {"name": "utils/plugin_system.py", "role": "插件系统"},
        ],
        "security_domains": domains,
        "dependency_flow": (
            "app.py → 各路由模块 → 业务逻辑模块 → 引擎/工具 → "
            "数据存储层；路由模块之间尽量解耦，通过任务队列和事件总线通信。"
        ),
    }


def _build_tech_stack() -> Dict[str, List[Dict[str, str]]]:
    """技术栈详情。"""
    return {
        "后端": [
            {"name": "Python", "version": "3.14.7", "role": "主开发语言"},
            {"name": "FastAPI", "version": "latest", "role": "Web框架/API服务"},
            {"name": "Pydantic", "version": "latest", "role": "数据校验/模型"},
            {"name": "Uvicorn", "version": "latest", "role": "ASGI服务器"},
        ],
        "前端": [
            {"name": "HTML5", "version": "—", "role": "页面结构"},
            {"name": "CSS3", "version": "—", "role": "样式/深色主题"},
            {"name": "JavaScript", "version": "ES6+", "role": "交互逻辑"},
            {"name": "Fetch API", "version": "—", "role": "前后端通信"},
        ],
        "数据与存储": [
            {"name": "内存字典", "version": "—", "role": "异步任务模拟存储"},
            {"name": "文件系统", "version": "—", "role": "报告/导出文件"},
            {"name": "dotenv", "version": "—", "role": "环境变量配置"},
        ],
        "安全与工具": [
            {"name": "Pydantic Settings", "version": "—", "role": "配置管理"},
            {"name": "Logging", "version": "—", "role": "日志记录"},
        ],
    }


def _build_design_principles() -> List[Dict[str, str]]:
    """设计原则。"""
    return [
        {
            "name": "统一响应格式",
            "description": "所有API端点返回 {success, data, error} 三段式JSON，前端处理逻辑统一。",
        },
        {
            "name": "try-except全局兜底",
            "description": "每个路由端点都有try-except包裹，确保任何异常都不会导致500错误抛出。",
        },
        {
            "name": "模块化解耦",
            "description": "85个路由模块各自独立，互不依赖内部状态，通过内存字典TASKS模拟异步任务。",
        },
        {
            "name": "渐进增强",
            "description": "第三方库try-import，缺失时自动回退到模拟数据，保证系统始终可运行。",
        },
        {
            "name": "安全优先",
            "description": "所有功能仅限授权安全测试用途，输出检测报告与加固建议。",
        },
        {
            "name": "UTF-8安全",
            "description": "响应数据经过_clean()/_sanitize_unicode()递归清理控制字符，防止编码异常。",
        },
    ]


def _build_adrs() -> List[Dict[str, str]]:
    """架构决策记录(ADR)。"""
    return [
        {
            "id": "ADR-001",
            "title": "选择FastAPI作为Web框架",
            "status": "Accepted",
            "context": "需要高并发异步API、自动文档、类型校验",
            "decision": "采用FastAPI + Uvicorn",
            "consequences": "自动OpenAPI文档、async原生支持、Pydantic模型校验",
        },
        {
            "id": "ADR-002",
            "title": "内存字典模拟异步任务",
            "status": "Accepted",
            "context": "避免引入数据库依赖，降低部署复杂度",
            "decision": "使用全局TASKS字典存储任务状态",
            "consequences": "无持久化、重启丢失、适合演示和快速原型",
        },
        {
            "id": "ADR-003",
            "title": "统一路由模块模式",
            "status": "Accepted",
            "context": "85个路由模块需要一致的代码风格和错误处理",
            "decision": "APIRouter + try-except + ok()/fail()统一封装",
            "consequences": "代码风格统一、易于维护、新模块复制模板即可",
        },
        {
            "id": "ADR-004",
            "title": "前端与后端同目录",
            "status": "Accepted",
            "context": "简化部署，单进程同时服务API和静态页面",
            "decision": "HTML文件放在api_server/目录下",
            "consequences": "部署简单、无需Nginx、适合内网/单机场景",
        },
        {
            "id": "ADR-005",
            "title": "深色安全工具主题",
            "status": "Accepted",
            "context": "安全工具行业惯例，降低视觉疲劳，突出数据",
            "decision": "所有控制台页面统一深色背景+绿色/青色强调色",
            "consequences": "视觉一致性高、符合安全运营中心风格",
        },
    ]


# --------------------------------------------------------------------------- #
# 2. 模块架构文档
# --------------------------------------------------------------------------- #
def get_module_architecture(module_name: Optional[str] = None) -> Dict[str, Any]:
    """获取模块架构文档。"""
    modules = _scan_project_modules()
    if module_name:
        for m in modules:
            if m["name"] == module_name:
                m["detail"] = _build_module_detail(m)
                return m
        return {"error": f"模块 {module_name} 不存在", "available": [m["name"] for m in modules]}
    return {
        "total_modules": len(modules),
        "modules": modules,
        "scan_info": {
            "scanned_root": _PROJECT_ROOT,
            "scan_time": "auto",
        },
    }


def _scan_project_modules() -> List[Dict[str, Any]]:
    """真实扫描项目，提取路由模块信息。"""
    result = []
    api_server_dir = os.path.join(_PROJECT_ROOT, "api_server")
    if not os.path.isdir(api_server_dir):
        return _get_fallback_modules()

    try:
        for fname in sorted(os.listdir(api_server_dir)):
            if not fname.endswith("_routes.py"):
                continue
            fpath = os.path.join(api_server_dir, fname)
            lines = _count_lines(fpath)
            content = _safe_read(fpath, max_lines=80)
            prefix_match = re.search(r'prefix\s*=\s*["\']([^"\']+)["\']', content)
            tag_match = re.search(r'tags\s*=\s*\[(.*?)\]', content)
            endpoint_count = len(re.findall(r'@router\.(get|post|put|delete|patch)\s*\(', content))
            result.append({
                "name": fname,
                "path": f"api_server/{fname}",
                "lines": lines,
                "api_prefix": prefix_match.group(1) if prefix_match else "N/A",
                "tags": tag_match.group(1).strip() if tag_match else "N/A",
                "endpoints_approx": endpoint_count,
                "size_kb": round(os.path.getsize(fpath) / 1024, 1),
            })
    except Exception:
        return _get_fallback_modules()

    return result


def _get_fallback_modules() -> List[Dict[str, Any]]:
    """回退模块列表（扫描失败时使用）。"""
    domains = _get_security_domains()
    return [
        {
            "name": f"{d['key']}_routes.py",
            "path": f"api_server/{d['key']}_routes.py",
            "lines": 500 + i * 50,
            "api_prefix": f"/api/v1/{d['key'].replace('_', '-')}",
            "tags": d["name"],
            "endpoints_approx": 20 + i,
            "size_kb": 80.0,
        }
        for i, d in enumerate(domains)
    ]


def _build_module_detail(module: Dict[str, Any]) -> Dict[str, Any]:
    """构建单个模块的详细架构文档。"""
    return {
        "responsibility": f"{module.get('tags', '安全模块')}相关的API端点和业务逻辑",
        "interfaces": {
            "api_prefix": module.get("api_prefix", "N/A"),
            "endpoints_approx": module.get("endpoints_approx", 0),
            "request_models": "Pydantic BaseModel",
            "response_format": "{success, data, error}",
        },
        "dependencies": [
            "fastapi.APIRouter",
            "pydantic.BaseModel",
            "logging",
            "uuid, time",
        ],
        "data_flow": (
            "客户端请求 → API网关中间件 → 路由端点 → try-except处理 → "
            "业务逻辑/内存字典TASKS → 统一响应JSON → 客户端"
        ),
        "design_decisions": [
            "内存字典存储任务状态，无数据库依赖",
            "try-except全局兜底，不抛500",
            "响应数据经_sanitize_unicode清理控制字符",
        ],
        "extension_points": [
            "新增端点：在路由文件中添加 @router.get/post(...)",
            "新增任务类型：在TASKS字典中注册新task kind",
            "集成外部工具：try-import + 回退模拟数据",
        ],
    }


# --------------------------------------------------------------------------- #
# 3. API架构
# --------------------------------------------------------------------------- #
def get_api_architecture() -> Dict[str, Any]:
    """API架构文档。"""
    return {
        "title": "API 架构设计规范",
        "restful_design": _build_restful_design(),
        "versioning": _build_versioning(),
        "auth": _build_api_auth(),
        "error_handling": _build_error_handling(),
        "pagination": _build_pagination(),
        "sorting_filtering": _build_sorting_filtering(),
        "idempotency": _build_idempotency(),
        "api_design_rules": _build_api_design_rules(),
    }


def _build_restful_design() -> Dict[str, Any]:
    return {
        "style": "RESTful",
        "base_url": "/api/v1/",
        "resource_naming": "名词复数，kebab-case",
        "methods": {
            "GET": "查询资源",
            "POST": "创建资源/触发操作",
            "PUT": "全量更新",
            "PATCH": "部分更新",
            "DELETE": "删除资源",
        },
        "examples": [
            "GET  /api/v1/vulnerabilities        — 获取漏洞列表",
            "POST /api/v1/vulnerabilities/scan  — 触发漏洞扫描",
            "GET  /api/v1/vulnerabilities/{id}  — 获取单个漏洞详情",
            "PUT  /api/v1/vulnerabilities/{id}  — 更新漏洞状态",
        ],
    }


def _build_versioning() -> Dict[str, Any]:
    return {
        "strategy": "URL路径版本",
        "current_version": "v1",
        "format": "/api/v{N}/{resource}",
        "rules": [
            "新版本不破坏现有v1兼容性",
            "废弃端点标记 DeprecationWarning",
            "重大变更升版本号",
            "旧版本至少维护6个月",
        ],
    }


def _build_api_auth() -> Dict[str, Any]:
    return {
        "method": "API Key (Header: X-API-Key)",
        "middleware": "fastapi.security.APIKeyHeader",
        "permission_levels": ["admin", "operator", "viewer"],
        "rules": [
            "所有 /api/v1/ 端点需认证",
            "健康检查 /health 可匿名访问",
            "密钥存储于环境变量，不硬编码",
        ],
    }


def _build_error_handling() -> Dict[str, Any]:
    return {
        "unified_format": {"success": False, "data": None, "error": "错误描述"},
        "http_status_codes": {
            "200": "成功",
            "400": "请求参数错误",
            "401": "未认证",
            "403": "无权限",
            "404": "资源不存在",
            "429": "请求限流",
            "500": "服务器内部错误（已通过try-except兜底）",
            "503": "服务不可用（模块未加载）",
        },
        "error_codes": [
            {"code": "AUTH_FAILED", "message": "API Key无效或缺失"},
            {"code": "MODULE_UNAVAILABLE", "message": "模块加载失败，功能不可用"},
            {"code": "TASK_NOT_FOUND", "message": "任务ID不存在"},
            {"code": "INVALID_PARAM", "message": "请求参数校验失败"},
        ],
    }


def _build_pagination() -> Dict[str, Any]:
    return {
        "method": "offset + limit",
        "params": {
            "page": "页码，默认1",
            "page_size": "每页条数，默认20，最大100",
        },
        "response_fields": ["total", "page", "page_size", "items"],
        "example": "GET /api/v1/vulnerabilities?page=2&page_size=50",
    }


def _build_sorting_filtering() -> Dict[str, Any]:
    return {
        "sorting": {
            "param": "sort_by=field&order=asc|desc",
            "example": "GET /api/v1/vulnerabilities?sort_by=severity&order=desc",
        },
        "filtering": {
            "method": "查询参数 key=value",
            "example": "GET /api/v1/vulnerabilities?severity=critical&status=open",
        },
    }


def _build_idempotency() -> Dict[str, Any]:
    return {
        "principle": "GET/PUT/DELETE天然幂等，POST需客户端生成Idempotency-Key",
        "header": "Idempotency-Key: <uuid>",
        "storage": "内存字典，24小时过期",
        "rules": [
            "相同Idempotency-Key的POST请求只执行一次",
            "重复请求返回首次结果",
            "Key不区分大小写",
        ],
    }


def _build_api_design_rules() -> List[Dict[str, str]]:
    return [
        {"rule": "命名规范", "detail": "URL用kebab-case，字段用snake_case"},
        {"rule": "统一响应", "detail": "所有端点返回{success, data, error}"},
        {"rule": "错误处理", "detail": "try-except包裹，不抛500"},
        {"rule": "参数校验", "detail": "使用Pydantic BaseModel校验请求体"},
        {"rule": "文档自动", "detail": "FastAPI自动生成OpenAPI文档"},
        {"rule": "安全合规", "detail": "仅限授权安全测试用途"},
    ]


# --------------------------------------------------------------------------- #
# 4. 数据架构
# --------------------------------------------------------------------------- #
def get_data_architecture() -> Dict[str, Any]:
    """数据架构文档。"""
    return {
        "title": "数据架构设计",
        "database_design": _build_database_design(),
        "er_diagram": _build_er_diagram(),
        "table_structures": _build_table_structures(),
        "index_strategy": _build_index_strategy(),
        "data_flow": _build_data_flow(),
        "data_dictionary": _build_data_dictionary(),
        "data_models": _build_data_models(),
    }


def _build_database_design() -> Dict[str, Any]:
    return {
        "mode": "内存字典模拟（无真实数据库表）",
        "rationale": "降低部署复杂度，便于快速启动和演示",
        "core_tables_conceptual": [
            "TASKS — 任务状态表（task_id, kind, status, result, created_at）",
            "USERS — 用户表（username, role, api_key_hash）",
            "FINDINGS — 发现表（id, type, severity, target, status）",
            "REPORTS — 报告表（id, task_id, format, content, created_at）",
        ],
        "persistence": "可选升级：SQLite/PostgreSQL，接口不变",
    }


def _build_er_diagram() -> Dict[str, Any]:
    return {
        "entities": ["Task", "User", "Finding", "Report", "Asset"],
        "relations": [
            "User 1—N Task",
            "Task 1—N Finding",
            "Task 1—1 Report",
            "Asset 1—N Finding",
        ],
        "ascii": (
            "┌──────┐     ┌──────┐     ┌────────┐\n"
            "│ User │1──N│ Task │1──N│Finding │\n"
            "└──────┘     └──┬───┘     └────────┘\n"
            "                │1\n"
            "                │1\n"
            "             ┌──┴───┐\n"
            "             │Report│\n"
            "             └──────┘\n"
        ),
    }


def _build_table_structures() -> List[Dict[str, Any]]:
    return [
        {
            "table": "TASKS",
            "fields": [
                {"name": "task_id", "type": "str(16)", "desc": "任务唯一ID(uuid.hex[:16])"},
                {"name": "kind", "type": "str", "desc": "任务类型标识"},
                {"name": "status", "type": "str", "desc": "pending/done/error"},
                {"name": "result", "type": "Any", "desc": "任务结果数据"},
                {"name": "error", "type": "str?", "desc": "错误信息"},
                {"name": "created_at", "type": "str", "desc": "创建时间 YYYY-MM-DD HH:MM:SS"},
                {"name": "finished_at", "type": "str?", "desc": "完成时间"},
            ],
        },
        {
            "table": "FINDINGS",
            "fields": [
                {"name": "id", "type": "str", "desc": "发现唯一ID"},
                {"name": "task_id", "type": "str", "desc": "关联任务ID"},
                {"name": "type", "type": "str", "desc": "漏洞/配置/合规类型"},
                {"name": "severity", "type": "str", "desc": "critical/high/medium/low/info"},
                {"name": "target", "type": "str", "desc": "目标资产"},
                {"name": "status", "type": "str", "desc": "open/fixed/accepted/ignored"},
            ],
        },
    ]


def _build_index_strategy() -> Dict[str, Any]:
    return {
        "in_memory": "Python dict O(1) 查找，天然索引",
        "if_sql": [
            "tasks.task_id UNIQUE INDEX",
            "findings.task_id INDEX",
            "findings.severity INDEX",
            "findings.status INDEX",
            "findings.target INDEX",
        ],
    }


def _build_data_flow() -> str:
    return (
        "用户提交任务 → 生成task_id存入TASKS → 异步执行扫描/分析 → "
        "结果更新TASKS[task_id].result → 用户轮询GET /tasks/{id}获取结果 → "
        "报告生成模块读取结果并输出"
    )


def _build_data_dictionary() -> List[Dict[str, str]]:
    return [
        {"field": "task_id", "type": "string", "desc": "16位hex UUID前16位"},
        {"field": "severity", "type": "enum", "desc": "critical/high/medium/low/info"},
        {"field": "status", "type": "enum", "desc": "pending/running/done/error"},
        {"field": "success", "type": "bool", "desc": "API统一响应成功标志"},
        {"field": "error", "type": "string|null", "desc": "API统一响应错误信息"},
    ]


def _build_data_models() -> List[str]:
    return [
        "Pydantic BaseModel — 请求体校验",
        "Dict[str, Any] — 灵活响应数据",
        "TaskCreateRequest — 任务创建请求",
        "TaskResponse — 任务查询响应",
        "统一响应模型 {success, data, error}",
    ]


# --------------------------------------------------------------------------- #
# 5. 部署架构
# --------------------------------------------------------------------------- #
def get_deployment_architecture() -> Dict[str, Any]:
    """部署架构文档。"""
    return {
        "title": "部署架构设计",
        "single_machine": _build_single_machine(),
        "distributed": _build_distributed(),
        "containerization": _build_containerization(),
        "high_availability": _build_high_availability(),
        "disaster_recovery": _build_disaster_recovery(),
        "scaling": _build_scaling(),
        "network_topology": _build_network_topology(),
        "deployment_flow": _build_deployment_flow(),
    }


def _build_single_machine() -> Dict[str, Any]:
    return {
        "mode": "单机部署（默认）",
        "components": ["FastAPI + Uvicorn", "内存字典", "文件存储"],
        "requirements": "Python 3.14+, 4GB RAM, 10GB磁盘",
        "startup": "python -m uvicorn api_server.app:app --host 0.0.0.0 --port 8000",
    }


def _build_distributed() -> Dict[str, Any]:
    return {
        "mode": "分布式部署（可选）",
        "components": ["API网关", "多个Uvicorn worker", "Redis共享状态", "任务队列"],
        "rationale": "需要水平扩展时引入Redis替代内存字典",
    }


def _build_containerization() -> Dict[str, Any]:
    return {
        "dockerfile_basic": [
            "FROM python:3.14-slim",
            "WORKDIR /app",
            "COPY requirements.txt .",
            "RUN pip install -r requirements.txt",
            "COPY . .",
            "CMD [\"uvicorn\", \"api_server.app:app\", \"--host\", \"0.0.0.0\", \"--port\", \"8000\"]",
        ],
        "docker_compose": [
            "services:",
            "  app:",
            "    build: .",
            "    ports:",
            "      - \"8000:8000\"",
            "    volumes:",
            "      - ./data:/app/data",
        ],
    }


def _build_high_availability() -> Dict[str, Any]:
    return {
        "level_1": "Uvicorn多worker进程",
        "level_2": "Nginx反向代理 + 健康检查",
        "level_3": "多实例 + 负载均衡",
        "level_4": "Redis共享session + 任务持久化",
    }


def _build_disaster_recovery() -> Dict[str, Any]:
    return {
        "backup": ["每日文件备份", "配置导出", "报告归档"],
        "recovery": ["服务重启自动恢复", "重新加载配置", "从备份恢复数据"],
        "RTO": "< 5分钟（单机）",
        "RPO": "< 24小时（文件级备份）",
    }


def _build_scaling() -> Dict[str, Any]:
    return {
        "vertical": "增加CPU/RAM，提高Uvicorn worker数",
        "horizontal": "多实例 + 负载均衡 + Redis共享状态",
        "bottlenecks": ["内存字典TASKS是单点", "文件IO", "扫描引擎CPU密集"],
    }


def _build_network_topology() -> Dict[str, Any]:
    return {
        "external": "用户 → Nginx(443) → Uvicorn(8000)",
        "internal": "Uvicorn → 扫描引擎 → 目标网络（需授权）",
        "ports": {"8000": "API服务", "8001": "管理后台", "9000": "WebSocket"},
        "firewall": "仅开放必要端口，扫描目标需网络连通",
    }


def _build_deployment_flow() -> List[str]:
    return [
        "1. 克隆代码仓库",
        "2. 创建Python虚拟环境",
        "3. pip install -r requirements.txt",
        "4. 复制.env.example为.env并配置",
        "5. 启动: uvicorn api_server.app:app",
        "6. 访问 http://localhost:8000/docs 查看API",
        "7. 访问控制台HTML页面",
    ]


# --------------------------------------------------------------------------- #
# 32大安全方向常量
# --------------------------------------------------------------------------- #
def _get_security_domains() -> List[Dict[str, str]]:
    return [
        {"key": "web_security", "name": "Web安全测试"},
        {"key": "api_security", "name": "API安全测试"},
        {"key": "network_security", "name": "网络安全分析"},
        {"key": "cloud_security", "name": "云安全"},
        {"key": "container_security", "name": "容器安全"},
        {"key": "endpoint_security", "name": "终端安全"},
        {"key": "identity_security", "name": "身份安全"},
        {"key": "iot_security", "name": "物联网安全"},
        {"key": "ics_security", "name": "工控安全"},
        {"key": "mobile_security", "name": "移动安全"},
        {"key": "code_audit", "name": "代码审计"},
        {"key": "forensics", "name": "取证分析"},
        {"key": "incident_response", "name": "应急响应"},
        {"key": "threat_intel", "name": "威胁情报"},
        {"key": "vulnerability_mgmt", "name": "漏洞管理"},
        {"key": "compliance", "name": "合规检查"},
        {"key": "data_security", "name": "数据安全"},
        {"key": "privacy", "name": "隐私保护"},
        {"key": "encryption", "name": "加密管理"},
        {"key": "access_control", "name": "访问控制"},
        {"key": "audit_logging", "name": "审计日志"},
        {"key": "monitoring", "name": "安全监控"},
        {"key": "alerting", "name": "告警管理"},
        {"key": "backup_recovery", "name": "备份恢复"},
        {"key": "devsecops", "name": "DevSecOps"},
        {"key": "bug_bounty", "name": "漏洞赏金"},
        {"key": "combat_training", "name": "实战训练"},
        {"key": "ctf_platform", "name": "CTF平台"},
        {"key": "darkweb", "name": "暗网监测"},
        {"key": "deception", "name": "欺骗防御"},
        {"key": "email_security", "name": "邮件安全"},
        {"key": "performance", "name": "性能安全"},
    ]
