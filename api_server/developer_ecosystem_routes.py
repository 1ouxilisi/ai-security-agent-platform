# -*- coding: utf-8 -*-
"""
developer_ecosystem_routes.py — 跨平台客户端与开发者生态 REST API（第24轮升级方向4）。

路由前缀：/api/v1/developer-ecosystem
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500 错误。
任务用内存字典 TASKS 模拟异步。
本模块仅用于授权的安全评估与开发者运营场景。
"""

from __future__ import annotations

import os
import re
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------- 模块 try-import ----------
try:
    from developer_ecosystem.cli_tool import cli_core, Colors, ProgressBar, OutputFormatter
    from developer_ecosystem.desktop_client import desktop_client, PlatformDetector, UpdateManager
    from developer_ecosystem.ide_plugin import (
        ide_plugin_core, code_scanner, pentest_helper,
        knowledge_base, plugin_integration, plugin_marketplace,
    )
    from developer_ecosystem.python_sdk import (
        sdk_client, async_sdk_client, sdk_examples, api_docs, sdk_versions,
        SDKExamples, APIDocumentation,
    )
    from developer_ecosystem.developer_portal import (
        portal, dev_account, marketplace, plugin_dev_sdk, plugin_review, community,
    )
    from developer_ecosystem.open_api import (
        api_gateway, auth_manager, version_manager,
        webhook_manager, usage_billing, api_security,
    )
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    import logging
    logging.getLogger("developer_ecosystem_routes").warning("模块导入失败: %s", _e)
    cli_core = None  # type: ignore
    desktop_client = None  # type: ignore
    ide_plugin_core = None  # type: ignore
    code_scanner = None  # type: ignore
    pentest_helper = None  # type: ignore
    knowledge_base = None  # type: ignore
    plugin_integration = None  # type: ignore
    plugin_marketplace = None  # type: ignore
    sdk_client = None  # type: ignore
    async_sdk_client = None  # type: ignore
    sdk_examples = None  # type: ignore
    api_docs = None  # type: ignore
    sdk_versions = None  # type: ignore
    portal = None  # type: ignore
    dev_account = None  # type: ignore
    marketplace = None  # type: ignore
    plugin_dev_sdk = None  # type: ignore
    plugin_review = None  # type: ignore
    community = None  # type: ignore
    api_gateway = None  # type: ignore
    auth_manager = None  # type: ignore
    version_manager = None  # type: ignore
    webhook_manager = None  # type: ignore
    usage_billing = None  # type: ignore
    api_security = None  # type: ignore
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/developer-ecosystem", tags=["开发者生态"])


# ==================== 响应工具 ====================

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理无效控制字符"""
    if isinstance(obj, str):
        return _CTRL_RE.sub("", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(x) for x in obj]
    return obj


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": _clean(data), "error": str(err)})


def _check() -> Optional[JSONResponse]:
    if not _MODULES_OK:
        return _fail("developer_ecosystem 模块未正确加载")
    return None


# ==================== 内存任务存储 ====================

TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(task_type: str) -> str:
    tid = f"{task_type}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {
        "task_id": tid, "type": task_type,
        "status": "pending", "result": None, "error": None,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    return tid


# ==================== 请求模型 ====================

class CLIExecReq(BaseModel):
    command: str
    args: List[str] = Field(default_factory=list)


class CodeScanReq(BaseModel):
    code: str
    filename: str = "untitled"


class PayloadReq(BaseModel):
    category: str = "xss"
    count: int = 4


class EncodeReq(BaseModel):
    data: str
    encoding: str = "base64"


class HashReq(BaseModel):
    data: str
    algorithm: str = "sha256"


class RegexReq(BaseModel):
    pattern: str
    text: str
    flags: str = ""


class HttpRequestReq(BaseModel):
    method: str = "GET"
    url: str = "https://example.com"
    headers: Dict[str, str] = Field(default_factory=dict)
    body: str = ""


class DevRegisterReq(BaseModel):
    email: str
    name: str
    company: str = ""


class AppCreateReq(BaseModel):
    developer_id: str
    app_name: str
    description: str = ""


class WebhookRegisterReq(BaseModel):
    name: str
    url: str
    events: List[str] = Field(default_factory=list)
    secret: str = ""


class WebhookTriggerReq(BaseModel):
    event: str
    payload: Dict[str, Any] = Field(default_factory=dict)


class PluginSubmitReq(BaseModel):
    developer_id: str
    plugin_id: str
    version: str
    package_path: str = ""


class PluginRateReq(BaseModel):
    score: int = 5
    comment: str = ""
    user: str = ""


class CommunityAskReq(BaseModel):
    title: str
    content: str
    author: str = ""


class AssetCreateReq(BaseModel):
    name: str
    atype: str = "host"
    address: str = ""


class ScanCreateReq(BaseModel):
    scan_type: str = "port"
    target: str = ""
    config: Dict[str, Any] = Field(default_factory=dict)


class ConfigSetReq(BaseModel):
    key: str
    value: str


class ApiKeyCreateReq(BaseModel):
    name: str = "default"
    scopes: List[str] = Field(default_factory=lambda: ["read"])


# ==================== 概览与健康 ====================

@router.get("/overview")
def get_overview():
    """开发者生态总览"""
    try:
        c = _check()
        if c:
            return c
        return _ok({
            "modules": {
                "cli_tool": "已加载", "desktop_client": "已加载",
                "ide_plugin": "已加载", "python_sdk": "已加载",
                "developer_portal": "已加载", "open_api": "已加载",
            },
            "cli_commands": len(cli_core.commands) if cli_core else 0,
            "ide_commands": len(ide_plugin_core.commands) if ide_plugin_core else 0,
            "plugins_marketplace": len(marketplace.plugins) if marketplace else 0,
            "webhooks": len(webhook_manager.webhooks) if webhook_manager else 0,
            "api_routes": len(api_gateway.routes) if api_gateway else 0,
            "tasks": len(TASKS),
            "version": "24.4.0",
        })
    except Exception as e:
        return _fail(str(e))


@router.get("/health")
def health_check():
    """健康检查"""
    try:
        return _ok({"status": "healthy", "timestamp": datetime.now().isoformat(timespec="seconds")})
    except Exception as e:
        return _fail(str(e))


# ==================== 1. CLI 工具端点 ====================

@router.get("/cli/commands")
def cli_list_commands():
    """列出所有 CLI 命令"""
    try:
        c = _check()
        if c:
            return c
        cmds = {k: v.help for k, v in cli_core.commands.items()
                if not any(k == a for a in v.aliases)}
        return _ok({"commands": cmds, "total": len(cmds)})
    except Exception as e:
        return _fail(str(e))


@router.post("/cli/execute")
def cli_execute(req: CLIExecReq):
    """执行 CLI 命令"""
    try:
        c = _check()
        if c:
            return c
        argv = [req.command] + req.args
        result = cli_core.run(argv)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/cli/config")
def cli_get_config():
    """获取 CLI 配置"""
    try:
        c = _check()
        if c:
            return c
        return _ok(cli_core.config.to_dict())
    except Exception as e:
        return _fail(str(e))


@router.post("/cli/config")
def cli_set_config(req: ConfigSetReq):
    """设置 CLI 配置"""
    try:
        c = _check()
        if c:
            return c
        result = cli_core._cmd_config_set(req.key, req.value)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/cli/assets")
def cli_list_assets():
    """CLI 资产列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok(cli_core._cmd_asset_list())
    except Exception as e:
        return _fail(str(e))


@router.post("/cli/assets")
def cli_add_asset(req: AssetCreateReq):
    """CLI 添加资产"""
    try:
        c = _check()
        if c:
            return c
        return _ok(cli_core._cmd_asset_add(req.name, req.atype, req.address))
    except Exception as e:
        return _fail(str(e))


@router.get("/cli/tasks")
def cli_list_tasks():
    """CLI 任务列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok(cli_core._cmd_task_list())
    except Exception as e:
        return _fail(str(e))


@router.post("/cli/tasks")
def cli_create_task(req: ScanCreateReq):
    """CLI 创建任务"""
    try:
        c = _check()
        if c:
            return c
        return _ok(cli_core._cmd_task_create(req.scan_type, req.target))
    except Exception as e:
        return _fail(str(e))


@router.get("/cli/reports")
def cli_list_reports():
    """CLI 报告列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok(cli_core._cmd_report_list())
    except Exception as e:
        return _fail(str(e))


@router.get("/cli/completion")
def cli_completion(shell: str = Query("bash")):
    """生成自动补全脚本"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"shell": shell, "script": cli_core._cmd_completion(shell)})
    except Exception as e:
        return _fail(str(e))


# ==================== 2. 桌面客户端端点 ====================

@router.get("/desktop/overview")
def desktop_overview():
    """桌面客户端总览"""
    try:
        c = _check()
        if c:
            return c
        return _ok(desktop_client.get_overview())
    except Exception as e:
        return _fail(str(e))


@router.get("/desktop/system-status")
def desktop_system_status():
    """系统资源状态"""
    try:
        c = _check()
        if c:
            return c
        from developer_ecosystem.desktop_client import ResourceMonitor
        return _ok(ResourceMonitor.get_snapshot())
    except Exception as e:
        return _fail(str(e))


@router.get("/desktop/updates")
def desktop_check_updates():
    """检查应用更新"""
    try:
        c = _check()
        if c:
            return c
        return _ok(desktop_client.updater.check_for_updates())
    except Exception as e:
        return _fail(str(e))


@router.get("/desktop/notifications")
def desktop_notifications():
    """通知中心"""
    try:
        c = _check()
        if c:
            return c
        return _ok(desktop_client.notifications.list())
    except Exception as e:
        return _fail(str(e))


@router.get("/desktop/settings")
def desktop_get_settings():
    """获取应用设置"""
    try:
        c = _check()
        if c:
            return c
        return _ok(desktop_client.settings.get_all())
    except Exception as e:
        return _fail(str(e))


@router.post("/desktop/scan/start")
def desktop_start_scan(target: str = Query(...)):
    """桌面端启动扫描"""
    try:
        c = _check()
        if c:
            return c
        return _ok(desktop_client.scanner.start(target))
    except Exception as e:
        return _fail(str(e))


@router.get("/desktop/platform")
def desktop_platform_info():
    """平台信息"""
    try:
        c = _check()
        if c:
            return c
        return _ok({
            "platform": PlatformDetector.get_platform(),
            "arch": PlatformDetector.get_arch(),
            "capabilities": PlatformDetector.get_capabilities(),
            "build_targets": PlatformDetector.get_build_targets(),
        })
    except Exception as e:
        return _fail(str(e))


# ==================== 3. IDE 插件端点 ====================

@router.get("/ide/manifest")
def ide_manifest():
    """获取 IDE 插件清单"""
    try:
        c = _check()
        if c:
            return c
        return _ok(ide_plugin_core.get_manifest())
    except Exception as e:
        return _fail(str(e))


@router.get("/ide/commands")
def ide_commands():
    """IDE 插件命令列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"commands": [cmd.to_dict() for cmd in ide_plugin_core.commands]})
    except Exception as e:
        return _fail(str(e))


@router.get("/ide/settings")
def ide_settings():
    """IDE 插件设置项"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"settings": [s.to_dict() for s in ide_plugin_core.settings.values()]})
    except Exception as e:
        return _fail(str(e))


@router.post("/ide/scan/code")
def ide_scan_code(req: CodeScanReq):
    """实时代码安全扫描"""
    try:
        c = _check()
        if c:
            return c
        return _ok(code_scanner.scan_content(req.code, req.filename))
    except Exception as e:
        return _fail(str(e))


@router.post("/ide/payload/generate")
def ide_generate_payload(req: PayloadReq):
    """生成渗透测试 Payload"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"category": req.category, "payloads": pentest_helper.generate_payload(req.category, req.count)})
    except Exception as e:
        return _fail(str(e))


@router.post("/ide/encode")
def ide_encode(req: EncodeReq):
    """编码"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"data": req.data, "encoding": req.encoding, "result": pentest_helper.encode(req.data, req.encoding)})
    except Exception as e:
        return _fail(str(e))


@router.post("/ide/decode")
def ide_decode(req: EncodeReq):
    """解码"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"data": req.data, "encoding": req.encoding, "result": pentest_helper.decode(req.data, req.encoding)})
    except Exception as e:
        return _fail(str(e))


@router.post("/ide/hash")
def ide_hash(req: HashReq):
    """Hash 计算"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"data": req.data, "algorithm": req.algorithm, "hash": pentest_helper.hash_value(req.data, req.algorithm)})
    except Exception as e:
        return _fail(str(e))


@router.post("/ide/regex/test")
def ide_regex_test(req: RegexReq):
    """正则表达式测试"""
    try:
        c = _check()
        if c:
            return c
        return _ok(pentest_helper.regex_test(req.pattern, req.text, req.flags))
    except Exception as e:
        return _fail(str(e))


@router.post("/ide/http/build")
def ide_http_build(req: HttpRequestReq):
    """HTTP 请求构造"""
    try:
        c = _check()
        if c:
            return c
        return _ok(pentest_helper.build_request(req.method, req.url, req.headers, req.body))
    except Exception as e:
        return _fail(str(e))


@router.get("/ide/knowledge/cve/{cve_id}")
def ide_query_cve(cve_id: str):
    """查询 CVE"""
    try:
        c = _check()
        if c:
            return c
        return _ok(knowledge_base.query_cve(cve_id))
    except Exception as e:
        return _fail(str(e))


@router.get("/ide/knowledge/cwe/{cwe_id}")
def ide_query_cwe(cwe_id: str):
    """查询 CWE"""
    try:
        c = _check()
        if c:
            return c
        return _ok(knowledge_base.query_cwe(cwe_id))
    except Exception as e:
        return _fail(str(e))


@router.get("/ide/knowledge/owasp")
def ide_query_owasp():
    """OWASP Top 10"""
    try:
        c = _check()
        if c:
            return c
        return _ok(knowledge_base.query_owasp())
    except Exception as e:
        return _fail(str(e))


@router.get("/ide/knowledge/best-practices")
def ide_best_practices(topic: str = Query("")):
    """安全最佳实践"""
    try:
        c = _check()
        if c:
            return c
        return _ok(knowledge_base.best_practices(topic))
    except Exception as e:
        return _fail(str(e))


@router.get("/ide/marketplace/list")
def ide_marketplace_list(category: str = Query(""), search: str = Query("")):
    """IDE 插件市场列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"plugins": plugin_marketplace.list(category, search), "total": len(plugin_marketplace.list(category, search))})
    except Exception as e:
        return _fail(str(e))


@router.get("/ide/marketplace/{plugin_id}")
def ide_marketplace_detail(plugin_id: str):
    """IDE 插件详情"""
    try:
        c = _check()
        if c:
            return c
        return _ok(plugin_marketplace.detail(plugin_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/ide/marketplace/{plugin_id}/install")
def ide_marketplace_install(plugin_id: str):
    """安装 IDE 插件"""
    try:
        c = _check()
        if c:
            return c
        return _ok(plugin_marketplace.install(plugin_id))
    except Exception as e:
        return _fail(str(e))


# ==================== 4. Python SDK 端点 ====================

@router.get("/sdk/overview")
def sdk_overview():
    """SDK 总览"""
    try:
        c = _check()
        if c:
            return c
        return _ok({
            "client_stats": sdk_client.get_stats(),
            "examples_count": len(sdk_examples.basic_examples()),
            "endpoints_documented": len(api_docs.ENDPOINTS),
            "error_codes": len(api_docs.ERROR_CODES),
            "versions": len(sdk_versions.VERSIONS),
        })
    except Exception as e:
        return _fail(str(e))


@router.get("/sdk/examples")
def sdk_examples_list():
    """SDK 示例代码"""
    try:
        c = _check()
        if c:
            return c
        return _ok({
            "quickstart": sdk_examples.quickstart(),
            "basic": sdk_examples.basic_examples(),
            "advanced": sdk_examples.advanced_examples(),
            "best_practices": sdk_examples.best_practices(),
            "faq": sdk_examples.faq(),
            "troubleshooting": sdk_examples.troubleshooting(),
        })
    except Exception as e:
        return _fail(str(e))


@router.get("/sdk/docs")
def sdk_api_docs():
    """API 文档（OpenAPI）"""
    try:
        c = _check()
        if c:
            return c
        return _ok({
            "openapi": api_docs.generate_openapi(),
            "markdown": api_docs.generate_markdown(),
            "error_codes": api_docs.get_error_codes(),
        })
    except Exception as e:
        return _fail(str(e))


@router.get("/sdk/versions")
def sdk_version_list():
    """SDK 版本列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({
            "versions": sdk_versions.list_versions(),
            "compatibility": sdk_versions.COMPATIBILITY_MATRIX,
            "deprecations": sdk_versions.deprecations(),
        })
    except Exception as e:
        return _fail(str(e))


@router.get("/sdk/versions/upgrade")
def sdk_upgrade_guide(from_ver: str = Query("24.1.0"), to_ver: str = Query("24.4.0")):
    """SDK 升级指南"""
    try:
        c = _check()
        if c:
            return c
        return _ok(sdk_versions.upgrade_guide(from_ver, to_ver))
    except Exception as e:
        return _fail(str(e))


# ==================== 5. 开发者门户端点 ====================

@router.get("/portal/home")
def portal_home():
    """开发者门户首页"""
    try:
        c = _check()
        if c:
            return c
        return _ok(portal.homepage())
    except Exception as e:
        return _fail(str(e))


@router.get("/portal/docs")
def portal_docs(category: str = Query("")):
    """文档中心"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"docs": portal.docs_center(category)})
    except Exception as e:
        return _fail(str(e))


@router.get("/portal/sdks")
def portal_sdk_downloads():
    """SDK 下载列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"sdks": portal.sdk_downloads()})
    except Exception as e:
        return _fail(str(e))


@router.get("/portal/faq")
def portal_faq():
    """常见问题"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"faq": portal.faq()})
    except Exception as e:
        return _fail(str(e))


@router.post("/portal/register")
def portal_register(req: DevRegisterReq):
    """开发者注册"""
    try:
        c = _check()
        if c:
            return c
        return _ok(dev_account.register(req.email, req.name, req.company))
    except Exception as e:
        return _fail(str(e))


@router.post("/portal/apps")
def portal_create_app(req: AppCreateReq):
    """创建应用"""
    try:
        c = _check()
        if c:
            return c
        return _ok(dev_account.create_app(req.developer_id, req.app_name, req.description))
    except Exception as e:
        return _fail(str(e))


@router.get("/portal/usage/{developer_id}")
def portal_usage(developer_id: str):
    """用量统计"""
    try:
        c = _check()
        if c:
            return c
        return _ok(dev_account.get_usage(developer_id))
    except Exception as e:
        return _fail(str(e))


@router.get("/portal/bill/{developer_id}")
def portal_bill(developer_id: str, month: str = Query("")):
    """账单"""
    try:
        c = _check()
        if c:
            return c
        return _ok(dev_account.get_bill(developer_id, month))
    except Exception as e:
        return _fail(str(e))


@router.get("/marketplace/list")
def marketplace_list(category: str = Query(""), search: str = Query(""), sort: str = Query("downloads")):
    """插件市场列表"""
    try:
        c = _check()
        if c:
            return c
        items = marketplace.list(category, search, sort)
        return _ok({"plugins": items, "total": len(items), "categories": marketplace.categories})
    except Exception as e:
        return _fail(str(e))


@router.get("/marketplace/{plugin_id}")
def marketplace_detail(plugin_id: str):
    """插件市场详情"""
    try:
        c = _check()
        if c:
            return c
        return _ok(marketplace.detail(plugin_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/marketplace/{plugin_id}/install")
def marketplace_install(plugin_id: str):
    """安装插件"""
    try:
        c = _check()
        if c:
            return c
        return _ok(marketplace.install(plugin_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/marketplace/{plugin_id}/rate")
def marketplace_rate(plugin_id: str, req: PluginRateReq):
    """评分评论"""
    try:
        c = _check()
        if c:
            return c
        return _ok(marketplace.rate(plugin_id, req.score, req.comment, req.user))
    except Exception as e:
        return _fail(str(e))


@router.get("/marketplace/{plugin_id}/versions")
def marketplace_versions(plugin_id: str):
    """插件版本历史"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"versions": marketplace.versions(plugin_id)})
    except Exception as e:
        return _fail(str(e))


@router.get("/dev-sdk/framework")
def dev_sdk_framework():
    """插件开发框架"""
    try:
        c = _check()
        if c:
            return c
        return _ok(plugin_dev_sdk.get_framework())
    except Exception as e:
        return _fail(str(e))


@router.get("/dev-sdk/examples")
def dev_sdk_examples():
    """插件开发示例"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"examples": plugin_dev_sdk.get_examples(), "debug_tools": plugin_dev_sdk.debug_tools()})
    except Exception as e:
        return _fail(str(e))


@router.get("/dev-sdk/release-flow")
def dev_sdk_release_flow():
    """插件发布流程"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"steps": plugin_dev_sdk.release_flow()})
    except Exception as e:
        return _fail(str(e))


@router.post("/review/submit")
def review_submit(req: PluginSubmitReq):
    """提交插件审核"""
    try:
        c = _check()
        if c:
            return c
        return _ok(plugin_review.submit(req.developer_id, req.plugin_id, req.version, req.package_path))
    except Exception as e:
        return _fail(str(e))


@router.get("/review/list")
def review_list(status: str = Query("")):
    """审核列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"submissions": plugin_review.list_submissions(status)})
    except Exception as e:
        return _fail(str(e))


@router.get("/review/standards")
def review_standards():
    """审核标准"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"standards": plugin_review.get_standards()})
    except Exception as e:
        return _fail(str(e))


@router.get("/community/posts")
def community_posts(category: str = Query("")):
    """社区帖子"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"posts": community.forum_posts(category)})
    except Exception as e:
        return _fail(str(e))


@router.post("/community/ask")
def community_ask(req: CommunityAskReq):
    """社区提问"""
    try:
        c = _check()
        if c:
            return c
        return _ok(community.ask(req.title, req.content, req.author))
    except Exception as e:
        return _fail(str(e))


@router.get("/community/events")
def community_events():
    """社区活动"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"events": community.events_list()})
    except Exception as e:
        return _fail(str(e))


@router.get("/community/leaderboard")
def community_leaderboard():
    """贡献者排行榜"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"rankings": community.leaderboard()})
    except Exception as e:
        return _fail(str(e))


# ==================== 6. 开放 API 端点 ====================

@router.get("/gateway/routes")
def gateway_routes():
    """API 网关路由"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"routes": api_gateway.get_routes(), "total": len(api_gateway.get_routes())})
    except Exception as e:
        return _fail(str(e))


@router.get("/gateway/metrics")
def gateway_metrics():
    """API 网关指标"""
    try:
        c = _check()
        if c:
            return c
        return _ok(api_gateway.get_metrics())
    except Exception as e:
        return _fail(str(e))


@router.post("/gateway/simulate")
def gateway_simulate(path: str = Query(...), method: str = Query("GET")):
    """模拟网关请求"""
    try:
        c = _check()
        if c:
            return c
        return _ok(api_gateway.simulate_request(path, method))
    except Exception as e:
        return _fail(str(e))


@router.post("/auth/api-key")
def auth_create_key(req: ApiKeyCreateReq):
    """创建 API Key"""
    try:
        c = _check()
        if c:
            return c
        return _ok(auth_manager.create_api_key(req.name, req.scopes))
    except Exception as e:
        return _fail(str(e))


@router.post("/auth/verify")
def auth_verify_key(key: str = Query(...)):
    """验证 API Key"""
    try:
        c = _check()
        if c:
            return c
        return _ok(auth_manager.verify_api_key(key))
    except Exception as e:
        return _fail(str(e))


@router.post("/auth/jwt")
def auth_issue_jwt(subject: str = Query("demo-user"), expires_in: int = 3600):
    """签发 JWT"""
    try:
        c = _check()
        if c:
            return c
        return _ok(auth_manager.issue_jwt(subject, expires_in=expires_in))
    except Exception as e:
        return _fail(str(e))


@router.post("/auth/sign")
def auth_sign_request(method: str = Query("GET"), path: str = Query("/api/v1/test"),
                      body: str = Query(""), secret: str = Query("test-secret")):
    """请求签名"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"signature": auth_manager.sign_request(method, path, body, secret)})
    except Exception as e:
        return _fail(str(e))


@router.get("/versions")
def api_versions():
    """API 版本列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"versions": version_manager.list_versions(), "stats": version_manager.version_stats()})
    except Exception as e:
        return _fail(str(e))


@router.post("/webhooks")
def webhook_register(req: WebhookRegisterReq):
    """注册 Webhook"""
    try:
        c = _check()
        if c:
            return c
        return _ok(webhook_manager.register(req.name, req.url, req.events, req.secret))
    except Exception as e:
        return _fail(str(e))


@router.get("/webhooks")
def webhook_list():
    """Webhook 列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"webhooks": webhook_manager.list(), "events": webhook_manager.available_events()})
    except Exception as e:
        return _fail(str(e))


@router.post("/webhooks/{wid}/trigger")
def webhook_trigger(wid: str, req: WebhookTriggerReq):
    """触发 Webhook 推送"""
    try:
        c = _check()
        if c:
            return c
        return _ok(webhook_manager.trigger(wid, req.event, req.payload))
    except Exception as e:
        return _fail(str(e))


@router.get("/webhooks/{wid}/logs")
def webhook_logs(wid: str):
    """Webhook 推送日志"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"logs": webhook_manager.delivery_logs(wid)})
    except Exception as e:
        return _fail(str(e))


@router.get("/usage/{api_key}")
def usage_get(api_key: str, days: int = Query(30)):
    """API 用量查询"""
    try:
        c = _check()
        if c:
            return c
        return _ok(usage_billing.get_usage(api_key, days))
    except Exception as e:
        return _fail(str(e))


@router.get("/billing/plans")
def billing_plans():
    """计费方案"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"plans": usage_billing.get_plans()})
    except Exception as e:
        return _fail(str(e))


@router.post("/security/validate")
def security_validate(data: str = Query(...)):
    """输入安全验证"""
    try:
        c = _check()
        if c:
            return c
        return _ok(api_security.validate_input(data))
    except Exception as e:
        return _fail(str(e))


@router.get("/security/rate-limit")
def security_rate_limit(client_id: str = Query("default"), limit: int = Query(100)):
    """速率限制检查"""
    try:
        c = _check()
        if c:
            return c
        return _ok(api_security.rate_limit_check(client_id, limit))
    except Exception as e:
        return _fail(str(e))


@router.post("/security/audit")
def security_audit_log(action: str = Query(""), actor: str = Query(""),
                       resource: str = Query(""), detail: str = Query("")):
    """审计日志"""
    try:
        c = _check()
        if c:
            return c
        return _ok(api_security.audit_log(action, actor, resource, detail))
    except Exception as e:
        return _fail(str(e))
