# -*- coding: utf-8 -*-
"""
mobile_deep_routes.py — 移动 APK 深度分析 REST API（第20轮升级 方向3，50 个端点）。

路由前缀: /api/v1/mobile-deep
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。

定位：仅用于授权的移动安全分析 / 检测 / 评估，输出加固与合规建议。
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/mobile-deep", tags=["移动APK分析做深"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from mobile_deep.apk_deep_parser import APKDeepParser, TOOLCHAIN
    from mobile_deep.security_vuln_detector import SecurityVulnDetector
    from mobile_deep.privacy_compliance import PrivacyComplianceAnalyzer, COMPLIANCE_FRAMEWORKS
    from mobile_deep.malware_analysis import MalwareAnalyzer
    from mobile_deep.dynamic_analysis import DynamicAnalyzer, FRIDA_TEMPLATES
    from mobile_deep.mobile_dashboard import MobileDashboard, ANALYSIS_TEMPLATES
    _MOD_AVAILABLE = True
    logger.info("mobile_deep_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("mobile_deep_routes: load failed: %s", e)


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理控制字符 / 无效 Unicode，防止 JSON 序列化失败。"""
    if isinstance(obj, str):
        return "".join(ch for ch in obj if ch == "\n" or ord(ch) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("移动深度分析模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ParseRequest(BaseModel):
    apk_path: str = ""
    code_sample: str = ""
    manifest_signals: Dict[str, Any] = Field(default_factory=dict)
    dex_strings: List[str] = Field(default_factory=list)


class VulnRequest(BaseModel):
    code_sample: str = ""
    manifest_signals: Dict[str, Any] = Field(default_factory=dict)


class PrivacyRequest(BaseModel):
    signals: Dict[str, Any] = Field(default_factory=dict)
    code_sample: str = ""
    dex_strings: List[str] = Field(default_factory=list)


class MalwareRequest(BaseModel):
    code_sample: str = ""
    strings: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)


class DynamicRequest(BaseModel):
    package: str = "com.demo.sampleapp"
    device: str = "emulator-5554"
    duration: int = 60
    template_id: str = "ssl_pinning_bypass"


class ConsoleTaskRequest(BaseModel):
    apk_id: str = "demo001"
    template: str = "standard"


class RegisterApkRequest(BaseModel):
    filename: str = "app-release.apk"
    size: int = 0
    package: str = ""
    version: str = "1.0.0"


# =========================================================================== #
# 1. APK 深度解析（8 个端点）
# =========================================================================== #
@router.post("/parse/structure")
def parse_structure(req: ParseRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(APKDeepParser(req.apk_path).parse_structure())
    except Exception as e:
        return fail(f"结构解析失败: {e}", 500)


@router.post("/parse/dex")
def parse_dex(req: ParseRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(APKDeepParser(req.apk_path).parse_dex())
    except Exception as e:
        return fail(f"DEX 解析失败: {e}", 500)


@router.post("/parse/manifest")
def parse_manifest(req: ParseRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(APKDeepParser(req.apk_path).parse_manifest())
    except Exception as e:
        return fail(f"Manifest 解析失败: {e}", 500)


@router.post("/parse/resources")
def parse_resources(req: ParseRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(APKDeepParser(req.apk_path).parse_resources())
    except Exception as e:
        return fail(f"资源解析失败: {e}", 500)


@router.post("/parse/decompile")
def parse_decompile(req: ParseRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(APKDeepParser(req.apk_path).decompile())
    except Exception as e:
        return fail(f"反编译失败: {e}", 500)


@router.post("/parse/native")
def parse_native(req: ParseRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(APKDeepParser(req.apk_path).analyze_native())
    except Exception as e:
        return fail(f"原生库分析失败: {e}", 500)


@router.post("/parse/all")
def parse_all(req: ParseRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(APKDeepParser(req.apk_path).analyze_all())
    except Exception as e:
        return fail(f"综合解析失败: {e}", 500)


@router.get("/parse/tools")
def parse_tools():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"toolchain": TOOLCHAIN,
                   "available": {k: bool(v) for k, v in TOOLCHAIN.items()}})
    except Exception as e:
        return fail(f"工具探测失败: {e}", 500)


# =========================================================================== #
# 2. 漏洞深度检测（7 个端点）
# =========================================================================== #
@router.post("/vuln/components")
def vuln_components(req: VulnRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(SecurityVulnDetector(req.code_sample, req.manifest_signals).check_components())
    except Exception as e:
        return fail(f"组件检测失败: {e}", 500)


@router.post("/vuln/storage")
def vuln_storage(req: VulnRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(SecurityVulnDetector(req.code_sample, req.manifest_signals).check_storage())
    except Exception as e:
        return fail(f"存储检测失败: {e}", 500)


@router.post("/vuln/network")
def vuln_network(req: VulnRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(SecurityVulnDetector(req.code_sample, req.manifest_signals).check_network())
    except Exception as e:
        return fail(f"网络检测失败: {e}", 500)


@router.post("/vuln/code")
def vuln_code(req: VulnRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(SecurityVulnDetector(req.code_sample, req.manifest_signals).check_code())
    except Exception as e:
        return fail(f"代码检测失败: {e}", 500)


@router.post("/vuln/permissions")
def vuln_permissions(req: VulnRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(SecurityVulnDetector(req.code_sample, req.manifest_signals).check_permissions())
    except Exception as e:
        return fail(f"权限检测失败: {e}", 500)


@router.post("/vuln/webview")
def vuln_webview(req: VulnRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(SecurityVulnDetector(req.code_sample, req.manifest_signals).check_webview())
    except Exception as e:
        return fail(f"WebView 检测失败: {e}", 500)


@router.post("/vuln/scan-all")
def vuln_scan_all(req: VulnRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(SecurityVulnDetector(req.code_sample, req.manifest_signals).scan_all())
    except Exception as e:
        return fail(f"综合漏洞扫描失败: {e}", 500)


# =========================================================================== #
# 3. 隐私合规（7 个端点）
# =========================================================================== #
@router.post("/privacy/collect")
def privacy_collect(req: PrivacyRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        signals = dict(req.signals)
        signals.setdefault("code_sample", req.code_sample)
        return ok(PrivacyComplianceAnalyzer().detect_personal_info(signals))
    except Exception as e:
        return fail(f"个人信息检测失败: {e}", 500)


@router.post("/privacy/sdks")
def privacy_sdks(req: PrivacyRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(PrivacyComplianceAnalyzer().detect_sdks(req.code_sample, req.dex_strings))
    except Exception as e:
        return fail(f"SDK 分析失败: {e}", 500)


@router.post("/privacy/policy")
def privacy_policy(req: PrivacyRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(PrivacyComplianceAnalyzer().assess_policy(req.signals))
    except Exception as e:
        return fail(f"隐私政策评估失败: {e}", 500)


@router.post("/privacy/cross-border")
def privacy_cross_border(req: PrivacyRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        domains = req.signals.get("domains") or req.code_sample.split()
        return ok(PrivacyComplianceAnalyzer().assess_cross_border(domains))
    except Exception as e:
        return fail(f"跨境评估失败: {e}", 500)


@router.post("/privacy/minor")
def privacy_minor(req: PrivacyRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(PrivacyComplianceAnalyzer().assess_minor(req.signals))
    except Exception as e:
        return fail(f"儿童隐私评估失败: {e}", 500)


@router.post("/privacy/report")
def privacy_report(req: PrivacyRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        pa = PrivacyComplianceAnalyzer()
        collected = pa.detect_personal_info(req.signals)
        sdks = pa.detect_sdks(req.code_sample, req.dex_strings)
        policy = pa.assess_policy(req.signals)
        border = pa.assess_cross_border(req.signals.get("domains"))
        minor = pa.assess_minor(req.signals)
        return ok(pa.build_report(collected, sdks, policy, border, minor))
    except Exception as e:
        return fail(f"合规报告生成失败: {e}", 500)


@router.get("/privacy/frameworks")
def privacy_frameworks():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(COMPLIANCE_FRAMEWORKS)
    except Exception as e:
        return fail(f"框架查询失败: {e}", 500)


# =========================================================================== #
# 4. 恶意软件分析（8 个端点）
# =========================================================================== #
@router.post("/malware/static")
def malware_static(req: MalwareRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MalwareAnalyzer(req.code_sample, req.strings, req.permissions).static_behavior())
    except Exception as e:
        return fail(f"静态行为分析失败: {e}", 500)


@router.post("/malware/network")
def malware_network(req: MalwareRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MalwareAnalyzer(req.code_sample, req.strings, req.permissions).network_behavior(req.urls))
    except Exception as e:
        return fail(f"网络行为分析失败: {e}", 500)


@router.post("/malware/data-theft")
def malware_data_theft(req: MalwareRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MalwareAnalyzer(req.code_sample, req.strings, req.permissions).data_theft())
    except Exception as e:
        return fail(f"数据窃取分析失败: {e}", 500)


@router.post("/malware/payment")
def malware_payment(req: MalwareRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MalwareAnalyzer(req.code_sample, req.strings, req.permissions).payment_fraud())
    except Exception as e:
        return fail(f"支付欺诈分析失败: {e}", 500)


@router.post("/malware/persistence")
def malware_persistence(req: MalwareRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MalwareAnalyzer(req.code_sample, req.strings, req.permissions).persistence())
    except Exception as e:
        return fail(f"持久化分析失败: {e}", 500)


@router.post("/malware/family")
def malware_family(req: MalwareRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MalwareAnalyzer(req.code_sample, req.strings, req.permissions).classify_family())
    except Exception as e:
        return fail(f"家族分类失败: {e}", 500)


@router.post("/malware/analyze-all")
def malware_analyze_all(req: MalwareRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MalwareAnalyzer(req.code_sample, req.strings, req.permissions).analyze_all())
    except Exception as e:
        return fail(f"恶意综合分析失败: {e}", 500)


@router.get("/malware/families")
def malware_families():
    try:
        g = _guard()
        if g is not None:
            return g
        from mobile_deep.malware_analysis import MALWARE_FAMILIES
        return ok({"count": len(MALWARE_FAMILIES),
                   "families": [{"family": f["family"], "type": f["type"],
                                 "risk": f["risk"]} for f in MALWARE_FAMILIES]})
    except Exception as e:
        return fail(f"家族库查询失败: {e}", 500)


# =========================================================================== #
# 5. 动态分析（7 个端点）
# =========================================================================== #
@router.post("/dynamic/behavior")
def dynamic_behavior(req: DynamicRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(DynamicAnalyzer(req.package, req.device).monitor_behavior(req.duration))
    except Exception as e:
        return fail(f"行为监控失败: {e}", 500)


@router.post("/dynamic/memory")
def dynamic_memory(req: DynamicRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(DynamicAnalyzer(req.package, req.device).memory_analysis())
    except Exception as e:
        return fail(f"内存分析失败: {e}", 500)


@router.post("/dynamic/traffic")
def dynamic_traffic(req: DynamicRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(DynamicAnalyzer(req.package, req.device).capture_traffic(req.duration))
    except Exception as e:
        return fail(f"流量捕获失败: {e}", 500)


@router.get("/dynamic/frida/templates")
def dynamic_frida_templates():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(DynamicAnalyzer().list_frida_templates())
    except Exception as e:
        return fail(f"Frida 模板查询失败: {e}", 500)


@router.post("/dynamic/frida/run")
def dynamic_frida_run(req: DynamicRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(DynamicAnalyzer(req.package, req.device).run_hook(req.template_id))
    except Exception as e:
        return fail(f"Frida Hook 执行失败: {e}", 500)


@router.post("/dynamic/ui")
def dynamic_ui(req: DynamicRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(DynamicAnalyzer(req.package, req.device).ui_automation())
    except Exception as e:
        return fail(f"UI 自动化失败: {e}", 500)


@router.post("/dynamic/run-full")
def dynamic_run_full(req: DynamicRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(DynamicAnalyzer(req.package, req.device).run_full(req.duration))
    except Exception as e:
        return fail(f"动态综合分析失败: {e}", 500)


# =========================================================================== #
# 6. 移动控制台（13 个端点）
# =========================================================================== #
@router.post("/console/apks")
def console_register_apk(req: RegisterApkRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MobileDashboard().register_apk(req.filename, req.size, req.package, req.version))
    except Exception as e:
        return fail(f"APK 登记失败: {e}", 500)


@router.get("/console/apks")
def console_list_apks():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MobileDashboard().list_apks())
    except Exception as e:
        return fail(f"APK 列表失败: {e}", 500)


@router.get("/console/apks/compare")
def console_compare(a: str = Query(...), b: str = Query(...)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MobileDashboard().compare_versions(a, b))
    except Exception as e:
        return fail(f"版本对比失败: {e}", 500)


@router.post("/console/tasks")
def console_create_task(req: ConsoleTaskRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MobileDashboard().create_task(req.apk_id, req.template))
    except Exception as e:
        return fail(f"任务创建失败: {e}", 500)


@router.get("/console/tasks")
def console_list_tasks():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MobileDashboard().list_tasks())
    except Exception as e:
        return fail(f"任务列表失败: {e}", 500)


@router.get("/console/tasks/{task_id}")
def console_get_task(task_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        t = MobileDashboard().get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(f"任务查询失败: {e}", 500)


@router.post("/console/tasks/{task_id}/cancel")
def console_cancel_task(task_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MobileDashboard().cancel_task(task_id))
    except Exception as e:
        return fail(f"任务取消失败: {e}", 500)


@router.get("/console/vulns")
def console_list_vulns(severity: Optional[str] = Query(default=None),
                       status: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MobileDashboard().list_vulns(severity, status))
    except Exception as e:
        return fail(f"漏洞列表失败: {e}", 500)


@router.post("/console/vulns/{vid}/mark")
def console_mark_vuln(vid: str,
                      status: str = Query(default="open"),
                      fp: Optional[bool] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MobileDashboard().mark_vuln(vid, status, fp))
    except Exception as e:
        return fail(f"漏洞标记失败: {e}", 500)


@router.get("/console/privacy")
def console_privacy():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MobileDashboard().privacy_view())
    except Exception as e:
        return fail(f"隐私视图失败: {e}", 500)


@router.get("/console/malware")
def console_malware():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MobileDashboard().malware_view())
    except Exception as e:
        return fail(f"恶意分析视图失败: {e}", 500)


@router.post("/console/report")
def console_report(apk_id: str = Query(default="demo001")):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MobileDashboard().build_report(apk_id))
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/console/overview")
def console_overview():
    try:
        g = _guard()
        if g is not None:
            return g
        md = MobileDashboard()
        return ok({
            "apks": md.list_apks(),
            "tasks": md.list_tasks(),
            "vulns": md.list_vulns(),
            "privacy": md.privacy_view(),
            "malware": md.malware_view(),
            "templates": ANALYSIS_TEMPLATES,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        return fail(f"总览失败: {e}", 500)



# =========================================================================== #
# 方向3（移动安全深度做实 v2）：真实漏洞检测 + 权限评级 + 动态框架
# 路由前缀不变 /api/v1/mobile-deep，新增 /v2/* 命名空间，30+ 端点。
# =========================================================================== #
try:
    from mobile_deep.mobile_deep_dashboard import (
        MobileDeepDashboard as _MDDV2,
    )
    from mobile_deep.apk_deep_analyzer import APKDeepAnalyzer as _APKV2
    from mobile_deep.static_code_scanner import (
        StaticCodeScanner as _SCSV2,
    )
    from mobile_deep.permission_risk_rater import (
        PermissionRiskRater as _PRRV2,
    )
    from mobile_deep.vuln_detector import VulnDetector as _VDV2
    from mobile_deep.dynamic_framework import (
        DynamicAnalysisFramework as _DAFV2,
    )
    _V2_OK = True
except Exception as _e2:
    logger.exception("mobile_deep_routes v2 load failed: %s", _e2)
    _V2_OK = False


class _V2Req(BaseModel):
    apk_path: str = ""
    code_sample: str = ""
    manifest_signals: Dict[str, Any] = Field(default_factory=dict)
    components: Dict[str, Any] = Field(default_factory=dict)
    storage_signals: Dict[str, Any] = Field(default_factory=dict)


def _v2_guard():
    if not _V2_OK:
        return fail("移动安全 v2 模块加载失败", 503)
    return None


# ---- APK 深度分析（6 端点） ----------------------------------------------- #
@router.post("/v2/apk/deep-analyze")
def v2_apk_deep_analyze(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_APKV2().analyze(req.apk_path, req.manifest_signals,
                                    req.code_sample))
    except Exception as e:
        return fail(f"APK 深度分析失败: {e}", 500)


@router.post("/v2/apk/manifest")
def v2_apk_manifest(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_APKV2()._parse_manifest_signals(req.manifest_signals))
    except Exception as e:
        return fail(f"Manifest 解析失败: {e}", 500)


@router.post("/v2/apk/components")
def v2_apk_components(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_APKV2()._extract_components(req.manifest_signals))
    except Exception as e:
        return fail(f"组件提取失败: {e}", 500)


@router.post("/v2/apk/permissions")
def v2_apk_permissions(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        perms = req.manifest_signals.get("permissions", [])
        return ok(_APKV2()._analyze_permissions(perms))
    except Exception as e:
        return fail(f"权限分类失败: {e}", 500)


@router.post("/v2/apk/signature")
def v2_apk_signature(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_APKV2()._analyze_signature(req.manifest_signals, None))
    except Exception as e:
        return fail(f"签名分析失败: {e}", 500)


@router.post("/v2/apk/resources")
def v2_apk_resources(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_APKV2()._analyze_resources(req.manifest_signals,
                                               req.code_sample, None))
    except Exception as e:
        return fail(f"资源分析失败: {e}", 500)


# ---- 静态代码扫描（4 端点） ----------------------------------------------- #
@router.post("/v2/static/scan")
def v2_static_scan(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_SCSV2().scan(code_sample=req.code_sample))
    except Exception as e:
        return fail(f"静态扫描失败: {e}", 500)


@router.get("/v2/static/rules")
def v2_static_rules():
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_SCSV2().list_rules())
    except Exception as e:
        return fail(f"规则列表失败: {e}", 500)


@router.post("/v2/static/hardcoded-secrets")
def v2_static_secrets(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        r = _SCSV2().scan(code_sample=req.code_sample)
        return ok([x for x in r["findings"]
                   if x["category"] == "hardcoded_secret"])
    except Exception as e:
        return fail(f"密钥检测失败: {e}", 500)


@router.post("/v2/static/unsafe-api")
def v2_static_unsafe(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        r = _SCSV2().scan(code_sample=req.code_sample)
        return ok([x for x in r["findings"]
                   if x["category"] == "unsafe_api"])
    except Exception as e:
        return fail(f"不安全 API 检测失败: {e}", 500)


# ---- 权限风险评级（3 端点） ----------------------------------------------- #
@router.post("/v2/permissions/rate")
def v2_perm_rate(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        perms = req.manifest_signals.get("permissions", [])
        return ok(_PRRV2().rate(perms))
    except Exception as e:
        return fail(f"权限评级失败: {e}", 500)


@router.get("/v2/permissions/db")
def v2_perm_db():
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_PRRV2().list_database())
    except Exception as e:
        return fail(f"权限库失败: {e}", 500)


@router.post("/v2/permissions/check-dangerous")
def v2_perm_dangerous(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        perms = req.manifest_signals.get("permissions", [])
        r = _PRRV2().rate(perms)
        return ok({"dangerous": [d for d in r["permissions"]
                                  if d["level"] in ("high", "critical")]})
    except Exception as e:
        return fail(f"危险权限识别失败: {e}", 500)


# ---- 常见漏洞检测（6 端点） ----------------------------------------------- #
@router.post("/v2/vuln/detect")
def v2_vuln_detect(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_VDV2().detect(req.manifest_signals, req.code_sample,
                                  req.components, req.storage_signals))
    except Exception as e:
        return fail(f"漏洞检测失败: {e}", 500)


@router.post("/v2/vuln/webview")
def v2_vuln_webview(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_VDV2()._check_webview(req.code_sample))
    except Exception as e:
        return fail(f"WebView 检测失败: {e}", 500)


@router.post("/v2/vuln/log-leak")
def v2_vuln_log(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_VDV2()._check_log_leak(req.code_sample))
    except Exception as e:
        return fail(f"日志泄露检测失败: {e}", 500)


@router.post("/v2/vuln/backup")
def v2_vuln_backup(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_VDV2()._check_backup(req.manifest_signals))
    except Exception as e:
        return fail(f"备份检测失败: {e}", 500)


@router.post("/v2/vuln/exported")
def v2_vuln_exported(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_VDV2()._check_exported_components(req.components))
    except Exception as e:
        return fail(f"导出组件检测失败: {e}", 500)


@router.post("/v2/vuln/insecure-storage")
def v2_vuln_storage(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_VDV2()._check_insecure_storage(req.code_sample,
                                                   req.storage_signals))
    except Exception as e:
        return fail(f"存储检测失败: {e}", 500)


# ---- 动态分析框架（6 端点） ----------------------------------------------- #
@router.get("/v2/dynamic/env")
def v2_dyn_env():
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_DAFV2().environment())
    except Exception as e:
        return fail(f"动态环境查询失败: {e}", 500)


@router.get("/v2/dynamic/scripts")
def v2_dyn_scripts():
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_DAFV2().list_scripts())
    except Exception as e:
        return fail(f"脚本列表失败: {e}", 500)


@router.get("/v2/dynamic/scripts/{name}")
def v2_dyn_script(name: str):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_DAFV2().get_script(name))
    except Exception as e:
        return fail(f"脚本获取失败: {e}", 500)


@router.get("/v2/dynamic/objection")
def v2_dyn_objection():
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_DAFV2().list_objection())
    except Exception as e:
        return fail(f"objection 模板失败: {e}", 500)


class _DynReq(BaseModel):
    pkg: str
    script: str = "ssl_unpin"
    device_id: str = ""


@router.post("/v2/dynamic/start")
def v2_dyn_start(req: _DynReq):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_DAFV2().start_task(req.pkg, req.script, req.device_id))
    except Exception as e:
        return fail(f"动态任务启动失败: {e}", 500)


@router.get("/v2/dynamic/tasks")
def v2_dyn_tasks():
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_DAFV2().list_tasks())
    except Exception as e:
        return fail(f"动态任务列表失败: {e}", 500)


# ---- 控制台聚合（5 端点） -------------------------------------------------- #
@router.post("/v2/assess/deep")
def v2_assess_deep(req: _V2Req):
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_MDDV2().deep_assess(req.apk_path, req.manifest_signals,
                                         req.code_sample))
    except Exception as e:
        return fail(f"深度体检失败: {e}", 500)


@router.get("/v2/assess/demo")
def v2_assess_demo():
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_MDDV2().demo_assess())
    except Exception as e:
        return fail(f"演示体检失败: {e}", 500)


@router.get("/v2/reports")
def v2_reports():
    try:
        g = _v2_guard()
        if g:
            return g
        return ok(_MDDV2().list_reports())
    except Exception as e:
        return fail(f"报告列表失败: {e}", 500)


@router.get("/v2/reports/{rid}")
def v2_report(rid: str):
    try:
        g = _v2_guard()
        if g:
            return g
        r = _MDDV2().get_report(rid)
        if not r:
            return fail("报告不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(f"报告查询失败: {e}", 500)


@router.get("/v2/overview")
def v2_overview():
    try:
        g = _v2_guard()
        if g:
            return g
        return ok({
            "v2_modules": ["apk_deep_analyzer", "static_code_scanner",
                           "permission_risk_rater", "vuln_detector",
                           "dynamic_framework", "mobile_deep_dashboard"],
            "endpoint_count": 30,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        return fail(f"v2 总览失败: {e}", 500)
