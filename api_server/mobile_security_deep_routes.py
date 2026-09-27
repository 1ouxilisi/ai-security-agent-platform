# -*- coding: utf-8 -*-
"""
mobile_security_deep_routes.py — 移动端安全深度 REST API（第29轮升级方向2）。

路由前缀：/api/v1/mobile-security-deep
覆盖：Android深度 / iOS深度 / 鸿蒙深度 / 移动漏洞POC / 隐私合规 / 测试评测 / 安全控制台
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。任务用内存字典模拟异步。
本模块仅用于授权的移动安全测试与防御研究场景。
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

try:  # 模块导入失败也不影响 app 启动
    from mobile_security_deep.android_deep import get_android_engine
    from mobile_security_deep.ios_deep import get_ios_engine
    from mobile_security_deep.harmonyos_deep import get_harmonyos_engine
    from mobile_security_deep.mobile_vuln_poc import get_vuln_poc_engine, SCAN_TYPES
    from mobile_security_deep.privacy_compliance import get_privacy_engine
    from mobile_security_deep.mobile_test_eval import get_test_eval_engine, OWASP_MOBILE_TOP10
    from mobile_security_deep.mobile_security_dashboard import (
        get_dashboard, DASHBOARD_METRICS, SYSTEM_SETTINGS,
    )
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    import logging
    logging.getLogger("mobile_security_deep_routes").warning("模块导入失败: %s", _e)
    get_android_engine = None  # type: ignore
    get_ios_engine = None  # type: ignore
    get_harmonyos_engine = None  # type: ignore
    get_vuln_poc_engine = None  # type: ignore
    get_privacy_engine = None  # type: ignore
    get_test_eval_engine = None  # type: ignore
    get_dashboard = None  # type: ignore
    SCAN_TYPES = []
    OWASP_MOBILE_TOP10 = []
    DASHBOARD_METRICS = {}
    SYSTEM_SETTINGS = {}
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/mobile-security-deep", tags=["移动端安全深度"])


# ==================== 响应工具 ====================

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理无效控制字符，避免 JSON 序列化异常"""
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


def _check_modules() -> Optional[JSONResponse]:
    if not _MODULES_OK:
        return _fail("mobile_security_deep 模块未正确加载")
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

class TextReq(BaseModel):
    text: str = ""
    package: str = ""


class AndroidAssessReq(BaseModel):
    package: str = "com.example.shop"
    manifest_text: str = ""
    code_text: str = ""


class IosAssessReq(BaseModel):
    bundle_id: str = "com.example.iosapp"
    plist_text: str = ""
    code_text: str = ""


class HmosAssessReq(BaseModel):
    bundle: str = "com.example.harmonyapp"
    config_text: str = ""
    code_text: str = ""


class ScanReq(BaseModel):
    target: str = "com.example.shop"
    scan_type: str = "深度扫描"
    platforms: List[str] = Field(default_factory=lambda: ["Android", "iOS"])


class PriorityReq(BaseModel):
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class PrivacyReportReq(BaseModel):
    app_name: str = "示例App"
    scan_text: str = ""


class PermsReq(BaseModel):
    permissions: List[str] = Field(default_factory=list)


class PlanReq(BaseModel):
    app: str = "示例App"
    platforms: List[str] = Field(default_factory=lambda: ["Android", "iOS"])


class EvalReq(BaseModel):
    app: str = "示例App"
    security: float = 82.0
    compliance: float = 78.0
    quality: float = 88.0
    ux: float = 85.0


class AlertResolveReq(BaseModel):
    note: str = ""


class SettingsReq(BaseModel):
    updates: Dict[str, Any] = Field(default_factory=dict)


# ======================================================================
# 一、Android 深度安全（10 端点）
# ======================================================================
@router.get("/android/info")
def android_info():
    """Android 引擎信息"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_android_engine().stats())
    except Exception as e:
        return _fail(str(e))


@router.post("/android/analyze/apk")
def android_analyze_apk(req: TextReq):
    """APK 深度信息（包名/签名/证书/对齐/混淆/加固）"""
    try:
        err = _check_modules()
        if err:
            return err
        pkg = req.package or "com.example.shop"
        return _ok(get_android_engine().analyze_apk_info(pkg))
    except Exception as e:
        return _fail(str(e))


@router.post("/android/analyze/manifest")
def android_analyze_manifest(req: TextReq):
    """Manifest 组件安全分析（导出/权限/Intent 重定向）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_android_engine().analyze_manifest(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/android/analyze/storage")
def android_analyze_storage(req: TextReq):
    """数据存储安全分析"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_android_engine().analyze_storage(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/android/analyze/network")
def android_analyze_network(req: TextReq):
    """网络安全分析（明文/SSL Pinning/中间人）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_android_engine().analyze_network(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/android/scan/code")
def android_scan_code(req: TextReq):
    """代码安全扫描（硬编码密钥/危险API/WebView/序列化）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_android_engine().scan_code(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/android/analyze/runtime")
def android_analyze_runtime(req: TextReq):
    """运行时安全（root/Frida/Xposed/反调试/完整性）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_android_engine().analyze_runtime(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/android/assessment/full")
def android_full_assessment(req: AndroidAssessReq):
    """Android 一键综合评估"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_android_engine().full_assessment(
            req.package, req.manifest_text, req.code_text))
    except Exception as e:
        return _fail(str(e))


@router.get("/android/samples")
def android_samples():
    """Android 样本列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_android_engine().list_samples())
    except Exception as e:
        return _fail(str(e))


@router.get("/android/dangerous-permissions")
def android_dangerous_perms():
    """已知危险权限字典"""
    try:
        err = _check_modules()
        if err:
            return err
        from mobile_security_deep.android_deep import DANGEROUS_PERMISSIONS
        return _ok(DANGEROUS_PERMISSIONS)
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 二、iOS 深度安全（8 端点）
# ======================================================================
@router.get("/ios/info")
def ios_info():
    """iOS 引擎信息"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_ios_engine().stats())
    except Exception as e:
        return _fail(str(e))


@router.post("/ios/analyze/ipa")
def ios_analyze_ipa(req: TextReq):
    """IPA 深度信息（entitlements/Provisioning/签名/加密）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_ios_engine().analyze_ipa(req.package or "com.example.iosapp"))
    except Exception as e:
        return _fail(str(e))


@router.post("/ios/analyze/plist")
def ios_analyze_plist(req: TextReq):
    """Info.plist 解析（权限/ATS/URL Scheme/Universal Links）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_ios_engine().analyze_info_plist(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/ios/scan/code")
def ios_scan_code(req: TextReq):
    """iOS 代码安全（硬编码/swizzling/dylib 注入）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_ios_engine().scan_code(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/ios/analyze/network")
def ios_analyze_network(req: TextReq):
    """iOS 网络安全（ATS/TLS/SSL Pinning）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_ios_engine().analyze_network(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/ios/analyze/data")
def ios_analyze_data(req: TextReq):
    """iOS 数据安全（Keychain/NSUserDefaults/数据保护级别）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_ios_engine().analyze_data(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/ios/analyze/runtime")
def ios_analyze_runtime(req: TextReq):
    """iOS 运行时防护（越狱/反调试/反Frida/完整性）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_ios_engine().analyze_runtime(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/ios/assessment/full")
def ios_full_assessment(req: IosAssessReq):
    """iOS 一键综合评估"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_ios_engine().full_assessment(
            req.bundle_id, req.plist_text, req.code_text))
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 三、鸿蒙深度安全（8 端点）
# ======================================================================
@router.get("/harmonyos/info")
def harmonyos_info():
    """鸿蒙引擎信息"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_harmonyos_engine().stats())
    except Exception as e:
        return _fail(str(e))


@router.post("/harmonyos/analyze/hap")
def harmonyos_analyze_hap(req: TextReq):
    """HAP 包分析（结构/签名/分布式能力）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_harmonyos_engine().analyze_hap(req.package or "com.example.harmonyapp"))
    except Exception as e:
        return _fail(str(e))


@router.post("/harmonyos/analyze/config")
def harmonyos_analyze_config(req: TextReq):
    """module.json5 解析（权限/组件/分布式声明）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_harmonyos_engine().analyze_module_config(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/harmonyos/analyze/distributed")
def harmonyos_analyze_distributed(req: TextReq):
    """分布式安全分析"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_harmonyos_engine().analyze_distributed(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/harmonyos/scan/code")
def harmonyos_scan_code(req: TextReq):
    """ArkTS/JS 代码安全扫描"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_harmonyos_engine().scan_code(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/harmonyos/analyze/runtime")
def harmonyos_analyze_runtime(req: TextReq):
    """鸿蒙运行时安全"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_harmonyos_engine().analyze_runtime(req.text))
    except Exception as e:
        return _fail(str(e))


@router.get("/harmonyos/ecosystem")
def harmonyos_ecosystem():
    """鸿蒙生态视图"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_harmonyos_engine().ecosystem_view())
    except Exception as e:
        return _fail(str(e))


@router.post("/harmonyos/assessment/full")
def harmonyos_full_assessment(req: HmosAssessReq):
    """鸿蒙一键综合评估"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_harmonyos_engine().full_assessment(
            req.bundle, req.config_text, req.code_text))
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 四、移动漏洞库与 POC（11 端点）
# ======================================================================
@router.get("/vuln/list")
def vuln_list(platform: Optional[str] = None,
              severity: Optional[str] = None,
              keyword: Optional[str] = None):
    """移动漏洞库列表（支持平台/等级/关键字过滤）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_vuln_poc_engine().list_vulns(platform, severity, keyword))
    except Exception as e:
        return _fail(str(e))


@router.get("/vuln/{vuln_id}")
def vuln_detail(vuln_id: str):
    """漏洞详情（含 POC 步骤/修复）"""
    try:
        err = _check_modules()
        if err:
            return err
        v = get_vuln_poc_engine().get_vuln(vuln_id)
        if not v:
            return _fail("漏洞未找到", {"vuln_id": vuln_id})
        return _ok(v)
    except Exception as e:
        return _fail(str(e))


@router.get("/vuln/categories")
def vuln_categories():
    """漏洞分类"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_vuln_poc_engine().categories())
    except Exception as e:
        return _fail(str(e))


@router.get("/poc/list")
def poc_list():
    """POC 库列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_vuln_poc_engine().list_pocs())
    except Exception as e:
        return _fail(str(e))


@router.get("/poc/{poc_id}")
def poc_detail(poc_id: str):
    """POC 详情（含代码）"""
    try:
        err = _check_modules()
        if err:
            return err
        p = get_vuln_poc_engine().get_poc(poc_id)
        if not p:
            return _fail("POC 未找到", {"poc_id": poc_id})
        return _ok(p)
    except Exception as e:
        return _fail(str(e))


@router.post("/vuln/scan")
def vuln_run_scan(req: ScanReq):
    """执行漏洞扫描（异步任务）"""
    try:
        err = _check_modules()
        if err:
            return err
        tid = _new_task("vuln-scan")
        result = get_vuln_poc_engine().run_scan(req.target, req.scan_type, req.platforms)
        TASKS[tid]["status"] = "done"
        TASKS[tid]["result"] = result
        return _ok({"task_id": tid, "result": result})
    except Exception as e:
        return _fail(str(e))


@router.get("/vuln/reports")
def vuln_reports():
    """扫描报告列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_vuln_poc_engine().list_reports())
    except Exception as e:
        return _fail(str(e))


@router.get("/vuln/reports/{report_id}")
def vuln_report_detail(report_id: str):
    """扫描报告详情"""
    try:
        err = _check_modules()
        if err:
            return err
        r = get_vuln_poc_engine().get_report(report_id)
        if not r:
            return _fail("报告未找到", {"report_id": report_id})
        return _ok(r)
    except Exception as e:
        return _fail(str(e))


@router.post("/vuln/prioritize")
def vuln_prioritize(req: PriorityReq):
    """漏洞优先级排序"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_vuln_poc_engine().prioritize(req.findings or None))
    except Exception as e:
        return _fail(str(e))


@router.get("/vuln/scan-types")
def vuln_scan_types():
    """扫描类型"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_vuln_poc_engine().scan_types())
    except Exception as e:
        return _fail(str(e))


@router.get("/vuln/stats")
def vuln_stats():
    """漏洞库统计"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_vuln_poc_engine().stats())
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 五、移动隐私合规（8 端点）
# ======================================================================
@router.post("/privacy/identify-pii")
def privacy_identify_pii(req: TextReq):
    """个人信息识别（正则扫描文本中的手机号/身份证/邮箱等）"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_engine().identify_personal_info(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/privacy/scan-sdks")
def privacy_scan_sdks(req: TextReq):
    """第三方 SDK 识别与行为分析"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_engine().scan_sdks(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/privacy/analyze-policy")
def privacy_analyze_policy(req: TextReq):
    """隐私政策文本分析"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_engine().analyze_policy(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/privacy/audit-permissions")
def privacy_audit_perms(req: PermsReq):
    """权限合规审计"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_engine().audit_permissions(req.permissions or None))
    except Exception as e:
        return _fail(str(e))


@router.get("/privacy/cross-border")
def privacy_cross_border():
    """数据跨境检查"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_engine().cross_border_check())
    except Exception as e:
        return _fail(str(e))


@router.post("/privacy/report")
def privacy_report(req: PrivacyReportReq):
    """生成隐私合规报告"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_engine().compliance_report(req.app_name, req.scan_text))
    except Exception as e:
        return _fail(str(e))


@router.get("/privacy/reports")
def privacy_reports():
    """合规报告列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_engine().list_reports())
    except Exception as e:
        return _fail(str(e))


@router.get("/privacy/stats")
def privacy_stats():
    """隐私引擎统计"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_engine().stats())
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 六、移动安全测试与评测（8 端点）
# ======================================================================
@router.post("/test/plan")
def test_plan(req: PlanReq):
    """生成测试计划"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_test_eval_engine().plan_test(req.app, req.platforms))
    except Exception as e:
        return _fail(str(e))


@router.post("/test/run")
def test_run(req: PlanReq):
    """执行测试（异步任务）"""
    try:
        err = _check_modules()
        if err:
            return err
        tid = _new_task("test-run")
        result = get_test_eval_engine().run_test(tid, req.app)
        TASKS[tid]["status"] = "done"
        TASKS[tid]["result"] = result
        return _ok({"task_id": tid, "result": result})
    except Exception as e:
        return _fail(str(e))


@router.post("/test/evaluate")
def test_evaluate(req: EvalReq):
    """安全评测打分"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_test_eval_engine().evaluate(
            req.app, req.security, req.compliance, req.quality, req.ux))
    except Exception as e:
        return _fail(str(e))


@router.get("/test/standards")
def test_standards():
    """移动安全标准库"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_test_eval_engine().standards())
    except Exception as e:
        return _fail(str(e))


@router.get("/test/best-practices")
def test_best_practices():
    """最佳实践库"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_test_eval_engine().best_practices())
    except Exception as e:
        return _fail(str(e))


@router.get("/test/owasp-top10")
def test_owasp_top10():
    """OWASP Mobile Top 10"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_test_eval_engine().owasp_top10())
    except Exception as e:
        return _fail(str(e))


@router.get("/test/trend")
def test_trend(days: int = 14):
    """测试趋势"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_test_eval_engine().trend(days))
    except Exception as e:
        return _fail(str(e))


@router.get("/test/reports")
def test_reports():
    """测试报告列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_test_eval_engine().list_reports())
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 七、安全控制台 & 系统设置（10 端点）
# ======================================================================
@router.get("/dashboard")
def dashboard():
    """控制台总览"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({
            "overview": get_dashboard().get_overview(),
            "platform_view": get_dashboard().get_platform_view(),
            "vuln_view": get_dashboard().get_vuln_view(),
            "compliance_view": get_dashboard().get_compliance_view(),
        })
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/platform")
def dashboard_platform():
    """平台分布视图"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dashboard().get_platform_view())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/vuln-view")
def dashboard_vuln():
    """漏洞视图"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dashboard().get_vuln_view())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/compliance-view")
def dashboard_compliance():
    """合规视图"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dashboard().get_compliance_view())
    except Exception as e:
        return _fail(str(e))


@router.get("/alerts")
def list_alerts(level: Optional[str] = None, status: Optional[str] = None):
    """告警列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dashboard().list_alerts(level, status))
    except Exception as e:
        return _fail(str(e))


@router.post("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: str, req: AlertResolveReq):
    """处理告警"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dashboard().resolve_alert(alert_id, req.note))
    except Exception as e:
        return _fail(str(e))


@router.get("/settings")
def get_settings():
    """系统设置项"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({"definitions": SYSTEM_SETTINGS,
                    "current": get_dashboard().settings})
    except Exception as e:
        return _fail(str(e))


@router.post("/settings")
def update_settings(req: SettingsReq):
    """更新系统设置"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dashboard().update_settings(req.updates))
    except Exception as e:
        return _fail(str(e))


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    """查询异步任务状态"""
    try:
        task = TASKS.get(task_id)
        if not task:
            return _fail("任务未找到", {"task_id": task_id})
        return _ok(task)
    except Exception as e:
        return _fail(str(e))


@router.get("/health")
def health():
    """健康检查"""
    try:
        return _ok({
            "status": "healthy",
            "modules_loaded": _MODULES_OK,
            "tasks": len(TASKS),
            "time": datetime.now().isoformat(timespec="seconds"),
        })
    except Exception as e:
        return _fail(str(e))
