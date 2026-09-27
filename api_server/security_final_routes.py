# -*- coding: utf-8 -*-
"""
security_final_routes.py — 安全最终加固 REST API（第22轮升级方向4）。

路由前缀: /api/v1/security-final
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。

安全边界：所有"渗透测试"均为对本平台自身代码 / 配置的只读静态评估，
不对任何外部目标发起攻击。
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/security-final", tags=["安全最终加固"])

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
# 业务模块加载（try-import，失败回退模拟数据）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    import sys
    if _PROJECT_ROOT not in sys.path:
        sys.path.insert(0, _PROJECT_ROOT)
    from security_final import (self_pentest_final, dep_vuln_final,
                                baseline_final, audit_monitor,
                                data_security_final, security_dashboard_final)
    from security_final.common import clean
    _MOD_AVAILABLE = True
    logger.info("security_final_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("security_final_routes: load failed: %s", e)

    def clean(obj: Any) -> Any:  # type: ignore[misc]
        return obj


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    task_id = uuid.uuid4().hex[:16]
    _TASKS[task_id] = {
        "task_id": task_id, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return task_id


def _finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
    if task_id in _TASKS:
        t = _TASKS[task_id]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


def _get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return _TASKS.get(task_id)


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("安全最终加固模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class PentestRequest(BaseModel):
    depth: str = Field(default="normal", description="quick/normal/deep")


class ReportRequest(BaseModel):
    report_type: str = Field(default="summary", description="summary/daily/weekly/monthly/pentest/compliance")


# --------------------------------------------------------------------------- #
# 控制台 HTML 页
# --------------------------------------------------------------------------- #
@router.get("/console", include_in_schema=False)
def console_page():
    try:
        page = os.path.join(os.path.dirname(__file__), "security_final_console.html")
        if not os.path.exists(page):
            return fail("控制台页面不存在", 404)
        return FileResponse(page, media_type="text/html; charset=utf-8")
    except Exception as e:
        return fail(f"打开控制台失败: {e}", 500)


# =========================================================================== #
# 1. 自身渗透测试最终版（6 个端点）
# =========================================================================== #
@router.get("/pentest/full-scan")
def pentest_full_scan(depth: str = Query(default="normal")):
    """全面渗透测试扫描（Web/API/移动/桌面/网络/配置/社会工程学）"""
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("pentest.full_scan")
        result = self_pentest_final.get_pentest_scanner().run_full_pentest()
        result["depth"] = depth
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("pentest_full_scan error")
        return fail(f"全面渗透扫描失败: {e}", 500)


@router.get("/pentest/owasp-top10")
def pentest_owasp_top10():
    """OWASP Top10 专项检测"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(self_pentest_final.get_pentest_scanner().owasp_top10_check())
    except Exception as e:
        return fail(f"OWASP Top10 检测失败: {e}", 500)


@router.get("/pentest/cwe-top25")
def pentest_cwe_top25():
    """CWE Top25 漏洞检测"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(self_pentest_final.get_pentest_scanner().cwe_top25_check())
    except Exception as e:
        return fail(f"CWE Top25 检测失败: {e}", 500)


@router.get("/pentest/report")
def pentest_report(report_type: str = Query(default="full")):
    """渗透测试报告生成"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(self_pentest_final.get_pentest_scanner().generate_report(report_type))
    except Exception as e:
        return fail(f"渗透测试报告生成失败: {e}", 500)


@router.get("/pentest/automation")
def pentest_automation():
    """渗透测试自动化流水线状态"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(self_pentest_final.get_pentest_scanner().automation_pipeline())
    except Exception as e:
        return fail(f"自动化流水线查询失败: {e}", 500)


@router.get("/pentest/quality")
def pentest_quality():
    """渗透测试质量保证指标"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(self_pentest_final.get_pentest_scanner().quality_assurance())
    except Exception as e:
        return fail(f"质量保证指标查询失败: {e}", 500)


# =========================================================================== #
# 2. 依赖漏洞最终扫描（6 个端点）
# =========================================================================== #
@router.get("/deps/scan")
def deps_scan():
    """依赖漏洞扫描（Python包/系统包/容器镜像/前端库）"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(dep_vuln_final.get_dep_scanner().scan_dependencies())
    except Exception as e:
        return fail(f"依赖漏洞扫描失败: {e}", 500)


@router.get("/deps/cve-lookup")
def deps_cve_lookup(cve_id: str = Query(...)):
    """CVE 漏洞详情查询"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(dep_vuln_final.get_dep_scanner().cve_lookup(cve_id))
    except Exception as e:
        return fail(f"CVE 查询失败: {e}", 500)


@router.get("/deps/prioritization")
def deps_prioritization():
    """漏洞优先级排序（CVSS/EPSS/可利用性/业务影响）"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(dep_vuln_final.get_dep_scanner().vuln_prioritization())
    except Exception as e:
        return fail(f"漏洞优先级排序失败: {e}", 500)


@router.get("/deps/remediation")
def deps_remediation():
    """漏洞修复方案（补丁/升级/配置/WAF虚拟补丁）"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(dep_vuln_final.get_dep_scanner().remediation_guide())
    except Exception as e:
        return fail(f"修复方案生成失败: {e}", 500)


@router.get("/deps/management")
def deps_management():
    """漏洞管理仪表盘"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(dep_vuln_final.get_dep_scanner().vuln_management())
    except Exception as e:
        return fail(f"漏洞管理查询失败: {e}", 500)


@router.get("/deps/sbom")
def deps_sbom(sbom_format: str = Query(default="spdx")):
    """SBOM 软件物料清单生成"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(dep_vuln_final.get_dep_scanner().generate_sbom(sbom_format))
    except Exception as e:
        return fail(f"SBOM 生成失败: {e}", 500)


# =========================================================================== #
# 3. 安全基线最终检查（7 个端点）
# =========================================================================== #
@router.get("/baseline/cis")
def baseline_cis():
    """CIS Benchmark 检查"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(baseline_final.get_baseline_checker().cis_benchmark())
    except Exception as e:
        return fail(f"CIS Benchmark 检查失败: {e}", 500)


@router.get("/baseline/asvs")
def baseline_asvs():
    """OWASP ASVS 验证"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(baseline_final.get_baseline_checker().owasp_asvs())
    except Exception as e:
        return fail(f"OWASP ASVS 检查失败: {e}", 500)


@router.get("/baseline/nist-csf")
def baseline_nist_csf():
    """NIST CSF 成熟度评估"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(baseline_final.get_baseline_checker().nist_csf())
    except Exception as e:
        return fail(f"NIST CSF 评估失败: {e}", 500)


@router.get("/baseline/djcp")
def baseline_djcp():
    """等保2.0 合规检查"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(baseline_final.get_baseline_checker().djcp_2_0())
    except Exception as e:
        return fail(f"等保2.0 检查失败: {e}", 500)


@router.get("/baseline/iso27001")
def baseline_iso27001():
    """ISO27001 评估"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(baseline_final.get_baseline_checker().iso27001())
    except Exception as e:
        return fail(f"ISO27001 评估失败: {e}", 500)


@router.get("/baseline/pci-dss")
def baseline_pci_dss():
    """PCI DSS 合规检查"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(baseline_final.get_baseline_checker().pci_dss())
    except Exception as e:
        return fail(f"PCI DSS 检查失败: {e}", 500)


@router.get("/baseline/comprehensive")
def baseline_comprehensive():
    """综合基线检查报告"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(baseline_final.get_baseline_checker().comprehensive_baseline_report())
    except Exception as e:
        return fail(f"综合基线报告生成失败: {e}", 500)


# =========================================================================== #
# 4. 安全审计与监控（6 个端点）
# =========================================================================== #
@router.get("/audit/logs")
def audit_logs(log_type: str = Query(default="all"), limit: int = Query(default=100)):
    """安全审计日志查询"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(audit_monitor.get_audit_monitor().audit_logs(log_type, limit))
    except Exception as e:
        return fail(f"审计日志查询失败: {e}", 500)


@router.get("/audit/integrity")
def audit_integrity():
    """日志完整性保护状态"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(audit_monitor.get_audit_monitor().log_integrity())
    except Exception as e:
        return fail(f"日志完整性查询失败: {e}", 500)


@router.get("/audit/monitoring")
def audit_monitoring():
    """实时安全监控面板"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(audit_monitor.get_audit_monitor().realtime_monitoring())
    except Exception as e:
        return fail(f"实时监控查询失败: {e}", 500)


@router.get("/audit/detection")
def audit_detection():
    """安全事件检测能力"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(audit_monitor.get_audit_monitor().incident_detection())
    except Exception as e:
        return fail(f"事件检测查询失败: {e}", 500)


@router.get("/audit/response")
def audit_response():
    """安全事件响应流程"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(audit_monitor.get_audit_monitor().incident_response())
    except Exception as e:
        return fail(f"事件响应查询失败: {e}", 500)


@router.get("/audit/compliance-report")
def audit_compliance_report():
    """安全合规报告"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(audit_monitor.get_audit_monitor().compliance_report())
    except Exception as e:
        return fail(f"合规报告生成失败: {e}", 500)


# =========================================================================== #
# 5. 数据安全最终加固（7 个端点）
# =========================================================================== #
@router.get("/data/classification")
def data_classification():
    """数据分类分级"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(data_security_final.get_data_security().data_classification())
    except Exception as e:
        return fail(f"数据分类分级查询失败: {e}", 500)


@router.get("/data/encryption")
def data_encryption():
    """数据加密状态与建议"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(data_security_final.get_data_security().data_encryption())
    except Exception as e:
        return fail(f"数据加密查询失败: {e}", 500)


@router.get("/data/masking")
def data_masking():
    """数据脱敏能力与示例"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(data_security_final.get_data_security().data_masking())
    except Exception as e:
        return fail(f"数据脱敏查询失败: {e}", 500)


@router.get("/data/access-control")
def data_access_control():
    """数据访问控制"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(data_security_final.get_data_security().data_access_control())
    except Exception as e:
        return fail(f"访问控制查询失败: {e}", 500)


@router.get("/data/backup-recovery")
def data_backup_recovery():
    """数据备份恢复方案"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(data_security_final.get_data_security().backup_recovery())
    except Exception as e:
        return fail(f"备份恢复查询失败: {e}", 500)


@router.get("/data/destruction")
def data_destruction():
    """数据销毁流程"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(data_security_final.get_data_security().data_destruction())
    except Exception as e:
        return fail(f"数据销毁查询失败: {e}", 500)


@router.get("/data/overview")
def data_overview():
    """数据安全综合总览"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(data_security_final.get_data_security().data_security_overview())
    except Exception as e:
        return fail(f"数据安全总览查询失败: {e}", 500)


# =========================================================================== #
# 6. 安全管理控制台（6 个端点）
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    """安全总览仪表盘"""
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("dash.overview")
        result = security_dashboard_final.get_dashboard().security_overview()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"安全总览查询失败: {e}", 500)


@router.get("/dashboard/vulns")
def dash_vulns():
    """漏洞管理"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(security_dashboard_final.get_dashboard().vulnerability_management())
    except Exception as e:
        return fail(f"漏洞管理查询失败: {e}", 500)


@router.get("/dashboard/compliance")
def dash_compliance():
    """合规管理"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(security_dashboard_final.get_dashboard().compliance_management())
    except Exception as e:
        return fail(f"合规管理查询失败: {e}", 500)


@router.get("/dashboard/events")
def dash_events():
    """安全事件"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(security_dashboard_final.get_dashboard().security_events())
    except Exception as e:
        return fail(f"安全事件查询失败: {e}", 500)


@router.get("/dashboard/config")
def dash_config():
    """安全配置"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(security_dashboard_final.get_dashboard().security_config())
    except Exception as e:
        return fail(f"安全配置查询失败: {e}", 500)


@router.get("/dashboard/report")
def dash_report(report_type: str = Query(default="summary")):
    """安全报告生成"""
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(security_dashboard_final.get_dashboard().security_reports(report_type))
    except Exception as e:
        return fail(f"安全报告生成失败: {e}", 500)


# =========================================================================== #
# 任务查询与元信息（3 个端点）
# =========================================================================== #
@router.get("/tasks/{task_id}")
def task_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok({"task_id": t["task_id"], "kind": t["kind"], "status": t["status"],
                   "created_at": t["created_at"], "finished_at": t["finished_at"]})
    except Exception as e:
        return fail(f"任务查询失败: {e}", 500)


@router.get("/tasks/{task_id}/result")
def task_result(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"任务结果查询失败: {e}", 500)


@router.get("/meta")
def meta_info():
    try:
        return ok({
            "module": "security_final",
            "version": "22.4.0",
            "round": "第22轮升级方向4",
            "direction": "安全最终加固",
            "core_modules": [
                "self_pentest_final", "dep_vuln_final", "baseline_final",
                "audit_monitor", "data_security_final", "security_dashboard_final",
            ],
            "note": "安全最终加固：所有检测均为只读静态分析，不对外部目标发起攻击",
        })
    except Exception as e:
        return fail(f"元信息失败: {e}", 500)
