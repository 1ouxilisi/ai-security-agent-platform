# -*- coding: utf-8 -*-
"""
supply_chain_routes.py — 供应链安全深化 REST API（第 15 轮方向 1，35 个端点）。

路由前缀: /api/v1/supply-chain
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。

设计定位：仅用于经过授权的供应链安全治理，输出检测/评估报告与加固建议。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/supply-chain", tags=["供应链安全"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from supply_chain.sbom_manager import SBOMManager, SBOM_FORMATS, SAMPLE_SBOMS
    from supply_chain.component_analyzer import ComponentAnalyzer, COMPONENT_HEALTH_CRITERIA
    from supply_chain.vulnerability_detector import VulnerabilityDetector, VULN_SEVERITY_LEVELS
    from supply_chain.license_compliance import LicenseComplianceChecker, LICENSE_LIBRARY
    from supply_chain.supplier_risk import SupplierRiskAssessor, SUPPLIER_RISK_FACTORS
    from supply_chain.supply_chain_workflow import (
        SupplyChainWorkflow, get_supply_chain_workflow, SUPPLY_CHAIN_STEPS,
    )
    _MOD_AVAILABLE = True
    logger.info("supply_chain_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("supply_chain_routes: load failed: %s", e)


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
def _clean(obj: Any) -> Any:
    """递归清理数据中的控制字符与无效Unicode。"""
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(item) for item in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("供应链安全模块不可用，请检查加载日志", 503)
    return None


def _task_view(t: Dict[str, Any]) -> Dict[str, Any]:
    return {"task_id": t["task_id"], "status": t["status"], "kind": t["kind"],
            "created_at": t["created_at"], "finished_at": t["finished_at"]}


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class GenerateSBOMRequest(BaseModel):
    name: str = "My Application"
    format: str = "spdx"
    components: List[Dict[str, Any]] = Field(default_factory=list)


class CompareSBOMRequest(BaseModel):
    sbom_a: str = ""
    sbom_b: str = ""


class AnalyzeComponentRequest(BaseModel):
    components: List[Dict[str, Any]] = Field(default_factory=list)


class ScanVulnRequest(BaseModel):
    components: List[Dict[str, Any]] = Field(default_factory=list)


class LicenseCheckRequest(BaseModel):
    components: List[Dict[str, Any]] = Field(default_factory=list)


class SupplierAssessRequest(BaseModel):
    supplier_ids: List[str] = Field(default_factory=list)


class AssessmentRunRequest(BaseModel):
    components: List[Dict[str, Any]] = Field(default_factory=list)


class ImportSBOMRequest(BaseModel):
    data: Dict[str, Any] = Field(default_factory=dict)
    format: str = "spdx"


# =========================================================================== #
# 1. SBOM 管理（8 个端点）
# =========================================================================== #
@router.post("/sbom/generate")
def sbom_generate(req: GenerateSBOMRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("sbom_generate")
        mgr = SBOMManager()
        comps = req.components if req.components else [
            {"name": "lodash", "version": "4.17.21", "ecosystem": "npm",
             "supplier": "OpenJS Foundation", "license": "MIT", "is_direct": True},
            {"name": "axios", "version": "1.6.0", "ecosystem": "npm",
             "supplier": "OpenJS Foundation", "license": "MIT", "is_direct": True},
            {"name": "react", "version": "18.2.0", "ecosystem": "npm",
             "supplier": "Meta Platforms", "license": "MIT", "is_direct": True},
        ]
        result = mgr.generate_sbom(req.name, comps, req.format)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("sbom_generate error")
        return fail(f"SBOM 生成失败: {e}", 500)


@router.get("/sbom/list")
def sbom_list():
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = SBOMManager()
        return ok({"sboms": mgr.list_sboms(), "total": len(mgr.list_sboms())})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/sbom/{sbom_id}")
def sbom_get(sbom_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = SBOMManager()
        sbom = mgr.get_sbom(sbom_id)
        if not sbom:
            return fail("SBOM 不存在", 404)
        return ok(sbom)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/sbom/{sbom_id}/components")
def sbom_components(sbom_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = SBOMManager()
        comps = mgr.get_components(sbom_id)
        return ok({"sbom_id": sbom_id, "components": comps, "total": len(comps)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/sbom/{sbom_id}/dependency-tree")
def sbom_dependency_tree(sbom_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = SBOMManager()
        return ok(mgr.get_dependency_tree(sbom_id))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/sbom/compare")
def sbom_compare(req: CompareSBOMRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = SBOMManager()
        result = mgr.compare_sboms(req.sbom_a, req.sbom_b)
        return ok(result)
    except Exception as e:
        return fail(f"SBOM 对比失败: {e}", 500)


@router.post("/sbom/import")
def sbom_import(req: ImportSBOMRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = SBOMManager()
        result = mgr.import_sbom(req.data, req.format)
        return ok(result)
    except Exception as e:
        return fail(f"SBOM 导入失败: {e}", 500)


@router.get("/sbom/{sbom_id}/export")
def sbom_export(sbom_id: str, format: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = SBOMManager()
        return ok(mgr.export_sbom(sbom_id, format))
    except Exception as e:
        return fail(f"SBOM 导出失败: {e}", 500)


# =========================================================================== #
# 2. 组件分析（6 个端点）
# =========================================================================== #
@router.post("/component/analyze")
def component_analyze(req: AnalyzeComponentRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("component_analyze")
        analyzer = ComponentAnalyzer()
        comps = req.components if req.components else [
            {"name": "lodash", "version": "4.17.21", "ecosystem": "npm", "is_direct": True},
            {"name": "axios", "version": "1.6.0", "ecosystem": "npm", "is_direct": True},
            {"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven", "is_direct": True},
            {"name": "openssl", "version": "1.1.1k", "ecosystem": "system", "is_direct": True},
            {"name": "left-pad", "version": "1.3.0", "ecosystem": "npm", "is_direct": False},
        ]
        result = analyzer.full_analysis(comps)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("component_analyze error")
        return fail(f"组件分析失败: {e}", 500)


@router.get("/component/{analysis_id}")
def component_get(analysis_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        analyzer = ComponentAnalyzer()
        result = analyzer.get_analysis(analysis_id)
        if not result:
            return fail("分析记录不存在", 404)
        return ok(result)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/component/list")
def component_list():
    try:
        g = _guard()
        if g is not None:
            return g
        analyzer = ComponentAnalyzer()
        return ok({"analyses": analyzer.list_analyses()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/component/fingerprint")
def component_fingerprint(name: str = Query(...), version: str = Query(default=""),
                           ecosystem: str = Query(default="")):
    try:
        g = _guard()
        if g is not None:
            return g
        analyzer = ComponentAnalyzer()
        return ok(analyzer.identify_component(name, version, ecosystem))
    except Exception as e:
        return fail(f"指纹识别失败: {e}", 500)


@router.get("/component/health-criteria")
def component_health_criteria():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(COMPONENT_HEALTH_CRITERIA)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/component/deprecated-scan")
def component_deprecated_scan(req: AnalyzeComponentRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        analyzer = ComponentAnalyzer()
        comps = req.components if req.components else [
            {"name": "left-pad", "version": "1.3.0"},
            {"name": "request", "version": "2.88.2"},
            {"name": "lodash", "version": "4.17.21"},
        ]
        return ok(analyzer.detect_deprecated(comps))
    except Exception as e:
        return fail(f"废弃组件扫描失败: {e}", 500)


# =========================================================================== #
# 3. 漏洞检测（7 个端点）
# =========================================================================== #
@router.post("/vulnerability/scan")
def vuln_scan(req: ScanVulnRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("vuln_scan")
        detector = VulnerabilityDetector()
        comps = req.components if req.components else [
            {"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven"},
            {"name": "openssl", "version": "1.1.1k", "ecosystem": "system"},
            {"name": "axios", "version": "1.6.0", "ecosystem": "npm"},
            {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
            {"name": "spring-core", "version": "5.3.20", "ecosystem": "maven"},
            {"name": "jackson-databind", "version": "2.13.0", "ecosystem": "maven"},
        ]
        result = detector.scan(comps)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("vuln_scan error")
        return fail(f"漏洞扫描失败: {e}", 500)


@router.get("/vulnerability/{scan_id}")
def vuln_get(scan_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        detector = VulnerabilityDetector()
        result = detector.get_scan(scan_id)
        if not result:
            return fail("扫描记录不存在", 404)
        return ok(result)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/vulnerability/list")
def vuln_list():
    try:
        g = _guard()
        if g is not None:
            return g
        detector = VulnerabilityDetector()
        return ok({"scans": detector.list_scans()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/vulnerability/lookup")
def vuln_lookup(cve_id: str = Query(...)):
    try:
        g = _guard()
        if g is not None:
            return g
        detector = VulnerabilityDetector()
        result = detector.lookup_cve(cve_id)
        if not result:
            return fail("CVE 记录不存在", 404)
        return ok(result)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/vulnerability/database")
def vuln_database(severity: Optional[str] = Query(default=None),
                   component: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        detector = VulnerabilityDetector()
        vulns = detector.list_vulnerabilities(severity, component)
        return ok({"vulnerabilities": vulns, "total": len(vulns),
                   "severity_levels": VULN_SEVERITY_LEVELS})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/vulnerability/zero-day-monitor")
def vuln_zero_day_monitor():
    try:
        g = _guard()
        if g is not None:
            return g
        detector = VulnerabilityDetector()
        return ok(detector.get_zero_day_monitor())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/vulnerability/alerts")
def vuln_alerts(severity: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        detector = VulnerabilityDetector()
        alerts = detector.get_alerts(severity)
        return ok({"alerts": alerts, "total": len(alerts)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 4. 许可证合规（6 个端点）
# =========================================================================== #
@router.post("/license/check")
def license_check(req: LicenseCheckRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("license_check")
        checker = LicenseComplianceChecker()
        comps = req.components if req.components else [
            {"name": "lodash", "version": "4.17.21", "license": "MIT"},
            {"name": "django", "version": "4.2.7", "license": "BSD-3-Clause"},
            {"name": "mysql", "version": "8.0.33", "license": "GPL-2.0"},
            {"name": "redis-server", "version": "7.0", "license": "SSPL-1.0"},
            {"name": "unknown-lib", "version": "1.0", "license": ""},
        ]
        result = checker.check(comps)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("license_check error")
        return fail(f"许可证合规检查失败: {e}", 500)


@router.get("/license/{report_id}")
def license_get(report_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        checker = LicenseComplianceChecker()
        result = checker.get_report(report_id)
        if not result:
            return fail("报告不存在", 404)
        return ok(result)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/license/list")
def license_list():
    try:
        g = _guard()
        if g is not None:
            return g
        checker = LicenseComplianceChecker()
        return ok({"reports": checker.list_reports()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/license/library")
def license_library(risk_category: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        checker = LicenseComplianceChecker()
        licenses = checker.list_licenses(risk_category)
        return ok({"licenses": licenses, "total": len(licenses),
                   "library_size": len(LICENSE_LIBRARY)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/license/identify")
def license_identify(name: str = Query(...)):
    try:
        g = _guard()
        if g is not None:
            return g
        checker = LicenseComplianceChecker()
        return ok(checker.identify_license(name))
    except Exception as e:
        return fail(f"识别失败: {e}", 500)


@router.get("/license/policies")
def license_policies():
    try:
        g = _guard()
        if g is not None:
            return g
        checker = LicenseComplianceChecker()
        return ok({"policies": checker.list_policies()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 5. 供应商风险（6 个端点）
# =========================================================================== #
@router.post("/supplier/assess")
def supplier_assess(req: SupplierAssessRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("supplier_assess")
        assessor = SupplierRiskAssessor()
        result = assessor.assess_suppliers(req.supplier_ids or None)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("supplier_assess error")
        return fail(f"供应商评估失败: {e}", 500)


@router.get("/supplier/list")
def supplier_list(risk_level: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        assessor = SupplierRiskAssessor()
        suppliers = assessor.list_suppliers(risk_level)
        return ok({"suppliers": suppliers, "total": len(suppliers)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/supplier/{supplier_id}/profile")
def supplier_profile(supplier_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        assessor = SupplierRiskAssessor()
        result = assessor.get_supplier_profile(supplier_id)
        if not result:
            return fail("供应商不存在", 404)
        return ok(result)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/supplier/{supplier_id}/scorecard")
def supplier_scorecard(supplier_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        assessor = SupplierRiskAssessor()
        return ok(assessor.scorecard(supplier_id))
    except Exception as e:
        return fail(f"评分卡生成失败: {e}", 500)


@router.get("/supplier/geopolitical-risks")
def supplier_geopolitical():
    try:
        g = _guard()
        if g is not None:
            return g
        assessor = SupplierRiskAssessor()
        return ok(assessor.get_geopolitical_risks())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/supplier/risk-factors")
def supplier_risk_factors():
    try:
        g = _guard()
        if g is not None:
            return g
        assessor = SupplierRiskAssessor()
        return ok(assessor.get_risk_factors())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 6. 综合评估（4 个端点）
# =========================================================================== #
@router.post("/assessment/run")
def assessment_run(req: AssessmentRunRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("supply_chain_assessment")
        wf = get_supply_chain_workflow()
        ctx = {"scan_id": task_id}
        if req.components:
            ctx["components"] = req.components
        result = wf.run_assessment(ctx)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("assessment_run error")
        return fail(f"供应链综合评估失败: {e}", 500)


@router.get("/assessment/{task_id}/status")
def assessment_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/assessment/{task_id}/results")
def assessment_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/assessment/history")
def assessment_history():
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_supply_chain_workflow()
        return ok({"history": wf.list_history(),
                   "workflow_steps": SUPPLY_CHAIN_STEPS})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)
