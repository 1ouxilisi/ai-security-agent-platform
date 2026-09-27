# -*- coding: utf-8 -*-
"""
real_validation_routes.py — 第28轮升级方向2：真实场景验证与误报率优化 REST API。

路由前缀: /api/v1/real-validation
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。
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

router = APIRouter(prefix="/api/v1/real-validation",
                   tags=["Real Validation 真实场景验证与误报率优化"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，带 fallback）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from real_validation.range_integration import (
        get_range_manager, RANGE_LIBRARY, DEPLOY_TYPES, RANGE_STATUSES,
    )
    from real_validation.scan_validation import (
        get_scan_validator, SCAN_TYPES, COMMON_PORTS, FALSE_POSITIVE_REASONS,
        FALSE_NEGATIVE_REASONS,
    )
    from real_validation.false_positive_optimizer import (
        get_fp_optimizer, RULE_CATEGORIES, RULE_ACTIONS, RULE_PRIORITIES,
        FILTER_MODES, ML_MODEL_TYPES, REVIEW_STATUSES,
    )
    from real_validation.vuln_verification import (
        get_vuln_verifier, CWE_CATEGORIES, OWASP_TOP10_2021,
        ATTACK_TACTICS, VERIFICATION_METHODS,
    )
    from real_validation.validation_framework import (
        get_validation_framework, VALIDATION_STANDARDS, BENCHMARK_TARGETS,
        CASE_PRIORITIES, CASE_STATUSES, CASE_CATEGORIES,
    )
    from real_validation.real_validation_dashboard import (
        get_dashboard, SYSTEM_SETTINGS, DASHBOARD_VERSION,
    )
    _MOD_AVAILABLE = True
    logger.info("real_validation_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("real_validation_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from real_validation.range_integration import (  # noqa
            get_range_manager, RANGE_LIBRARY, DEPLOY_TYPES, RANGE_STATUSES,
        )
        from real_validation.scan_validation import (  # noqa
            get_scan_validator, SCAN_TYPES, COMMON_PORTS, FALSE_POSITIVE_REASONS,
            FALSE_NEGATIVE_REASONS,
        )
        from real_validation.false_positive_optimizer import (  # noqa
            get_fp_optimizer, RULE_CATEGORIES, RULE_ACTIONS, RULE_PRIORITIES,
            FILTER_MODES, ML_MODEL_TYPES, REVIEW_STATUSES,
        )
        from real_validation.vuln_verification import (  # noqa
            get_vuln_verifier, CWE_CATEGORIES, OWASP_TOP10_2021,
            ATTACK_TACTICS, VERIFICATION_METHODS,
        )
        from real_validation.validation_framework import (  # noqa
            get_validation_framework, VALIDATION_STANDARDS, BENCHMARK_TARGETS,
            CASE_PRIORITIES, CASE_STATUSES, CASE_CATEGORIES,
        )
        from real_validation.real_validation_dashboard import (  # noqa
            get_dashboard, SYSTEM_SETTINGS, DASHBOARD_VERSION,
        )
        _MOD_AVAILABLE = True
        logger.info("real_validation_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("real_validation_routes: fallback load failed: %s", e2)


# 绑定模块到仪表盘
if _MOD_AVAILABLE:
    try:
        get_dashboard().bind_modules(
            range_manager=get_range_manager(),
            scan_validator=get_scan_validator(),
            fp_optimizer=get_fp_optimizer(),
            vuln_verifier=get_vuln_verifier(),
            validation_framework=get_validation_framework(),
        )
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    tid = uuid.uuid4().hex[:16]
    TASKS[tid] = {
        "task_id": tid, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return tid


def _finish_task(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in TASKS:
        t = TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        chars = [c for c in obj if ord(c) >= 32 or c in ("\t", "\n", "\r")]
        s = "".join(chars)
        return s.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, tuple):
        return [_clean(v) for v in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("Real Validation 模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class DeployReq(BaseModel):
    deploy_type: str = "docker"
    host: str = "127.0.0.1"
    port: Optional[int] = None
    version: str = "latest"


class ScanReq(BaseModel):
    target_host: str = "127.0.0.1"
    target_port: int = 80
    scan_type: str = "nmap_port"
    scan_depth: str = "normal"


class FPMarkReq(BaseModel):
    reason: Optional[str] = None


class FNRecordReq(BaseModel):
    vuln_name: str
    cve: Optional[str] = None
    reason: Optional[str] = None


class RuleReq(BaseModel):
    name: str
    category: str = "version_exact"
    condition: Dict[str, Any] = Field(default_factory=dict)
    action: str = "filter"
    priority: str = "P2"
    confidence_threshold: float = 0.5
    description: str = ""


class ReviewReq(BaseModel):
    result: str = "approved"
    reviewer: str = "admin"
    feedback: str = ""


class VerifyReq(BaseModel):
    method: str = "poc"


class TestCaseReq(BaseModel):
    name: str
    category: str = "web"
    priority: str = "P2"
    target: str = ""
    steps: List[str] = Field(default_factory=list)
    expected: str = ""


class SettingsReq(BaseModel):
    auto_verify: Optional[bool] = None
    auto_filter_fp: Optional[bool] = None
    confidence_threshold: Optional[float] = None
    review_enabled: Optional[bool] = None
    continuous_scan: Optional[bool] = None


# =========================================================================== #
# 模块1：真实靶场集成 (range_integration) — 端点 1~14
# =========================================================================== #

@router.get("/ranges/library")
def ranges_library():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_range_manager().list_range_library())
    except Exception as e:
        logger.exception("ranges_library error")
        return fail(str(e))


@router.get("/ranges")
def list_ranges(category: Optional[str] = None, status: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_range_manager().list_ranges(category=category, status=status))
    except Exception as e:
        return fail(str(e))


@router.get("/ranges/{range_id}")
def get_range(range_id: str):
    try:
        g = _guard()
        if g:
            return g
        r = get_range_manager().get_range(range_id)
        if not r:
            return fail("靶场不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(str(e))


@router.post("/ranges/{range_id}/deploy")
def deploy_range(range_id: str, req: DeployReq):
    try:
        g = _guard()
        if g:
            return g
        result = get_range_manager().deploy(
            range_id, deploy_type=req.deploy_type, host=req.host,
            port=req.port, version=req.version)
        if not result.get("success"):
            return fail(result.get("error", "部署失败"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/ranges/{range_id}/start")
def start_range(range_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_range_manager().start(range_id)
        if not result.get("success"):
            return fail(result.get("error", "启动失败"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/ranges/{range_id}/stop")
def stop_range(range_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_range_manager().stop(range_id)
        if not result.get("success"):
            return fail(result.get("error", "停止失败"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/ranges/{range_id}/restart")
def restart_range(range_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_range_manager().restart(range_id)
        if not result.get("success"):
            return fail(result.get("error", "重启失败"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/ranges/{range_id}/reset")
def reset_range(range_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_range_manager().reset(range_id)
        if not result.get("success"):
            return fail(result.get("error", "重置失败"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/ranges/{range_id}/snapshot")
def create_snapshot(range_id: str, name: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        result = get_range_manager().create_snapshot(range_id, name=name)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.get("/snapshots")
def list_snapshots(range_id: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_range_manager().list_snapshots(range_id=range_id))
    except Exception as e:
        return fail(str(e))


@router.post("/snapshots/{snapshot_id}/restore")
def restore_snapshot(snapshot_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_range_manager().restore_snapshot(snapshot_id)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/ranges/{range_id}/clone")
def clone_range(range_id: str, new_name: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        result = get_range_manager().clone_range(range_id, new_name=new_name)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.get("/ranges/{range_id}/monitor")
def monitor_range(range_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_range_manager().get_monitor(range_id)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/ranges/{range_id}/verify")
def verify_range(range_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_range_manager().verify_range(range_id)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 模块2：真实扫描验证 (scan_validation) — 端点 15~26
# =========================================================================== #

@router.post("/scans/execute")
def execute_scan(req: ScanReq):
    try:
        g = _guard()
        if g:
            return g
        scan = get_scan_validator().execute_scan(
            req.target_host, req.target_port, req.scan_type, req.scan_depth)
        return ok(scan)
    except Exception as e:
        return fail(str(e))


@router.get("/scans")
def list_scans(limit: int = 30):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_scan_validator().list_scans(limit=limit))
    except Exception as e:
        return fail(str(e))


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    try:
        g = _guard()
        if g:
            return g
        s = get_scan_validator().get_scan(scan_id)
        if not s:
            return fail("扫描不存在", 404)
        return ok(s)
    except Exception as e:
        return fail(str(e))


@router.get("/scans/{scan_id}/analyze")
def analyze_scan(scan_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_scan_validator().analyze_results(scan_id)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/scans/{scan_id}/fp-mark/{vuln_id}")
def mark_fp(scan_id: str, vuln_id: str, req: FPMarkReq):
    try:
        g = _guard()
        if g:
            return g
        result = get_scan_validator().mark_false_positive(
            scan_id, vuln_id, reason=req.reason)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/scans/{scan_id}/fn-record")
def record_fn(scan_id: str, req: FNRecordReq):
    try:
        g = _guard()
        if g:
            return g
        result = get_scan_validator().mark_false_negative(
            scan_id, req.vuln_name, cve=req.cve, reason=req.reason)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.get("/fp-list")
def list_fp(limit: int = 50):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_scan_validator().list_false_positives(limit=limit))
    except Exception as e:
        return fail(str(e))


@router.get("/fn-list")
def list_fn(limit: int = 50):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_scan_validator().list_false_negatives(limit=limit))
    except Exception as e:
        return fail(str(e))


@router.get("/scans/{scan_id}/report")
def scan_report(scan_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_scan_validator().generate_report(scan_id))
    except Exception as e:
        return fail(str(e))


@router.get("/scan-stats")
def scan_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_scan_validator().stats())
    except Exception as e:
        return fail(str(e))


@router.get("/scan-types")
def scan_types():
    try:
        return ok({"scan_types": SCAN_TYPES, "common_ports": COMMON_PORTS})
    except Exception as e:
        return fail(str(e))


@router.get("/fp-reasons")
def fp_reasons():
    try:
        return ok({"fp_reasons": FALSE_POSITIVE_REASONS,
                   "fn_reasons": FALSE_NEGATIVE_REASONS})
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 模块3：误报率优化 (false_positive_optimizer) — 端点 27~40
# =========================================================================== #

@router.get("/fp-rules")
def list_rules(category: Optional[str] = None, enabled_only: bool = False):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_fp_optimizer().list_rules(category=category,
                                                  enabled_only=enabled_only))
    except Exception as e:
        return fail(str(e))


@router.post("/fp-rules")
def add_rule(req: RuleReq):
    try:
        g = _guard()
        if g:
            return g
        result = get_fp_optimizer().add_rule(
            name=req.name, category=req.category, condition=req.condition,
            action=req.action, priority=req.priority,
            confidence_threshold=req.confidence_threshold,
            description=req.description)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.get("/fp-rules/{rule_id}")
def get_rule(rule_id: str):
    try:
        g = _guard()
        if g:
            return g
        r = get_fp_optimizer().get_rule(rule_id)
        if not r:
            return fail("规则不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(str(e))


@router.put("/fp-rules/{rule_id}")
def update_rule(rule_id: str, req: RuleReq):
    try:
        g = _guard()
        if g:
            return g
        result = get_fp_optimizer().update_rule(
            rule_id, name=req.name, category=req.category,
            condition=req.condition, action=req.action, priority=req.priority,
            confidence_threshold=req.confidence_threshold,
            description=req.description)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.delete("/fp-rules/{rule_id}")
def delete_rule(rule_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_fp_optimizer().delete_rule(rule_id)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/fp-rules/{rule_id}/test")
def test_rule(rule_id: str, sample_count: int = 10):
    try:
        g = _guard()
        if g:
            return g
        import random
        samples = [{"service": "http", "version": f"2.4.{i}",
                     "confidence": random.uniform(0.3, 0.95)}
                    for i in range(sample_count)]
        result = get_fp_optimizer().test_rule(rule_id, samples)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/fp-filter")
def filter_vulns(mode: str = "rule_based", vuln_count: int = 20):
    try:
        g = _guard()
        if g:
            return g
        import random
        sample_vulns = [
            {"vuln_id": f"v{i}", "cve": f"CVE-2024-{1000+i}",
             "name": f"漏洞{i}", "service": random.choice(["http", "mysql", "ssh"]),
             "version": "2.4.49", "confidence": random.uniform(0.3, 0.95),
             "is_false_positive": random.random() < 0.2}
            for i in range(vuln_count)
        ]
        result = get_fp_optimizer().filter_vulnerabilities(sample_vulns, mode=mode)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.get("/fp-models")
def list_models():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_fp_optimizer().list_models())
    except Exception as e:
        return fail(str(e))


@router.post("/fp-models/{model_type}/predict")
def predict_model(model_type: str, confidence: float = 0.8, service: str = "http"):
    try:
        g = _guard()
        if g:
            return g
        result = get_fp_optimizer().predict(
            model_type,
            {"confidence": confidence, "service": service, "cve_id": "CVE-2024-0001"})
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/fp-models/{model_type}/retrain")
def retrain_model(model_type: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_fp_optimizer().retrain_model(model_type)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.get("/fp-review-queue")
def review_queue(status: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_fp_optimizer().list_review_queue(status=status))
    except Exception as e:
        return fail(str(e))


@router.post("/fp-review/{review_id}/process")
def process_review(review_id: str, req: ReviewReq):
    try:
        g = _guard()
        if g:
            return g
        result = get_fp_optimizer().process_review(
            review_id, result=req.result, reviewer=req.reviewer,
            feedback=req.feedback)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.get("/fp-review-stats")
def review_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_fp_optimizer().review_stats())
    except Exception as e:
        return fail(str(e))


@router.post("/fp-optimize")
def run_optimization():
    try:
        g = _guard()
        if g:
            return g
        result = get_fp_optimizer().run_optimization()
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 模块4：漏洞确认与验证 (vuln_verification) — 端点 41~52
# =========================================================================== #

@router.get("/vulns")
def list_vulns(severity: Optional[str] = None, verified: Optional[bool] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_vuln_verifier().list_vulns(severity=severity, verified=verified))
    except Exception as e:
        return fail(str(e))


@router.get("/vulns/{vuln_id}")
def get_vuln(vuln_id: str):
    try:
        g = _guard()
        if g:
            return g
        v = get_vuln_verifier().get_vuln(vuln_id)
        if not v:
            return fail("漏洞不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.post("/vulns/{vuln_id}/confirm")
def confirm_vuln(vuln_id: str, req: VerifyReq):
    try:
        g = _guard()
        if g:
            return g
        result = get_vuln_verifier().confirm_vuln(vuln_id, method=req.method)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/vulns/{vuln_id}/rate")
def rate_vuln(vuln_id: str, business_value: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        result = get_vuln_verifier().rate_vuln(
            vuln_id, business_value=business_value)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/vulns/{vuln_id}/classify")
def classify_vuln(vuln_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_vuln_verifier().classify_vuln(vuln_id)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.get("/vuln-trends")
def vuln_trends(days: int = 30):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_vuln_verifier().get_trends(days=days))
    except Exception as e:
        return fail(str(e))


@router.get("/vuln-reports")
def vuln_reports(limit: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_vuln_verifier().list_reports(limit=limit))
    except Exception as e:
        return fail(str(e))


@router.post("/vuln-reports/generate")
def gen_vuln_report(vuln_id: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        result = get_vuln_verifier().generate_report(vuln_id=vuln_id)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.get("/vuln-stats")
def vuln_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_vuln_verifier().stats())
    except Exception as e:
        return fail(str(e))


@router.get("/cwe-categories")
def cwe_categories():
    try:
        return ok({"cwe_categories": CWE_CATEGORIES,
                   "owasp_top10": OWASP_TOP10_2021,
                   "attack_tactics": ATTACK_TACTICS,
                   "verification_methods": VERIFICATION_METHODS})
    except Exception as e:
        return fail(str(e))


@router.get("/vuln-remediation/{vuln_id}")
def remediation(vuln_id: str):
    try:
        g = _guard()
        if g:
            return g
        v = get_vuln_verifier().get_vuln(vuln_id)
        if not v:
            return fail("漏洞不存在", 404)
        # 调用内部方法
        from real_validation.vuln_verification import VulnVerifier
        advice = VulnVerifier._remediation_advice(get_vuln_verifier(), v)
        return ok({"vuln_id": vuln_id, "advice": advice})
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 模块5：验证体系与基准 (validation_framework) — 端点 53~62
# =========================================================================== #

@router.get("/standards")
def list_standards():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_validation_framework().list_standards())
    except Exception as e:
        return fail(str(e))


@router.get("/benchmarks")
def list_benchmarks():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_validation_framework().list_benchmarks())
    except Exception as e:
        return fail(str(e))


@router.post("/benchmarks/{benchmark_id}/run")
def run_benchmark(benchmark_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_validation_framework().run_benchmark(benchmark_id)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.get("/test-cases")
def list_test_cases(category: Optional[str] = None,
                    status: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_validation_framework().list_test_cases(
            category=category, status=status))
    except Exception as e:
        return fail(str(e))


@router.post("/test-cases")
def add_test_case(req: TestCaseReq):
    try:
        g = _guard()
        if g:
            return g
        result = get_validation_framework().add_test_case(
            name=req.name, category=req.category, priority=req.priority,
            target=req.target, steps=req.steps, expected=req.expected)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.delete("/test-cases/{case_id}")
def delete_test_case(case_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_validation_framework().delete_test_case(case_id)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/test-cases/{case_id}/run")
def run_test_case(case_id: str, mode: str = "semi_auto"):
    try:
        g = _guard()
        if g:
            return g
        result = get_validation_framework().run_test_case(case_id, mode=mode)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/regression")
def run_regression(category: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_validation_framework().run_regression(category=category))
    except Exception as e:
        return fail(str(e))


@router.get("/metrics")
def validation_metrics():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_validation_framework().get_metrics())
    except Exception as e:
        return fail(str(e))


@router.post("/framework-report")
def framework_report():
    try:
        g = _guard()
        if g:
            return g
        result = get_validation_framework().generate_report()
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 模块6：控制台数据聚合 (real_validation_dashboard) — 端点 63~70
# =========================================================================== #

@router.get("/overview")
def dashboard_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().get_overview())
    except Exception as e:
        return fail(str(e))


@router.get("/trends")
def dashboard_trends(days: int = 7):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().get_trends(days=days))
    except Exception as e:
        return fail(str(e))


@router.get("/health")
def dashboard_health():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().get_health())
    except Exception as e:
        return fail(str(e))


@router.get("/settings")
def get_settings():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().get_settings())
    except Exception as e:
        return fail(str(e))


@router.put("/settings")
def update_settings(req: SettingsReq):
    try:
        g = _guard()
        if g:
            return g
        updates = {k: v for k, v in req.dict().items() if v is not None}
        return ok(get_dashboard().update_settings(updates))
    except Exception as e:
        return fail(str(e))


@router.post("/export")
def export_report(fmt: str = "json"):
    try:
        g = _guard()
        if g:
            return g
        result = get_dashboard().export_report(fmt=fmt)
        if not result.get("success"):
            return fail(result.get("error"))
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.get("/exports")
def list_exports(limit: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().list_exports(limit=limit))
    except Exception as e:
        return fail(str(e))


@router.get("/info")
def module_info():
    try:
        return ok({
            "version": DASHBOARD_VERSION,
            "module": "real_validation",
            "round": 28,
            "direction": "真实场景验证与误报率优化",
            "modules": [
                "range_integration", "scan_validation",
                "false_positive_optimizer", "vuln_verification",
                "validation_framework", "real_validation_dashboard",
            ],
        })
    except Exception as e:
        return fail(str(e))
