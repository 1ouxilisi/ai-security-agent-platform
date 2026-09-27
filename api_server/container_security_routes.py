# -*- coding: utf-8 -*-
"""
container_security_routes.py — 容器与 Kubernetes 安全 REST API（36 个端点）。

路由前缀: /api/v1/container-security
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。

设计定位：仅用于经过授权的容器/K8s 安全检测、审计与加固建议。
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

router = APIRouter(prefix="/api/v1/container-security", tags=["容器与Kubernetes安全"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from container_security.image_scanner import ImageScanner
    from container_security.runtime_security import RuntimeSecurity
    from container_security.k8s_config_audit import K8sConfigAuditor, CIS_K8S_CHECKS
    from container_security.k8s_runtime_security import (
        K8sRuntimeSecurity, ATTACK_CONTAINERS_TACTICS,
    )
    from container_security.infrastructure_security import InfrastructureSecurity
    from container_security.container_dashboard import ContainerDashboard
    _MOD_AVAILABLE = True
    logger.info("container_security_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("container_security_routes: load failed: %s", e)


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
# 统一响应（_clean 递归清理控制字符）
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理数据中的控制字符与无效Unicode代理对。"""
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
        return fail("容器与K8s安全模块不可用，请检查加载日志", 503)
    return None


def _task_view(t: Dict[str, Any]) -> Dict[str, Any]:
    return {"task_id": t["task_id"], "status": t["status"], "kind": t["kind"],
            "created_at": t["created_at"], "finished_at": t["finished_at"]}


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ImageScanRequest(BaseModel):
    image_ref: str = "nginx:alpine"


class K8sAuditRequest(BaseModel):
    manifest: str = ""
    cluster_name: str = "production-cluster"


class RuntimeAssessRequest(BaseModel):
    container_id: str = ""


class InfraAssessRequest(BaseModel):
    scope: str = "all"


# =========================================================================== #
# 1. 容器镜像安全扫描（6 个端点）
# =========================================================================== #
@router.post("/images/scan")
def images_scan(req: ImageScanRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("image_scan")
        scanner = ImageScanner(req.image_ref)
        result = scanner.scan()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("images_scan error")
        return fail(f"镜像扫描失败: {e}", 500)


@router.get("/images/{task_id}/status")
def images_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/images/{task_id}/results")
def images_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/images/history")
def images_history():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"history": ImageScanner().scan_history()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/images/vuln-db")
def images_vuln_db(severity: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        from container_security.image_scanner import OS_CVE_DB, APP_DEP_CVE_DB
        items = [{"cve": v["cve"], "package": v["pkg"], "severity": v["severity"],
                  "cvss": v["cvss"], "fixed": v["fixed"], "desc": v["desc"]}
                 for v in OS_CVE_DB + APP_DEP_CVE_DB]
        if severity:
            items = [i for i in items if i["severity"] == severity]
        return ok({"total": len(items), "items": items})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/images/sensitive-patterns")
def images_sensitive_patterns():
    try:
        g = _guard()
        if g is not None:
            return g
        from container_security.image_scanner import SENSITIVE_PATTERNS
        items = [{"key": k, "label": v[1], "pattern": v[0].pattern}
                 for k, v in SENSITIVE_PATTERNS.items()]
        return ok({"total": len(items), "patterns": items})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 2. 容器运行时安全（7 个端点）
# =========================================================================== #
@router.get("/runtime/containers")
def runtime_containers():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"containers": RuntimeSecurity().list_containers()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/runtime/assess")
def runtime_assess(req: RuntimeAssessRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("runtime_assess")
        result = RuntimeSecurity(req.container_id).assess()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("runtime_assess error")
        return fail(f"运行时评估失败: {e}", 500)


@router.get("/runtime/{container_id}/processes")
def runtime_processes(container_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(RuntimeSecurity(container_id).monitor_processes())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/runtime/{container_id}/filesystem")
def runtime_filesystem(container_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(RuntimeSecurity(container_id).monitor_filesystem())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/runtime/{container_id}/network")
def runtime_network(container_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(RuntimeSecurity(container_id).monitor_network())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/runtime/{container_id}/syscalls")
def runtime_syscalls(container_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(RuntimeSecurity(container_id).audit_syscalls())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/runtime/threats")
def runtime_threats():
    try:
        g = _guard()
        if g is not None:
            return g
        threats = RuntimeSecurity().detect_threats()
        return ok({"threats": threats, "total": len(threats)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/runtime/isolation-checks")
def runtime_isolation_checks():
    try:
        g = _guard()
        if g is not None:
            return g
        checks = RuntimeSecurity().check_isolation()
        violations = [c for c in checks if not c["passed"]]
        return ok({"checks": checks, "total": len(checks),
                   "violations": len(violations)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 3. Kubernetes 配置审计（6 个端点）
# =========================================================================== #
@router.post("/k8s-config/audit")
def k8s_config_audit(req: K8sAuditRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("k8s_config_audit")
        result = K8sConfigAuditor(req.manifest).audit()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("k8s_config_audit error")
        return fail(f"K8s配置审计失败: {e}", 500)


@router.get("/k8s-config/resources")
def k8s_config_resources():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(K8sConfigAuditor().parse_manifests())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/k8s-config/rbac")
def k8s_config_rbac():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(K8sConfigAuditor().audit_rbac())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/k8s-config/secrets")
def k8s_config_secrets():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(K8sConfigAuditor().check_secrets())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/k8s-config/network-policies")
def k8s_config_network_policies():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(K8sConfigAuditor().check_network_policies())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/k8s-config/cis-benchmark")
def k8s_config_cis(level: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        result = K8sConfigAuditor().run_cis_benchmark()
        if level:
            result["results"] = [r for r in result["results"] if r["level"] == level]
        return ok(result)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 4. Kubernetes 运行时安全（6 个端点）
# =========================================================================== #
@router.get("/k8s-runtime/api-audit")
def k8s_runtime_api_audit():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(K8sRuntimeSecurity().audit_api_logs())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/k8s-runtime/pod-anomalies")
def k8s_runtime_pod_anomalies():
    try:
        g = _guard()
        if g is not None:
            return g
        anomalies = K8sRuntimeSecurity().detect_pod_anomalies()
        return ok({"anomalies": anomalies, "total": len(anomalies)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/k8s-runtime/threats")
def k8s_runtime_threats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(K8sRuntimeSecurity().detect_cluster_threats())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/k8s-runtime/admission")
def k8s_runtime_admission():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(K8sRuntimeSecurity().check_admission_control())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/k8s-runtime/cluster-resources")
def k8s_runtime_cluster_resources():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(K8sRuntimeSecurity().monitor_cluster_resources())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/k8s-runtime/assess")
def k8s_runtime_assess(req: K8sAuditRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("k8s_runtime_assess")
        result = K8sRuntimeSecurity(req.cluster_name).assess()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("k8s_runtime_assess error")
        return fail(f"K8s运行时评估失败: {e}", 500)


# =========================================================================== #
# 5. 容器基础设施安全（6 个端点）
# =========================================================================== #
@router.get("/infra/docker-daemon")
def infra_docker_daemon():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(InfrastructureSecurity().audit_docker_daemon())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/infra/containerd")
def infra_containerd():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(InfrastructureSecurity().audit_containerd())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/infra/runtime")
def infra_runtime():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(InfrastructureSecurity().audit_runtime())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/infra/registry")
def infra_registry():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(InfrastructureSecurity().audit_registry())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/infra/cicd")
def infra_cicd():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(InfrastructureSecurity().audit_cicd())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/infra/iac")
def infra_iac():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(InfrastructureSecurity().scan_iac())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 6. 容器安全运营仪表盘（6 个端点）
# =========================================================================== #
@router.get("/dashboard/assets")
def dashboard_assets():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ContainerDashboard().asset_overview())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/posture")
def dashboard_posture():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ContainerDashboard().security_posture())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/alerts")
def dashboard_alerts():
    try:
        g = _guard()
        if g is not None:
            return g
        alerts = ContainerDashboard().realtime_alerts()
        return ok({"alerts": alerts, "total": len(alerts)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/vulnerabilities")
def dashboard_vulnerabilities():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ContainerDashboard().vulnerability_management())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/compliance")
def dashboard_compliance():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ContainerDashboard().compliance_status())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/metrics")
def dashboard_metrics():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ContainerDashboard().security_metrics())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/summary")
def dashboard_summary():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ContainerDashboard().dashboard())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)
