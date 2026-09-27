# -*- coding: utf-8 -*-
"""
devsecops_deep_routes.py — 第26轮升级方向2：安全自动化与 DevSecOps 深度平台 REST API。

路由前缀: /api/v1/devsecops-deep
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。

覆盖 7 大模块 60+ 端点：
    总览/设置 · CI/CD · SAST · 依赖 · 容器 · IaC · 安全即代码
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

router = APIRouter(prefix="/api/v1/devsecops-deep", tags=["DevSecOps Deep 深度平台"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，带 fallback）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from devsecops_deep.cicd_security import get_cicd_security, DEFAULT_GATE_RULES
    from devsecops_deep.sast_deep import get_sast_deep
    from devsecops_deep.dependency_deep import get_dependency_deep
    from devsecops_deep.container_deep import get_container_deep
    from devsecops_deep.iac_security import get_iac_security
    from devsecops_deep.security_as_code import get_security_as_code
    from devsecops_deep.devsecops_dashboard import (
        get_devsecops_dashboard, SYSTEM_SETTINGS,
    )
    _MOD_AVAILABLE = True
    logger.info("devsecops_deep_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("devsecops_deep_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from devsecops_deep.cicd_security import get_cicd_security, DEFAULT_GATE_RULES  # noqa
        from devsecops_deep.sast_deep import get_sast_deep  # noqa
        from devsecops_deep.dependency_deep import get_dependency_deep  # noqa
        from devsecops_deep.container_deep import get_container_deep  # noqa
        from devsecops_deep.iac_security import get_iac_security  # noqa
        from devsecops_deep.security_as_code import get_security_as_code  # noqa
        from devsecops_deep.devsecops_dashboard import (  # noqa
            get_devsecops_dashboard, SYSTEM_SETTINGS,
        )
        _MOD_AVAILABLE = True
        logger.info("devsecops_deep_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("devsecops_deep_routes: fallback load failed: %s", e2)


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
        return fail("DevSecOps Deep 模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class PipelineCreateReq(BaseModel):
    name: str
    kind: str = "generic"
    stages: List[str] = Field(default_factory=list)
    scans: List[str] = Field(default_factory=list)


class PipelineUpdateReq(BaseModel):
    name: Optional[str] = None
    kind: Optional[str] = None
    status: Optional[str] = None
    default_branch: Optional[str] = None
    stages: Optional[List[str]] = None
    scans: Optional[List[str]] = None


class PipelineRunReq(BaseModel):
    branch: str = "main"
    commit: str = "abc1234"
    findings: Dict[str, int] = Field(default_factory=dict)


class GateRuleReq(BaseModel):
    key: str
    value: int


class GateEvaluateReq(BaseModel):
    findings: Dict[str, int] = Field(default_factory=dict)


class SASTScanReq(BaseModel):
    code: str
    filename: str = "snippet.py"
    lang: str = "python"


class SASTRuleReq(BaseModel):
    rid: str
    name: str
    category: str = "custom"
    severity: str = "medium"
    pattern: str = ""
    cwe: str = ""
    fix: str = ""


class DepScanReq(BaseModel):
    text: str
    source: str = "requirements.txt"


class ContainerAnalyzeReq(BaseModel):
    extra_layers: List[Dict[str, Any]] = Field(default_factory=list)


class RuntimeCheckReq(BaseModel):
    name: str = "unnamed"
    privileged: bool = False
    docker_sock_mounted: bool = False
    host_network: bool = False
    cap_sys_admin: bool = False
    host_path_mount: bool = False
    run_as_root: bool = True
    read_only_rootfs: bool = False
    cpu_limit: bool = True
    mem_limit: bool = True
    exposed_ports: List[int] = Field(default_factory=list)
    network_mode: str = "bridge"


class IaCScanReq(BaseModel):
    content: str
    filename: str = "main.tf"
    lang: str = "auto"


class SaCPolicyReq(BaseModel):
    name: str
    severity: str = "medium"
    rules: List[str] = Field(default_factory=list)
    author: str = "sec-team"


class SaCPolicyValidateReq(BaseModel):
    policy_text: str


class SaCControlReq(BaseModel):
    name: str
    framework: str = "NIST"
    status: str = "partial"


class SaCFlowReq(BaseModel):
    name: str
    steps: List[str] = Field(default_factory=list)
    approvers: List[str] = Field(default_factory=list)


class SaCConfigReq(BaseModel):
    name: str
    items: List[str] = Field(default_factory=list)


class SaCTestReq(BaseModel):
    code: str
    context: Dict[str, Any] = Field(default_factory=dict)


class SettingsUpdateReq(BaseModel):
    fields: Dict[str, Any] = Field(default_factory=dict)


# =========================================================================== #
# 一、总览 / 系统设置
# =========================================================================== #
@router.get("/overview")
def overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_devsecops_dashboard().overview())
    except Exception as e:  # noqa: BLE001
        logger.exception("overview error")
        return fail(str(e))


@router.get("/summary")
def summary():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_devsecops_dashboard().summary_by_module())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/settings")
def get_settings():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_devsecops_dashboard().get_settings())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.put("/settings")
def update_settings(req: SettingsUpdateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_devsecops_dashboard().update_settings(req.fields))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/health")
def health():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_devsecops_dashboard().health_check())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/tasks")
def list_tasks():
    try:
        return ok(list(TASKS.values()))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 二、CI/CD 安全
# =========================================================================== #
@router.get("/cicd/pipelines")
def list_pipelines(status: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_cicd_security().list_pipelines(status))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/cicd/pipelines")
def create_pipeline(req: PipelineCreateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_cicd_security().create_pipeline(
            req.name, req.kind, req.stages or None, req.scans or None))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/cicd/pipelines/{pid}")
def get_pipeline(pid: str):
    try:
        g = _guard()
        if g:
            return g
        p = get_cicd_security().get_pipeline(pid)
        if not p:
            return fail("管道不存在", 404)
        return ok(p)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.put("/cicd/pipelines/{pid}")
def update_pipeline(pid: str, req: PipelineUpdateReq):
    try:
        g = _guard()
        if g:
            return g
        fields = {k: v for k, v in req.dict().items() if v is not None}
        p = get_cicd_security().update_pipeline(pid, **fields)
        if not p:
            return fail("管道不存在", 404)
        return ok(p)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.delete("/cicd/pipelines/{pid}")
def delete_pipeline(pid: str):
    try:
        g = _guard()
        if g:
            return g
        ok_del = get_cicd_security().delete_pipeline(pid)
        if not ok_del:
            return fail("管道不存在", 404)
        return ok({"deleted": pid})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/cicd/pipelines/{pid}/toggle")
def toggle_pipeline(pid: str):
    try:
        g = _guard()
        if g:
            return g
        p = get_cicd_security().toggle_pipeline(pid)
        if not p:
            return fail("管道不存在", 404)
        return ok(p)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/cicd/pipelines/{pid}/run")
def run_pipeline(pid: str, req: PipelineRunReq):
    try:
        g = _guard()
        if g:
            return g
        tid = _new_task("pipeline-run")
        result = get_cicd_security().run_pipeline(
            pid, req.branch, req.commit, req.findings or None)
        if not result:
            _finish_task(tid, None, "管道不存在")
            return fail("管道不存在", 404)
        _finish_task(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/cicd/pipelines/{pid}/rerun")
def rerun_pipeline(pid: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_cicd_security().rerun_pipeline(pid)
        if not result:
            return fail("管道不存在", 404)
        return ok(result)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/cicd/runs")
def list_runs(pid: Optional[str] = Query(None), limit: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_cicd_security().list_runs(pid, limit))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/cicd/runs/{run_id}")
def get_run(run_id: str):
    try:
        g = _guard()
        if g:
            return g
        r = get_cicd_security().get_run(run_id)
        if not r:
            return fail("运行记录不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/cicd/gate/rules")
def get_gate_rules():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_cicd_security().get_gate_rules())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.put("/cicd/gate/rules")
def set_gate_rule(req: GateRuleReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_cicd_security().set_gate_rule(req.key, req.value))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/cicd/gate/evaluate")
def evaluate_gate(req: GateEvaluateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_cicd_security().evaluate_gate(req.findings))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/cicd/metrics")
def cicd_metrics():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_cicd_security().metrics())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/cicd/report")
def cicd_report(pid: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_cicd_security().security_report(pid))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 三、SAST 代码安全
# =========================================================================== #
@router.get("/sast/rules")
def sast_rules(category: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_sast_deep().list_rules(category))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/sast/rules")
def sast_add_rule(req: SASTRuleReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_sast_deep().add_rule(req.rid, req.name, req.category,
                                           req.severity, req.pattern,
                                           req.cwe, req.fix))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/sast/scan")
def sast_scan(req: SASTScanReq):
    try:
        g = _guard()
        if g:
            return g
        tid = _new_task("sast-scan")
        result = get_sast_deep().scan_code(req.code, req.filename, req.lang)
        _finish_task(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/sast/runs")
def sast_runs(limit: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_sast_deep().list_runs(limit))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/sast/runs/{sid}")
def sast_run_detail(sid: str):
    try:
        g = _guard()
        if g:
            return g
        r = get_sast_deep().get_run(sid)
        if not r:
            return fail("扫描记录不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/sast/quality")
def sast_quality(req: SASTScanReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_sast_deep().quality_analyze(req.code))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/sast/report")
def sast_report():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_sast_deep().scan_report())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 四、依赖安全
# =========================================================================== #
@router.post("/dependency/parse")
def dep_parse(req: DepScanReq):
    try:
        g = _guard()
        if g:
            return g
        return ok({"dependencies": get_dependency_deep().parse_requirements(req.text)})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/dependency/scan")
def dep_scan(req: DepScanReq):
    try:
        g = _guard()
        if g:
            return g
        tid = _new_task("dep-scan")
        result = get_dependency_deep().scan_requirements(req.text, req.source)
        _finish_task(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/dependency/runs")
def dep_runs(limit: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dependency_deep().list_runs(limit))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/dependency/runs/{sid}")
def dep_run_detail(sid: str):
    try:
        g = _guard()
        if g:
            return g
        r = get_dependency_deep().get_run(sid)
        if not r:
            return fail("扫描记录不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/dependency/outdated")
def dep_outdated():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dependency_deep().outdated_deps())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/dependency/report")
def dep_report():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dependency_deep().report())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 五、容器安全
# =========================================================================== #
@router.get("/container/images")
def container_images():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_container_deep().list_images())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/container/images/{iid}/analyze")
def container_analyze(iid: str, req: ContainerAnalyzeReq):
    try:
        g = _guard()
        if g:
            return g
        tid = _new_task("container-analyze")
        result = get_container_deep().analyze_layers(iid, req.extra_layers or None)
        if not result:
            _finish_task(tid, None, "镜像不存在")
            return fail("镜像不存在", 404)
        _finish_task(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/container/runtime-check")
def container_runtime(req: RuntimeCheckReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_container_deep().runtime_check(req.dict()))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/container/network-check")
def container_network(req: RuntimeCheckReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_container_deep().network_check(req.dict()))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/container/compliance")
def container_compliance(req: RuntimeCheckReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_container_deep().compliance_check(req.dict()))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/container/lifecycle")
def container_lifecycle():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_container_deep().lifecycle_controls())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/container/runs")
def container_runs(limit: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_container_deep().list_runs(limit))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/container/report")
def container_report():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_container_deep().report())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 六、IaC 安全
# =========================================================================== #
@router.get("/iac/rules")
def iac_rules(provider: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_iac_security().list_rules(provider))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/iac/policies")
def iac_policies():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_iac_security().list_policies())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/iac/policies")
def iac_add_policy(name: str = Query(...), enforce: str = "warn"):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_iac_security().add_policy(name, enforce))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/iac/scan")
def iac_scan(req: IaCScanReq):
    try:
        g = _guard()
        if g:
            return g
        tid = _new_task("iac-scan")
        result = get_iac_security().scan_iac(req.content, req.filename, req.lang)
        _finish_task(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/iac/runs")
def iac_runs(limit: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_iac_security().list_runs(limit))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/iac/runs/{sid}")
def iac_run_detail(sid: str):
    try:
        g = _guard()
        if g:
            return g
        r = get_iac_security().get_run(sid)
        if not r:
            return fail("扫描记录不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/iac/compliance-map")
def iac_compliance_map():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_iac_security().compliance_map())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/iac/report")
def iac_report():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_iac_security().report())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 七、安全即代码 SaC
# =========================================================================== #
@router.get("/sac/policies")
def sac_policies():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().list_policies())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/sac/policies")
def sac_create_policy(req: SaCPolicyReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().create_policy(
            req.name, req.severity, req.rules, req.author))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/sac/policies/validate")
def sac_validate_policy(req: SaCPolicyValidateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().validate_policy(req.policy_text))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/sac/controls")
def sac_controls(status: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().list_controls(status))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/sac/controls")
def sac_register_control(req: SaCControlReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().register_control(
            req.name, req.framework, req.status))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/sac/flows")
def sac_flows():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().list_flows())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/sac/flows")
def sac_create_flow(req: SaCFlowReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().create_flow(req.name, req.steps, req.approvers))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/sac/configs")
def sac_configs():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().list_configs())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/sac/configs")
def sac_create_config(req: SaCConfigReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().create_config(req.name, req.items))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/sac/tests")
def sac_tests():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().list_tests())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/sac/tests/evaluate")
def sac_evaluate_test(req: SaCTestReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().evaluate_test(req.code, req.context))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/sac/audits")
def sac_audits():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().list_audits())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/sac/audits/run")
def sac_run_audit(scope: str = "all"):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().run_audit(scope))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/sac/report")
def sac_report():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_as_code().report())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))
