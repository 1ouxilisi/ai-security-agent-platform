# -*- coding: utf-8 -*-
"""
devsecops_routes.py — DevSecOps 全链路安全 REST API。

路由前缀: /api/v1/devsecops
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。
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

router = APIRouter(prefix="/api/v1/devsecops", tags=["DevSecOps全链路安全"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from devsecops.pipeline_security import (
        get_pipeline_auditor, CI_PLATFORMS, SECRET_PATTERNS, SCRIPT_RULES,
    )
    from devsecops.repo_security import (
        get_repo_assessor, BRANCH_PROTECTION_RULES, PRE_COMMIT_HOOKS,
        MERGE_GATES,
    )
    from devsecops.build_artifact_security import (
        get_build_artifact_security, DOCKERFILE_RULES,
    )
    from devsecops.deployment_runtime_security import (
        get_deployment_runtime_security, PSS_LEVELS, RUNTIME_THREATS,
    )
    from devsecops.security_gate import (
        get_security_gate, BLOCK_RULES, WARN_RULES, GATE_LEVELS,
    )
    from devsecops.devsecops_maturity import (
        get_devsecops_maturity, MATURITY_LEVELS, DIMENSIONS,
        TOOLCHAIN_CAPABILITIES,
    )
    from devsecops.devsecops_workflow import (
        get_devsecops_workflow, WORKFLOW_STEPS,
    )
    _MOD_AVAILABLE = True
    logger.info("devsecops_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("devsecops_routes: load failed: %s", e)


# --------------------------------------------------------------------------- #
# 任务存储
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    tid = uuid.uuid4().hex[:16]
    _TASKS[tid] = {
        "task_id": tid, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return tid


def _finish(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in _TASKS:
        t = _TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


def _get_task(tid: str) -> Optional[Dict[str, Any]]:
    return _TASKS.get(tid)


def _task_view(t: Dict[str, Any]) -> Dict[str, Any]:
    return {"task_id": t["task_id"], "status": t["status"], "kind": t["kind"],
            "created_at": t["created_at"], "finished_at": t["finished_at"]}


# --------------------------------------------------------------------------- #
# 统一响应（清理控制字符）
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(ch if ord(ch) >= 32 or ch in "\n\t" else " "
                       for ch in obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(v) for v in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("DevSecOps 模块不可用", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class PipelineAuditReq(BaseModel):
    platform: str = "github_actions"
    config_text: str = ""
    signals: Dict[str, Any] = Field(default_factory=dict)


class SecretScanReq(BaseModel):
    content: str = ""
    source: str = "pipeline.yml"


class ScriptAuditReq(BaseModel):
    script: str = ""
    filename: str = "build.sh"


class SignalsReq(BaseModel):
    signals: Dict[str, Any] = Field(default_factory=dict)


class LockReq(BaseModel):
    ecosystem: str = "python"
    signals: Dict[str, Any] = Field(default_factory=dict)


class SbomReq(BaseModel):
    components: List[Dict[str, Any]] = Field(default_factory=list)
    fmt: str = "cyclonedx-json"


class RepoFullReq(BaseModel):
    signals: Dict[str, Any] = Field(default_factory=dict)


class DockerfileReq(BaseModel):
    content: str = ""
    filename: str = "Dockerfile"


class ImageReq(BaseModel):
    image: str = "app:latest"
    vulns: List[Dict[str, Any]] = Field(default_factory=list)


class WorkloadReq(BaseModel):
    kind: str = "Deployment"
    manifest: Dict[str, Any] = Field(default_factory=dict)


class GateReq(BaseModel):
    signals: Dict[str, Any] = Field(default_factory=dict)


class ExemptionReq(BaseModel):
    rule_id: str
    reason: str = ""
    expires: str = ""


class GenConfigReq(BaseModel):
    platform: str = "github_actions"
    gate_level: str = "L2"


class WorkflowRunReq(BaseModel):
    signals: Dict[str, Any] = Field(default_factory=dict)


# =========================================================================== #
# 1. 流水线安全 (8 个端点)
# =========================================================================== #
@router.post("/pipeline/audit")
def pipeline_audit(req: PipelineAuditReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("pipeline")
        result = get_pipeline_auditor().audit_pipeline_config(
            req.platform, req.config_text, req.signals)
        _finish(tid, result)
        return ok({"task_id": tid, "status": "done", "result": result})
    except Exception as e:
        logger.exception("pipeline_audit error")
        return fail(f"流水线审计失败: {e}", 500)


@router.post("/pipeline/scan-secrets")
def pipeline_scan_secrets(req: SecretScanReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("pipeline_secrets")
        result = get_pipeline_auditor().scan_hardcoded_secrets(
            req.content, req.source)
        _finish(tid, result)
        return ok({"task_id": tid, "status": "done", "result": result})
    except Exception as e:
        return fail(f"密钥扫描失败: {e}", 500)


@router.post("/pipeline/audit-script")
def pipeline_audit_script(req: ScriptAuditReq):
    try:
        g = _guard()
        if g is not None:
            return g
        result = get_pipeline_auditor().audit_build_script(req.script, req.filename)
        return ok(result)
    except Exception as e:
        return fail(f"脚本审计失败: {e}", 500)


@router.post("/pipeline/isolation")
def pipeline_isolation(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_pipeline_auditor().assess_build_isolation(req.signals))
    except Exception as e:
        return fail(f"隔离评估失败: {e}", 500)


@router.post("/pipeline/dep-locking")
def pipeline_dep_locking(req: LockReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_pipeline_auditor().check_dependency_locking(
            req.ecosystem, req.signals))
    except Exception as e:
        return fail(f"依赖锁定检查失败: {e}", 500)


@router.post("/pipeline/signing")
def pipeline_signing(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_pipeline_auditor().verify_artifact_signing(req.signals))
    except Exception as e:
        return fail(f"签名验证失败: {e}", 500)


@router.post("/pipeline/sbom")
def pipeline_sbom(req: SbomReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_pipeline_auditor().generate_sbom(req.components, req.fmt))
    except Exception as e:
        return fail(f"SBOM 生成失败: {e}", 500)


@router.get("/pipeline/platforms")
def pipeline_platforms():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"platforms": CI_PLATFORMS,
                   "secret_patterns_count": len(SECRET_PATTERNS),
                   "script_rules_count": len(SCRIPT_RULES)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 2. 代码仓库 (8 个端点)
# =========================================================================== #
@router.post("/repo/full")
def repo_full(req: RepoFullReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("repo")
        result = get_repo_assessor().full_assess(req.signals)
        _finish(tid, result)
        return ok({"task_id": tid, "status": "done", "result": result})
    except Exception as e:
        return fail(f"仓库评估失败: {e}", 500)


@router.post("/repo/git-config")
def repo_git_config(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_repo_assessor().audit_git_config(req.signals.get("git_config")))
    except Exception as e:
        return fail(f"Git 配置审计失败: {e}", 500)


@router.post("/repo/branch-protection")
def repo_branch_protection(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_repo_assessor().assess_branch_protection(
            req.signals.get("branch_rules")))
    except Exception as e:
        return fail(f"分支保护评估失败: {e}", 500)


@router.post("/repo/codeowners")
def repo_codeowners(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_repo_assessor().check_codeowners(
            req.signals.get("content", ""), req.signals.get("files", [])))
    except Exception as e:
        return fail(f"CODEOWNERS 检查失败: {e}", 500)


@router.post("/repo/commit-signing")
def repo_commit_signing(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_repo_assessor().assess_commit_signing(req.signals))
    except Exception as e:
        return fail(f"提交签名评估失败: {e}", 500)


@router.post("/repo/secret-scan")
def repo_secret_scan(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_repo_assessor().assess_secret_scan(
            req.signals.get("hooks"), req.signals.get("scan")))
    except Exception as e:
        return fail(f"Secret 扫描评估失败: {e}", 500)


@router.post("/repo/dep-pr")
def repo_dep_pr(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_repo_assessor().assess_dep_pr(req.signals.get("prs")))
    except Exception as e:
        return fail(f"依赖 PR 检查失败: {e}", 500)


@router.post("/repo/merge-gates")
def repo_merge_gates(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_repo_assessor().assess_merge_gates(req.signals.get("enabled")))
    except Exception as e:
        return fail(f"合并门禁评估失败: {e}", 500)


# =========================================================================== #
# 3. 构建与制品 (6 个端点)
# =========================================================================== #
@router.post("/build/dockerfile")
def build_dockerfile(req: DockerfileReq):
    try:
        g = _guard()
        if g is not None:
            return g
        result = get_build_artifact_security().scan_dockerfile(
            req.content, req.filename)
        return ok(result)
    except Exception as e:
        return fail(f"Dockerfile 扫描失败: {e}", 500)


@router.post("/build/image")
def build_image(req: ImageReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_build_artifact_security().scan_image_vulns(
            req.image, req.vulns))
    except Exception as e:
        return fail(f"镜像扫描失败: {e}", 500)


@router.get("/build/base-image")
def build_base_image(base: str = Query("ubuntu:22.04")):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_build_artifact_security().assess_base_image(base))
    except Exception as e:
        return fail(f"基础镜像评估失败: {e}", 500)


@router.post("/build/cache")
def build_cache(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_build_artifact_security().assess_build_cache(req.signals))
    except Exception as e:
        return fail(f"构建缓存评估失败: {e}", 500)


@router.post("/build/registry")
def build_registry(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_build_artifact_security().assess_registry(
            req.signals.get("registry_type", "nexus"), req.signals))
    except Exception as e:
        return fail(f"制品库评估失败: {e}", 500)


@router.post("/build/supply-chain")
def build_supply_chain(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_build_artifact_security().detect_supply_chain(req.signals))
    except Exception as e:
        return fail(f"供应链检测失败: {e}", 500)


# =========================================================================== #
# 4. 部署与运行时 (7 个端点)
# =========================================================================== #
@router.post("/deploy/workload")
def deploy_workload(req: WorkloadReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_deployment_runtime_security().audit_workload(
            req.kind, req.manifest))
    except Exception as e:
        return fail(f"工作负载审计失败: {e}", 500)


@router.post("/deploy/rbac")
def deploy_rbac(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_deployment_runtime_security().assess_rbac(req.signals.get("roles")))
    except Exception as e:
        return fail(f"RBAC 评估失败: {e}", 500)


@router.post("/deploy/netpol")
def deploy_netpol(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_deployment_runtime_security().assess_network_policy(
            req.signals.get("namespaces"),
            req.signals.get("default_deny", False)))
    except Exception as e:
        return fail(f"网络策略评估失败: {e}", 500)


@router.post("/deploy/pss")
def deploy_pss(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_deployment_runtime_security().assess_pss(
            req.signals.get("enforced", "baseline"),
            req.signals.get("exemptions")))
    except Exception as e:
        return fail(f"PSS 评估失败: {e}", 500)


@router.post("/deploy/secrets")
def deploy_secrets(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_deployment_runtime_security().assess_secrets(req.signals))
    except Exception as e:
        return fail(f"Secrets 评估失败: {e}", 500)


@router.post("/deploy/runtime-detect")
def deploy_runtime_detect(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_deployment_runtime_security().assess_runtime_detection(
            req.signals.get("alerts")))
    except Exception as e:
        return fail(f"运行时检测失败: {e}", 500)


@router.post("/deploy/istio")
def deploy_istio(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_deployment_runtime_security().assess_istio(req.signals))
    except Exception as e:
        return fail(f"Istio 评估失败: {e}", 500)


# =========================================================================== #
# 5. 安全门禁 (7 个端点)
# =========================================================================== #
@router.post("/gate/evaluate")
def gate_evaluate(req: GateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("gate")
        result = get_security_gate().evaluate(req.signals)
        _finish(tid, result)
        return ok({"task_id": tid, "status": "done", "result": result})
    except Exception as e:
        return fail(f"门禁评估失败: {e}", 500)


@router.get("/gate/rules")
def gate_rules():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_security_gate().list_rules())
    except Exception as e:
        return fail(f"规则查询失败: {e}", 500)


@router.post("/gate/exemptions")
def gate_grant_exemption(req: ExemptionReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_security_gate().grant_exemption(
            req.rule_id, req.reason, req.expires))
    except Exception as e:
        return fail(f"豁免失败: {e}", 500)


@router.get("/gate/exemptions")
def gate_list_exemptions():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"exemptions": get_security_gate().list_exemptions()})
    except Exception as e:
        return fail(f"豁免列表失败: {e}", 500)


@router.delete("/gate/exemptions/{rule_id}")
def gate_revoke_exemption(rule_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        ok_flag = get_security_gate().revoke_exemption(rule_id)
        return ok({"revoked": ok_flag, "rule_id": rule_id})
    except Exception as e:
        return fail(f"撤销豁免失败: {e}", 500)


@router.post("/gate/config")
def gate_config(req: GenConfigReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_security_gate().generate_pipeline_config(
            req.platform, req.gate_level))
    except Exception as e:
        return fail(f"生成配置失败: {e}", 500)


@router.get("/gate/history")
def gate_history():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"history": get_security_gate().list_history()})
    except Exception as e:
        return fail(f"历史查询失败: {e}", 500)


# =========================================================================== #
# 6. 成熟度评估 (6 个端点)
# =========================================================================== #
@router.post("/maturity/assess")
def maturity_assess(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("maturity")
        result = get_devsecops_maturity().assess(req.signals)
        _finish(tid, result)
        return ok({"task_id": tid, "status": "done", "result": result})
    except Exception as e:
        return fail(f"成熟度评估失败: {e}", 500)


@router.get("/maturity/levels")
def maturity_levels():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"levels": MATURITY_LEVELS,
                   "dimensions": DIMENSIONS,
                   "toolchain_capabilities": TOOLCHAIN_CAPABILITIES})
    except Exception as e:
        return fail(f"等级查询失败: {e}", 500)


@router.post("/maturity/toolchain")
def maturity_toolchain(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_devsecops_maturity().assess_toolchain(
            req.signals.get("present")))
    except Exception as e:
        return fail(f"工具链评估失败: {e}", 500)


@router.post("/maturity/process")
def maturity_process(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_devsecops_maturity().assess_process(req.signals))
    except Exception as e:
        return fail(f"流程评估失败: {e}", 500)


@router.post("/maturity/culture")
def maturity_culture(req: SignalsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_devsecops_maturity().assess_culture(req.signals))
    except Exception as e:
        return fail(f"文化评估失败: {e}", 500)


@router.get("/maturity/history")
def maturity_history():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"history": get_devsecops_maturity().list_history()})
    except Exception as e:
        return fail(f"历史查询失败: {e}", 500)


# =========================================================================== #
# 7. 综合工作流 (4 个端点)
# =========================================================================== #
@router.post("/workflow/run")
def workflow_run(req: WorkflowRunReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("workflow")
        result = get_devsecops_workflow().run(req.signals)
        _finish(tid, result)
        return ok({"task_id": tid, "status": "done", "result": result})
    except Exception as e:
        logger.exception("workflow_run error")
        return fail(f"全链路评估失败: {e}", 500)


@router.get("/workflow/{task_id}/status")
def workflow_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/workflow/{task_id}/results")
def workflow_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/workflow/history")
def workflow_history():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"history": get_devsecops_workflow().list_history(),
                   "steps": WORKFLOW_STEPS})
    except Exception as e:
        return fail(f"历史查询失败: {e}", 500)


# =========================================================================== #
# 8. 任务查询通用端点
# =========================================================================== #
@router.get("/tasks/{task_id}/status")
def task_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/tasks/{task_id}/results")
def task_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)
