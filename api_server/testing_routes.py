# -*- coding: utf-8 -*-
"""
testing_routes.py — 测试体系与 CI/CD REST API（第19轮升级方向4）。

路由前缀: /api/v1/testing
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/testing", tags=["测试体系与CI/CD"])


# --------------------------------------------------------------------------- #
# 业务模块加载（try-import，失败回退模拟）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from testing.unit_testing import UnitTestingManager
    from testing.integration_testing import IntegrationTestingManager
    from testing.performance_testing import PerformanceTestingManager
    from testing.security_testing import SecurityTestingManager
    from testing.cicd_pipeline import CICDManager
    from testing.test_dashboard import TestDashboardManager
    _UT = UnitTestingManager()
    _IT = IntegrationTestingManager()
    _PT = PerformanceTestingManager()
    _ST = SecurityTestingManager()
    _CD = CICDManager()
    _DB = TestDashboardManager()
    _MOD_AVAILABLE = True
    logger.info("testing_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("testing_routes: load failed: %s", e)


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


# --------------------------------------------------------------------------- #
# 统一响应 / 控制字符清理
# --------------------------------------------------------------------------- #
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理字符串中的控制字符，防止 UTF-8 / JSON 异常。"""
    if isinstance(obj, str):
        return _CTRL_RE.sub(" ", obj).encode("utf-8", errors="replace").decode("utf-8", "replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("测试体系模块不可用，请检查加载日志", 503)
    return None


def _task_view(t: Dict[str, Any]) -> Dict[str, Any]:
    return {"task_id": t["task_id"], "status": t["status"], "kind": t["kind"],
            "created_at": t["created_at"], "finished_at": t["finished_at"]}


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class GenTemplateRequest(BaseModel):
    module_path: str = ""


class RunLoadRequest(BaseModel):
    users: int = 200
    duration_s: int = 180


class FuzzRequest(BaseModel):
    target: str = "/api/v1/testing/unit/overview"
    iterations: int = 1000


class DeployRequest(BaseModel):
    env: str = "staging"
    strategy: str = "rolling"


class GateEvaluateRequest(BaseModel):
    metrics: Dict[str, float] = Field(default_factory=dict)


class CreateCaseRequest(BaseModel):
    title: str = ""
    ctype: str = "unit"
    priority: str = "P2"


class CreateBugRequest(BaseModel):
    title: str = ""
    severity: str = "S3-major"


class BaselineRequest(BaseModel):
    endpoint: str = ""
    p95: float = 0.0


# =========================================================================== #
# 一、单元测试（8 个端点）
# =========================================================================== #
@router.get("/unit/overview")
def unit_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(_UT.overview())
    except Exception as e:
        logger.exception("unit_overview error")
        return fail(f"单元测试概览失败: {e}", 500)


@router.get("/unit/framework/config")
def unit_framework_config():
    try:
        g = _guard()
        if g:
            return g
        return ok({"pytest_ini": _UT.framework.config.to_pytest_ini(),
                   "tools": _UT.framework.detected_tools,
                   "markers": _UT.framework.config.markers,
                   "parallel_workers": _UT.framework.config.parallel_workers})
    except Exception as e:
        return fail(f"配置查询失败: {e}", 500)


@router.get("/unit/discover")
def unit_discover():
    try:
        g = _guard()
        if g:
            return g
        return ok(_UT.framework.discover_tests())
    except Exception as e:
        return fail(f"测试发现失败: {e}", 500)


@router.get("/unit/scan-modules")
def unit_scan_modules(limit: int = Query(default=40, ge=1, le=200)):
    try:
        g = _guard()
        if g:
            return g
        return ok(_UT.generator.scan_core_modules(limit=limit))
    except Exception as e:
        return fail(f"模块扫描失败: {e}", 500)


@router.post("/unit/generate-template")
def unit_generate_template(req: GenTemplateRequest):
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("unit_template")
        result = _UT.generator.generate_templates(req.module_path)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"模板生成失败: {e}", 500)


@router.get("/unit/coverage/run")
def unit_coverage_run():
    try:
        g = _guard()
        if g:
            return g
        return ok(_UT.coverage.measure())
    except Exception as e:
        return fail(f"覆盖率测量失败: {e}", 500)


@router.get("/unit/data/templates")
def unit_data_templates():
    try:
        g = _guard()
        if g:
            return g
        return ok({"templates": _UT.factory.templates(),
                   "factory_methods": ["gen_user", "gen_scan_target", "gen_vuln"]})
    except Exception as e:
        return fail(f"测试数据查询失败: {e}", 500)


@router.get("/unit/mocks")
def unit_mocks():
    try:
        g = _guard()
        if g:
            return g
        return ok(_UT.mocks.list_mocks())
    except Exception as e:
        return fail(f"Mock 查询失败: {e}", 500)


# =========================================================================== #
# 二、集成测试（7 个端点）
# =========================================================================== #
@router.get("/integration/overview")
def integration_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(_IT.overview())
    except Exception as e:
        return fail(f"集成测试概览失败: {e}", 500)


@router.get("/integration/scan-api")
def integration_scan_api():
    try:
        g = _guard()
        if g:
            return g
        return ok(_IT.api.scan())
    except Exception as e:
        return fail(f"API 端点扫描失败: {e}", 500)


@router.get("/integration/generate-cases")
def integration_generate_cases(limit: int = Query(default=12, ge=1, le=60)):
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("integration_cases")
        result = _IT.api.generate_cases(limit=limit)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"集成用例生成失败: {e}", 500)


@router.get("/integration/db/run")
def integration_db_run():
    try:
        g = _guard()
        if g:
            return g
        return ok(_IT.db.run())
    except Exception as e:
        return fail(f"数据库集成测试失败: {e}", 500)


@router.get("/integration/service/run")
def integration_service_run():
    try:
        g = _guard()
        if g:
            return g
        return ok(_IT.svc.run())
    except Exception as e:
        return fail(f"服务集成测试失败: {e}", 500)


@router.get("/integration/e2e/script")
def integration_e2e_script():
    try:
        g = _guard()
        if g:
            return g
        return ok({"scenarios": _IT.e2e.scenarios(), "script": _IT.e2e.script()})
    except Exception as e:
        return fail(f"E2E 脚本生成失败: {e}", 500)


@router.get("/integration/contract/verify")
def integration_contract_verify():
    try:
        g = _guard()
        if g:
            return g
        return ok(_IT.contract.verify())
    except Exception as e:
        return fail(f"契约验证失败: {e}", 500)


# =========================================================================== #
# 三、性能测试（8 个端点）
# =========================================================================== #
@router.get("/performance/overview")
def performance_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(_PT.overview())
    except Exception as e:
        return fail(f"性能概览失败: {e}", 500)


@router.post("/performance/load/run")
def performance_load_run(req: RunLoadRequest):
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("load_test")
        result = _PT.load.run(users=req.users, duration_s=req.duration_s)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"负载测试失败: {e}", 500)


@router.get("/performance/stress/run")
def performance_stress_run():
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("stress_test")
        result = _PT.stress.run()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"压力测试失败: {e}", 500)


@router.get("/performance/soak/run")
def performance_soak_run(hours: int = Query(default=24, ge=1, le=168)):
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("soak_test")
        result = _PT.soak.run(hours=hours)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"Soak 测试失败: {e}", 500)


@router.get("/performance/spike/run")
def performance_spike_run():
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("spike_test")
        result = _PT.spike.run()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"尖峰测试失败: {e}", 500)


@router.get("/performance/baseline/list")
def performance_baseline_list():
    try:
        g = _guard()
        if g:
            return g
        return ok(_PT.baseline.list_baselines())
    except Exception as e:
        return fail(f"基线查询失败: {e}", 500)


@router.post("/performance/baseline/establish")
def performance_baseline_establish(req: BaselineRequest):
    try:
        g = _guard()
        if g:
            return g
        m = {"p50": req.p95 * 0.6, "p95": req.p95, "p99": req.p95 * 1.4,
             "rps": 500.0}
        return ok(_PT.baseline.establish(req.endpoint, m))
    except Exception as e:
        return fail(f"建立基线失败: {e}", 500)


@router.get("/performance/script/locust")
def performance_locust_script():
    try:
        g = _guard()
        if g:
            return g
        return ok({"script": _PT.scriptgen.locust_script(),
                   "tool_available": _PT.load.__class__ and True})
    except Exception as e:
        return fail(f"脚本生成失败: {e}", 500)


# =========================================================================== #
# 四、安全测试（7 个端点）
# =========================================================================== #
@router.get("/security/overview")
def security_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(_ST.overview())
    except Exception as e:
        return fail(f"安全概览失败: {e}", 500)


@router.get("/security/sast/run")
def security_sast_run(limit_files: int = Query(default=300, ge=10, le=2000)):
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("sast")
        result = _ST.sast.scan(limit_files=limit_files)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"SAST 扫描失败: {e}", 500)


@router.get("/security/dast/run")
def security_dast_run(target: str = Query(default="http://127.0.0.1:8000")):
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("dast")
        result = _ST.dast.scan(target)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"DAST 扫描失败: {e}", 500)


@router.get("/security/deps/scan")
def security_deps_scan():
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("dep_audit")
        result = _ST.dep.scan()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"依赖扫描失败: {e}", 500)


@router.post("/security/fuzz/run")
def security_fuzz_run(req: FuzzRequest):
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("fuzz")
        result = _ST.fuzzer.run(target=req.target, iterations=req.iterations)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"模糊测试失败: {e}", 500)


@router.get("/security/regression/check")
def security_regression_check(recurrence_codes: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        baseline = ["PY001", "PY003", "PY007", "PY008", "PY011"]
        _ST.regression.set_baseline(baseline)
        current = (recurrence_codes or "").split(",") if recurrence_codes else []
        return ok(_ST.regression.check([c for c in current if c]))
    except Exception as e:
        return fail(f"安全回归检查失败: {e}", 500)


@router.get("/security/rules")
def security_rules():
    try:
        g = _guard()
        if g:
            return g
        return ok({"sast_rules": [{"code": c, "severity": s, "desc": d, "fix": f}
                                  for c, s, d, _rx, f in
                                  [(r[0], r[1], r[2], r[4]) for r in
                                   __import__("testing.security_testing", fromlist=["SAST_RULES"]).SAST_RULES]],
                   "dast_rules": _ST.dast.RULES})
    except Exception as e:
        return fail(f"规则查询失败: {e}", 500)


# =========================================================================== #
# 五、CI/CD 流水线（8 个端点）
# =========================================================================== #
@router.get("/cicd/overview")
def cicd_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(_CD.overview())
    except Exception as e:
        return fail(f"CI/CD 概览失败: {e}", 500)


@router.get("/cicd/pipeline/yaml")
def cicd_pipeline_yaml(kind: str = Query(default="github")):
    try:
        g = _guard()
        if g:
            return g
        if kind == "gitlab":
            return ok({"kind": kind, "yaml": _CD.definition.gitlab_ci_yaml()})
        return ok({"kind": kind, "yaml": _CD.definition.github_actions_yaml()})
    except Exception as e:
        return fail(f"流水线配置生成失败: {e}", 500)


@router.get("/cicd/pipeline/stages")
def cicd_pipeline_stages():
    try:
        g = _guard()
        if g:
            return g
        return ok({"stages": _CD.definition.stages()})
    except Exception as e:
        return fail(f"阶段查询失败: {e}", 500)


@router.post("/cicd/gate/evaluate")
def cicd_gate_evaluate(req: GateEvaluateRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(_CD.gate.evaluate(req.metrics))
    except Exception as e:
        return fail(f"门禁评估失败: {e}", 500)


@router.get("/cicd/gate/rules")
def cicd_gate_rules():
    try:
        g = _guard()
        if g:
            return g
        return ok({"rules": _CD.gate.RULES})
    except Exception as e:
        return fail(f"门禁规则查询失败: {e}", 500)


@router.post("/cicd/deploy/run")
def cicd_deploy_run(req: DeployRequest):
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("deploy")
        result = _CD.deploy.deploy(env=req.env, strategy=req.strategy)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"部署失败: {e}", 500)


@router.get("/cicd/artifact/list")
def cicd_artifact_list():
    try:
        g = _guard()
        if g:
            return g
        return ok(_CD.artifacts.list())
    except Exception as e:
        return fail(f"制品查询失败: {e}", 500)


@router.get("/cicd/monitor/dashboard")
def cicd_monitor_dashboard():
    try:
        g = _guard()
        if g:
            return g
        return ok(_CD.monitor.dashboard())
    except Exception as e:
        return fail(f"流水线监控失败: {e}", 500)


# =========================================================================== #
# 六、测试管理与仪表盘（8 个端点）
# =========================================================================== #
@router.get("/dashboard/cases")
def dashboard_cases(ctype: Optional[str] = Query(default=None),
                    priority: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        return ok(_DB.cases.list(ctype=ctype, priority=priority))
    except Exception as e:
        return fail(f"用例查询失败: {e}", 500)


@router.post("/dashboard/cases")
def dashboard_create_case(req: CreateCaseRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(_DB.cases.create(req.title or "未命名用例", req.ctype, req.priority))
    except Exception as e:
        return fail(f"创建用例失败: {e}", 500)


@router.get("/dashboard/executions")
def dashboard_executions():
    try:
        g = _guard()
        if g:
            return g
        return ok(_DB.executions.history())
    except Exception as e:
        return fail(f"执行记录查询失败: {e}", 500)


@router.post("/dashboard/executions/start")
def dashboard_executions_start(name: str = Query(default="manual-run"),
                              ctype: str = Query(default="all")):
    try:
        g = _guard()
        if g:
            return g
        return ok(_DB.executions.start_run(name, ctype))
    except Exception as e:
        return fail(f"启动测试轮次失败: {e}", 500)


@router.get("/dashboard/bugs")
def dashboard_bugs():
    try:
        g = _guard()
        if g:
            return g
        return ok(_DB.bugs.list())
    except Exception as e:
        return fail(f"缺陷查询失败: {e}", 500)


@router.post("/dashboard/bugs")
def dashboard_create_bug(req: CreateBugRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(_DB.bugs.create(req.title or "未命名缺陷", req.severity))
    except Exception as e:
        return fail(f"创建缺陷失败: {e}", 500)


@router.get("/dashboard/metrics")
def dashboard_metrics():
    try:
        g = _guard()
        if g:
            return g
        return ok(_DB.metrics.metrics())
    except Exception as e:
        return fail(f"度量查询失败: {e}", 500)


@router.get("/dashboard/view")
def dashboard_view():
    try:
        g = _guard()
        if g:
            return g
        return ok(_DB.dashboard.dashboard())
    except Exception as e:
        return fail(f"仪表盘查询失败: {e}", 500)


@router.get("/dashboard/report")
def dashboard_report(kind: str = Query(default="comprehensive")):
    try:
        g = _guard()
        if g:
            return g
        return ok(_DB.reports.report(kind))
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


# =========================================================================== #
# 七、任务查询（3 个端点）
# =========================================================================== #
@router.get("/tasks/{task_id}")
def task_status(task_id: str):
    try:
        t = _TASKS.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"任务查询失败: {e}", 500)


@router.get("/tasks/{task_id}/result")
def task_result(task_id: str):
    try:
        t = _TASKS.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"结果查询失败: {e}", 500)


@router.get("/tasks")
def task_list():
    try:
        return ok({"total": len(_TASKS),
                   "tasks": [_task_view(t) for t in list(_TASKS.values())[-30:]]})
    except Exception as e:
        return fail(f"任务列表失败: {e}", 500)
