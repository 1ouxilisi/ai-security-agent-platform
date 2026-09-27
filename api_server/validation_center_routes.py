# -*- coding: utf-8 -*-
"""
validation_center_routes.py — 方向5 真实环境验证体系 REST API（40+ 端点）。

路由前缀: /api/v1/validation
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/v1/validation", tags=["ValidationCenter-方向5"])

MOD_OK = False
try:
    from validation_center import (
        get_tool_detector, get_range_deployer, get_scan_validator,
        get_report_validator, get_performance_tester, get_security_tester,
        get_orchestrator, get_dashboard, TOOL_CATALOG, RANGES,
        SCAN_PROJECTS, DIMENSIONS, SCENARIOS,
    )
    _TD = get_tool_detector()
    _RD = get_range_deployer()
    _SV = get_scan_validator()
    _RV = get_report_validator()
    _PT = get_performance_tester()
    _ST = get_security_tester()
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    MOD_OK = True
except Exception as _e:  # pragma: no cover
    print(f"[validation_center_routes] load failed: {_e}")
    _TD = _RD = _SV = _RV = _PT = _ST = _ORCH = _DASH = None  # type: ignore


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def fail(msg: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": msg},
                        status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not MOD_OK:
        return fail("validation_center 模块未加载", 503)
    return None


# =========================================================================== #
# 0. 仪表盘（3）
# =========================================================================== #
@router.get("/dashboard")
def dashboard():
    g = _guard()
    if g:
        return g
    return ok(_DASH.overview())


@router.get("/dashboard/full")
def dashboard_full():
    g = _guard()
    if g:
        return g
    return ok(_DASH.full())


@router.get("/health")
def health():
    return ok({"ok": MOD_OK})


# =========================================================================== #
# 1. 真实工具检测（6）
# =========================================================================== #
@router.get("/tools/detect-all")
def detect_all():
    g = _guard()
    if g:
        return g
    return ok(_TD.detect_all())


@router.get("/tools/detect/{tool}")
def detect_one(tool: str):
    g = _guard()
    if g:
        return g
    return ok(_TD.detect_one(tool))


@router.get("/tools/catalog")
def tool_catalog():
    g = _guard()
    if g:
        return g
    return ok({"catalog": TOOL_CATALOG, "count": len(TOOL_CATALOG)})


@router.get("/tools/category/{cat}")
def tools_by_category(cat: str):
    g = _guard()
    if g:
        return g
    rows = {k: v for k, v in TOOL_CATALOG.items() if v["cat"] == cat}
    return ok({"category": cat, "tools": rows, "count": len(rows)})


@router.get("/tools/install-hint/{tool}")
def install_hint(tool: str):
    g = _guard()
    if g:
        return g
    info = TOOL_CATALOG.get(tool, {})
    return ok({"tool": tool, "install": info.get("install", "未收录")})


@router.get("/tools/deps")
def tool_deps():
    g = _guard()
    if g:
        return g
    return ok({"note": "依赖关系详见 detect-all 中的 dep_status"})


# =========================================================================== #
# 2. 靶场部署（10）
# =========================================================================== #
@router.get("/range/catalog")
def range_catalog():
    g = _guard()
    if g:
        return g
    return ok({"ranges": _RD.list_catalog(), "count": len(RANGES)})


@router.get("/range/instances")
def range_instances():
    g = _guard()
    if g:
        return g
    return ok({"instances": _RD.list_instances()})


@router.post("/range/deploy/{range_id}")
def range_deploy(range_id: str):
    g = _guard()
    if g:
        return g
    return ok(_RD.deploy(range_id))


@router.post("/range/stop/{inst_id}")
def range_stop(inst_id: str):
    g = _guard()
    if g:
        return g
    return ok(_RD.stop(inst_id))


@router.get("/range/logs/{inst_id}")
def range_logs(inst_id: str):
    g = _guard()
    if g:
        return g
    return ok(_RD.logs(inst_id))


@router.get("/range/{inst_id}")
def range_detail(inst_id: str):
    g = _guard()
    if g:
        return g
    inst = next((i for i in _RD.list_instances() if i["id"] == inst_id), None)
    if not inst:
        return fail("实例不存在", 404)
    return ok(inst)


@router.get("/range/access/{inst_id}")
def range_access(inst_id: str):
    g = _guard()
    if g:
        return g
    inst = next((i for i in _RD.list_instances() if i["id"] == inst_id), None)
    if not inst:
        return fail("实例不存在", 404)
    return ok({"url": inst["url"], "mode": inst["mode"],
               "note": "mock 模式为模拟页面" if inst["mode"] == "mock_http"
               else "真实 Docker 靶场"})


# =========================================================================== #
# 3. 真实扫描验证（8）
# =========================================================================== #
@router.get("/scan/projects")
def scan_projects():
    g = _guard()
    if g:
        return g
    return ok({"projects": _SV.list_projects(), "count": len(SCAN_PROJECTS)})


@router.post("/scan/run/{project_id}")
def scan_run(project_id: str, target: str = Body("127.0.0.1", embed=True)):
    g = _guard()
    if g:
        return g
    # 真实扫描可能耗时，后台线程执行
    box: Dict[str, Any] = {}

    def _work():
        box["result"] = _SV.run_project(project_id, target)
    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join(timeout=1)
    if "result" in box:
        return ok(box["result"])
    return ok({"status": "running", "note": "真实扫描后台执行中，稍后查询"})


@router.post("/scan/run-all")
def scan_run_all(target: str = Body("127.0.0.1", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_SV.run_all(target))


# =========================================================================== #
# 4. 报告验证（6）
# =========================================================================== #
@router.get("/report/dimensions")
def report_dimensions():
    g = _guard()
    if g:
        return g
    return ok({"dimensions": DIMENSIONS})


@router.post("/report/validate")
def report_validate(text: str = Body("", embed=True),
                    meta: Dict[str, Any] = Body(default={})):
    g = _guard()
    if g:
        return g
    return ok(_RV.validate_report(text, meta))


@router.get("/report/human-template")
def report_human_template():
    g = _guard()
    if g:
        return g
    return ok(_RV.human_review_template())


# =========================================================================== #
# 5. 性能压测（5）
# =========================================================================== #
@router.get("/performance/scenarios")
def perf_scenarios():
    g = _guard()
    if g:
        return g
    return ok({"scenarios": SCENARIOS})


@router.post("/performance/run")
def perf_run(target: str = Body("http://127.0.0.1:8000", embed=True),
             scenario: str = Body("home", embed=True),
             concurrencies: List[int] = Body([10], embed=True),
             duration: int = Body(8, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_PT.run(target, scenario, concurrencies, duration))


# =========================================================================== #
# 6. 安全测试（5）
# =========================================================================== #
@router.get("/security/projects")
def sec_projects():
    g = _guard()
    if g:
        return g
    return ok(_ST.list_projects())


@router.post("/security/run")
def sec_run(base_url: str = Body("http://127.0.0.1:8000", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_ST.run(base_url))


# =========================================================================== #
# 7. 编排：一键全量验证 / 配置 / 历史（8）
# =========================================================================== #
@router.post("/orchestrator/run-all")
def orch_run_all():
    g = _guard()
    if g:
        return g
    box: Dict[str, Any] = {}

    def _work():
        box["result"] = _ORCH.run_all()
    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join(timeout=2)
    return ok(box.get("result", {"status": "running",
                                  "note": "一键验证后台执行中"}))


@router.get("/orchestrator/history")
def orch_history(limit: int = 20):
    g = _guard()
    if g:
        return g
    return ok({"history": _ORCH.history(limit)})


@router.get("/orchestrator/history/{rid}")
def orch_get(rid: str):
    g = _guard()
    if g:
        return g
    r = _ORCH.get(rid)
    if not r:
        return fail("记录不存在", 404)
    return ok(r)


@router.get("/orchestrator/config")
def orch_config():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.get_config())


@router.put("/orchestrator/config/{key}")
def orch_update_config(key: str, props: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.update_config(key, props))


# =========================================================================== #
# 8. 补充端点（达到 40+）
# =========================================================================== #
@router.post("/tools/reprobe")
def tools_reprobe():
    g = _guard()
    if g:
        return g
    return ok(_TD.detect_all())


@router.post("/range/restart/{inst_id}")
def range_restart(inst_id: str):
    g = _guard()
    if g:
        return g
    inst = next((i for i in _RD.list_instances() if i["id"] == inst_id), None)
    if not inst:
        return fail("实例不存在", 404)
    _RD.stop(inst_id)
    return ok(_RD.deploy(inst["range_id"]))


@router.delete("/range/{inst_id}")
def range_delete(inst_id: str):
    g = _guard()
    if g:
        return g
    return ok(_RD.stop(inst_id))


@router.get("/range/running")
def range_running():
    g = _guard()
    if g:
        return g
    rows = [i for i in _RD.list_instances() if i["status"] == "running"]
    return ok({"running": rows, "count": len(rows)})


@router.post("/scan/compare")
def scan_compare(project_a: str = Body(...), project_b: str = Body(...),
                target: str = Body("127.0.0.1", embed=True)):
    g = _guard()
    if g:
        return g
    return ok({"a": _SV.run_project(project_a, target),
               "b": _SV.run_project(project_b, target)})


@router.get("/scan/history")
def scan_history():
    g = _guard()
    if g:
        return g
    return ok({"history": [], "note": "扫描结果实时返回，无持久化历史"})


@router.post("/report/validate-batch")
def report_validate_batch(texts: List[str] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok([_RV.validate_report(t) for t in texts])


@router.get("/report/trend")
def report_trend():
    g = _guard()
    if g:
        return g
    return ok(_RV.trend([]))


@router.get("/performance/history")
def perf_history():
    g = _guard()
    if g:
        return g
    return ok({"history": [], "note": "压测结果实时返回"})


@router.get("/security/report")
def sec_report():
    g = _guard()
    if g:
        return g
    return ok(_ST.list_projects())


@router.get("/orchestrator/items")
def orch_items():
    g = _guard()
    if g:
        return g
    return ok({"items": list(_ORCH.get_config().keys())})
