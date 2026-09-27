# -*- coding: utf-8 -*-
"""
workflow_v2_routes.py — 端到端工作流执行器 REST API（第16轮升级·方向1）。

路由前缀: /api/v1/workflow-executor
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 + 后台线程模拟异步，
但任务内部真实调用项目已有检测模块（非模拟数据）。
"""

from __future__ import annotations

import io
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/workflow-executor",
                   tags=["端到端工作流"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from workflow_v2.workflow_engine import (
        run_workflow, retry_failed, identify_target, DEPS, HANDLERS,
    )
    from workflow_v2.execution_tracker import TRACKER
    from workflow_v2.scenario_templates import LIBRARY
    from workflow_v2.workflow_visualization import (
        build_dag, compute_critical_path, node_detail,
    )
    from workflow_v2.batch_scheduler import SCHEDULER
    from workflow_v2.e2e_verifier import run_self_test
    _MOD_AVAILABLE = True
    logger.info("workflow_v2_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("workflow_v2_routes: load failed: %s", e)


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理控制字符/不可序列化对象。"""
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8",
                                                           errors="replace")
    if isinstance(obj, dict):
        return {str(k): _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    if isinstance(obj, (int, float, bool)) or obj is None:
        return obj
    return str(obj)


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class OneShotRequest(BaseModel):
    target: str = Field(..., description="IP/域名/URL/APK路径/合约路径/AI端点")
    scenario_id: str = "web_full_assessment"
    options: Dict[str, Any] = Field(default_factory=dict)


class BatchRequest(BaseModel):
    targets: List[str] = Field(default_factory=list)
    raw_text: str = ""
    scenario_id: str = "web_full_assessment"
    options: Dict[str, Any] = Field(default_factory=dict)
    priority: str = "medium"


class CustomScenario(BaseModel):
    id: Optional[str] = None
    name: str = ""
    description: str = ""
    target_types: List[str] = Field(default_factory=list)
    steps: List[Dict[str, Any]] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# 后台执行（真实检测模块在子线程跑）
# --------------------------------------------------------------------------- #
def _run_in_background(task_id: str, target: str, scenario_id: str,
                       options: Dict[str, Any]) -> None:
    try:
        run_workflow(target, scenario_id, options=options, task_id=task_id)
    except Exception as e:  # noqa: BLE001
        logger.exception("background workflow failed: %s", e)
        t = TRACKER.get(task_id)
        if t:
            t.mark_failed(str(e))


# =========================================================================== #
# 1) 一键评估 / 任务管理
# =========================================================================== #
@router.post("/one-shot")
def one_shot_assessment(req: OneShotRequest):
    """提交一个端到端评估任务（后台真实执行检测模块）。"""
    try:
        if not _MOD_AVAILABLE:
            return fail("工作流模块不可用", 503)
        if not req.target.strip():
            return fail("target 不能为空")
        tpl = LIBRARY.get(req.scenario_id)
        if tpl is None:
            return fail(f"未知场景: {req.scenario_id}")
        task = TRACKER.create_task(
            target=req.target.strip(), scenario_id=req.scenario_id,
            scenario_name=tpl["name"], step_defs=tpl["steps"],
            options=req.options)
        threading.Thread(
            target=_run_in_background,
            args=(task.task_id, req.target.strip(), req.scenario_id,
                  req.options),
            daemon=True).start()
        return ok({"task_id": task.task_id, "status": task.status,
                   "scenario": tpl["name"]})
    except Exception as e:  # noqa: BLE001
        logger.exception("one-shot error")
        return fail(str(e), 500)


@router.get("/tasks")
def list_tasks(status: Optional[str] = Query(None),
               limit: int = Query(100, le=500)):
    try:
        return ok(TRACKER.list_tasks(status=status, limit=limit))
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/tasks/{task_id}")
def get_task(task_id: str, include_steps: bool = True,
             step_filter: Optional[str] = None):
    try:
        t = TRACKER.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t.to_dict(include_steps=include_steps,
                           step_filter=step_filter))
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/tasks/{task_id}/steps")
def get_task_steps(task_id: str):
    try:
        t = TRACKER.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok([task_step.to_dict()
                   for task_step in (t.steps[sid] for sid in t.step_order)])
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/tasks/{task_id}/steps/{step_id}/logs")
def get_step_logs(task_id: str, step_id: str):
    try:
        t = TRACKER.get(task_id)
        if not t or step_id not in t.steps:
            return fail("步骤不存在", 404)
        s = t.steps[step_id]
        return ok({"step_id": step_id, "logs": s.logs,
                   "status": s.status, "error": s.error,
                   "traceback": s.traceback})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.post("/tasks/{task_id}/retry")
def retry_task(task_id: str):
    try:
        if not _MOD_AVAILABLE:
            return fail("模块不可用", 503)
        t = TRACKER.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        # 后台重试
        threading.Thread(
            target=lambda: retry_failed(task_id), daemon=True).start()
        return ok({"task_id": task_id, "message": "已在后台重试失败步骤"})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: str):
    try:
        ok_flag = TRACKER.cancel(task_id)
        if not ok_flag:
            return fail("任务无法取消（不存在或已结束）", 400)
        return ok({"task_id": task_id, "status": "cancelled"})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/tasks/{task_id}/report")
def get_report(task_id: str):
    try:
        t = TRACKER.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok({"task_id": task_id, "status": t.status,
                   "risk_score": t.result.get("risk_score"),
                   "risk_level": t.result.get("risk_level"),
                   "report": t.result.get("report"),
                   "elapsed_ms": t.elapsed_ms})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/target-recognize")
def recognize_target(target: str = Query(...)):
    try:
        return ok(identify_target(target))
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/deps-status")
def deps_status():
    try:
        mods = {}
        for k, v in DEPS.items():
            if k.startswith("_err"):
                continue
            mods[k] = {"available": v is not None}
        degraded = [k for k, v in DEPS.items()
                   if k.startswith("_err")]
        return ok({"modules": mods, "errors": {
            k: DEPS[k] for k in degraded}})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


# =========================================================================== #
# 2) 执行追踪
# =========================================================================== #
@router.get("/tracker/stats")
def tracker_stats():
    try:
        return ok({"by_status": TRACKER.count_by_status(),
                   "handlers": sorted(HANDLERS.keys())})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.post("/tracker/purge")
def tracker_purge(keep: int = Query(200)):
    try:
        return ok({"purged": TRACKER.purge(keep=keep)})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


# =========================================================================== #
# 3) 场景模板
# =========================================================================== #
@router.get("/scenarios")
def list_scenarios():
    try:
        return ok(LIBRARY.list_templates())
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str):
    try:
        tpl = LIBRARY.get(scenario_id)
        if not tpl:
            return fail("场景不存在", 404)
        return ok(tpl)
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.post("/scenarios")
def add_scenario(req: CustomScenario):
    try:
        created = LIBRARY.add_template({
            "id": req.id, "name": req.name,
            "description": req.description,
            "target_types": req.target_types, "steps": req.steps,
        })
        return ok(created)
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.put("/scenarios/{scenario_id}")
def update_scenario(scenario_id: str, req: CustomScenario):
    try:
        patch = {"name": req.name, "description": req.description,
                 "target_types": req.target_types, "steps": req.steps}
        updated = LIBRARY.update_template(scenario_id, patch)
        if not updated:
            return fail("自定义场景不存在", 404)
        return ok(updated)
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.delete("/scenarios/{scenario_id}")
def delete_scenario(scenario_id: str):
    try:
        if not LIBRARY.delete_template(scenario_id):
            return fail("场景不存在或为内置不可删", 404)
        return ok({"deleted": scenario_id})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


# =========================================================================== #
# 4) 可视化 DAG
# =========================================================================== #
@router.get("/tasks/{task_id}/dag")
def task_dag(task_id: str):
    try:
        t = TRACKER.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(build_dag(t))
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/tasks/{task_id}/critical-path")
def task_critical_path(task_id: str):
    try:
        t = TRACKER.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        path = compute_critical_path(t)
        return ok({"task_id": task_id, "critical_path": path,
                   "details": [node_detail(t, sid) for sid in path]})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/tasks/{task_id}/steps/{step_id}/detail")
def task_step_detail(task_id: str, step_id: str):
    try:
        t = TRACKER.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        d = node_detail(t, step_id)
        if not d:
            return fail("步骤不存在", 404)
        return ok(d)
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


# =========================================================================== #
# 5) 批量调度
# =========================================================================== #
@router.post("/batch/submit")
def batch_submit(req: BatchRequest):
    try:
        targets = list(req.targets)
        if req.raw_text:
            targets += [ln.strip() for ln in req.raw_text.splitlines()
                        if ln.strip()]
        targets = [t for t in targets if t]
        if not targets:
            return fail("没有有效目标")
        result = SCHEDULER.submit(targets, req.scenario_id,
                                  options=req.options,
                                  priority=req.priority)
        return ok(result)
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/batch/status")
def batch_status():
    try:
        return ok(SCHEDULER.queue_status())
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/batch/list")
def batch_list():
    try:
        return ok(SCHEDULER.list_batches())
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/batch/{batch_id}")
def batch_detail(batch_id: str):
    try:
        d = SCHEDULER.batch_detail(batch_id)
        if not d:
            return fail("批次不存在", 404)
        return ok(d)
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.post("/batch/cancel-pending")
def batch_cancel_pending():
    try:
        return ok({"cancelled": SCHEDULER.cancel_pending()})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.post("/batch/{batch_id}/retry")
def batch_retry(batch_id: str):
    try:
        return ok({"retried": SCHEDULER.retry_failed_batch(batch_id)})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/batch/{batch_id}/export")
def batch_export(batch_id: Optional[str] = None):
    try:
        data = SCHEDULER.export_zip(batch_id)
        return Response(
            content=data,
            media_type="application/zip",
            headers={"Content-Disposition":
                     f"attachment; filename=workflow_reports_{batch_id or 'all'}.zip"},
        )
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


# =========================================================================== #
# 6) 端到端验证
# =========================================================================== #
_VERIFY_HISTORY: List[Dict[str, Any]] = []


@router.post("/verify/run")
def verify_run(target: str = Query("127.0.0.1"),
               scenario_id: str = Query("web_full_assessment")):
    try:
        if not _MOD_AVAILABLE:
            return fail("模块不可用", 503)
        result = run_self_test(target=target, scenario_id=scenario_id)
        _VERIFY_HISTORY.append(result)
        if len(_VERIFY_HISTORY) > 50:
            _VERIFY_HISTORY.pop(0)
        return ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("verify run error")
        return fail(str(e), 500)


@router.get("/verify/last")
def verify_last():
    try:
        if not _VERIFY_HISTORY:
            return ok(None)
        return ok(_VERIFY_HISTORY[-1])
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/verify/history")
def verify_history(limit: int = Query(20, le=100)):
    try:
        return ok(list(reversed(_VERIFY_HISTORY[-limit:])))
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


# =========================================================================== #
# 综合：健康检查 / 模块清单
# =========================================================================== #
@router.get("/handlers")
def list_handlers():
    try:
        return ok({"count": len(HANDLERS), "handlers": sorted(HANDLERS.keys())})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)


@router.get("/health")
def health():
    try:
        return ok({"status": "up", "module_available": _MOD_AVAILABLE,
                   "time": time.strftime("%Y-%m-%d %H:%M:%S")})
    except Exception as e:  # noqa: BLE001
        return fail(str(e), 500)
