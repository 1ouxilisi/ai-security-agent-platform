# -*- coding: utf-8 -*-
"""
devsecops_pro_routes.py — 方向3 DevSecOps Pro REST API（50+ 端点 + WebSocket）。

路由前缀: /api/v1/devsecops-pro
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/devsecops-pro",
                   tags=["DevSecOpsPro-方向3"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from devsecops_pro import (
        get_orchestrator, get_dashboard, get_realtime_push,
        get_cicd_phase, get_sast_phase, get_sca_phase,
        get_secrets_phase, get_iac_phase, get_container_phase,
        get_gate_phase, get_risk_phase, get_ai_analysis,
        get_report_generator, STAGES, REPORTS_DIR,
    )
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _RT = get_realtime_push()
    _CICD = get_cicd_phase()
    _SAST = get_sast_phase()
    _SCA = get_sca_phase()
    _SEC = get_secrets_phase()
    _IAC = get_iac_phase()
    _CON = get_container_phase()
    _GATE = get_gate_phase()
    _RISK = get_risk_phase()
    _AI = get_ai_analysis()
    _REP = get_report_generator()
    _MOD_AVAILABLE = True
    logger.info("devsecops_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("devsecops_pro_routes: load failed: %s", e)
    _ORCH = None  # type: ignore
    _DASH = None  # type: ignore
    _RT = None  # type: ignore


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c == "\n" or c == "\t"
                       or ord(c) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data),
                         "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE or _ORCH is None:
        return fail("DevSecOps Pro 模块未加载", 503)
    return None


# =========================================================================== #
# 1. 任务管理（八阶段一键全流程）
# =========================================================================== #
@router.post("/start")
def start_scan(target: str = Body(..., embed=True,
                                  description="代码仓库/目录路径")):
    """启动一键八阶段 DevSecOps 扫描（后台线程）。"""
    g = _guard()
    if g:
        return g
    t = _ORCH.create_task(target)
    threading.Thread(target=_ORCH.run_full,
                     args=(target, t.task_id), daemon=True).start()
    return ok({"task_id": t.task_id, "target": target,
               "status": t.status, "stage": t.stage,
               "progress": t.progress})


@router.get("/tasks")
def list_tasks():
    g = _guard()
    if g:
        return g
    return ok({"tasks": _ORCH.list_tasks()})


@router.get("/task/{task_id}")
def task_detail(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.to_dict())


@router.get("/task/{task_id}/status")
def task_status(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok({"task_id": task_id, "status": t.status,
               "stage": t.stage, "progress": t.progress,
               "log": t.log[-30:]})


@router.get("/task/{task_id}/results")
def task_results(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok({
        "task_id": task_id, "target": t.target,
        "status": t.status, "stage": t.stage,
        "progress": t.progress,
        "cicd": t.cicd, "sast": t.sast, "sca": t.sca,
        "secrets": t.secrets, "iac": t.iac,
        "container": t.container, "gate": t.gate,
        "risk": t.risk, "ai": t.ai,
        "report_path": t.report_path,
    })


@router.delete("/task/{task_id}")
def cancel_task(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    t.status = "cancelled"
    t.log.append("[!] 任务被用户取消")
    return ok({"task_id": task_id, "status": "cancelled"})


# =========================================================================== #
# 2. 阶段1：CI/CD 集成
# =========================================================================== #
@router.get("/cicd/tools")
def cicd_tools():
    g = _guard()
    if g:
        return g
    return ok(_CICD.tool_status())


@router.post("/cicd/generate")
def cicd_generate(platform: str = Body(...),
                  repo: str = Body(default=""),
                  branch: str = Body(default="main"),
                  stages: Optional[List[str]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    cfg = _CICD.generate_config(platform, repo, branch, stages)
    return ok(cfg.to_dict())


@router.post("/cicd/save")
def cicd_save(platform: str = Body(...),
              repo: str = Body(default=""),
              branch: str = Body(default="main"),
              target_dir: str = Body(...)):
    g = _guard()
    if g:
        return g
    cfg = _CICD.generate_config(platform, repo, branch)
    path = _CICD.save_config(cfg, target_dir)
    return ok({"saved_to": path, "config": cfg.to_dict()})


@router.post("/cicd/trigger")
def cicd_trigger(platform: str = Body(...),
                 repo: str = Body(...),
                 ref: str = Body(default="main")):
    g = _guard()
    if g:
        return g
    res = _CICD.trigger_pipeline(platform, repo, ref)
    return ok(res.to_dict())


@router.get("/cicd/status")
def cicd_status(platform: str = Query(...),
                repo: str = Query(...),
                run_id: str = Query(default="latest")):
    g = _guard()
    if g:
        return g
    res = _CICD.pipeline_status(platform, repo, run_id)
    return ok(res.to_dict())


@router.get("/cicd/platforms")
def cicd_platforms():
    g = _guard()
    if g:
        return g
    return ok({"platforms": list(_CICD.PLATFORMS)})


# =========================================================================== #
# 3. 阶段2：SAST 扫描
# =========================================================================== #
@router.get("/sast/tools")
def sast_tools():
    g = _guard()
    if g:
        return g
    return ok(_SAST.tool_status())


@router.post("/sast/scan")
def sast_scan(target: str = Body(...),
              rulepack: str = Body(default="auto"),
              languages: Optional[List[str]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_SAST.scan(target, rulepack, languages))
    except Exception as e:  # noqa: BLE001
        return fail(f"SAST 扫描失败: {e}")


@router.get("/sast/rulepacks")
def sast_rulepacks():
    g = _guard()
    if g:
        return g
    return ok({"rulepacks": ["owasp", "security-audit", "secrets", "ci"],
               "languages": ["python", "javascript", "java", "go",
                             "rust", "c", "cpp"]})


# =========================================================================== #
# 4. 阶段3：SCA 扫描
# =========================================================================== #
@router.get("/sca/tools")
def sca_tools():
    g = _guard()
    if g:
        return g
    return ok(_SCA.tool_status())


@router.post("/sca/scan")
def sca_scan(target: str = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_SCA.scan(target))
    except Exception as e:  # noqa: BLE001
        return fail(f"SCA 扫描失败: {e}")


@router.get("/sca/managers")
def sca_managers():
    g = _guard()
    if g:
        return g
    return ok({"managers": list(_SCA.MANIFEST_FILES.keys())})


# =========================================================================== #
# 5. 阶段4：Secrets 扫描
# =========================================================================== #
@router.get("/secrets/tools")
def secrets_tools():
    g = _guard()
    if g:
        return g
    return ok(_SEC.tool_status())


@router.post("/secrets/scan")
def secrets_scan(target: str = Body(...),
                 scan_history: bool = Body(default=False)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_SEC.scan(target, scan_history))
    except Exception as e:  # noqa: BLE001
        return fail(f"Secrets 扫描失败: {e}")


@router.get("/secrets/types")
def secrets_types():
    g = _guard()
    if g:
        return g
    return ok({"types": ["AWS Key", "GCP Key", "Private Key", "JWT",
                         "GitHub Token", "Slack Token", "Stripe Key",
                         "DB Connection String", "Hardcoded Password"]})


# =========================================================================== #
# 6. 阶段5：IaC 安全
# =========================================================================== #
@router.get("/iac/tools")
def iac_tools():
    g = _guard()
    if g:
        return g
    return ok(_IAC.tool_status())


@router.post("/iac/scan")
def iac_scan(target: str = Body(...),
             iac_type: str = Body(default="auto")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_IAC.scan(target, iac_type))
    except Exception as e:  # noqa: BLE001
        return fail(f"IaC 扫描失败: {e}")


@router.get("/iac/types")
def iac_types():
    g = _guard()
    if g:
        return g
    return ok({"types": ["Terraform", "CloudFormation", "Kubernetes",
                        "Dockerfile", "ARM"]})


# =========================================================================== #
# 7. 阶段6：容器安全
# =========================================================================== #
@router.get("/container/tools")
def container_tools():
    g = _guard()
    if g:
        return g
    return ok(_CON.tool_status())


@router.post("/container/scan-image")
def container_scan_image(image: str = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_CON.scan_image(image))
    except Exception as e:  # noqa: BLE001
        return fail(f"镜像扫描失败: {e}")


@router.post("/container/scan-fs")
def container_scan_fs(root: str = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_CON.scan_filesystem(root))
    except Exception as e:  # noqa: BLE001
        return fail(f"文件系统扫描失败: {e}")


# =========================================================================== #
# 8. 阶段7：安全门禁
# =========================================================================== #
@router.get("/gate/rules")
def gate_rules():
    g = _guard()
    if g:
        return g
    return ok({"rules": _GATE.list_rules()})


@router.put("/gate/rules/{name}")
def gate_update_rule(name: str,
                     level: Optional[str] = Body(default=None),
                     threshold: Optional[int] = Body(default=None)):
    g = _guard()
    if g:
        return g
    ok_flag = _GATE.update_rule(name, level, threshold)
    if not ok_flag:
        return fail("rule not found", 404)
    return ok({"rules": _GATE.list_rules()})


@router.post("/gate/evaluate")
def gate_evaluate(sast: Dict[str, Any] = Body(default_factory=dict),
                  sca: Dict[str, Any] = Body(default_factory=dict),
                  secrets: Dict[str, Any] = Body(default_factory=dict),
                  iac: Dict[str, Any] = Body(default_factory=dict),
                  container: Dict[str, Any] = Body(default_factory=dict)):
    g = _guard()
    if g:
        return g
    res = _GATE.evaluate(sast, sca, secrets, iac, container)
    return ok(res.to_dict())


@router.get("/gate/report/{task_id}")
def gate_report(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok({"gate": t.gate, "reasons": t.gate.get("reasons", [])})


# =========================================================================== #
# 9. 阶段8：风险评级
# =========================================================================== #
@router.post("/risk/rate")
def risk_rate(sast: Dict[str, Any] = Body(default_factory=dict),
              sca: Dict[str, Any] = Body(default_factory=dict),
              secrets: Dict[str, Any] = Body(default_factory=dict),
              iac: Dict[str, Any] = Body(default_factory=dict),
              container: Dict[str, Any] = Body(default_factory=dict)):
    g = _guard()
    if g:
        return g
    res = _RISK.rate(sast, sca, secrets, iac, container)
    return ok(res.to_dict())


@router.get("/risk/trend")
def risk_trend():
    g = _guard()
    if g:
        return g
    return ok({"trend": _RISK.trend_history()})


@router.get("/risk/maturity")
def risk_maturity():
    g = _guard()
    if g:
        return g
    return ok({"levels": ["critical", "high", "medium", "low"],
               "maturity_levels": ["危险（Chaotic）", "起步（Initial）",
                                   "合规（Defined）", "良好（Managed）",
                                   "优秀（Leader）"]})


# =========================================================================== #
# 10. AI 分析
# =========================================================================== #
@router.post("/ai/analyze")
def ai_analyze(sast: Dict[str, Any] = Body(default_factory=dict),
              sca: Dict[str, Any] = Body(default_factory=dict),
              secrets: Dict[str, Any] = Body(default_factory=dict),
              iac: Dict[str, Any] = Body(default_factory=dict),
              container: Dict[str, Any] = Body(default_factory=dict),
              gate: Dict[str, Any] = Body(default_factory=dict),
              risk: Dict[str, Any] = Body(default_factory=dict)):
    g = _guard()
    if g:
        return g
    res = _AI.analyze(sast, sca, secrets, iac, container, gate, risk)
    return ok(res.to_dict())


@router.get("/ai/fix-suggestions/{task_id}")
def ai_fix(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok({"fix_suggestions": t.ai.get("fix_suggestions", [])})


@router.get("/ai/attack-paths/{task_id}")
def ai_paths(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok({"attack_paths": t.ai.get("attack_paths", [])})


@router.get("/ai/roadmap/{task_id}")
def ai_roadmap(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok({"roadmap": t.ai.get("roadmap", [])})


# =========================================================================== #
# 11. 报告生成
# =========================================================================== #
@router.post("/report/generate/{task_id}")
def report_generate(task_id: str, fmt: str = Body(default="html")):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    from devsecops_pro.report_generator import DevSecOpsReportData
    rd = DevSecOpsReportData(
        task_id=t.task_id, target=t.target,
        started_at=t.created_at,
        finished_at=t.finished_at or "",
        cicd=t.cicd, sast=t.sast, sca=t.sca,
        secrets=t.secrets, iac=t.iac,
        container=t.container, gate=t.gate,
        risk=t.risk, ai=t.ai,
    )
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = _REP.save(rd, REPORTS_DIR, fmt)
    return ok({"report_path": path, "format": fmt})


@router.get("/report/markdown/{task_id}")
def report_md(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    from devsecops_pro.report_generator import DevSecOpsReportData
    rd = DevSecOpsReportData(
        task_id=t.task_id, target=t.target,
        started_at=t.created_at,
        finished_at=t.finished_at or "",
        cicd=t.cicd, sast=t.sast, sca=t.sca,
        secrets=t.secrets, iac=t.iac,
        container=t.container, gate=t.gate,
        risk=t.risk, ai=t.ai,
    )
    return ok({"markdown": _REP.generate_markdown(rd)})


@router.get("/reports")
def list_reports():
    g = _guard()
    if g:
        return g
    if not os.path.exists(REPORTS_DIR):
        return ok({"reports": []})
    files = sorted(os.listdir(REPORTS_DIR), reverse=True)
    return ok({"reports": files, "dir": REPORTS_DIR})


# =========================================================================== #
# 12. 仪表盘聚合
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    g = _guard()
    if g:
        return g
    return ok(_DASH.overview())


@router.get("/dashboard/recent")
def dash_recent(limit: int = Query(default=10)):
    g = _guard()
    if g:
        return g
    return ok({"tasks": _DASH.recent_tasks(limit)})


@router.get("/dashboard/stages")
def dash_stages():
    g = _guard()
    if g:
        return g
    return ok({"stages": _DASH.stage_status()})


@router.get("/dashboard/tools")
def dash_tools():
    g = _guard()
    if g:
        return g
    return ok(_DASH.tools_status())


@router.get("/dashboard/events/{task_id}")
def dash_events(task_id: str):
    g = _guard()
    if g:
        return g
    return ok({"events": _DASH.event_stream(task_id)})


# =========================================================================== #
# 13. WebSocket 实时推送
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_endpoint(websocket: WebSocket, task_id: str):
    """实时推送扫描进度/日志/思考/结果。"""
    await websocket.accept()
    if not _MOD_AVAILABLE:
        await websocket.send_json({"type": "error",
                                   "message": "模块未加载"})
        await websocket.close()
        return
    _RT.subscribe(task_id, websocket)
    # 先补发历史
    for ev in _RT.history(task_id):
        try:
            await websocket.send_json(ev)
        except Exception:
            break
    try:
        sent_index = len(_RT.history(task_id))
        while True:
            # 轮询新事件
            hist = _RT.history(task_id)
            if len(hist) > sent_index:
                for ev in hist[sent_index:]:
                    await websocket.send_json(ev)
                sent_index = len(hist)
            # 心跳
            await websocket.send_json({"type": "ping",
                                       "ts": __import__("time").time()})
            await __import__("asyncio").sleep(1.5)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _RT.unsubscribe(task_id, websocket)
