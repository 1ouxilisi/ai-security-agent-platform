# -*- coding: utf-8 -*-
"""
red_blue_pro_routes.py — 红蓝对抗 Pro REST API（45+ 端点 + WebSocket）。

路由前缀: /api/v1/red-blue-pro
WebSocket: /ws/red-blue-pro/{task_id}
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/red-blue-pro",
                   tags=["红蓝对抗Pro-方向1"])


# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from red_blue_pro import (
        get_orchestrator, get_dashboard, get_realtime_push,
        get_red_recon_phase, get_red_initial_access_phase,
        get_red_execution_phase, get_red_privesc_phase,
        get_red_lateral_phase, get_red_objective_phase,
        get_blue_detection_phase, get_blue_response_phase,
        get_blue_attribution_phase, get_purple_debrief,
        get_ai_analysis, get_report_generator, STAGES, REPORTS_DIR,
    )
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _PUSH = get_realtime_push()
    _MOD_AVAILABLE = True
    logger.info("red_blue_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("red_blue_pro_routes: load failed: %s", e)
    _ORCH = None  # type: ignore
    _DASH = None  # type: ignore
    _PUSH = None  # type: ignore


_LOOP: Optional[asyncio.AbstractEventLoop] = None


def _capture_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _LOOP
    _LOOP = loop


def _bridge_event(ev: Dict[str, Any]) -> None:
    if _PUSH is None:
        return
    if _LOOP is None or not _LOOP.is_running():
        return
    task_id = ev.get("task_id", "")
    try:
        asyncio.run_coroutine_threadsafe(
            _PUSH.broadcast(task_id, ev), _LOOP)
    except Exception:
        pass


if _MOD_AVAILABLE and _ORCH is not None:
    _ORCH.on_event = _bridge_event


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
        return fail("红蓝对抗 Pro 模块未加载", 503)
    return None


# =========================================================================== #
# 1. 任务管理
# =========================================================================== #
@router.post("/start")
def start_rb(target: str = Body(..., embed=True,
                               description="目标域名/IP")):
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
    return ok(t.to_dict())


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
# 2. 红队阶段1：侦察
# =========================================================================== #
@router.post("/red/recon/subdomains")
def red_subs(domain: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.recon.subfinder_enum(domain).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"子域名枚举失败: {e}")


@router.post("/red/recon/emails")
def red_emails(domain: str = Body(..., embed=True),
               limit: int = Body(default=100)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.recon.harvester_emails(domain, limit).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"邮箱收集失败: {e}")


@router.post("/red/recon/employees")
def red_employees(domain: str = Body(..., embed=True),
                  company: str = Body(default="")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.recon.employee_enum(domain, company).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"员工收集失败: {e}")


@router.post("/red/recon/hibp")
def red_hibp(email: str = Body(..., embed=True),
             api_key: str = Body(default="")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.recon.hibp_check(email, api_key).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"HIBP 检测失败: {e}")


@router.post("/red/recon/osint")
def red_osint(domain: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.recon.osint_dashboard(domain).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"OSINT 失败: {e}")


@router.get("/red/recon/tools")
def red_recon_tools():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.recon.tool_status())


# =========================================================================== #
# 3. 红队阶段2：初始访问
# =========================================================================== #
@router.get("/red/ia/phishing/templates")
def ia_phish_tpl(brand: str = Query(default=""),
                 domain: str = Query(default="")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.ia.phishing_templates(brand, domain))


@router.post("/red/ia/payload")
def ia_payload(payload: str = Body(default="windows/meterpreter/reverse_tcp"),
               lhost: str = Body(default="10.10.10.1"),
               lport: int = Body(default=4444),
               fmt: str = Body(default="exe")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.ia.generate_payload(payload, lhost, lport,
                                            fmt).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"Payload 生成失败: {e}")


@router.post("/red/ia/exploit/search")
def ia_exploit_search(keyword: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.ia.exploit_search(keyword).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"Exploit 检索失败: {e}")


@router.post("/red/ia/msf/run")
def ia_msf(module: str = Body(..., embed=True),
           options: str = Body(default="")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.ia.msf_module_run(module, options).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"MSF 调用失败: {e}")


@router.post("/red/ia/spray")
def ia_spray(target: str = Body(..., embed=True),
             service: str = Body(default="smb"),
             password: str = Body(default="Password123!")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.ia.password_spray(target, service,
                                          password).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"密码喷洒失败: {e}")


@router.post("/red/ia/brute")
def ia_brute(target: str = Body(..., embed=True),
             service: str = Body(default="ssh")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.ia.brute_force(target, service).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"暴力破解失败: {e}")


@router.get("/red/ia/tools")
def ia_tools():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.ia.tool_status())


# =========================================================================== #
# 4. 红队阶段3：执行
# =========================================================================== #
@router.get("/red/exec/shells")
def exec_shells(lhost: str = Query(default="10.10.10.1"),
                lport: int = Query(default=4444)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.exec.command_exec_templates(lhost, lport))


@router.post("/red/exec/macro")
def exec_macro(b64: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.exec.code_exec_macro(b64).to_dict())


@router.post("/red/exec/powershell")
def exec_ps(command: str = Body(default="whoami")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.exec.code_exec_powershell(command).to_dict())


@router.get("/red/exec/persistence")
def exec_persist():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.exec.persistence_list())


@router.post("/red/exec/persistence/render")
def exec_persist_render(kind: str = Body(default="windows_scheduled_task"),
                        payload_path: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.exec.persistence_render(kind, payload_path).to_dict())


@router.get("/red/exec/demo")
def exec_demo():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.exec.execute_demo())


# =========================================================================== #
# 5. 红队阶段4：提权
# =========================================================================== #
@router.post("/red/privesc/windows")
def priv_win():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.priv.windows_audit().to_dict())


@router.post("/red/privesc/linux")
def priv_linux():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.priv.linux_audit().to_dict())


@router.post("/red/privesc/cve")
def priv_cve(os_string: str = Body(..., embed=True),
             kernel: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.priv.cve_fingerprint(os_string, kernel).to_dict())


@router.post("/red/privesc/audit")
def priv_audit():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.priv.audit().to_dict())


@router.get("/red/privesc/tools")
def priv_tools():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.priv.tool_status())


# =========================================================================== #
# 6. 红队阶段5：横向
# =========================================================================== #
@router.post("/red/lateral/smb")
def lat_smb(target: str = Body(..., embed=True),
            user: str = Body(...), password: str = Body(default=""),
            command: str = Body(default="whoami")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.lat.via_smb(target, user, password, command).to_dict())


@router.post("/red/lateral/wmi")
def lat_wmi(target: str = Body(..., embed=True),
            user: str = Body(...), password: str = Body(default=""),
            command: str = Body(default="whoami")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.lat.via_wmi(target, user, password, command).to_dict())


@router.post("/red/lateral/winrm")
def lat_winrm(target: str = Body(..., embed=True),
              user: str = Body(...), password: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.lat.via_winrm(target, user, password).to_dict())


@router.post("/red/lateral/pth")
def lat_pth(target: str = Body(..., embed=True),
            user: str = Body(...), nt_hash: str = Body(...),
            domain: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.lat.pass_the_hash(target, user, nt_hash,
                                      domain).to_dict())


@router.get("/red/lateral/tools")
def lat_tools():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.lat.tool_status())


# =========================================================================== #
# 7. 红队阶段6：目标
# =========================================================================== #
@router.post("/red/objective/files")
def obj_files(paths: Optional[List[str]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.obj.file_collect(paths).to_dict())


@router.post("/red/objective/db")
def obj_db(db_type: str = Body(default="mssql"),
           host: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.obj.db_dump(db_type, host).to_dict())


@router.get("/red/objective/creds")
def obj_creds():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.obj.cred_export().to_dict())


@router.post("/red/objective/backdoor")
def obj_backdoor(kind: str = Body(default="ssh_key")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.obj.backdoor_install(kind).to_dict())


@router.post("/red/objective/cleanup/logs")
def obj_cleanup(os_type: str = Body(default="windows")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.obj.log_clean(os_type).to_dict())


@router.get("/red/objective/tools")
def obj_tools():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.obj.tool_status())


# =========================================================================== #
# 8. 蓝队阶段1：检测
# =========================================================================== #
@router.get("/blue/detection/rules")
def blue_rules():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.det.suricata_rules())


@router.post("/blue/detection/windows-log")
def blue_winlog(lines: Optional[List[str]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.det.analyze_windows_log(sample=lines).to_dict())


@router.post("/blue/detection/syslog")
def blue_syslog(lines: Optional[List[str]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.det.analyze_syslog(lines).to_dict())


@router.post("/blue/detection/login")
def blue_login(logins: Optional[List[Dict[str, Any]]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.det.anomaly_login(logins).to_dict())


@router.post("/blue/detection/process")
def blue_proc(procs: Optional[List[str]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.det.anomaly_process(procs).to_dict())


@router.post("/blue/detection/ioc")
def blue_ioc(observables: Optional[List[str]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.det.ioc_match(observables).to_dict())


@router.get("/blue/detection/tools")
def blue_det_tools():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.det.tool_status())


# =========================================================================== #
# 9. 蓝队阶段2：响应
# =========================================================================== #
@router.get("/blue/response/lifecycle")
def blue_life():
    g = _guard()
    if g:
        return g
    return ok({"lifecycle": _ORCH.resp.ir_lifecycle()})


@router.post("/blue/response/isolate")
def blue_isolate(host: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.resp.isolate_host(host).to_dict())


@router.post("/blue/response/eradicate")
def blue_erad():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.resp.eradicate_malware().to_dict())


@router.post("/blue/response/recover")
def blue_rec():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.resp.recover_system().to_dict())


@router.post("/blue/response/full")
def blue_full(host: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.resp.run_full(host))


# =========================================================================== #
# 10. 蓝队阶段3：溯源
# =========================================================================== #
@router.post("/blue/attribution/timeline")
def blue_tl(logs: Optional[List[Dict[str, Any]]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.attr.rebuild_timeline(logs).to_dict())


@router.get("/blue/attribution/profile")
def blue_profile():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.attr.attacker_profile().to_dict())


@router.post("/blue/attribution/impact")
def blue_impact(hosts: int = Body(default=5),
                accounts: int = Body(default=12),
                records: int = Body(default=0)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.attr.impact_assessment(hosts, accounts,
                                           records).to_dict())


@router.post("/blue/attribution/full")
def blue_full_attr(logs: Optional[List[Dict[str, Any]]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.attr.full_attribution(logs).to_dict())


# =========================================================================== #
# 11. 紫队复盘
# =========================================================================== #
@router.post("/purple/compare")
def purple_compare(red_stages: List[Dict[str, Any]] = Body(...),
                   blue_alerts: List[Dict[str, Any]] = Body(
                       default_factory=list)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.purple.compare(red_stages, blue_alerts).to_dict())


@router.get("/purple/maturity")
def purple_maturity():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.purple.maturity_assessment())


# =========================================================================== #
# 12. AI 分析
# =========================================================================== #
@router.post("/ai/analyze")
def ai_analyze(red: Dict[str, Any] = Body(default={}),
               blue: Dict[str, Any] = Body(default={})):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.ai.analyze(red, blue))


@router.post("/ai/chain")
def ai_chain(red: Dict[str, Any] = Body(default={}),
             blue: Dict[str, Any] = Body(default={})):
    g = _guard()
    if g:
        return g
    r = _ORCH.ai.analyze(red, blue)
    return ok({"attack_chain": r.get("attack_chain", {})})


# =========================================================================== #
# 13. 报告
# =========================================================================== #
@router.get("/report/{task_id}")
def get_report(task_id: str, fmt: str = Query(default="html")):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    if fmt == "md":
        return ok({"markdown": t.report_markdown, "path": t.report_path})
    return ok({"html": t.report_html, "path": t.report_path})


@router.post("/report/{task_id}/regen")
def regen_report(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    import time as _time
    import os
    from red_blue_pro.report_generator import ReportData
    rd = ReportData(
        task_id=t.task_id, target=t.target,
        started_at=t.created_at,
        finished_at=_time.strftime("%Y-%m-%d %H:%M:%S"),
        red=t.red, blue=t.blue, purple=t.purple, analysis=t.analysis)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = _ORCH.report.save(rd, REPORTS_DIR, "html")
    t.report_path = path
    t.report_html = _ORCH.report.generate_html(rd)
    t.report_markdown = _ORCH.report.generate_markdown(rd)
    return ok({"task_id": task_id, "report_path": path})


# =========================================================================== #
# 14. 仪表盘
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
    return ok({"stages": [{"key": k, "label": n, "progress": p}
                          for k, n, p in STAGES]})


@router.get("/dashboard/tools")
def dash_tools():
    g = _guard()
    if g:
        return g
    return ok(_DASH.tool_matrix())


# =========================================================================== #
# 15. 事件历史
# =========================================================================== #
@router.get("/events/{task_id}")
def task_events(task_id: str):
    g = _guard()
    if g:
        return g
    return ok({"events": _PUSH.history(task_id)})


# =========================================================================== #
# 16. WebSocket
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_rb(websocket: WebSocket, task_id: str):
    if not _MOD_AVAILABLE:
        await websocket.close(code=1011)
        return
    _capture_loop(asyncio.get_running_loop())
    await _PUSH.connect(websocket, task_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _PUSH.disconnect(task_id, websocket)
    except Exception:
        _PUSH.disconnect(task_id, websocket)
