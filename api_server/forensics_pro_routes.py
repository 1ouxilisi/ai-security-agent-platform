# -*- coding: utf-8 -*-
"""
forensics_pro_routes.py — 方向2 取证 Pro REST API（50+ 端点 + WebSocket）。

路由前缀: /api/v1/forensics-pro
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/forensics-pro",
                   tags=["ForensicsPro-方向2"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from forensics_pro import (
        get_orchestrator, get_dashboard, get_realtime_push,
        get_evidence_acquisition_phase, get_evidence_preservation_phase,
        get_disk_forensics_phase, get_memory_forensics_phase,
        get_network_forensics_phase, get_log_forensics_phase,
        get_malware_analysis_phase, get_forensics_report_phase,
        get_ai_analysis, get_report_generator,
        STAGES, REPORTS_DIR, VOL_PLUGINS,
    )
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _RT = get_realtime_push()
    _ACQ = get_evidence_acquisition_phase()
    _PRES = get_evidence_preservation_phase()
    _DISK = get_disk_forensics_phase()
    _MEM = get_memory_forensics_phase()
    _NET = get_network_forensics_phase()
    _LOG = get_log_forensics_phase()
    _MW = get_malware_analysis_phase()
    _RPT = get_forensics_report_phase()
    _AI = get_ai_analysis()
    _REP = get_report_generator()
    _MOD_AVAILABLE = True
    logger.info("forensics_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("forensics_pro_routes: load failed: %s", e)
    _ORCH = _DASH = _RT = None  # type: ignore
    _ACQ = _PRES = _DISK = _MEM = None  # type: ignore
    _NET = _LOG = _MW = _RPT = None  # type: ignore
    _AI = _REP = None  # type: ignore


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
        return fail("Forensics Pro 模块未加载", 503)
    return None


# =========================================================================== #
# 0. 任务管理（八阶段一键全流程）
# =========================================================================== #
@router.post("/start")
def start_forensics(name: str = Body("数字取证全流程", embed=True)):
    g = _guard()
    if g:
        return g
    t = _ORCH.create_task(name)
    threading.Thread(target=_ORCH.run_full,
                     args=(t.task_id,), daemon=True).start()
    return ok({"task_id": t.task_id, "name": name,
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


@router.get("/stages")
def stages():
    g = _guard()
    if g:
        return g
    return ok({"stages": [{"key": k, "label": n, "progress": p}
                          for k, n, p in STAGES]})


# =========================================================================== #
# 1. 阶段1 证据获取
# =========================================================================== #
@router.get("/acquisition/tools")
def acq_tools():
    g = _guard()
    if g:
        return g
    return ok(_ACQ.tool_status())


@router.get("/acquisition/evidence")
def acq_list(evidence_type: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"evidence": _ACQ.list_evidence(evidence_type)})


@router.get("/acquisition/evidence/{eid}")
def acq_detail(eid: str):
    g = _guard()
    if g:
        return g
    r = _ACQ.get_evidence(eid)
    if r is None:
        return fail("evidence not found", 404)
    return ok(r)


@router.post("/acquisition/tasks")
def acq_create_task(evidence_type: str = Body("disk"),
                    target: str = Body(""),
                    operator: str = Body("取证员"),
                    location: str = Body("现场A")):
    g = _guard()
    if g:
        return g
    return ok(_ACQ.create_task(evidence_type, target,
                               operator=operator, location=location))


@router.get("/acquisition/tasks")
def acq_list_tasks():
    g = _guard()
    if g:
        return g
    return ok({"tasks": _ACQ.list_tasks()})


@router.post("/acquisition/tasks/{tid}/run")
def acq_run(tid: str):
    g = _guard()
    if g:
        return g
    return ok(_ACQ.run_acquisition(tid))


@router.get("/acquisition/stats")
def acq_stats():
    g = _guard()
    if g:
        return g
    return ok(_ACQ.stats())


# =========================================================================== #
# 2. 阶段2 证据保全
# =========================================================================== #
@router.post("/preservation/chains")
def pres_create(evidence_id: str = Body(...),
                case_id: str = Body(""),
                custodian: str = Body("保管人")):
    g = _guard()
    if g:
        return g
    return ok(_PRES.create_chain(evidence_id, case_id, custodian))


@router.get("/preservation/chains")
def pres_list():
    g = _guard()
    if g:
        return g
    return ok({"chains": _PRES.list_chains()})


@router.get("/preservation/chains/{cid}")
def pres_detail(cid: str):
    g = _guard()
    if g:
        return g
    r = _PRES.get_chain(cid)
    if r is None:
        return fail("chain not found", 404)
    return ok(r)


@router.post("/preservation/chains/{cid}/verify")
def pres_verify(cid: str):
    g = _guard()
    if g:
        return g
    return ok(_PRES.verify_integrity(cid))


@router.post("/preservation/chains/{cid}/write-protect")
def pres_wp(cid: str, enabled: bool = Body(True, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_PRES.set_write_protect(cid, enabled))


@router.post("/preservation/chains/{cid}/ntp")
def pres_ntp(cid: str):
    g = _guard()
    if g:
        return g
    return ok(_PRES.ntp_sync(cid))


@router.post("/preservation/chains/{cid}/transfer")
def pres_transfer(cid: str,
                  new_custodian: str = Body(...),
                  new_location: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_PRES.transfer_custody(cid, new_custodian, new_location))


@router.post("/preservation/chains/{cid}/status")
def pres_status(cid: str, status: str = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_PRES.update_status(cid, status))


@router.get("/preservation/audit")
def pres_audit(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok({"audit": _PRES.audit_log(limit)})


@router.get("/preservation/stats")
def pres_stats():
    g = _guard()
    if g:
        return g
    return ok(_PRES.stats())


# =========================================================================== #
# 3. 阶段3 磁盘取证
# =========================================================================== #
@router.get("/disk/filesystem")
def disk_fs(fs_type: str = Query("NTFS")):
    g = _guard()
    if g:
        return g
    return ok(_DISK.analyze_filesystem(fs_type))


@router.post("/disk/recover-deleted")
def disk_recover():
    g = _guard()
    if g:
        return g
    return ok(_DISK.recover_deleted())


@router.get("/disk/carving")
def disk_carving():
    g = _guard()
    if g:
        return g
    return ok(_DISK.file_carving())


@router.get("/disk/metadata")
def disk_meta():
    g = _guard()
    if g:
        return g
    return ok(_DISK.metadata_analysis())


@router.get("/disk/timeline")
def disk_timeline():
    g = _guard()
    if g:
        return g
    return ok(_DISK.build_timeline())


@router.get("/disk/registry")
def disk_reg():
    g = _guard()
    if g:
        return g
    return ok(_DISK.registry_analysis())


@router.get("/disk/recycle-bin")
def disk_recycle():
    g = _guard()
    if g:
        return g
    return ok(_DISK.recycle_bin_analysis())


@router.get("/disk/prefetch")
def disk_prefetch():
    g = _guard()
    if g:
        return g
    return ok(_DISK.prefetch_analysis())


@router.get("/disk/browser")
def disk_browser(browser: str = Query("chrome")):
    g = _guard()
    if g:
        return g
    return ok(_DISK.browser_history(browser))


@router.get("/disk/email")
def disk_email(client: str = Query("outlook")):
    g = _guard()
    if g:
        return g
    return ok(_DISK.email_analysis(client))


@router.get("/disk/encrypted")
def disk_enc():
    g = _guard()
    if g:
        return g
    return ok(_DISK.encrypted_container_detect())


@router.get("/disk/stats")
def disk_stats():
    g = _guard()
    if g:
        return g
    return ok(_DISK.stats())


# =========================================================================== #
# 4. 阶段4 内存取证（Volatility3）
# =========================================================================== #
@router.get("/memory/tools")
def mem_tools():
    g = _guard()
    if g:
        return g
    return ok(_MEM.tool_status())


@router.get("/memory/plugins")
def mem_plugins():
    g = _guard()
    if g:
        return g
    return ok({"plugins": VOL_PLUGINS})


@router.post("/memory/run")
def mem_run(plugin: str = Body(...),
            image_path: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_MEM.run_plugin(plugin, image_path))


@router.post("/memory/run-all")
def mem_run_all(image_path: str = Body("", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_MEM.run_all(image_path))


@router.get("/memory/findings")
def mem_findings():
    g = _guard()
    if g:
        return g
    return ok(_MEM.list_findings())


@router.get("/memory/stats")
def mem_stats():
    g = _guard()
    if g:
        return g
    return ok(_MEM.stats())


# =========================================================================== #
# 5. 阶段5 网络取证
# =========================================================================== #
@router.get("/network/tools")
def net_tools():
    g = _guard()
    if g:
        return g
    return ok(_NET.tool_status())


@router.post("/network/analyze-pcap")
def net_analyze(pcap_path: str = Body("", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_NET.analyze_pcap(pcap_path))


@router.get("/network/protocols")
def net_proto():
    g = _guard()
    if g:
        return g
    return ok(_NET.protocol_distribution())


@router.get("/network/sessions")
def net_sessions():
    g = _guard()
    if g:
        return g
    return ok(_NET.session_stats())


@router.get("/network/anomalies")
def net_anomaly():
    g = _guard()
    if g:
        return g
    return ok(_NET.anomaly_detect())


@router.get("/network/intrusions")
def net_intrusion():
    g = _guard()
    if g:
        return g
    return ok(_NET.intrusion_detect())


@router.get("/network/exfiltration")
def net_exfil():
    g = _guard()
    if g:
        return g
    return ok(_NET.exfiltration_analysis())


@router.get("/network/certificates")
def net_cert():
    g = _guard()
    if g:
        return g
    return ok(_NET.certificate_analysis())


@router.get("/network/reconstruction")
def net_recon():
    g = _guard()
    if g:
        return g
    return ok(_NET.session_reconstruction())


@router.post("/network/ioc-match")
def net_ioc(ioc_type: str = Body(...), value: str = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_NET.ioc_match(ioc_type, value))


@router.get("/network/ioc-library")
def net_ioc_lib():
    g = _guard()
    if g:
        return g
    return ok(_NET.ioc_library())


@router.get("/network/alerts")
def net_alerts():
    g = _guard()
    if g:
        return g
    return ok({"alerts": _NET.list_alerts()})


@router.get("/network/stats")
def net_stats():
    g = _guard()
    if g:
        return g
    return ok(_NET.stats())


# =========================================================================== #
# 6. 阶段6 日志取证
# =========================================================================== #
@router.get("/logs/system")
def log_system():
    g = _guard()
    if g:
        return g
    return ok(_LOG.system_log_analysis())


@router.get("/logs/app")
def log_app():
    g = _guard()
    if g:
        return g
    return ok(_LOG.app_log_analysis())


@router.get("/logs/security")
def log_sec():
    g = _guard()
    if g:
        return g
    return ok(_LOG.security_log_analysis())


@router.get("/logs/logins")
def log_login():
    g = _guard()
    if g:
        return g
    return ok(_LOG.login_analysis())


@router.get("/logs/attack-path")
def log_path():
    g = _guard()
    if g:
        return g
    return ok(_LOG.attack_path_reconstruct())


@router.get("/logs/behavior")
def log_behavior():
    g = _guard()
    if g:
        return g
    return ok(_LOG.user_behavior_analysis())


@router.get("/logs/correlation")
def log_corr():
    g = _guard()
    if g:
        return g
    return ok(_LOG.correlation())


@router.get("/logs/timeline")
def log_tl():
    g = _guard()
    if g:
        return g
    return ok(_LOG.build_timeline())


@router.get("/logs/evidence")
def log_ev():
    g = _guard()
    if g:
        return g
    return ok(_LOG.extract_evidence())


@router.get("/logs/integrity")
def log_int():
    g = _guard()
    if g:
        return g
    return ok(_LOG.integrity_verify())


@router.get("/logs/stats")
def log_stats():
    g = _guard()
    if g:
        return g
    return ok(_LOG.stats())


# =========================================================================== #
# 7. 阶段7 恶意软件分析
# =========================================================================== #
@router.post("/malware/static")
def mw_static(file_path: str = Body("sample.exe", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_MW.static_analysis(file_path))


@router.post("/malware/dynamic")
def mw_dynamic(sample_id: str = Body("", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_MW.dynamic_analysis(sample_id))


@router.post("/malware/classify")
def mw_classify(sample_id: str = Body("", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_MW.classify(sample_id))


@router.post("/malware/ioc")
def mw_ioc(sample_id: str = Body("", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_MW.extract_ioc(sample_id))


@router.get("/malware/samples")
def mw_samples():
    g = _guard()
    if g:
        return g
    return ok({"samples": _MW.list_samples()})


@router.get("/malware/iocs")
def mw_iocs():
    g = _guard()
    if g:
        return g
    return ok({"iocs": _MW.list_iocs()})


@router.get("/malware/stats")
def mw_stats():
    g = _guard()
    if g:
        return g
    return ok(_MW.stats())


# =========================================================================== #
# 8. 阶段8 取证报告
# =========================================================================== #
@router.post("/report/generate")
def rpt_generate(case_name: str = Body("取证分析报告"),
                 case_id: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_RPT.generate(case_name, case_id))


@router.get("/report/list")
def rpt_list():
    g = _guard()
    if g:
        return g
    return ok({"reports": _RPT.list_reports()})


@router.get("/report/{rid}")
def rpt_detail(rid: str):
    g = _guard()
    if g:
        return g
    r = _RPT.get_report(rid)
    if r is None:
        return fail("report not found", 404)
    return ok(r)


@router.post("/report/{rid}/export")
def rpt_export(rid: str, fmt: str = Body("md", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_RPT.export(rid, fmt))


# =========================================================================== #
# 9. AI 分析
# =========================================================================== #
@router.post("/ai/analyze")
def ai_analyze(evidence: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_AI.analyze_evidence(evidence))


@router.post("/ai/batch")
def ai_batch():
    g = _guard()
    if g:
        return g
    return ok(_AI.batch_analyze(_ACQ.list_evidence()))


@router.get("/ai/timeline")
def ai_timeline():
    g = _guard()
    if g:
        return g
    return ok(_AI.build_timeline(_LOG.build_timeline()["timeline"]))


@router.get("/ai/suspect")
def ai_suspect():
    g = _guard()
    if g:
        return g
    return ok(_AI.suspect_profile())


@router.get("/ai/correlate")
def ai_corr():
    g = _guard()
    if g:
        return g
    return ok(_AI.correlate_evidence(_ACQ.list_evidence()))


@router.get("/ai/anomaly")
def ai_anom():
    g = _guard()
    if g:
        return g
    return ok(_AI.anomaly_detect())


@router.get("/ai/history")
def ai_hist(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok({"history": _AI.history(limit)})


# =========================================================================== #
# 10. 取证大屏仪表盘
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    g = _guard()
    if g:
        return g
    return ok(_DASH.overview())


@router.get("/dashboard/full")
def dash_full():
    g = _guard()
    if g:
        return g
    return ok(_DASH.full_screen())


@router.get("/dashboard/evidence-status")
def dash_es():
    g = _guard()
    if g:
        return g
    return ok(_DASH.evidence_status())


@router.get("/dashboard/stage-progress")
def dash_sp():
    g = _guard()
    if g:
        return g
    return ok({"stages": _DASH.stage_progress()})


@router.get("/dashboard/findings")
def dash_fd():
    g = _guard()
    if g:
        return g
    return ok(_DASH.findings_distribution())


@router.get("/dashboard/evidence-types")
def dash_et():
    g = _guard()
    if g:
        return g
    return ok(_DASH.evidence_type_distribution())


@router.get("/dashboard/attack-timeline")
def dash_at():
    g = _guard()
    if g:
        return g
    return ok({"timeline": _DASH.attack_timeline()})


@router.get("/dashboard/top-findings")
def dash_tf(n: int = Query(10)):
    g = _guard()
    if g:
        return g
    return ok({"top": _DASH.top_findings(n)})


@router.get("/dashboard/recent-alerts")
def dash_ra(limit: int = Query(20)):
    g = _guard()
    if g:
        return g
    return ok({"alerts": _DASH.recent_alerts(limit)})


# =========================================================================== #
# 11. 报告生成（MD/HTML）
# =========================================================================== #
@router.post("/report/export")
def report_gen(fmt: str = Body("both", embed=True)):
    g = _guard()
    if g:
        return g
    r = _REP.generate(fmt)
    return ok({k: v for k, v in r.items() if k != "html"})


@router.get("/report/latest")
def report_latest():
    g = _guard()
    if g:
        return g
    import os
    if not os.path.isdir(REPORTS_DIR):
        return ok({"files": []})
    files = sorted(os.listdir(REPORTS_DIR), reverse=True)
    return ok({"dir": REPORTS_DIR, "files": files[:20]})


# =========================================================================== #
# 12. WebSocket 实时推送
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_endpoint(websocket: WebSocket, task_id: str):
    """实时推送进度/日志/思考/告警/发现/结果。"""
    await websocket.accept()
    if not _MOD_AVAILABLE:
        await websocket.send_json({"type": "error",
                                   "message": "模块未加载"})
        await websocket.close()
        return
    _RT.subscribe(task_id, websocket)
    for ev in _RT.history(task_id):
        try:
            await websocket.send_json(ev)
        except Exception:
            break
    try:
        sent_index = len(_RT.history(task_id))
        while True:
            hist = _RT.history(task_id)
            if len(hist) > sent_index:
                for ev in hist[sent_index:]:
                    await websocket.send_json(ev)
                sent_index = len(hist)
            await websocket.send_json({"type": "ping",
                                       "ts": time.time()})
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _RT.unsubscribe(task_id, websocket)
