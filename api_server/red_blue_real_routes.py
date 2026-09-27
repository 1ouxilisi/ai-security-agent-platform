# -*- coding: utf-8 -*-
"""
red_blue_real_routes.py — 方向4：红蓝对抗真实化 REST API（70+ 端点 + WebSocket）。

路由前缀: /api/v1/red-blue-real
WebSocket: /ws/red-blue-real/{task_id}
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

router = APIRouter(prefix="/api/v1/red-blue-real",
                   tags=["红蓝对抗真实化-方向4"])

# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from red_blue_real import (
        get_real_orchestrator, get_real_dashboard,
        get_red_attack_chain, get_blue_detection,
        get_purple_debrief_real, get_red_tools, get_blue_tools,
        get_attack_navigator, get_real_report_generator,
    )
    _ORCH = get_real_orchestrator()
    _DASH = get_real_dashboard()
    _RED = get_red_attack_chain()
    _BLUE = get_blue_detection()
    _PURPLE = get_purple_debrief_real()
    _RTOOLS = get_red_tools()
    _BTOOLS = get_blue_tools()
    _NAV = get_attack_navigator()
    _REP = get_real_report_generator()
    _MOD_AVAILABLE = True
    logger.info("red_blue_real_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("red_blue_real_routes: load failed: %s", e)
    _ORCH = _DASH = _RED = _BLUE = _PURPLE = None  # type: ignore
    _RTOOLS = _BTOOLS = _NAV = _REP = None  # type: ignore


_LOOP: Optional[asyncio.AbstractEventLoop] = None
_WS_CLIENTS: Dict[str, List[WebSocket]] = {}


def _capture_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _LOOP
    _LOOP = loop


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": str(message)[:1500]}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("红蓝对抗真实化模块未加载", 503)
    return None


# =========================================================================== #
# 任务管理
# =========================================================================== #
@router.post("/start")
def start_real(target: str = Body(..., embed=True, description="目标IP/域名")):
    g = _guard()
    if g:
        return g
    t = _ORCH.create_task(target)
    threading.Thread(target=_ORCH.run_full,
                     args=(target, t.task_id), daemon=True).start()
    return ok({"task_id": t.task_id, "target": target,
               "status": t.status, "stage": t.stage, "progress": t.progress})


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
    return ok(t.to_dict()) if t else fail("task not found", 404)


@router.get("/task/{task_id}/status")
def task_status(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if not t:
        return fail("task not found", 404)
    return ok({"task_id": task_id, "status": t.status, "stage": t.stage,
               "progress": t.progress, "log": t.log[-30:]})


@router.get("/task/{task_id}/results")
def task_results(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    return ok(t.to_dict()) if t else fail("task not found", 404)


@router.delete("/task/{task_id}")
def cancel_task(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if not t:
        return fail("task not found", 404)
    t.status = "cancelled"
    t.log.append("[!] 任务被取消")
    return ok({"task_id": task_id, "status": "cancelled"})


# =========================================================================== #
# 真实红队 - 初始访问
# =========================================================================== #
@router.post("/red/ia/phishing-email")
def r_ia_email(template: str = Body(default="o365_quota"),
               from_addr: str = Body(default="it@example.com"),
               to_addr: str = Body(default="user@example.com"),
               landing_url: str = Body(default="https://login.example.com/verify"),
               subject: str = Body(default=""),
               brand: str = Body(default="microsoft"),
               company: str = Body(default="Example")):
    g = _guard()
    if g:
        return g
    return ok(_RED.initial_access.generate_phishing_email(
        template, from_addr, to_addr, subject, landing_url, brand, company))


@router.post("/red/ia/macro")
def r_ia_macro(kind: str = Body(default="downloader_powershell"),
               c2_url: str = Body(default="http://c2.example.com/p.ps1")):
    g = _guard()
    if g:
        return g
    return ok(_RED.initial_access.generate_macro(kind, c2_url))


@router.post("/red/ia/lnk")
def r_ia_lnk(target_cmd: str = Body(default="powershell -w hidden calc.exe"),
             lnk_name: str = Body(default="doc.lnk")):
    g = _guard()
    if g:
        return g
    return ok(_RED.initial_access.generate_malicious_lnk(target_cmd, lnk_name))


@router.post("/red/ia/iso")
def r_ia_iso(payload_dir: str = Body(default=""),
             iso_name: str = Body(default="update.iso")):
    g = _guard()
    if g:
        return g
    return ok(_RED.initial_access.generate_iso(payload_dir, iso_name))


@router.post("/red/ia/phish-page")
def r_ia_page(clone_url: str = Body(default="https://login.microsoftonline.com"),
              page_name: str = Body(default="o365.html")):
    g = _guard()
    if g:
        return g
    return ok(_RED.initial_access.generate_phish_page(clone_url, page_name))


@router.post("/red/ia/smtp-send")
def r_ia_send(smtp_host: str = Body(default=""), smtp_port: int = 587,
              username: str = Body(default=""), password: str = Body(default=""),
              from_addr: str = Body(default=""),
              to_list: List[str] = Body(default=[]),
              subject: str = Body(default=""), body: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_RED.initial_access.send_phishing_email(
        smtp_host, smtp_port, username, password, from_addr, to_list,
        subject, body))


@router.post("/red/ia/track")
def r_ia_track(events: List[Dict[str, Any]] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_RED.initial_access.track_click(events))


@router.get("/red/ia/tools")
def r_ia_tools():
    g = _guard()
    if g:
        return g
    return ok(_RED.initial_access.tool_status())


# =========================================================================== #
# 真实红队 - 执行
# =========================================================================== #
@router.get("/red/exec/empire")
def r_exec_empire(uri: str = Query(default="http://127.0.0.1:1337/api")):
    g = _guard()
    if g:
        return g
    return ok(_RED.execution.empire_status(uri))


@router.get("/red/exec/cs")
def r_exec_cs():
    g = _guard()
    if g:
        return g
    return ok(_RED.execution.cs_listener())


@router.post("/red/exec/run")
def r_exec_run(shell: str = Body(default="powershell"),
               command: str = Body(default="whoami")):
    g = _guard()
    if g:
        return g
    return ok(_RED.execution.run_command(shell, command))


@router.get("/red/exec/fileless")
def r_exec_fileless(technique: str = Query(default="iex")):
    g = _guard()
    if g:
        return g
    return ok(_RED.execution.fileless_templates(technique))


@router.get("/red/exec/inject")
def r_exec_inject():
    g = _guard()
    if g:
        return g
    return ok(_RED.execution.inject_templates())


@router.get("/red/exec/tools")
def r_exec_tools():
    g = _guard()
    if g:
        return g
    return ok(_RED.execution.tool_status())


# =========================================================================== #
# 真实红队 - 持久化
# =========================================================================== #
@router.get("/red/persist/registry")
def r_persist_reg(hive: str = Query(default="HKCU"),
                  key: str = Query(default=r"Software\Microsoft\Windows\CurrentVersion\Run")):
    g = _guard()
    if g:
        return g
    return ok(_RED.persistence.registry_query(hive, key))


@router.post("/red/persist/registry-add")
def r_persist_regadd(name: str = Body(...), command: str = Body(...),
                     hive: str = Body(default="HKCU"),
                     execute: bool = Body(default=False)):
    g = _guard()
    if g:
        return g
    return ok(_RED.persistence.registry_add(name, command, hive, execute))


@router.get("/red/persist/tasks")
def r_persist_tasks():
    g = _guard()
    if g:
        return g
    return ok(_RED.persistence.scheduled_tasks_list())


@router.post("/red/persist/task-create")
def r_persist_taskcreate(name: str = Body(default="Upd"),
                         command: str = Body(default="powershell -w hidden calc.exe"),
                         execute: bool = Body(default=False)):
    g = _guard()
    if g:
        return g
    return ok(_RED.persistence.scheduled_task_create(name, command, execute))


@router.get("/red/persist/services")
def r_persist_services():
    g = _guard()
    if g:
        return g
    return ok(_RED.persistence.service_query())


@router.get("/red/persist/wmi")
def r_persist_wmi():
    g = _guard()
    if g:
        return g
    return ok(_RED.persistence.wmi_persistence())


@router.get("/red/persist/catalog")
def r_persist_catalog():
    g = _guard()
    if g:
        return g
    return ok(_RED.persistence.persistence_catalog())


# =========================================================================== #
# 真实红队 - 提权
# =========================================================================== #
@router.get("/red/privesc/potato")
def r_potato():
    g = _guard()
    if g:
        return g
    return ok(_RED.privesc.juicy_potato())


@router.get("/red/privesc/spoofer")
def r_spoofer():
    g = _guard()
    if g:
        return g
    return ok(_RED.privesc.print_spoofer())


@router.get("/red/privesc/uac")
def r_uac():
    g = _guard()
    if g:
        return g
    return ok(_RED.privesc.uac_bypass_catalog())


@router.get("/red/privesc/kernel-cves")
def r_kernel():
    g = _guard()
    if g:
        return g
    return ok(_RED.privesc.kernel_cves())


@router.get("/red/privesc/linux")
def r_linux_priv():
    g = _guard()
    if g:
        return g
    return ok(_RED.privesc.linux_privesc_audit())


@router.get("/red/privesc/token")
def r_token():
    g = _guard()
    if g:
        return g
    return ok(_RED.privesc.token_techniques())


@router.get("/red/privesc/tools")
def r_priv_tools():
    g = _guard()
    if g:
        return g
    return ok(_RED.privesc.tool_status())


# =========================================================================== #
# 真实红队 - 防御规避
# =========================================================================== #
@router.get("/red/evade/amsi")
def r_amsi():
    g = _guard()
    if g:
        return g
    return ok(_RED.defense_evasion.amsi_bypass())


@router.get("/red/evade/etw")
def r_etw():
    g = _guard()
    if g:
        return g
    return ok(_RED.defense_evasion.etw_bypass())


@router.get("/red/evade/edr")
def r_edr():
    g = _guard()
    if g:
        return g
    return ok(_RED.defense_evasion.edr_bypass())


@router.get("/red/evade/obfuscation")
def r_obf():
    g = _guard()
    if g:
        return g
    return ok(_RED.defense_evasion.obfuscation())


@router.get("/red/evade/encryption")
def r_enc():
    g = _guard()
    if g:
        return g
    return ok(_RED.defense_evasion.encryption_primitives())


@router.get("/red/evade/anti")
def r_anti():
    g = _guard()
    if g:
        return g
    return ok(_RED.defense_evasion.anti_sandbox_debug())


# =========================================================================== #
# 真实红队 - 凭证访问
# =========================================================================== #
@router.get("/red/creds/mimikatz")
def r_mimi(action: str = Query(default="sekurlsa::logonpasswords")):
    g = _guard()
    if g:
        return g
    return ok(_RED.credential_access.mimikatz(action))


@router.get("/red/creds/lazagne")
def r_lazagne():
    g = _guard()
    if g:
        return g
    return ok(_RED.credential_access.lazagne())


@router.get("/red/creds/browser")
def r_browser():
    g = _guard()
    if g:
        return g
    return ok(_RED.credential_access.browser_creds())


@router.get("/red/creds/vault")
def r_vault():
    g = _guard()
    if g:
        return g
    return ok(_RED.credential_access.windows_vault())


@router.get("/red/creds/wifi")
def r_wifi():
    g = _guard()
    if g:
        return g
    return ok(_RED.credential_access.wifi_passwords())


@router.get("/red/creds/ssh")
def r_ssh():
    g = _guard()
    if g:
        return g
    return ok(_RED.credential_access.ssh_keys())


@router.get("/red/creds/cloud")
def r_cloud():
    g = _guard()
    if g:
        return g
    return ok(_RED.credential_access.cloud_creds())


@router.get("/red/creds/tools")
def r_creds_tools():
    g = _guard()
    if g:
        return g
    return ok(_RED.credential_access.tool_status())


# =========================================================================== #
# 真实红队 - 横向移动
# =========================================================================== #
@router.post("/red/lateral/smb")
def r_lat_smb(target: str = Body(...), user: str = Body(...),
              password: str = Body(default=""), command: str = Body(default="whoami")):
    g = _guard()
    if g:
        return g
    return ok(_RED.lateral.smb_lateral(target, user, password, command))


@router.post("/red/lateral/winrm")
def r_lat_winrm(target: str = Body(...), user: str = Body(...),
                password: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_RED.lateral.winrm_lateral(target, user, password))


@router.post("/red/lateral/ssh")
def r_lat_ssh(target: str = Body(...), user: str = Body(...),
              key_path: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_RED.lateral.ssh_lateral(target, user, key_path))


@router.get("/red/lateral/rdp")
def r_lat_rdp(target: str = Query(...)):
    g = _guard()
    if g:
        return g
    return ok(_RED.lateral.rdp_lateral(target))


@router.post("/red/lateral/wmi")
def r_lat_wmi(target: str = Body(...), user: str = Body(...),
              password: str = Body(default=""), command: str = Body(default="whoami")):
    g = _guard()
    if g:
        return g
    return ok(_RED.lateral.wmi_lateral(target, user, password, command))


@router.get("/red/lateral/dcom")
def r_lat_dcom():
    g = _guard()
    if g:
        return g
    return ok(_RED.lateral.dcom_lateral())


@router.post("/red/lateral/pth")
def r_lat_pth(target: str = Body(...), user: str = Body(...),
              nt_hash: str = Body(...), domain: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_RED.lateral.pass_the_hash(target, user, nt_hash, domain))


@router.get("/red/lateral/overpass")
def r_lat_op(target: str = Query(...), user: str = Query(default="admin"),
             nt_hash: str = Query(default="aad3b435b51404e")):
    g = _guard()
    if g:
        return g
    return ok(_RED.lateral.overpass_hash(target, user, nt_hash))


@router.get("/red/lateral/tools")
def r_lat_tools():
    g = _guard()
    if g:
        return g
    return ok(_RED.lateral.tool_status())


# =========================================================================== #
# 真实红队 - 数据外泄
# =========================================================================== #
@router.post("/red/exfil/compress")
def r_exf_compress(src: str = Body(default=""), archive: str = Body(default=""),
                   password: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_RED.exfiltration.compress(src, archive, password))


@router.post("/red/exfil/http")
def r_exf_http(file_path: str = Body(...), url: str = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_RED.exfiltration.exfil_http(file_path, url))


@router.get("/red/exfil/dns")
def r_exf_dns(data: str = Query(default="secret"),
              dns_server: str = Query(default="8.8.8.8")):
    g = _guard()
    if g:
        return g
    return ok(_RED.exfiltration.exfil_dns(data, dns_server))


@router.post("/red/exfil/ftp")
def r_exf_ftp(file_path: str = Body(...), ftp_url: str = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_RED.exfiltration.exfil_ftp(file_path, ftp_url))


@router.get("/red/exfil/cloud")
def r_exf_cloud():
    g = _guard()
    if g:
        return g
    return ok(_RED.exfiltration.exfil_cloud())


@router.get("/red/exfil/catalog")
def r_exf_catalog():
    g = _guard()
    if g:
        return g
    return ok(_RED.exfiltration.exfil_catalog())


@router.get("/red/exfil/tools")
def r_exf_tools():
    g = _guard()
    if g:
        return g
    return ok(_RED.exfiltration.tool_status())


# =========================================================================== #
# 真实蓝队 - 日志收集
# =========================================================================== #
@router.get("/blue/log/winlog")
def b_winlog(log: str = Query(default="Security"), max_events: int = 50):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.log_collection.windows_eventlog(log, max_events))


@router.get("/blue/log/sysmon")
def b_sysmon(max_events: int = 50):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.log_collection.sysmon_log(max_events))


@router.get("/blue/log/powershell")
def b_pslog(max_events: int = 50):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.log_collection.powershell_log(max_events))


@router.get("/blue/log/auditd")
def b_auditd():
    g = _guard()
    if g:
        return g
    return ok(_BLUE.log_collection.auditd_log())


@router.post("/blue/log/web")
def b_weblog(paths: List[str] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.log_collection.web_log(paths or None))


@router.post("/blue/log/enrich")
def b_enrich(lines: List[str] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.log_collection.parse_and_enrich(lines))


@router.get("/blue/log/tools")
def b_log_tools():
    g = _guard()
    if g:
        return g
    return ok(_BLUE.log_collection.tool_status())


# =========================================================================== #
# 真实蓝队 - 入侵检测
# =========================================================================== #
@router.post("/blue/ids/sigma")
def b_sigma(logs: List[Dict[str, Any]] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ids.sigma_match(logs))


@router.post("/blue/ids/yara")
def b_yara(text: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ids.yara_match(text))


@router.get("/blue/ids/suricata")
def b_suri():
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ids.suricata_status())


@router.get("/blue/ids/snort")
def b_snort():
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ids.snort_status())


@router.post("/blue/ids/ioc")
def b_ioc(observables: List[str] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ids.ioc_match(observables))


@router.post("/blue/ids/anomaly")
def b_anomaly(metrics: List[float] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ids.anomaly_detect(metrics))


@router.get("/blue/ids/tools")
def b_ids_tools():
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ids.tool_status())


# =========================================================================== #
# 真实蓝队 - EDR 检测
# =========================================================================== #
@router.get("/blue/edr/process-tree")
def b_proc():
    g = _guard()
    if g:
        return g
    return ok(_BLUE.edr.process_tree())


@router.get("/blue/edr/netstat")
def b_net():
    g = _guard()
    if g:
        return g
    return ok(_BLUE.edr.network_connections())


@router.post("/blue/edr/cmdline")
def b_cmd(cmdlines: List[str] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.edr.commandline_analysis(cmdlines))


@router.get("/blue/edr/registry")
def b_reg():
    g = _guard()
    if g:
        return g
    return ok(_BLUE.edr.registry_monitor())


@router.post("/blue/edr/chain")
def b_chain(events: List[Dict[str, Any]] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.edr.behavior_chain(events))


@router.get("/blue/edr/tools")
def b_edr_tools():
    g = _guard()
    if g:
        return g
    return ok(_BLUE.edr.tool_status())


# =========================================================================== #
# 真实蓝队 - 威胁狩猎
# =========================================================================== #
@router.post("/blue/hunt/ttp")
def b_ttp(technique: str = Body(default="T1059.001"),
          logs: List[Dict[str, Any]] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.hunt.ttp_query(technique, logs))


@router.get("/blue/hunt/hypothesis")
def b_hyp(h: str = Query(default="钓鱼->宏->横向")):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.hunt.hypothesis_driven(h))


@router.post("/blue/hunt/data")
def b_data(metrics: List[float] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.hunt.data_driven(metrics))


@router.post("/blue/hunt/query")
def b_query(engine: str = Body(default="kql"), query: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.hunt.hunt_query(engine, query))


@router.post("/blue/hunt/report")
def b_huntrep(hypothesis: str = Body(default=""),
              findings: List[str] = Body(default=[]),
              conclusion: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.hunt.hunt_report(hypothesis, findings, conclusion))


@router.get("/blue/hunt/tools")
def b_hunt_tools():
    g = _guard()
    if g:
        return g
    return ok(_BLUE.hunt.tool_status())


# =========================================================================== #
# 真实蓝队 - 事件响应
# =========================================================================== #
@router.post("/blue/ir/isolate")
def b_isolate(host: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ir.isolate_host(host))


@router.post("/blue/ir/block-ip")
def b_blockip(ip: str = Body(...), execute: bool = Body(default=False)):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ir.block_ip(ip, execute))


@router.post("/blue/ir/reset-pwd")
def b_resetpwd(user: str = Body(default=""), execute: bool = Body(default=False)):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ir.reset_password(user, execute))


@router.get("/blue/ir/evidence")
def b_evidence():
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ir.collect_evidence())


@router.get("/blue/ir/recover")
def b_recover():
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ir.recover_system())


@router.post("/blue/ir/timeline")
def b_timeline(events: List[Dict[str, Any]] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ir.build_timeline(events))


@router.post("/blue/ir/report")
def b_irreport(overview: str = Body(default=""),
               attack_path: List[str] = Body(default=[]),
               impact: str = Body(default=""), lessons: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_BLUE.ir.ir_report(overview, attack_path, impact, lessons))


# =========================================================================== #
# 真实紫队复盘
# =========================================================================== #
@router.post("/purple/compare")
def p_compare(red_steps: List[Dict[str, Any]] = Body(...),
              blue_alerts: List[Dict[str, Any]] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_PURPLE.compare_steps(red_steps, blue_alerts))


@router.post("/purple/metrics")
def p_metrics(comparison: Dict[str, Any] = Body(...), total_fp: int = 0):
    g = _guard()
    if g:
        return g
    return ok(_PURPLE.detection_metrics(comparison, total_fp))


@router.post("/purple/gaps")
def p_gaps(comparison: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_PURPLE.gap_analysis(comparison))


@router.post("/purple/full")
def p_full(red_steps: List[Dict[str, Any]] = Body(...),
           blue_alerts: List[Dict[str, Any]] = Body(default=[]),
           total_fp: int = 0):
    g = _guard()
    if g:
        return g
    return ok(_PURPLE.full_debrief(red_steps, blue_alerts, total_fp))


# =========================================================================== #
# 真实工具集成
# =========================================================================== #
@router.get("/tools/red/health")
def tools_red():
    g = _guard()
    if g:
        return g
    return ok(_RTOOLS.health())


@router.get("/tools/blue/health")
def tools_blue():
    g = _guard()
    if g:
        return g
    return ok(_BTOOLS.health())


@router.post("/tools/red/msf/payload")
def tools_msf(payload: str = Body(default="windows/meterpreter/reverse_tcp"),
              lhost: str = Body(default="127.0.0.1"), lport: int = 4444):
    g = _guard()
    if g:
        return g
    return ok(_RTOOLS.msf.msfvenom_payload(payload, lhost, lport))


@router.get("/tools/red/empire/login")
def tools_empire_login():
    g = _guard()
    if g:
        return g
    return ok(_RTOOLS.empire.login())


@router.get("/tools/red/empire/agents")
def tools_empire_agents():
    g = _guard()
    if g:
        return g
    return ok(_RTOOLS.empire.list_agents())


@router.get("/tools/blue/suricata/alerts")
def tools_suri_alerts(limit: int = 50):
    g = _guard()
    if g:
        return g
    return ok(_BTOOLS.suricata.alerts(limit))


@router.post("/tools/blue/es/query")
def tools_es_query(index: str = Body(default="*"), q: str = Body(default="*"),
                   size: int = 20):
    g = _guard()
    if g:
        return g
    return ok(_BTOOLS.elasticsearch.query(index, q, size))


# =========================================================================== #
# ATT&CK Navigator
# =========================================================================== #
@router.post("/navigator/attack")
def nav_attack(red_steps: List[Dict[str, Any]] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_NAV.attack_coverage(red_steps))


@router.post("/navigator/detection")
def nav_detect(detected: List[str] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_NAV.detection_coverage(detected))


@router.post("/navigator/gap")
def nav_gap(red_steps: List[Dict[str, Any]] = Body(default=[]),
            detected: List[str] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_NAV.gap_coverage(red_steps, detected))


@router.post("/navigator/layer")
def nav_layer(red_steps: List[Dict[str, Any]] = Body(default=[]),
              detected: List[str] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_NAV.navigator_layer(red_steps, detected))


# =========================================================================== #
# 真实报告
# =========================================================================== #
@router.get("/report/{task_id}")
def get_report(task_id: str, fmt: str = Query(default="html")):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if not t:
        return fail("task not found", 404)
    if fmt == "md":
        from red_blue_real.real_report_generator import RealReportData
        rd = RealReportData(task_id=t.task_id, target=t.target,
                           started_at=t.created_at, red=t.red, blue=t.blue,
                           purple=t.purple, tools=t.tools, navigator=t.navigator)
        return ok({"markdown": _REP.generate_markdown(rd), "path": t.report_path})
    return ok({"path": t.report_path, "report_dir": _REP.__module__ and ""})


# =========================================================================== #
# 仪表盘
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
    from red_blue_real.real_orchestrator import STAGES
    return ok({"stages": [{"key": k, "label": n, "progress": p}
                          for k, n, p in STAGES]})


@router.get("/dashboard/tools")
def dash_tools():
    g = _guard()
    if g:
        return g
    return ok(_DASH.tool_matrix())


# =========================================================================== #
# WebSocket
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_real(websocket: WebSocket, task_id: str):
    if not _MOD_AVAILABLE:
        await websocket.close(code=1011)
        return
    _capture_loop(asyncio.get_running_loop())
    await websocket.accept()
    _WS_CLIENTS.setdefault(task_id, []).append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if websocket in _WS_CLIENTS.get(task_id, []):
            _WS_CLIENTS[task_id].remove(websocket)
