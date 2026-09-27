# -*- coding: utf-8 -*-
"""
real_tools_deep_routes.py — 真实工具集成深度增强 REST API（60+ 端点）。

路由前缀: /api/v1/real-tools-deep
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。

设计定位：仅用于经过授权的网络安全评估与渗透测试环境。
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

router = APIRouter(prefix="/api/v1/real-tools-deep", tags=["真实工具集成深度增强"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from real_tools_deep import nmap_deep, sqlmap_deep, metasploit_deep, other_tools, tool_orchestration
    from real_tools_deep.real_tools_dashboard import RealToolsDashboard, get_dashboard
    _MOD_AVAILABLE = True
    logger.info("real_tools_deep_routes: all modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("real_tools_deep_routes: load failed: %s", e)
    nmap_deep = None  # type: ignore
    sqlmap_deep = None  # type: ignore
    metasploit_deep = None  # type: ignore
    other_tools = None  # type: ignore
    tool_orchestration = None  # type: ignore
    RealToolsDashboard = None  # type: ignore
    get_dashboard = None  # type: ignore


# --------------------------------------------------------------------------- #
# 任务存储（内存字典）
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}
_DASHBOARD = get_dashboard() if get_dashboard else None


def _new_task(kind: str) -> str:
    tid = uuid.uuid4().hex[:16]
    _TASKS[tid] = {
        "task_id": tid, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return tid


def _finish_task(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in _TASKS:
        t = _TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        obj = obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
        return "".join(ch for ch in obj if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("真实工具集成模块未加载，请检查导入日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class NmapScanRequest(BaseModel):
    targets: List[str] = Field(default_factory=lambda: ["127.0.0.1"])
    scan_type: str = "syn"
    ports: str = "1-1000"
    timing: int = 3
    version_detection: bool = True
    os_detection: bool = False
    scripts: str = ""


class NmapCommandRequest(BaseModel):
    target: str = "127.0.0.1"
    scan_type: str = "syn"
    ports: str = "1-1000"
    timing: int = 3
    version_detection: bool = True
    os_detection: bool = False
    script: str = ""
    output_format: str = "xml"
    host_discovery: str = ""
    traceroute: bool = False
    top_ports: int = 0
    timeout: int = 0
    max_retries: int = 0
    max_rate: int = 0
    fragmentation: bool = False


class NmapReportRequest(BaseModel):
    scan_result: Dict[str, Any] = Field(default_factory=dict)
    report_name: str = ""
    export_format: str = "json"


class NmapScriptAddRequest(BaseModel):
    name: str = ""
    description: str = ""
    categories: List[str] = Field(default_factory=list)
    path: str = ""


class NmapConfigRequest(BaseModel):
    key: str = ""
    value: Any = None


class DeepSQLMapScanRequest(BaseModel):
    target_url: str = ""
    post_data: str = ""
    param: str = ""
    dbms: str = ""
    technique: str = "BEUSTQ"
    level: int = 1
    risk: int = 1
    threads: int = 1
    enumerate_dbs: bool = False


class SQLMapCommandRequest(BaseModel):
    target_url: str = ""
    action: str = "scan"
    db_name: str = ""
    table_name: str = ""
    start: int = 0
    limit: int = 10
    file_path: str = ""
    technique: str = "BEUSTQ"
    level: int = 1
    risk: int = 1


class SQLMapReportRequest(BaseModel):
    scan_result: Dict[str, Any] = Field(default_factory=dict)
    report_name: str = ""
    export_format: str = "json"


class SQLMapConfigRequest(BaseModel):
    key: str = ""
    value: Any = None


class DeepMsfExploitRequest(BaseModel):
    module_path: str = "exploit/unix/ftp/vsftpd_234_backdoor"
    rhosts: str = "127.0.0.1"
    payload: str = "meterpreter/reverse_tcp"
    lhost: str = "0.0.0.0"
    lport: int = 4444
    rport: int = 21


class MsfAuxiliaryRequest(BaseModel):
    module_path: str = "auxiliary/scanner/portscan/tcp"
    rhosts: str = "127.0.0.1"
    rport: int = 80


class MsfPostActionRequest(BaseModel):
    post_module: str = "post/multi/gather/env"


class MsfMigrateRequest(BaseModel):
    pid: int = 0


class MsfReportRequest(BaseModel):
    exploit_result: Dict[str, Any] = Field(default_factory=dict)
    export_format: str = "json"


class MsfConfigRequest(BaseModel):
    key: str = ""
    value: Any = None


class NiktoScanRequest(BaseModel):
    target: str = "127.0.0.1"
    port: int = 80
    ssl: bool = False
    timeout: int = 60


class HydraCrackRequest(BaseModel):
    target: str = "127.0.0.1"
    service: str = "ssh"
    username: str = ""
    userlist: str = ""
    passlist: str = ""
    port: int = 0
    threads: int = 4


class JohnCrackRequest(BaseModel):
    hash_file: str = "hashes.txt"
    hash_format: str = "raw-md5"
    wordlist: str = ""
    rules: bool = False
    incremental: bool = False


class NucleiScanRequest(BaseModel):
    target: str = "http://127.0.0.1"
    templates: str = ""
    severity: str = ""
    tags: str = ""
    rate_limit: int = 150


class BatchRequest(BaseModel):
    tool: str = "nikto"
    targets: List[str] = Field(default_factory=list)


class ScheduleRequest(BaseModel):
    tool: str = "nuclei"
    target: str = "127.0.0.1"
    cron: str = "0 2 * * *"


class WorkflowCreateRequest(BaseModel):
    name: str = ""
    template: str = "recon_workflow"
    target: str = "127.0.0.1"


class WorkflowReportRequest(BaseModel):
    instance_id: str = ""


# ===================================================================== #
# 1. 仪表盘 / 工具总览
# ===================================================================== #

@router.get("/dashboard/overview")
def api_dashboard_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(_DASHBOARD.get_overview())
    except Exception as e:
        logger.exception("dashboard overview error")
        return fail(str(e), 500)


@router.get("/dashboard/nmap-summary")
def api_dashboard_nmap_summary():
    try:
        g = _guard()
        if g:
            return g
        return ok(_DASHBOARD.get_nmap_summary())
    except Exception as e:
        logger.exception("dashboard nmap summary error")
        return fail(str(e), 500)


@router.get("/dashboard/sqlmap-summary")
def api_dashboard_sqlmap_summary():
    try:
        g = _guard()
        if g:
            return g
        return ok(_DASHBOARD.get_sqlmap_summary())
    except Exception as e:
        logger.exception("dashboard sqlmap summary error")
        return fail(str(e), 500)


@router.get("/dashboard/msf-summary")
def api_dashboard_msf_summary():
    try:
        g = _guard()
        if g:
            return g
        return ok(_DASHBOARD.get_metasploit_summary())
    except Exception as e:
        logger.exception("dashboard msf summary error")
        return fail(str(e), 500)


@router.get("/dashboard/other-summary")
def api_dashboard_other_summary():
    try:
        g = _guard()
        if g:
            return g
        return ok(_DASHBOARD.get_other_tools_summary())
    except Exception as e:
        logger.exception("dashboard other summary error")
        return fail(str(e), 500)


@router.get("/dashboard/workflow-summary")
def api_dashboard_workflow_summary():
    try:
        g = _guard()
        if g:
            return g
        return ok(_DASHBOARD.get_workflow_summary())
    except Exception as e:
        logger.exception("dashboard workflow summary error")
        return fail(str(e), 500)


@router.get("/dashboard/vulnerabilities")
def api_dashboard_vulnerabilities():
    try:
        g = _guard()
        if g:
            return g
        return ok(_DASHBOARD.get_vulnerability_list())
    except Exception as e:
        logger.exception("dashboard vulnerabilities error")
        return fail(str(e), 500)


@router.get("/dashboard/assets")
def api_dashboard_assets():
    try:
        g = _guard()
        if g:
            return g
        return ok(_DASHBOARD.get_asset_list())
    except Exception as e:
        logger.exception("dashboard assets error")
        return fail(str(e), 500)


@router.get("/dashboard/tasks")
def api_dashboard_tasks():
    try:
        return ok(list(_TASKS.values()))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/dashboard/tasks/{task_id}")
def api_dashboard_task_detail(task_id: str):
    try:
        if task_id not in _TASKS:
            return fail("任务不存在", 404)
        return ok(_TASKS[task_id])
    except Exception as e:
        return fail(str(e), 500)


# ===================================================================== #
# 2. Nmap 模块（12 端点）
# ===================================================================== #

@router.get("/nmap/status")
def api_nmap_status():
    try:
        g = _guard()
        if g:
            return g
        scanner = nmap_deep.get_scanner()
        return ok({
            "version": scanner.version,
            "available": scanner.available,
            "last_scan": scanner.last_scan_result,
            "scan_types": nmap_deep.SCAN_TYPES,
            "output_formats": nmap_deep.OUTPUT_FORMATS,
        })
    except Exception as e:
        logger.exception("nmap status error")
        return fail(str(e), 500)


@router.post("/nmap/scan")
def api_nmap_scan(req: NmapScanRequest):
    try:
        g = _guard()
        if g:
            return g
        scanner = nmap_deep.get_scanner()
        result = scanner.scan(
            targets=req.targets, scan_type=req.scan_type,
            ports=req.ports, timing=req.timing,
            version_detection=req.version_detection,
            os_detection=req.os_detection,
            scripts=req.scripts,
        )
        _DASHBOARD.record_scan("nmap", ",".join(req.targets), result)
        tid = _new_task("nmap_scan")
        _finish_task(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:
        logger.exception("nmap scan error")
        return fail(str(e), 500)


@router.post("/nmap/build-command")
def api_nmap_build_command(req: NmapCommandRequest):
    try:
        g = _guard()
        if g:
            return g
        builder = nmap_deep.NmapCommandBuilder()
        builder.add_target(req.target).set_scan_type(req.scan_type)
        builder.set_port_range(req.ports).set_timing_template(req.timing)
        if req.version_detection:
            builder.set_version_detection()
        if req.os_detection:
            builder.set_os_detection()
        if req.script:
            builder.set_script(req.script)
        if req.host_discovery:
            builder.set_host_discovery(req.host_discovery)
        if req.traceroute:
            builder.set_traceroute()
        if req.top_ports > 0:
            builder.set_top_ports(req.top_ports)
        if req.timeout > 0:
            builder.set_timeout(req.timeout)
        if req.max_retries > 0:
            builder.set_max_retries(req.max_retries)
        if req.max_rate > 0:
            builder.set_rate_control(req.max_rate)
        if req.fragmentation:
            builder.set_fragmentation()
        builder.set_output_format(req.output_format)
        command = builder.build()
        return ok({"command": command, "args": builder.args, "targets": builder.targets})
    except Exception as e:
        logger.exception("nmap build command error")
        return fail(str(e), 500)


@router.post("/nmap/parse-xml")
def api_nmap_parse_xml(xml_content: str = Query("", description="Nmap XML输出内容")):
    try:
        g = _guard()
        if g:
            return g
        parsed = nmap_deep.NmapXMLParser.parse(xml_content)
        return ok(parsed)
    except Exception as e:
        logger.exception("nmap parse xml error")
        return fail(str(e), 500)


@router.get("/nmap/last-result")
def api_nmap_last_result():
    try:
        g = _guard()
        if g:
            return g
        scanner = nmap_deep.get_scanner()
        return ok(scanner.last_scan_result)
    except Exception as e:
        logger.exception("nmap last result error")
        return fail(str(e), 500)


@router.post("/nmap/generate-report")
def api_nmap_generate_report(req: NmapReportRequest):
    try:
        g = _guard()
        if g:
            return g
        gen = nmap_deep.get_report_generator()
        report = gen.generate(req.scan_result, req.report_name)
        return ok(report)
    except Exception as e:
        logger.exception("nmap generate report error")
        return fail(str(e), 500)


@router.post("/nmap/export-report")
def api_nmap_export_report(req: NmapReportRequest):
    try:
        g = _guard()
        if g:
            return g
        gen = nmap_deep.get_report_generator()
        report = gen.generate(req.scan_result, req.report_name)
        exported = gen.export_report(report, req.export_format)
        return ok({"format": req.export_format, "content": exported[:5000]})
    except Exception as e:
        logger.exception("nmap export report error")
        return fail(str(e), 500)


@router.get("/nmap/scripts/list")
def api_nmap_scripts_list(category: str = Query("")):
    try:
        g = _guard()
        if g:
            return g
        mgr = nmap_deep.get_nse_manager()
        scripts = mgr.list_scripts(category)
        return ok({"scripts": scripts, "count": len(scripts)})
    except Exception as e:
        logger.exception("nmap scripts list error")
        return fail(str(e), 500)


@router.get("/nmap/scripts/search")
def api_nmap_scripts_search(keyword: str = Query("")):
    try:
        g = _guard()
        if g:
            return g
        mgr = nmap_deep.get_nse_manager()
        results = mgr.search_scripts(keyword)
        return ok({"results": results, "count": len(results)})
    except Exception as e:
        logger.exception("nmap scripts search error")
        return fail(str(e), 500)


@router.post("/nmap/scripts/add-custom")
def api_nmap_scripts_add_custom(req: NmapScriptAddRequest):
    try:
        g = _guard()
        if g:
            return g
        mgr = nmap_deep.get_nse_manager()
        script = mgr.add_custom_script(req.name, req.description, req.categories, req.path)
        return ok(script)
    except Exception as e:
        logger.exception("nmap add custom script error")
        return fail(str(e), 500)


@router.get("/nmap/scripts/categories")
def api_nmap_scripts_categories():
    try:
        g = _guard()
        if g:
            return g
        return ok({"categories": nmap_deep.NSE_CATEGORIES})
    except Exception as e:
        return fail(str(e), 500)


@router.put("/nmap/config")
def api_nmap_config(req: NmapConfigRequest):
    try:
        g = _guard()
        if g:
            return g
        mgr = nmap_deep.get_tool_manager()
        result = mgr.update_config(req.key, req.value)
        return ok(result)
    except Exception as e:
        logger.exception("nmap config error")
        return fail(str(e), 500)


# ===================================================================== #
# 3. SQLMap 模块（10 端点）
# ===================================================================== #

@router.get("/sqlmap/status")
def api_sqlmap_status():
    try:
        g = _guard()
        if g:
            return g
        scanner = sqlmap_deep.get_scanner()
        return ok({
            "version": scanner.version,
            "available": scanner.available,
            "last_result": scanner.last_result,
            "techniques": sqlmap_deep.INJECTION_TECHNIQUES,
            "dbms_types": sqlmap_deep.DBMS_TYPES,
        })
    except Exception as e:
        logger.exception("sqlmap status error")
        return fail(str(e), 500)


@router.post("/sqlmap/scan")
def api_sqlmap_scan(req: DeepSQLMapScanRequest):
    try:
        g = _guard()
        if g:
            return g
        scanner = sqlmap_deep.get_scanner()
        result = scanner.scan(
            target_url=req.target_url, post_data=req.post_data,
            param=req.param, dbms=req.dbms, technique=req.technique,
            level=req.level, risk=req.risk, threads=req.threads,
            enumerate_dbs=req.enumerate_dbs,
        )
        _DASHBOARD.record_scan("sqlmap", req.target_url, result)
        tid = _new_task("sqlmap_scan")
        _finish_task(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:
        logger.exception("sqlmap scan error")
        return fail(str(e), 500)


@router.post("/sqlmap/build-command")
def api_sqlmap_build_command(req: SQLMapCommandRequest):
    try:
        g = _guard()
        if g:
            return g
        builder = sqlmap_deep.SQLMapCommandBuilder()
        builder.set_target_url(req.target_url)
        builder.set_technique(req.technique)
        builder.set_level(req.level).set_risk(req.risk).set_batch()
        if req.action == "enumerate_dbs":
            builder.enumerate_databases()
        elif req.action == "enumerate_tables":
            builder.enumerate_tables(req.db_name)
        elif req.action == "dump_table":
            builder.dump_table(req.table_name, req.db_name, req.start, req.limit)
        elif req.action == "enumerate_users":
            builder.enumerate_users()
        elif req.action == "enumerate_passwords":
            builder.enumerate_passwords()
        elif req.action == "get_shell":
            builder.get_shell()
        elif req.action == "sql_shell":
            builder.get_sql_shell()
        elif req.action == "read_file":
            builder.read_file(req.file_path)
        command = builder.build()
        return ok({"command": command})
    except Exception as e:
        logger.exception("sqlmap build command error")
        return fail(str(e), 500)


@router.post("/sqlmap/enumerate-dbs")
def api_sqlmap_enumerate_dbs(req: SQLMapCommandRequest):
    try:
        g = _guard()
        if g:
            return g
        scanner = sqlmap_deep.get_scanner()
        result = scanner.scan(req.target_url, technique=req.technique,
                               level=req.level, risk=req.risk, enumerate_dbs=True)
        return ok(result)
    except Exception as e:
        logger.exception("sqlmap enumerate dbs error")
        return fail(str(e), 500)


@router.post("/sqlmap/dump-table")
def api_sqlmap_dump_table(req: SQLMapCommandRequest):
    try:
        g = _guard()
        if g:
            return g
        scanner = sqlmap_deep.get_scanner()
        # 模拟 dump
        mock = scanner.scan(req.target_url, technique=req.technique,
                            level=req.level, risk=req.risk)
        return ok({"target": req.target_url, "db": req.db_name,
                   "table": req.table_name, "dumped": mock.get("parsed", {}).get("data_sample", [])})
    except Exception as e:
        logger.exception("sqlmap dump table error")
        return fail(str(e), 500)


@router.post("/sqlmap/get-shell")
def api_sqlmap_get_shell(req: SQLMapCommandRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok({"target": req.target_url, "shell_obtained": False,
                   "message": "Shell获取需要数据库写入权限，当前为模拟模式"})
    except Exception as e:
        logger.exception("sqlmap get shell error")
        return fail(str(e), 500)


@router.post("/sqlmap/read-file")
def api_sqlmap_read_file(req: SQLMapCommandRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok({"target": req.target_url, "file": req.file_path,
                   "content": "模拟文件读取内容（/etc/passwd 或 Windows 等效文件）"})
    except Exception as e:
        logger.exception("sqlmap read file error")
        return fail(str(e), 500)


@router.post("/sqlmap/generate-report")
def api_sqlmap_generate_report(req: SQLMapReportRequest):
    try:
        g = _guard()
        if g:
            return g
        gen = sqlmap_deep.get_report_generator()
        report = gen.generate(req.scan_result, req.report_name)
        return ok(report)
    except Exception as e:
        logger.exception("sqlmap generate report error")
        return fail(str(e), 500)


@router.post("/sqlmap/export-report")
def api_sqlmap_export_report(req: SQLMapReportRequest):
    try:
        g = _guard()
        if g:
            return g
        gen = sqlmap_deep.get_report_generator()
        report = gen.generate(req.scan_result, req.report_name)
        exported = gen.export_report(report, req.export_format)
        return ok({"format": req.export_format, "content": exported[:5000]})
    except Exception as e:
        logger.exception("sqlmap export report error")
        return fail(str(e), 500)


@router.put("/sqlmap/config")
def api_sqlmap_config(req: SQLMapConfigRequest):
    try:
        g = _guard()
        if g:
            return g
        mgr = sqlmap_deep.get_tool_manager()
        result = mgr.update_config(req.key, req.value)
        return ok(result)
    except Exception as e:
        logger.exception("sqlmap config error")
        return fail(str(e), 500)


# ===================================================================== #
# 4. Metasploit 模块（12 端点）
# ===================================================================== #

@router.get("/msf/status")
def api_msf_status():
    try:
        g = _guard()
        if g:
            return g
        client = metasploit_deep.get_client()
        return ok({
            "version": client.version,
            "connected": client.connected,
            "module_categories": metasploit_deep.MODULE_CATEGORIES,
            "payload_types": metasploit_deep.PAYLOAD_TYPES,
            "active_sessions": len(client.list_sessions()),
        })
    except Exception as e:
        logger.exception("msf status error")
        return fail(str(e), 500)


@router.post("/msf/connect")
def api_msf_connect():
    try:
        g = _guard()
        if g:
            return g
        client = metasploit_deep.get_client()
        result = client.connect()
        return ok(result)
    except Exception as e:
        logger.exception("msf connect error")
        return fail(str(e), 500)


@router.get("/msf/modules/search")
def api_msf_modules_search(category: str = Query("exploits"), keyword: str = Query("")):
    try:
        g = _guard()
        if g:
            return g
        client = metasploit_deep.get_client()
        results = client.module_search(category, keyword)
        return ok({"category": category, "results": results, "count": len(results)})
    except Exception as e:
        logger.exception("msf modules search error")
        return fail(str(e), 500)


@router.get("/msf/modules/details")
def api_msf_modules_details(module_path: str = Query("")):
    try:
        g = _guard()
        if g:
            return g
        client = metasploit_deep.get_client()
        details = client.module_details(module_path)
        return ok(details)
    except Exception as e:
        logger.exception("msf modules details error")
        return fail(str(e), 500)


@router.post("/msf/exploit")
def api_msf_exploit(req: DeepMsfExploitRequest):
    try:
        g = _guard()
        if g:
            return g
        client = metasploit_deep.get_client()
        options = {"RHOSTS": req.rhosts, "RPORT": req.rport,
                   "LHOST": req.lhost, "LPORT": req.lport}
        result = client.execute_exploit(req.module_path, options, req.payload)
        tid = _new_task("msf_exploit")
        _finish_task(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:
        logger.exception("msf exploit error")
        return fail(str(e), 500)


@router.post("/msf/auxiliary")
def api_msf_auxiliary(req: MsfAuxiliaryRequest):
    try:
        g = _guard()
        if g:
            return g
        client = metasploit_deep.get_client()
        options = {"RHOSTS": req.rhosts, "RPORT": req.rport}
        result = client.execute_auxiliary(req.module_path, options)
        return ok(result)
    except Exception as e:
        logger.exception("msf auxiliary error")
        return fail(str(e), 500)


@router.get("/msf/sessions")
def api_msf_sessions():
    try:
        g = _guard()
        if g:
            return g
        client = metasploit_deep.get_client()
        sessions = client.list_sessions()
        return ok({"sessions": sessions, "count": len(sessions)})
    except Exception as e:
        logger.exception("msf sessions list error")
        return fail(str(e), 500)


@router.get("/msf/sessions/{sid}")
def api_msf_session_detail(sid: int):
    try:
        g = _guard()
        if g:
            return g
        client = metasploit_deep.get_client()
        info = client.session_info(sid)
        if info is None:
            return fail("会话不存在", 404)
        return ok(info)
    except Exception as e:
        logger.exception("msf session detail error")
        return fail(str(e), 500)


@router.post("/msf/sessions/{sid}/post")
def api_msf_session_post(sid: int, req: MsfPostActionRequest):
    try:
        g = _guard()
        if g:
            return g
        client = metasploit_deep.get_client()
        result = client.session_run_post(sid, req.post_module)
        return ok(result)
    except Exception as e:
        logger.exception("msf session post error")
        return fail(str(e), 500)


@router.post("/msf/sessions/{sid}/migrate")
def api_msf_session_migrate(sid: int, req: MsfMigrateRequest):
    try:
        g = _guard()
        if g:
            return g
        client = metasploit_deep.get_client()
        result = client.session_migrate(sid, req.pid)
        return ok(result)
    except Exception as e:
        logger.exception("msf session migrate error")
        return fail(str(e), 500)


@router.delete("/msf/sessions/{sid}")
def api_msf_session_kill(sid: int):
    try:
        g = _guard()
        if g:
            return g
        client = metasploit_deep.get_client()
        result = client.session_kill(sid)
        return ok(result)
    except Exception as e:
        logger.exception("msf session kill error")
        return fail(str(e), 500)


@router.post("/msf/generate-report")
def api_msf_generate_report(req: MsfReportRequest):
    try:
        g = _guard()
        if g:
            return g
        gen = metasploit_deep.get_report_generator()
        client = metasploit_deep.get_client()
        report = gen.generate(
            req.exploit_result,
            sessions=client.list_sessions(),
            post_actions=[],
        )
        return ok(report)
    except Exception as e:
        logger.exception("msf generate report error")
        return fail(str(e), 500)


# ===================================================================== #
# 5. 其他工具（Nikto/Hydra/John/nuclei）（10 端点）
# ===================================================================== #

@router.get("/other/versions")
def api_other_versions():
    try:
        g = _guard()
        if g:
            return g
        mgr = other_tools.get_manager()
        return ok(mgr.get_all_versions())
    except Exception as e:
        logger.exception("other versions error")
        return fail(str(e), 500)


@router.post("/other/nikto/scan")
def api_other_nikto_scan(req: NiktoScanRequest):
    try:
        g = _guard()
        if g:
            return g
        mgr = other_tools.get_manager()
        result = mgr.nikto.scan(req.target, req.port, req.ssl, req.timeout)
        tid = _new_task("nikto_scan")
        _finish_task(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:
        logger.exception("nikto scan error")
        return fail(str(e), 500)


@router.post("/other/hydra/crack")
def api_other_hydra_crack(req: HydraCrackRequest):
    try:
        g = _guard()
        if g:
            return g
        mgr = other_tools.get_manager()
        result = mgr.hydra.crack(
            req.target, req.service, req.username,
            req.userlist, req.passlist, req.port, req.threads,
        )
        tid = _new_task("hydra_crack")
        _finish_task(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:
        logger.exception("hydra crack error")
        return fail(str(e), 500)


@router.post("/other/john/crack")
def api_other_john_crack(req: JohnCrackRequest):
    try:
        g = _guard()
        if g:
            return g
        mgr = other_tools.get_manager()
        result = mgr.john.crack(
            req.hash_file, req.hash_format, req.wordlist,
            req.rules, req.incremental,
        )
        tid = _new_task("john_crack")
        _finish_task(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:
        logger.exception("john crack error")
        return fail(str(e), 500)


@router.post("/other/nuclei/scan")
def api_other_nuclei_scan(req: NucleiScanRequest):
    try:
        g = _guard()
        if g:
            return g
        mgr = other_tools.get_manager()
        result = mgr.nuclei.scan(
            req.target, req.templates, req.severity, req.tags, req.rate_limit,
        )
        tid = _new_task("nuclei_scan")
        _finish_task(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:
        logger.exception("nuclei scan error")
        return fail(str(e), 500)


@router.post("/other/nuclei/update-templates")
def api_other_nuclei_update():
    try:
        g = _guard()
        if g:
            return g
        mgr = other_tools.get_manager()
        result = mgr.nuclei.update_templates()
        return ok(result)
    except Exception as e:
        logger.exception("nuclei update templates error")
        return fail(str(e), 500)


@router.get("/other/nuclei/templates")
def api_other_nuclei_templates(category: str = Query("")):
    try:
        g = _guard()
        if g:
            return g
        mgr = other_tools.get_manager()
        templates = mgr.nuclei.list_templates(category)
        return ok({"templates": templates, "count": len(templates)})
    except Exception as e:
        logger.exception("nuclei templates error")
        return fail(str(e), 500)


@router.post("/other/batch")
def api_other_batch(req: BatchRequest):
    try:
        g = _guard()
        if g:
            return g
        mgr = other_tools.get_manager()
        result = mgr.run_batch(req.tool, req.targets)
        return ok(result)
    except Exception as e:
        logger.exception("other batch error")
        return fail(str(e), 500)


@router.post("/other/schedule")
def api_other_schedule(req: ScheduleRequest):
    try:
        g = _guard()
        if g:
            return g
        mgr = other_tools.get_manager()
        result = mgr.schedule_job(req.tool, req.target, req.cron)
        return ok(result)
    except Exception as e:
        logger.exception("other schedule error")
        return fail(str(e), 500)


@router.get("/other/batch-jobs")
def api_other_batch_jobs():
    try:
        g = _guard()
        if g:
            return g
        mgr = other_tools.get_manager()
        return ok({"batch_jobs": mgr.batch_jobs, "scheduled_jobs": mgr.scheduled_jobs})
    except Exception as e:
        logger.exception("other batch jobs error")
        return fail(str(e), 500)


# ===================================================================== #
# 6. 工具编排 / 工作流（10 端点）
# ===================================================================== #

@router.get("/workflow/templates")
def api_workflow_templates():
    try:
        g = _guard()
        if g:
            return g
        return ok(tool_orchestration.WORKFLOW_TEMPLATES)
    except Exception as e:
        logger.exception("workflow templates error")
        return fail(str(e), 500)


@router.post("/workflow/create")
def api_workflow_create(req: WorkflowCreateRequest):
    try:
        g = _guard()
        if g:
            return g
        engine = tool_orchestration.get_engine()
        inst = engine.create_instance(req.name, req.template, req.target)
        return ok(inst.to_dict())
    except Exception as e:
        logger.exception("workflow create error")
        return fail(str(e), 500)


@router.post("/workflow/execute/{instance_id}")
def api_workflow_execute(instance_id: str):
    try:
        g = _guard()
        if g:
            return g
        engine = tool_orchestration.get_engine()
        result = engine.execute_instance(instance_id)
        return ok(result)
    except Exception as e:
        logger.exception("workflow execute error")
        return fail(str(e), 500)


@router.get("/workflow/instances")
def api_workflow_instances(status: str = Query("")):
    try:
        g = _guard()
        if g:
            return g
        engine = tool_orchestration.get_engine()
        instances = engine.list_instances(status)
        return ok({"instances": instances, "count": len(instances)})
    except Exception as e:
        logger.exception("workflow instances error")
        return fail(str(e), 500)


@router.get("/workflow/instances/{instance_id}")
def api_workflow_instance_detail(instance_id: str):
    try:
        g = _guard()
        if g:
            return g
        engine = tool_orchestration.get_engine()
        inst = engine.get_instance(instance_id)
        if inst is None:
            return fail("工作流实例不存在", 404)
        return ok(inst.to_dict())
    except Exception as e:
        logger.exception("workflow instance detail error")
        return fail(str(e), 500)


@router.post("/workflow/instances/{instance_id}/pause")
def api_workflow_pause(instance_id: str):
    try:
        g = _guard()
        if g:
            return g
        engine = tool_orchestration.get_engine()
        result = engine.pause_instance(instance_id)
        return ok(result)
    except Exception as e:
        logger.exception("workflow pause error")
        return fail(str(e), 500)


@router.post("/workflow/instances/{instance_id}/resume")
def api_workflow_resume(instance_id: str):
    try:
        g = _guard()
        if g:
            return g
        engine = tool_orchestration.get_engine()
        result = engine.resume_instance(instance_id)
        return ok(result)
    except Exception as e:
        logger.exception("workflow resume error")
        return fail(str(e), 500)


@router.delete("/workflow/instances/{instance_id}")
def api_workflow_cancel(instance_id: str):
    try:
        g = _guard()
        if g:
            return g
        engine = tool_orchestration.get_engine()
        result = engine.cancel_instance(instance_id)
        return ok(result)
    except Exception as e:
        logger.exception("workflow cancel error")
        return fail(str(e), 500)


@router.get("/workflow/monitor")
def api_workflow_monitor():
    try:
        g = _guard()
        if g:
            return g
        monitor = tool_orchestration.get_monitor()
        return ok(monitor.get_dashboard())
    except Exception as e:
        logger.exception("workflow monitor error")
        return fail(str(e), 500)


@router.get("/workflow/report/{instance_id}")
def api_workflow_report(instance_id: str):
    try:
        g = _guard()
        if g:
            return g
        monitor = tool_orchestration.get_monitor()
        report = monitor.generate_report(instance_id)
        return ok(report)
    except Exception as e:
        logger.exception("workflow report error")
        return fail(str(e), 500)


@router.get("/workflow/optimizations")
def api_workflow_optimizations():
    try:
        g = _guard()
        if g:
            return g
        optimizer = tool_orchestration.get_optimizer()
        engine = tool_orchestration.get_engine()
        return ok({
            "recommendations": optimizer.recommend_optimizations(engine),
            "best_practices": optimizer.get_best_practices(),
        })
    except Exception as e:
        logger.exception("workflow optimizations error")
        return fail(str(e), 500)
