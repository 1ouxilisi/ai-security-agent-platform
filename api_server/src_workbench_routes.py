# -*- coding: utf-8 -*-
"""
src_workbench_routes.py — SRC 挖洞工作台 REST API（34 端点）。

路由前缀: /api/v1/src-workbench
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/src-workbench",
                   tags=["SRC挖洞工作台"])

# --------------------------------------------------------------------------- #
# 模块加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from src_workbench.asset_discovery import AssetDiscovery
    from src_workbench.port_scan import PortScanner, COMMON_PORTS
    from src_workbench.vuln_scan import VulnScanner
    from src_workbench.report_generator import SRCReportGenerator
    from src_workbench.project_tracker import ProjectTracker, VALID_PLATFORMS, VALID_STATUSES
    from src_workbench.src_dashboard import SRCDashboard

    _asset = AssetDiscovery()
    _port = PortScanner()
    _vuln = VulnScanner()
    _report = SRCReportGenerator()
    _tracker = ProjectTracker()
    _dashboard = SRCDashboard()
    _MOD_AVAILABLE = True
    logger.info("src_workbench_routes: all modules loaded OK")
except Exception as e:
    logger.exception("src_workbench_routes: load failed: %s", e)
    _asset = None  # type: ignore
    _port = None   # type: ignore
    _vuln = None   # type: ignore
    _report = None # type: ignore
    _tracker = None # type: ignore
    _dashboard = None # type: ignore


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c == "\n" or c == "\t" or ord(c) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("SRC Workbench 模块未加载", 503)
    return None


# =========================================================================== #
# 1. 资产侦察（5 端点）
# =========================================================================== #
@router.post("/recon/start")
def recon_start(
    domain: str = Body(..., embed=True),
):
    """开始资产侦察：子域名发现 + 存活检测。"""
    g = _guard()
    if g:
        return g
    task = _asset.run_recon(domain)
    return ok(task)


@router.get("/recon/status/{task_id}")
def recon_status(task_id: str):
    """查询侦察任务状态。"""
    g = _guard()
    if g:
        return g
    task = _asset.get_task(task_id)
    if not task:
        return fail("Task not found", 404)
    return ok(task)


@router.get("/recon/results/{task_id}")
def recon_results(task_id: str):
    """获取侦察结果。"""
    g = _guard()
    if g:
        return g
    task = _asset.get_task(task_id)
    if not task:
        return fail("Task not found", 404)
    return ok({
        "subdomains": task.get("subdomains", []),
        "live_hosts": task.get("live_hosts", []),
        "stats": {
            "total_subdomains": len(task.get("subdomains", [])),
            "live_count": len([h for h in task.get("live_hosts", []) if h.get("is_live")]),
        },
    })


@router.get("/recon/list")
def recon_list():
    """侦察任务列表。"""
    g = _guard()
    if g:
        return g
    return ok(_asset.list_tasks())


@router.delete("/recon/{task_id}")
def recon_delete(task_id: str):
    """删除侦察任务。"""
    g = _guard()
    if g:
        return g
    deleted = _asset.delete_task(task_id)
    return ok({"deleted": deleted})


# =========================================================================== #
# 2. 端口扫描（5 端点）
# =========================================================================== #
@router.post("/portscan/run")
def portscan_run(
    hosts: List[Dict[str, Any]] = Body(..., embed=True),
    ports: Optional[List[int]] = Body(None, embed=True),
):
    """对存活主机列表执行 nmap 端口扫描。"""
    g = _guard()
    if g:
        return g
    result = _port.scan_hosts(hosts, ports)
    return ok(result)


@router.get("/portscan/status/{task_id}")
def portscan_status(task_id: str):
    g = _guard()
    if g:
        return g
    task = _port.get_task(task_id)
    if not task:
        return fail("Task not found", 404)
    return ok(task)


@router.get("/portscan/results/{task_id}")
def portscan_results(task_id: str):
    g = _guard()
    if g:
        return g
    task = _port.get_task(task_id)
    if not task:
        return fail("Task not found", 404)
    return ok({
        "results": task.get("results", []),
        "open_ports_count": task.get("open_ports_count", 0),
    })


@router.get("/portscan/list")
def portscan_list():
    g = _guard()
    if g:
        return g
    return ok(_port.list_tasks())


@router.get("/portscan/common-ports")
def portscan_common_ports():
    """返回常用 SRC 关注端口列表。"""
    g = _guard()
    if g:
        return g
    return ok({"ports": COMMON_PORTS})


# =========================================================================== #
# 3. 漏洞扫描（5 端点）
# =========================================================================== #
@router.post("/vulnscan/run")
def vulnscan_run(
    urls: List[str] = Body(..., embed=True),
    categories: Optional[List[str]] = Body(None, embed=True),
    severity: Optional[List[str]] = Body(None, embed=True),
):
    """对 URL 列表执行 nuclei 漏洞扫描。"""
    g = _guard()
    if g:
        return g
    result = _vuln.run_scan(urls, categories=categories, severity=severity)
    return ok(result)


@router.get("/vulnscan/status/{task_id}")
def vulnscan_status(task_id: str):
    g = _guard()
    if g:
        return g
    task = _vuln.get_task(task_id)
    if not task:
        return fail("Task not found", 404)
    return ok(task)


@router.get("/vulnscan/results/{task_id}")
def vulnscan_results(task_id: str):
    g = _guard()
    if g:
        return g
    task = _vuln.get_task(task_id)
    if not task:
        return fail("Task not found", 404)
    return ok({
        "findings": task.get("findings", []),
        "summary": task.get("summary", {}),
    })


@router.get("/vulnscan/list")
def vulnscan_list():
    g = _guard()
    if g:
        return g
    return ok(_vuln.list_tasks())


@router.get("/vulnscan/categories")
def vulnscan_categories():
    """返回模板分类选项。"""
    g = _guard()
    if g:
        return g
    return ok({
        "categories": [
            {"key": "cve", "label": "CVE 漏洞"},
            {"key": "exposure", "label": "暴露面板/信息泄露"},
            {"key": "vulnerability", "label": "通用漏洞"},
            {"key": "tech", "label": "技术栈识别"},
        ],
        "severities": ["critical", "high", "medium", "low", "info"],
    })


# =========================================================================== #
# 4. SRC 报告生成（7 端点）
# =========================================================================== #
@router.post("/report/generate")
def report_generate(
    finding: Dict[str, Any] = Body(..., embed=True),
    platform: str = Body("butian", embed=True),
    project_name: str = Body("", embed=True),
):
    """从单个 finding 生成 SRC 报告。"""
    g = _guard()
    if g:
        return g
    report = _report.generate_from_finding(finding, platform, project_name)
    return ok(report)


@router.post("/report/generate-batch")
def report_generate_batch(
    findings: List[Dict[str, Any]] = Body(..., embed=True),
    platform: str = Body("butian", embed=True),
    project_name: str = Body("", embed=True),
    severity_filter: Optional[List[str]] = Body(None, embed=True),
):
    """批量生成 SRC 报告。"""
    g = _guard()
    if g:
        return g
    reports = _report.generate_batch(findings, platform, project_name, severity_filter)
    return ok({"reports": reports, "count": len(reports)})


@router.get("/report/list")
def report_list(
    project_name: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    g = _guard()
    if g:
        return g
    return ok(_report.list_reports(project_name, status))


@router.get("/report/{report_id}")
def report_detail(report_id: str):
    g = _guard()
    if g:
        return g
    r = _report.get_report(report_id)
    if not r:
        return fail("Report not found", 404)
    return ok(r)


@router.get("/report/{report_id}/markdown")
def report_markdown(report_id: str):
    """获取 Markdown 格式的报告文本（可直接复制提交补天/HackerOne）。"""
    g = _guard()
    if g:
        return g
    md = _report.format_markdown(report_id)
    if not md:
        return fail("Report not found", 404)
    return ok({"markdown": md})


@router.put("/report/{report_id}/status")
def report_update_status(
    report_id: str,
    status: str = Body(..., embed=True),
    bounty: float = Body(0, embed=True),
):
    """更新报告状态：submitted/reviewing/confirmed/fixed/ignored。"""
    g = _guard()
    if g:
        return g
    r = _report.update_report_status(report_id, status, bounty)
    if not r:
        return fail("Report not found", 404)
    return ok(r)


@router.delete("/report/{report_id}")
def report_delete(report_id: str):
    g = _guard()
    if g:
        return g
    deleted = _report.delete_report(report_id)
    return ok({"deleted": deleted})


# =========================================================================== #
# 5. 项目管理（7 端点）
# =========================================================================== #
@router.get("/projects")
def project_list(
    status: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
):
    g = _guard()
    if g:
        return g
    return ok(_tracker.list_projects(status, platform))


@router.post("/projects/create")
def project_create(
    name: str = Body(..., embed=True),
    domain: str = Body(..., embed=True),
    platform: str = Body("butian", embed=True),
    description: str = Body("", embed=True),
):
    """创建 SRC 项目。"""
    g = _guard()
    if g:
        return g
    project = _tracker.create_project(name, domain, platform, description)
    return ok(project)


@router.get("/projects/{project_id}")
def project_detail(project_id: str):
    g = _guard()
    if g:
        return g
    p = _tracker.get_project(project_id)
    if not p:
        return fail("Project not found", 404)
    return ok(p)


@router.put("/projects/{project_id}/progress")
def project_update_progress(
    project_id: str,
    step: str = Body(..., embed=True),
    data: Optional[Dict[str, Any]] = Body(None, embed=True),
):
    g = _guard()
    if g:
        return g
    p = _tracker.update_progress(project_id, step, data)
    if not p:
        return fail("Project not found", 404)
    return ok(p)


@router.put("/projects/{project_id}/pause")
def project_pause(project_id: str):
    g = _guard()
    if g:
        return g
    p = _tracker.pause_project(project_id)
    if not p:
        return fail("Project not found", 404)
    return ok(p)


@router.put("/projects/{project_id}/complete")
def project_complete(project_id: str):
    g = _guard()
    if g:
        return g
    p = _tracker.complete_project(project_id)
    if not p:
        return fail("Project not found", 404)
    return ok(p)


@router.delete("/projects/{project_id}")
def project_delete(project_id: str):
    g = _guard()
    if g:
        return g
    deleted = _tracker.delete_project(project_id)
    return ok({"deleted": deleted})


# =========================================================================== #
# 6. 统计 & 流水线 & 工具状态（5 端点）
# =========================================================================== #
@router.get("/stats")
def stats():
    """全局统计：本月提交数/确认数/赏金总额。"""
    g = _guard()
    if g:
        return g
    return ok(_tracker.get_stats())


@router.post("/pipeline/run")
def pipeline_run(
    domain: str = Body(..., embed=True),
    project_name: Optional[str] = Body(None, embed=True),
    platform: str = Body("butian", embed=True),
    do_port_scan: bool = Body(True, embed=True),
    do_vuln_scan: bool = Body(True, embed=True),
    auto_report: bool = Body(True, embed=True),
):
    """一键执行完整 SRC 挖洞流水线。"""
    g = _guard()
    if g:
        return g
    result = _dashboard.run_full_pipeline(
        domain, project_name, platform,
        do_port_scan, do_vuln_scan, auto_report,
    )
    return ok(result)


@router.get("/pipeline/{pipeline_id}")
def pipeline_status(pipeline_id: str):
    g = _guard()
    if g:
        return g
    p = _dashboard.get_pipeline(pipeline_id)
    if not p:
        return fail("Pipeline not found", 404)
    return ok(p)


@router.get("/pipeline/list")
def pipeline_list():
    g = _guard()
    if g:
        return g
    return ok(_dashboard.list_pipelines())


@router.get("/tools/status")
def tools_status():
    """检查安全工具（nmap/nuclei/subfinder/httpx）是否可用。"""
    g = _guard()
    if g:
        return g
    return ok(_dashboard.tool_status())
