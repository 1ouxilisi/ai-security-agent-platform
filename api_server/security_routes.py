# -*- coding: utf-8 -*-
""""""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/security", tags=["楂樼骇瀹夊叏"])

# 寤惰繜瀵煎叆鐨勬ā鍧楀疄渚嬶紙鍦ㄩ娆′娇鐢ㄦ椂鍒濆鍖栵級
_lifecycle = None
_discovery = None
_auditor = None
_analyzer = None


def _lc():
    global _lifecycle
    if _lifecycle is None:
        from security.vuln_lifecycle import get_lifecycle
        _lifecycle = get_lifecycle()
    return _lifecycle


def _ad():
    global _discovery
    if _discovery is None:
        from security.asset_discovery import get_discovery
        _discovery = get_discovery()
    return _discovery


def _ca():
    global _auditor
    if _auditor is None:
        from security.compliance_audit import get_auditor
        _auditor = get_auditor()
    return _auditor


def _ap():
    global _analyzer
    if _analyzer is None:
        from security.attack_path import get_analyzer
        _analyzer = get_analyzer()
    return _analyzer


def _ok(data: Any) -> Dict[str, Any]:
    return {"success": True, "data": data}


def _err(msg: str) -> Dict[str, Any]:
    return {"success": False, "error": str(msg)}


# ---------------------------------------------------------------------- #
# 璇锋眰妯″瀷
# ---------------------------------------------------------------------- #
class TransitionReq(BaseModel):
    to_status: str
    changed_by: str = "system"
    note: str = ""


class AssignReq(BaseModel):
    assignee: str
    note: str = ""


class VerifyReq(BaseModel):
    result: bool
    verified_by: str = "system"


class ScanReq(BaseModel):
    cidr: str = Field(..., description="鐩爣 CIDR 鎴?IP")
    scan_type: str = Field("port", description="ping/port/full")


class VulnCreateReq(BaseModel):
    title: str
    severity: str = "medium"
    target: str = ""
    description: str = ""
    cve: str = ""


class AuditReq(BaseModel):
    framework: str = "mlps2"
    target_data: Optional[Dict[str, Any]] = None


class AttackGraphReq(BaseModel):
    assets: List[Dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------- #
# 婕忔礊鐢熷懡鍛ㄦ湡
# ---------------------------------------------------------------------- #
@router.get("/vuln-lifecycle/list")
def vuln_list(status: Optional[str] = Query(None)):
    try:
        return _ok(_lc().list_vulnerabilities(status))
    except Exception as e:
        return _err(e)


@router.post("/vuln-lifecycle")
def vuln_create(req: VulnCreateReq):
    try:
        return _ok(_lc().create_vulnerability(req.title, req.severity,
                                             req.target, req.description, req.cve))
    except Exception as e:
        return _err(e)


@router.post("/vuln-lifecycle/{vuln_id}/transition")
def vuln_transition(vuln_id: str, req: TransitionReq):
    try:
        return _ok(_lc().transition(vuln_id, req.to_status, req.changed_by, req.note))
    except Exception as e:
        return _err(e)


@router.post("/vuln-lifecycle/{vuln_id}/assign")
def vuln_assign(vuln_id: str, req: AssignReq):
    try:
        return _ok(_lc().assign(vuln_id, req.assignee, req.note))
    except Exception as e:
        return _err(e)


@router.post("/vuln-lifecycle/{vuln_id}/verify")
def vuln_verify(vuln_id: str, req: VerifyReq):
    try:
        return _ok(_lc().verify(vuln_id, req.result, req.verified_by))
    except Exception as e:
        return _err(e)


@router.get("/vuln-lifecycle/{vuln_id}/history")
def vuln_history(vuln_id: str):
    try:
        return _ok(_lc().get_history(vuln_id))
    except Exception as e:
        return _err(e)


@router.get("/vuln-lifecycle/overdue")
def vuln_overdue():
    try:
        return _ok(_lc().check_overdue())
    except Exception as e:
        return _err(e)


@router.get("/vuln-lifecycle/stats")
def vuln_stats():
    try:
        return _ok(_lc().get_stats())
    except Exception as e:
        return _err(e)


# ---------------------------------------------------------------------- #
# 璧勪骇鍙戠幇
# ---------------------------------------------------------------------- #
@router.post("/asset-discovery/scan")
def asset_scan(req: ScanReq):
    try:
        ad = _ad()
        if req.scan_type == "ping":
            return _ok({"alive": ad.ip_scan(req.cidr)})
        if req.scan_type == "port":
            ports = ad.port_scan(req.cidr)
            return _ok({"ip": req.cidr, "open_ports": ports})
        alive = ad.ip_scan(req.cidr)
        results = [{"ip": ip, "open_ports": ad.port_scan(ip)} for ip in alive[:8]]
        return _ok({"alive": alive, "details": results})
    except Exception as e:
        return _err(e)


@router.get("/asset-discovery/assets")
def asset_list():
    try:
        return _ok(_ad().list_assets())
    except Exception as e:
        return _err(e)


@router.get("/asset-discovery/{asset_id}")
def asset_get(asset_id: str):
    try:
        a = _ad().get_asset(asset_id)
        return _ok(a) if a else _err("资产不存在")
    except Exception as e:
        return _err(e)


@router.post("/asset-discovery/{asset_id}/detect-changes")
def asset_detect_changes(asset_id: str):
    try:
        return _ok(_ad().detect_changes(asset_id))
    except Exception as e:
        return _err(e)


@router.get("/asset-discovery/{asset_id}/risk")
def asset_risk(asset_id: str):
    try:
        return _ok(_ad().calculate_risk(asset_id))
    except Exception as e:
        return _err(e)


# ---------------------------------------------------------------------- #
# 鍚堣瀹¤
# ---------------------------------------------------------------------- #
@router.post("/compliance/audit")
def compliance_audit(req: AuditReq):
    try:
        return _ok(_ca().run_audit(req.framework, req.target_data))
    except Exception as e:
        return _err(e)


@router.get("/compliance/audits")
def compliance_list(framework: Optional[str] = Query(None)):
    try:
        return _ok(_ca().list_audits(framework))
    except Exception as e:
        return _err(e)


@router.get("/compliance/{audit_id}/report")
def compliance_report(audit_id: str):
    try:
        a = _ca().get_audit(audit_id)
        if not a:
            return _err("未知错误")
        return _ok(a.get("report", {}))
    except Exception as e:
        return _err(e)


@router.get("/compliance/checklists")
def compliance_checklists(framework: str = Query("mlps2")):
    try:
        return _ok(_ca().list_checklists(framework))
    except Exception as e:
        return _err(e)


@router.get("/compliance/trend")
def compliance_trend(audit_id1: str, audit_id2: str):
    try:
        return _ok(_ca().compare_audits(audit_id1, audit_id2))
    except Exception as e:
        return _err(e)


# ---------------------------------------------------------------------- #
# 鏀诲嚮璺緞
# ---------------------------------------------------------------------- #
@router.post("/attack-path/generate")
def attack_generate(req: AttackGraphReq):
    try:
        g = _ap().build_attack_graph(req.assets, req.vulnerabilities)
        paths = _ap().get_critical_paths(g, top_n=5)
        return _ok({"graph": g, "critical_paths": paths})
    except Exception as e:
        return _err(e)


@router.get("/attack-path/{graph_id}/critical-paths")
def attack_critical(graph_id: str, n: int = Query(5)):
    try:
        g = _ap().get_graph(graph_id)
        if not g:
            return _err("鏀诲嚮鍥句笉瀛樺湪")
        return _ok(_ap().get_critical_paths(g, top_n=n))
    except Exception as e:
        return _err(e)


@router.get("/attack-path/{graph_id}/mitigations")
def attack_mitigations(graph_id: str):
    try:
        g = _ap().get_graph(graph_id)
        if not g:
            return _err("鏀诲嚮鍥句笉瀛樺湪")
        paths = _ap().get_critical_paths(g, top_n=5)
        return _ok(_ap().get_mitigations(g, paths))
    except Exception as e:
        return _err(e)


@router.get("/attack-path/{graph_id}/visualize")
def attack_visualize(graph_id: str, format: str = Query("mermaid")):
    try:
        g = _ap().get_graph(graph_id)
        if not g:
            return _err("鏀诲嚮鍥句笉瀛樺湪")
        paths = _ap().get_critical_paths(g, top_n=5)
        if format == "mermaid":
            return _ok({"format": "mermaid", "content": _ap().generate_mermaid(g, paths)})
        if format == "svg":
            return _ok({"format": "svg", "content": _ap().generate_svg(g, paths)})
        if format == "html":
            return _ok({"format": "html", "content": _ap().generate_html(g, paths)})
        return _err("未知错误")
    except Exception as e:
        return _err(e)


# ============== 绗叚杞? SSL/TLS + 鎶ュ憡鐢熸垚 + CVE鎼滅储 ==============
import os as _os
import time as _time
import json as _json
from fastapi.responses import HTMLResponse, PlainTextResponse


class _SSLDetectReq(BaseModel):
    target: str
    port: int = 443
    timeout: int = 10


@router.post("/ssl-detect")
def ssl_detect(req: _SSLDetectReq):
    """
    try:
        from asm.ssl_report import SSLTLSDetector
        detector = SSLTLSDetector(req.target, req.port, req.timeout)
        return _ok(detector.detect())
    except Exception as e:
        return _err(e)


@router.post("/report/generate", response_class=HTMLResponse)
def report_generate(target: str, format: str = "html", scan_data: Dict[str, Any] = None):
    """
    try:
        from asm.ssl_report import ReportGenerator
        data = scan_data or {"summary": {}, "phases": {}}
        if format == "markdown":
            return PlainTextResponse(
                content=ReportGenerator.generate_markdown(target, data),
                media_type="text/markdown"
            )
        return HTMLResponse(content=ReportGenerator.generate_html(target, data))
    except Exception as e:
        return HTMLResponse(content=f"<h1>鎶ュ憡鐢熸垚澶辫触: {e}</h1>", status_code=500)


@router.get("/cve-search")
def cve_search(keyword: str, limit: int = 10):
    """搜索CVE漏洞库"""
    try:
        db_path = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "data", "vuln_database.json")
        with open(db_path, "r", encoding="utf-8") as f:
            db = _json.load(f)
        vulns = db.get("vulnerabilities", [])
        kw = keyword.lower()
        results = []
        for v in vulns:
            text = (v.get("cve_id", "") + " " + v.get("title", "") + " " +
                    v.get("description", "") + " " + v.get("vendor", "")).lower()
            if kw in text:
                results.append({
                    "cve_id": v.get("cve_id", ""),
                    "title": v.get("title", ""),
                    "severity": v.get("severity", ""),
                    "cvss_score": v.get("cvss_score", ""),
                    "vendor": v.get("vendor", ""),
                    "product": v.get("product", "")
                })
                if len(results) >= limit:
                    break
        return _ok({"keyword": keyword, "total": len(results), "results": results})
    except Exception as e:
        return _err(e)


# ============== 绗叓杞? OWASP + 鎵弿鍘嗗彶 + 瀹氭椂璋冨害 ==============
_owasp_mapper = None
_scan_history = None
_scheduler = None

def _om():
    global _owasp_mapper
    if _owasp_mapper is None:
        from asm.compliance_scheduler import OWASPMapper
        _owasp_mapper = OWASPMapper()
    return _owasp_mapper

def _sh():
    global _scan_history
    if _scan_history is None:
        from asm.compliance_scheduler import ScanHistory
        _scan_history = ScanHistory()
    return _scan_history

def _sc():
    global _scheduler
    if _scheduler is None:
        from asm.compliance_scheduler import ScheduledScanner
        _scheduler = ScheduledScanner()
    return _scheduler

class _OWASPMapReq(BaseModel):
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)

class _ScheduleReq(BaseModel):
    target: str
    interval_minutes: int = 60
    scan_type: str = "full"

@router.post("/owasp/map")
def owasp_map(req: _OWASPMapReq):
    try:
        return _ok(_om().map(req.vulnerabilities))
    except Exception as e:
        return _err(e)

@router.get("/scan-history/list")
def scan_history_list(target: Optional[str] = Query(None), limit: int = 20):
    try:
        return _ok(_sh().list_scans(target, limit))
    except Exception as e:
        return _err(e)

@router.get("/scan-history/stats")
def scan_history_stats():
    try:
        return _ok(_sh().get_stats())
    except Exception as e:
        return _err(e)

@router.post("/schedule/add")
def schedule_add(req: _ScheduleReq):
    try:
        job_id = "job_" + str(int(_time.time()))
        return _ok(_sc().add_job(job_id, req.target, req.interval_minutes, req.scan_type))
    except Exception as e:
        return _err(e)

@router.get("/schedule/list")
def schedule_list():
    try:
        return _ok(_sc().list_jobs())
    except Exception as e:
        return _err(e)

@router.delete("/schedule/{job_id}")
def schedule_remove(job_id: str):
    try:
        return _ok({"removed": _sc().remove_job(job_id)})
    except Exception as e:
        return _err(e)


