# -*- coding: utf-8 -*-
"""
threat_intel_routes.py — 威胁情报与攻击面管理 REST API（第23轮升级方向3）。

路由前缀：/api/v1/threat-intel
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。
任务用内存字典 TASKS 模拟异步任务。
"""

from __future__ import annotations

import os
import re
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging as log  # type: ignore

try:
    from threat_intel.intel_sources import get_intel_source_manager, extract_iocs
    from threat_intel.ioc_manager import get_ioc_manager
    from threat_intel.attack_surface import get_attack_surface_manager
    from threat_intel.vuln_intel import get_vuln_intel_manager
    from threat_intel.threat_actor import get_threat_actor_manager
    from threat_intel.intel_dashboard import get_intel_dashboard
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    log.warning("threat_intel_routes: 模块导入失败: %s", _e)
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/threat-intel", tags=["威胁情报与攻击面管理"])


# ==================== 响应工具 ====================

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理无效控制字符，避免 JSON 序列化异常"""
    if isinstance(obj, str):
        return _CTRL_RE.sub("", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(x) for x in obj]
    return obj


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": _clean(data), "error": str(err)})


# ==================== 内存任务存储 ====================

TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(task_type: str) -> str:
    tid = f"{task_type}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {"task_id": tid, "type": task_type, "status": "pending",
                  "result": None, "error": None, "created_at": datetime.now().isoformat()}
    return tid


def _run_task(task_type: str, func, *args, **kwargs) -> str:
    tid = _new_task(task_type)
    TASKS[tid]["status"] = "running"
    try:
        TASKS[tid]["result"] = func(*args, **kwargs)
        TASKS[tid]["status"] = "success"
    except Exception as e:
        TASKS[tid]["status"] = "failed"
        TASKS[tid]["error"] = str(e)
    return tid


# ==================== 请求模型 ====================

class IngestReq(BaseModel):
    ioc: str = ""
    type: Optional[str] = None
    title: str = ""
    severity: str = "medium"
    confidence: int = 70
    in_the_wild: bool = False
    tags: List[str] = []
    source: str = "custom"


class TextReq(BaseModel):
    text: str = ""
    source: str = "custom"


class IOCAddReq(BaseModel):
    value: str
    type: Optional[str] = None
    severity: str = "medium"
    actor: str = ""
    tags: List[str] = []
    source: str = "manual"
    confidence: int = 70


class IOCRateReq(BaseModel):
    severity: str = "high"
    confidence: int = 80


class CustomSourceReq(BaseModel):
    name: str
    url: str = ""
    fmt: str = "json"
    note: str = ""


class ConfigureReq(BaseModel):
    config: Dict[str, Any] = {}


class MatchTextReq(BaseModel):
    text: str
    context: str = "log"


class HuntReq(BaseModel):
    mode: str = "ttp"
    query: str = ""
    template_id: str = ""


class SettingsReq(BaseModel):
    patch: Dict[str, Any] = {}


class RuleReq(BaseModel):
    name: str
    condition: str = ""
    level: str = "medium"
    notify: List[str] = ["webhook"]
    enabled: bool = True


class RespondReq(BaseModel):
    action: str = "mitigate"
    assignee: str = ""


class SimulateReq(BaseModel):
    actor_id: str = "cl0p"
    target_profile: str = "制造业"


# ==================== 情报源 API ====================

@router.get("/intel-sources/list")
def list_intel_sources(group: Optional[str] = Query(None),
                       only_enabled: bool = False):
    try:
        if not _MODULES_OK:
            return _fail("模块未就绪")
        m = get_intel_source_manager()
        return _ok(m.list_sources(group=group, only_enabled=only_enabled))
    except Exception as e:
        return _fail(str(e))


@router.get("/intel-sources/{sid}")
def get_intel_source(sid: str):
    try:
        m = get_intel_source_manager()
        s = m.get_source(sid)
        if not s:
            return _fail("情报源不存在")
        return _ok(s)
    except Exception as e:
        return _fail(str(e))


@router.post("/intel-sources/{sid}/enable")
def enable_intel_source(sid: str, enabled: bool = True):
    try:
        m = get_intel_source_manager()
        return _ok(m.enable_source(sid, enabled))
    except Exception as e:
        return _fail(str(e))


@router.post("/intel-sources/{sid}/configure")
def configure_intel_source(sid: str, req: ConfigureReq):
    try:
        m = get_intel_source_manager()
        return _ok(m.configure_source(sid, req.config))
    except Exception as e:
        return _fail(str(e))


@router.post("/intel-sources/custom")
def add_custom_source(req: CustomSourceReq):
    try:
        m = get_intel_source_manager()
        return _ok(m.add_custom_source(req.name, req.url, req.fmt, req.note))
    except Exception as e:
        return _fail(str(e))


@router.post("/intel-sources/{sid}/pull")
def pull_intel_source(sid: str):
    try:
        m = get_intel_source_manager()
        return _ok(m.pull_source(sid))
    except Exception as e:
        return _fail(str(e))


@router.post("/intel-sources/refresh-all")
def refresh_all_sources():
    try:
        m = get_intel_source_manager()
        return _ok(m.refresh_all())
    except Exception as e:
        return _fail(str(e))


@router.post("/intel-sources/ingest")
def ingest_feed(req: IngestReq):
    try:
        m = get_intel_source_manager()
        rec = m.ingest({"ioc": req.ioc, "type": req.type, "title": req.title,
                        "severity": req.severity, "confidence": req.confidence,
                        "in_the_wild": req.in_the_wild, "tags": req.tags}, req.source)
        return _ok(rec)
    except Exception as e:
        return _fail(str(e))


@router.post("/intel-sources/ingest-text")
def ingest_text(req: TextReq):
    try:
        m = get_intel_source_manager()
        return _ok({"extracted": m.ingest_text(req.text, req.source)})
    except Exception as e:
        return _fail(str(e))


@router.post("/intel-sources/import-csv")
def import_csv(req: TextReq):
    try:
        m = get_intel_source_manager()
        return _ok({"imported": m.import_csv(req.text, req.source)})
    except Exception as e:
        return _fail(str(e))


@router.post("/intel-sources/import-stix")
def import_stix(req: Dict[str, Any]):
    try:
        m = get_intel_source_manager()
        return _ok({"imported": m.import_stix_taxii(req)})
    except Exception as e:
        return _fail(str(e))


@router.get("/feeds/query")
def query_feeds(q: str = "", type: Optional[str] = None,
                severity: Optional[str] = None, limit: int = 100):
    try:
        m = get_intel_source_manager()
        return _ok(m.query(q=q, typ=type, severity=severity, limit=limit))
    except Exception as e:
        return _fail(str(e))


@router.get("/feeds/{fid}/quality")
def feed_quality(fid: str):
    try:
        m = get_intel_source_manager()
        return _ok({"id": fid, "quality_score": m.quality_score(fid)})
    except Exception as e:
        return _fail(str(e))


@router.post("/sources/expire-archive")
def expire_archive_sources():
    try:
        m = get_intel_source_manager()
        return _ok(m.expire_and_archive())
    except Exception as e:
        return _fail(str(e))


# ==================== IOC API ====================

@router.post("/iocs/validate")
def validate_ioc(req: IngestReq):
    try:
        from threat_intel.ioc_manager import IOCManager
        return _ok(IOCManager.validate(req.ioc, req.type))
    except Exception as e:
        return _fail(str(e))


@router.post("/iocs")
def add_ioc(req: IOCAddReq):
    try:
        m = get_ioc_manager()
        return _ok(m.add_ioc(req.value, req.type, severity=req.severity,
                             actor=req.actor, tags=req.tags,
                             source=req.source, confidence=req.confidence))
    except Exception as e:
        return _fail(str(e))


@router.get("/iocs/list")
def list_iocs(type: Optional[str] = None, severity: Optional[str] = None,
              status: Optional[str] = None, q: str = ""):
    try:
        m = get_ioc_manager()
        return _ok(m.list_iocs(typ=type, severity=severity, status=status, q=q))
    except Exception as e:
        return _fail(str(e))


@router.get("/iocs/{iid}")
def get_ioc(iid: str):
    try:
        m = get_ioc_manager()
        rec = m.get(iid)
        if not rec:
            return _fail("IOC不存在")
        return _ok(rec)
    except Exception as e:
        return _fail(str(e))


@router.post("/iocs/{iid}/transition")
def transition_ioc(iid: str, status: str = "verified"):
    try:
        m = get_ioc_manager()
        return _ok(m.transition(iid, status))
    except Exception as e:
        return _fail(str(e))


@router.post("/iocs/{iid}/rate")
def rate_ioc(iid: str, req: IOCRateReq):
    try:
        m = get_ioc_manager()
        return _ok(m.rate(iid, req.severity, req.confidence))
    except Exception as e:
        return _fail(str(e))


@router.post("/iocs/match-text")
def match_text_ioc(req: MatchTextReq):
    try:
        m = get_ioc_manager()
        return _ok({"hits": m.match_text(req.text, req.context)})
    except Exception as e:
        return _fail(str(e))


@router.post("/iocs/match-assets")
def match_assets_ioc(assets: List[Dict[str, Any]]):
    try:
        m = get_ioc_manager()
        return _ok({"matches": m.match_assets(assets)})
    except Exception as e:
        return _fail(str(e))


@router.post("/iocs/hunt")
def hunt_ioc(req: HuntReq):
    try:
        m = get_ioc_manager()
        return _ok(m.hunt(query=req.query))
    except Exception as e:
        return _fail(str(e))


@router.get("/iocs/export/{fmt}")
def export_iocs(fmt: str):
    try:
        m = get_ioc_manager()
        if fmt == "json":
            body = m.export_json()
        elif fmt == "csv":
            body = m.export_csv()
        elif fmt == "stix":
            import json as _j
            body = _j.dumps(m.export_stix(), ensure_ascii=False, indent=2)
        elif fmt == "openioc":
            body = m.export_openioc()
        elif fmt == "suricata":
            body = m.export_suricata()
        elif fmt == "snort":
            body = m.export_snort()
        elif fmt == "yara":
            body = m.export_yara()
        else:
            return _fail("不支持的导出格式: " + fmt)
        return PlainTextResponse(body, media_type="text/plain; charset=utf-8")
    except Exception as e:
        return _fail(str(e))


@router.post("/iocs/whitelist")
def add_whitelist(req: IngestReq):
    try:
        m = get_ioc_manager()
        return _ok({"whitelisted": m.add_whitelist(req.ioc)})
    except Exception as e:
        return _fail(str(e))


@router.get("/iocs/stats")
def ioc_stats():
    try:
        m = get_ioc_manager()
        return _ok(m.stats())
    except Exception as e:
        return _fail(str(e))


# ==================== 攻击面 API ====================

@router.get("/assets/list")
def list_assets(type: Optional[str] = None, q: str = ""):
    try:
        m = get_attack_surface_manager()
        return _ok(m.list_assets(typ=type, q=q))
    except Exception as e:
        return _fail(str(e))


@router.get("/assets/{aid}")
def profile_asset(aid: str):
    try:
        m = get_attack_surface_manager()
        return _ok(m.profile(aid))
    except Exception as e:
        return _fail(str(e))


@router.post("/assets/discover/subdomains")
def discover_subdomains(req: TextReq):
    try:
        m = get_attack_surface_manager()
        return _ok({"assets": m.discover_subdomains(req.text)})
    except Exception as e:
        return _fail(str(e))


@router.post("/assets/discover/scan")
def discover_scan(req: TextReq):
    try:
        m = get_attack_surface_manager()
        return _ok(m.discover_by_scan(req.text))
    except Exception as e:
        return _fail(str(e))


@router.post("/assets/discover/ct")
def discover_ct(req: TextReq):
    try:
        m = get_attack_surface_manager()
        return _ok({"assets": m.discover_from_ct(req.text)})
    except Exception as e:
        return _fail(str(e))


@router.get("/attack-surface/analyze")
def analyze_attack_surface():
    try:
        m = get_attack_surface_manager()
        return _ok(m.analyze())
    except Exception as e:
        return _fail(str(e))


@router.post("/attack-surface/monitor-tick")
def monitor_tick():
    try:
        m = get_attack_surface_manager()
        return _ok(m.monitor_tick())
    except Exception as e:
        return _fail(str(e))


@router.get("/attack-surface/alerts")
def surface_alerts(level: Optional[str] = None):
    try:
        m = get_attack_surface_manager()
        return _ok(m.list_alerts(level))
    except Exception as e:
        return _fail(str(e))


@router.get("/attack-surface/report")
def surface_report():
    try:
        m = get_attack_surface_manager()
        return _ok(m.report())
    except Exception as e:
        return _fail(str(e))


@router.get("/attack-surface/stats")
def surface_stats():
    try:
        m = get_attack_surface_manager()
        return _ok(m.stats())
    except Exception as e:
        return _fail(str(e))


# ==================== 漏洞情报 API ====================

@router.get("/vulns/list")
def list_vulns(severity: Optional[str] = None, in_the_wild: Optional[bool] = None,
               q: str = "", limit: int = 100):
    try:
        m = get_vuln_intel_manager()
        return _ok(m.list_vulns(severity=severity, in_the_wild=in_the_wild,
                                q=q, limit=limit))
    except Exception as e:
        return _fail(str(e))


@router.get("/vulns/{cve}")
def get_vuln(cve: str):
    try:
        m = get_vuln_intel_manager()
        v = m.get(cve)
        if not v:
            return _fail("漏洞不存在")
        return _ok(v)
    except Exception as e:
        return _fail(str(e))


@router.post("/vulns")
def add_vuln(req: Dict[str, Any]):
    try:
        m = get_vuln_intel_manager()
        return _ok(m.add_vuln(req))
    except Exception as e:
        return _fail(str(e))


@router.post("/vulns/match-assets")
def match_vuln_assets(assets: List[Dict[str, Any]]):
    try:
        m = get_vuln_intel_manager()
        return _ok({"matches": m.match_assets(assets)})
    except Exception as e:
        return _fail(str(e))


@router.post("/vulns/alerts/raise")
def raise_vuln_alerts():
    try:
        m = get_vuln_intel_manager()
        return _ok({"alerts": m.raise_alerts()})
    except Exception as e:
        return _fail(str(e))


@router.get("/vulns/alerts")
def list_vuln_alerts(level: Optional[str] = None):
    try:
        m = get_vuln_intel_manager()
        return _ok(m.list_alerts(level))
    except Exception as e:
        return _fail(str(e))


@router.get("/vulns/trends")
def vuln_trends():
    try:
        m = get_vuln_intel_manager()
        return _ok(m.trends())
    except Exception as e:
        return _fail(str(e))


@router.get("/vulns/kb")
def vuln_kb(q: str = ""):
    try:
        m = get_vuln_intel_manager()
        return _ok(m.kb(q))
    except Exception as e:
        return _fail(str(e))


@router.post("/vulns/{cve}/respond")
def respond_vuln(cve: str, req: RespondReq):
    try:
        m = get_vuln_intel_manager()
        return _ok(m.respond(cve, req.action, req.assignee))
    except Exception as e:
        return _fail(str(e))


@router.get("/vulns/responses")
def list_responses():
    try:
        m = get_vuln_intel_manager()
        return _ok(m.list_responses())
    except Exception as e:
        return _fail(str(e))


@router.get("/vulns/stats")
def vuln_stats():
    try:
        m = get_vuln_intel_manager()
        return _ok(m.stats())
    except Exception as e:
        return _fail(str(e))


# ==================== 威胁Actor / TTPs API ====================

@router.get("/actors/list")
def list_actors(severity: Optional[str] = None, industry: str = "", q: str = ""):
    try:
        m = get_threat_actor_manager()
        return _ok(m.list_actors(severity=severity, industry=industry, q=q))
    except Exception as e:
        return _fail(str(e))


@router.get("/actors/{aid}")
def get_actor(aid: str):
    try:
        m = get_threat_actor_manager()
        a = m.get_actor(aid)
        if not a:
            return _fail("Actor不存在")
        return _ok(a)
    except Exception as e:
        return _fail(str(e))


@router.get("/actors/{aid}/ttps")
def actor_ttps(aid: str):
    try:
        m = get_threat_actor_manager()
        return _ok(m.actor_ttps(aid))
    except Exception as e:
        return _fail(str(e))


@router.get("/actors/{aid}/kill-chain")
def actor_kill_chain(aid: str):
    try:
        m = get_threat_actor_manager()
        return _ok(m.kill_chain(aid))
    except Exception as e:
        return _fail(str(e))


@router.get("/ttps/list")
def list_ttps(tactic: Optional[str] = None):
    try:
        m = get_threat_actor_manager()
        return _ok(m.list_techniques(tactic))
    except Exception as e:
        return _fail(str(e))


@router.get("/tactics/list")
def list_tactics():
    try:
        m = get_threat_actor_manager()
        return _ok(m.list_tactics())
    except Exception as e:
        return _fail(str(e))


@router.post("/simulate")
def simulate_attack(req: SimulateReq):
    try:
        m = get_threat_actor_manager()
        return _ok(m.simulate(req.actor_id, req.target_profile))
    except Exception as e:
        return _fail(str(e))


@router.get("/actors/stats")
def actor_stats():
    try:
        m = get_threat_actor_manager()
        return _ok(m.stats())
    except Exception as e:
        return _fail(str(e))


# ==================== 控制台 / 告警 / 狩猎 / 设置 API ====================

@router.get("/dashboard/overview")
def dashboard_overview():
    try:
        d = get_intel_dashboard()
        return _ok(d.overview())
    except Exception as e:
        return _fail(str(e))


@router.post("/alerts/evaluate")
def evaluate_alerts():
    try:
        d = get_intel_dashboard()
        return _ok({"new_alerts": d.evaluate_alerts()})
    except Exception as e:
        return _fail(str(e))


@router.get("/alerts/list")
def list_alerts(level: Optional[str] = None, status: Optional[str] = None):
    try:
        d = get_intel_dashboard()
        return _ok(d.list_alerts(level=level, status=status))
    except Exception as e:
        return _fail(str(e))


@router.post("/alerts/{alert_id}/handle")
def handle_alert(alert_id: str, action: str = "close", note: str = ""):
    try:
        d = get_intel_dashboard()
        return _ok(d.handle_alert(alert_id, action, note))
    except Exception as e:
        return _fail(str(e))


@router.post("/alerts/{alert_id}/notify")
def notify_alert(alert_id: str):
    try:
        d = get_intel_dashboard()
        return _ok(d.notify(alert_id))
    except Exception as e:
        return _fail(str(e))


@router.get("/alerts/stats")
def alerts_stats():
    try:
        d = get_intel_dashboard()
        return _ok(d.alert_stats())
    except Exception as e:
        return _fail(str(e))


@router.get("/hunt/templates")
def hunt_templates():
    try:
        d = get_intel_dashboard()
        return _ok(d.hunt_templates())
    except Exception as e:
        return _fail(str(e))


@router.post("/hunt/run")
def run_hunt(req: HuntReq):
    try:
        d = get_intel_dashboard()
        return _ok(d.run_hunt(req.template_id, req.mode, req.query))
    except Exception as e:
        return _fail(str(e))


@router.get("/hunt/history")
def hunt_history():
    try:
        d = get_intel_dashboard()
        return _ok(d.actors.list_hunting())
    except Exception as e:
        return _fail(str(e))


@router.get("/search")
def global_search(q: str = ""):
    try:
        d = get_intel_dashboard()
        return _ok(d.global_search(q))
    except Exception as e:
        return _fail(str(e))


@router.get("/settings")
def get_settings():
    try:
        d = get_intel_dashboard()
        return _ok(d.get_settings())
    except Exception as e:
        return _fail(str(e))


@router.post("/settings")
def update_settings(req: SettingsReq):
    try:
        d = get_intel_dashboard()
        return _ok(d.update_settings(req.patch))
    except Exception as e:
        return _fail(str(e))


@router.post("/rules")
def add_rule(req: RuleReq):
    try:
        d = get_intel_dashboard()
        return _ok(d.add_rule(req.model_dump()))
    except Exception as e:
        return _fail(str(e))


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: str):
    try:
        d = get_intel_dashboard()
        return _ok(d.delete_rule(rule_id))
    except Exception as e:
        return _fail(str(e))


@router.get("/audit")
def list_audit():
    try:
        d = get_intel_dashboard()
        return _ok(d.list_audit())
    except Exception as e:
        return _fail(str(e))


@router.post("/cleanup")
def cleanup_data():
    try:
        d = get_intel_dashboard()
        return _ok(d.cleanup())
    except Exception as e:
        return _fail(str(e))


@router.get("/health")
def ti_health():
    return _ok({"modules_ready": _MODULES_OK,
                "iocs": get_ioc_manager().stats()["total"],
                "assets": get_attack_surface_manager().stats()["total_assets"],
                "alerts": len(get_intel_dashboard().alerts)})
