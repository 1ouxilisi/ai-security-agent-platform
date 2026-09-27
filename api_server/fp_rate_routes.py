#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fp_rate_routes.py — P0-1 真实工具路由 + P0-2 误报率验证路由。

包含两个 router：
- tools_router  prefix=/api/v1/real-tools-deep   （真实 nmap/sqlmap/nuclei/nikto/dirb/dirsearch 执行）
- router        prefix=/api/v1/real-validation     （靶场管理 / 误报率测试 / 历史 / 报告）

统一响应 {success, data, error}。工具未安装时明确报错，不返回 mock。
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from real_tools_deep import nmap_deep, sqlmap_deep, other_tools
from real_validation.fp_rate import get_validator

tools_router = APIRouter(prefix="/api/v1/real-tools-deep", tags=["P0-1 真实工具执行"])
router = APIRouter(prefix="/api/v1/real-validation", tags=["P0-2 误报率验证"])

_nmap = nmap_deep.get_scanner()
_sqlmap = sqlmap_deep.get_scanner()
_tools = other_tools.get_manager()
_validator = get_validator()


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return [_clean(i) for i in obj]
    return obj


def _ok(data: Any = None) -> Dict[str, Any]:
    return {"success": True, "data": _clean(data), "error": None}


def _err(msg: str) -> Dict[str, Any]:
    return {"success": False, "data": None, "error": msg}


# ============================================================
# 请求模型
# ============================================================
class NmapScanReq(BaseModel):
    targets: List[str] = Field(default_factory=lambda: ["127.0.0.1"])
    scan_type: str = "connect"          # syn/connect/udp/...
    ports: str = "1-1000"
    timing: int = 3
    version_detection: bool = True
    os_detection: bool = False
    scripts: str = ""
    timeout: int = 300


class SQLMapReq(BaseModel):
    target_url: str
    post_data: str = ""
    param: str = ""
    dbms: str = ""
    technique: str = "BEUSTQ"
    level: int = 1
    risk: int = 1
    threads: int = 1
    enumerate_dbs: bool = False
    timeout: int = 300


class NucleiReq(BaseModel):
    target: str
    templates: str = ""
    severity: str = ""
    tags: str = ""
    rate_limit: int = 150
    timeout: int = 300


class NiktoReq(BaseModel):
    target: str
    port: int = 80
    ssl: bool = False
    timeout: int = 300


class DirReq(BaseModel):
    url: str
    wordlist: str = ""
    extensions: str = "php,html,txt"
    timeout: int = 300


class AddRangeReq(BaseModel):
    rid: str
    name: str
    url: str
    known_vuln_types: List[str] = Field(default_factory=list)
    known_vuln_count: int = 0
    difficulty: str = "medium"


class FPRunReq(BaseModel):
    range_id: Optional[str] = None
    url: str = ""
    known_types: List[str] = Field(default_factory=list)
    known_count: int = 0
    nmap_timeout: int = 120
    nuclei_timeout: int = 180
    nikto_timeout: int = 120


# ============================================================
# P0-1：真实工具执行路由 (/api/v1/real-tools-deep)
# ============================================================
@tools_router.get("/nmap/status")
def nmap_status() -> Dict[str, Any]:
    return _ok(nmap_deep.get_tool_manager().detect_version())


@tools_router.post("/nmap/scan")
def nmap_scan(req: NmapScanReq) -> Dict[str, Any]:
    res = _nmap.scan(
        targets=req.targets, scan_type=req.scan_type, ports=req.ports,
        timing=req.timing, version_detection=req.version_detection,
        os_detection=req.os_detection, scripts=req.scripts, timeout=req.timeout,
    )
    return _clean(res) if isinstance(res, dict) else _ok(res)


@tools_router.get("/sqlmap/status")
def sqlmap_status() -> Dict[str, Any]:
    return _ok(sqlmap_deep.get_tool_manager().detect_version())


@tools_router.post("/sqlmap/scan")
def sqlmap_scan(req: SQLMapReq) -> Dict[str, Any]:
    res = _sqlmap.scan(
        target_url=req.target_url, post_data=req.post_data, param=req.param,
        dbms=req.dbms, technique=req.technique, level=req.level, risk=req.risk,
        threads=req.threads, enumerate_dbs=req.enumerate_dbs, timeout=req.timeout,
    )
    return _clean(res) if isinstance(res, dict) else _ok(res)


@tools_router.get("/nuclei/status")
def nuclei_status() -> Dict[str, Any]:
    return _ok({"available": _tools.nuclei.available, "version": _tools.nuclei.version,
                "path": _tools.nuclei.actual_path, "error": _tools.nuclei.probe_error})


@tools_router.post("/nuclei/scan")
def nuclei_scan(req: NucleiReq) -> Dict[str, Any]:
    res = _tools.nuclei.scan(target=req.target, templates=req.templates,
                             severity=req.severity, tags=req.tags,
                             rate_limit=req.rate_limit, timeout=req.timeout)
    return _clean(res) if isinstance(res, dict) else _ok(res)


@tools_router.get("/nikto/status")
def nikto_status() -> Dict[str, Any]:
    return _ok({"available": _tools.nikto.available, "version": _tools.nikto.version,
                "path": _tools.nikto.actual_path, "error": _tools.nikto.probe_error})


@tools_router.post("/nikto/scan")
def nikto_scan(req: NiktoReq) -> Dict[str, Any]:
    res = _tools.nikto.scan(target=req.target, port=req.port, ssl=req.ssl, timeout=req.timeout)
    return _clean(res) if isinstance(res, dict) else _ok(res)


@tools_router.get("/dirb/status")
def dirb_status() -> Dict[str, Any]:
    return _ok({"available": _tools.dirb.available, "path": _tools.dirb.actual_path,
                "error": _tools.dirb.probe_error})


@tools_router.post("/dirb/scan")
def dirb_scan(req: DirReq) -> Dict[str, Any]:
    res = _tools.dirb.scan(url=req.url, wordlist=req.wordlist, timeout=req.timeout)
    return _clean(res) if isinstance(res, dict) else _ok(res)


@tools_router.get("/dirsearch/status")
def dirsearch_status() -> Dict[str, Any]:
    return _ok({"available": _tools.dirsearch.available, "path": _tools.dirsearch.actual_path,
                "error": _tools.dirsearch.probe_error})


@tools_router.post("/dirsearch/scan")
def dirsearch_scan(req: DirReq) -> Dict[str, Any]:
    res = _tools.dirsearch.scan(url=req.url, extensions=req.extensions, timeout=req.timeout)
    return _clean(res) if isinstance(res, dict) else _ok(res)


@tools_router.get("/hydra/status")
def hydra_status() -> Dict[str, Any]:
    return _ok({"available": _tools.hydra.available, "path": _tools.hydra.actual_path,
                "error": _tools.hydra.probe_error})


@tools_router.get("/tools-status")
def all_tools_status() -> Dict[str, Any]:
    return _ok(_tools.get_all_versions())


# ============================================================
# P0-2：误报率验证路由 (/api/v1/real-validation/fp-test)
# ============================================================
@router.get("/fp-test/ranges")
def fp_list_ranges() -> Dict[str, Any]:
    return _ok(_validator.list_ranges())


@router.post("/fp-test/ranges")
def fp_add_range(req: AddRangeReq) -> Dict[str, Any]:
    return _ok(_validator.add_range(req.rid, req.name, req.url,
                                    req.known_vuln_types, req.known_vuln_count,
                                    req.difficulty))


@router.get("/fp-test/ranges/{rid}")
def fp_get_range(rid: str) -> Dict[str, Any]:
    if rid not in _validator.ranges:
        return _err(f"靶场不存在: {rid}")
    return _ok({"id": rid, **_validator.ranges[rid]})


@router.put("/fp-test/ranges/{rid}/status")
def fp_set_range_status(rid: str, status: str = Query(...)) -> Dict[str, Any]:
    res = _validator.update_range_status(rid, status)
    return res if not res.get("success") else _ok(res["data"])


@router.post("/fp-test/run")
def fp_run(req: FPRunReq) -> Dict[str, Any]:
    rec = _validator.run_fp_test(
        range_id=req.range_id, url=req.url,
        known_types=req.known_types, known_count=req.known_count,
        timeouts={"nmap": req.nmap_timeout, "nuclei": req.nuclei_timeout,
                  "nikto": req.nikto_timeout},
    )
    return _ok(rec)


@router.get("/fp-test/results")
def fp_results() -> Dict[str, Any]:
    latest = _validator.get_latest()
    if latest is None:
        return _ok({"has_result": False, "record": None})
    return _ok({"has_result": True, "record": latest})


@router.get("/fp-test/history")
def fp_history(limit: int = 50) -> Dict[str, Any]:
    return _ok(_validator.get_history(limit=limit))


@router.get("/fp-test/trend")
def fp_trend() -> Dict[str, Any]:
    return _ok(_validator.get_trend())


@router.get("/fp-test/report")
def fp_report() -> Dict[str, Any]:
    path = _validator.generate_html_report()
    return _ok({"report_path": path, "generated_at": __import__("time").strftime("%Y-%m-%d %H:%M:%S")})


@router.get("/fp-test/record/{test_id}")
def fp_record(test_id: str) -> Dict[str, Any]:
    for h in reversed(_validator.history):
        if h["test_id"] == test_id:
            return _ok(h)
    return _err(f"记录不存在: {test_id}")


@router.get("/fp-test/tools-status")
def fp_tools_status() -> Dict[str, Any]:
    return _ok({
        "nmap": {"available": _nmap.available, "version": _nmap.version,
                 "error": _nmap.probe_error},
        "sqlmap": {"available": _sqlmap.available, "version": _sqlmap.version,
                   "error": _sqlmap.probe_error},
        "nuclei": {"available": _tools.nuclei.available, "version": _tools.nuclei.version,
                   "error": _tools.nuclei.probe_error},
        "nikto": {"available": _tools.nikto.available, "version": _tools.nikto.version,
                  "error": _tools.nikto.probe_error},
    })


@router.get("/fp-test/overview")
def fp_overview() -> Dict[str, Any]:
    latest = _validator.get_latest()
    return _ok({
        "ranges_total": len(_validator.ranges),
        "history_total": len(_validator.history),
        "latest": latest,
        "tools": {
            "nmap": _nmap.available, "sqlmap": _sqlmap.available,
            "nuclei": _tools.nuclei.available, "nikto": _tools.nikto.available,
        },
    })
