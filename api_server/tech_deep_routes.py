# -*- coding: utf-8 -*-
"""tech_deep_routes.py — 技术深度大升级 REST API（30+ 端点）。

路由前缀: /api/v1/tech-deep
统一响应: {"success": bool, "data": ..., "error": ...}
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tech-deep",
                   tags=["技术深度大升级"])

# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from tech_deep_upgrade import (
        WebPentestDeepEngine, InternalPentestDeepEngine,
        MobileSecurityDeepEngine, CloudSecurityDeepEngine,
        TechDeepDashboard,
        FINGERPRINT_DB, DIR_WORDLISTS, NUCLEI_TAGS,
        SMB_ENUM_COMMANDS, AD_QUERY_TEMPLATES,
        APK_ANALYZERS, FRIDA_SCRIPTS,
        CLOUD_PROVIDERS, CONFIG_BASELINE_CHECKS,
        TECH_SCORE_BASELINE, CAPABILITY_MATRIX,
    )
    _DASH = TechDeepDashboard()
    _WEB = WebPentestDeepEngine()
    _INT = InternalPentestDeepEngine()
    _MOB = MobileSecurityDeepEngine()
    _CLD = CloudSecurityDeepEngine()
    _MOD_AVAILABLE = True
    logger.info("tech_deep_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("tech_deep_routes: load failed: %s", e)
    _DASH = None  # type: ignore
    _WEB = None  # type: ignore
    _INT = None  # type: ignore
    _MOB = None  # type: ignore
    _CLD = None  # type: ignore
    FINGERPRINT_DB: List[Dict[str, Any]] = []  # type: ignore
    DIR_WORDLISTS: Dict[str, str] = {}  # type: ignore
    NUCLEI_TAGS: Dict[str, List[str]] = {}  # type: ignore
    SMB_ENUM_COMMANDS: Dict[str, str] = {}  # type: ignore
    AD_QUERY_TEMPLATES: Dict[str, str] = {}  # type: ignore
    APK_ANALYZERS: List[str] = []  # type: ignore
    FRIDA_SCRIPTS: List[str] = []  # type: ignore
    CLOUD_PROVIDERS: List[Dict[str, Any]] = []  # type: ignore
    CONFIG_BASELINE_CHECKS: List[Dict[str, Any]] = []  # type: ignore
    TECH_SCORE_BASELINE: Dict[str, Any] = {}  # type: ignore
    CAPABILITY_MATRIX: List[Dict[str, Any]] = []  # type: ignore


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def fail(msg: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": msg},
                        status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE or _DASH is None:
        return fail("技术深度模块未加载", 503)
    return None


# --------------------------------------------------------------------------- #
# 1. 总览 / 评分 / 能力矩阵（3 端点）
# --------------------------------------------------------------------------- #
@router.get("/overview")
def overview():
    """技术深度总览（评分 + 能力矩阵 + 工具状态）。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.overview())


@router.get("/score")
def score():
    """技术深度评分（6.5 → 9.0）。"""
    g = _guard()
    if g:
        return g
    return ok(TECH_SCORE_BASELINE)


@router.get("/capability-matrix")
def capability_matrix():
    """能力矩阵。"""
    g = _guard()
    if g:
        return g
    return ok(CAPABILITY_MATRIX)


# --------------------------------------------------------------------------- #
# 2. Web 渗透深度（10 端点）
# --------------------------------------------------------------------------- #
@router.post("/web/fingerprint")
def web_fingerprint(url: str = Body(..., embed=True)):
    """指纹识别（100+ 内置指纹库）。"""
    g = _guard()
    if g:
        return g
    return ok(_WEB.fp.identify(url))


@router.get("/web/fingerprint-db")
def web_fingerprint_db():
    """内置指纹库清单。"""
    g = _guard()
    if g:
        return g
    return ok({"count": len(FINGERPRINT_DB),
               "categories": sorted({f["category"] for f in FINGERPRINT_DB}),
               "items": FINGERPRINT_DB})


@router.post("/web/nuclei/scan")
def web_nuclei_scan(
    url: str = Body(..., embed=True),
    tags: Optional[List[str]] = Body(None),
    severity: Optional[str] = Body(None),
):
    """nuclei 全量模板扫描。"""
    g = _guard()
    if g:
        return g
    return ok(_WEB.nuclei.scan(url, tags=tags, severity=severity))


@router.get("/web/nuclei/tags")
def web_nuclei_tags():
    """nuclei 模板 tag 分组。"""
    g = _guard()
    if g:
        return g
    return ok(NUCLEI_TAGS)


@router.post("/web/sqli/detect")
def web_sqli_detect(
    url: str = Body(..., embed=True),
    param: Optional[str] = Body(None),
):
    """SQL 注入检测（sqlmap）。"""
    g = _guard()
    if g:
        return g
    return ok(_WEB.sqli.detect(url, param))


@router.post("/web/sqli/dbs")
def web_sqli_dbs(url: str = Body(..., embed=True)):
    """枚举数据库。"""
    g = _guard()
    if g:
        return g
    return ok(_WEB.sqli.enumerate_dbs(url))


@router.post("/web/sqli/tables")
def web_sqli_tables(
    url: str = Body(..., embed=True),
    db: str = Body(...),
):
    """枚举表。"""
    g = _guard()
    if g:
        return g
    return ok(_WEB.sqli.enumerate_tables(url, db))


@router.post("/web/sqli/columns")
def web_sqli_columns(
    url: str = Body(..., embed=True),
    db: str = Body(...),
    table: str = Body(...),
):
    """枚举列。"""
    g = _guard()
    if g:
        return g
    return ok(_WEB.sqli.enumerate_columns(url, db, table))


@router.post("/web/sqli/dump")
def web_sqli_dump(
    url: str = Body(..., embed=True),
    db: str = Body(...),
    table: str = Body(...),
    limit: int = Body(10),
):
    """dump 表数据。"""
    g = _guard()
    if g:
        return g
    return ok(_WEB.sqli.dump_table(url, db, table, limit))


@router.post("/web/xss/scan")
def web_xss_scan(
    url: str = Body(..., embed=True),
    param: Optional[str] = Body(None),
):
    """XSS 检测 + 利用建议。"""
    g = _guard()
    if g:
        return g
    return ok(_WEB.xss.scan(url, param))


@router.post("/web/dir/scan")
def web_dir_scan(
    url: str = Body(..., embed=True),
    wordlist: str = Body("common"),
    recursive: bool = Body(True),
):
    """多字典目录扫描。"""
    g = _guard()
    if g:
        return g
    return ok(_WEB.dir.scan(url, wordlist, recursive))


@router.get("/web/dir/wordlists")
def web_dir_wordlists():
    """可用字典。"""
    g = _guard()
    if g:
        return g
    return ok(DIR_WORDLISTS)


@router.post("/web/full/start")
def web_full_start(
    url: str = Body(..., embed=True),
    stages: Optional[List[str]] = Body(None),
):
    """一键 Web 深度扫描（后台线程）。"""
    g = _guard()
    if g:
        return g
    tid = _WEB.create_task(url, stages)
    threading.Thread(target=_WEB.run, args=(tid,), daemon=True).start()
    return ok({"task_id": tid, "url": url})


@router.get("/web/full/status/{task_id}")
def web_full_status(task_id: str):
    t = _WEB.get_task(task_id)
    if not t:
        return fail("task not found", 404)
    return ok(t)


# --------------------------------------------------------------------------- #
# 3. 内网渗透（7 端点）
# --------------------------------------------------------------------------- #
@router.post("/internal/smb/scan")
def internal_smb_scan(host: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_INT.smb.scan_host(host))


@router.post("/internal/smb/shares")
def internal_smb_shares(
    host: str = Body(..., embed=True),
    user: str = Body(""),
    password: str = Body(""),
):
    g = _guard()
    if g:
        return g
    return ok(_INT.smb.list_shares(host, user, password))


@router.post("/internal/smb/users")
def internal_smb_users(host: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_INT.smb.enum_users(host))


@router.post("/internal/ad/query")
def internal_ad_query(
    dc: str = Body(...),
    base_dn: str = Body(...),
    filter: str = Body("(objectClass=*)"),
    user: str = Body(""),
    password: str = Body(""),
):
    g = _guard()
    if g:
        return g
    return ok(_INT.ad.query(dc, base_dn, filter, user, password))


@router.get("/internal/ad/templates")
def internal_ad_templates():
    g = _guard()
    if g:
        return g
    return ok(AD_QUERY_TEMPLATES)


@router.post("/internal/lateral/detect")
def internal_lateral_detect(host: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_INT.lateral.detect_vectors(host))


@router.post("/internal/cred/dump")
def internal_cred_dump(
    host: str = Body(...),
    user: str = Body(...),
    password: str = Body(...),
):
    g = _guard()
    if g:
        return g
    return ok(_INT.cred.dump_sam(host, user, password))


@router.post("/internal/cred/pth")
def internal_cred_pth(
    host: str = Body(...),
    user: str = Body(...),
    nt_hash: str = Body(...),
):
    g = _guard()
    if g:
        return g
    return ok(_INT.cred.pass_the_hash(host, user, nt_hash))


# --------------------------------------------------------------------------- #
# 4. 移动安全（4 端点）
# --------------------------------------------------------------------------- #
@router.post("/mobile/apk/analyze")
def mobile_apk_analyze(apk_path: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_MOB.analyze_apk(apk_path))


@router.get("/mobile/apk/analyzers")
def mobile_apk_analyzers():
    g = _guard()
    if g:
        return g
    return ok({"tools": APK_ANALYZERS, "available": _MOB.tool_status()})


@router.get("/mobile/frida/devices")
def mobile_frida_devices():
    g = _guard()
    if g:
        return g
    return ok(_MOB.frida.list_devices())


@router.get("/mobile/frida/scripts")
def mobile_frida_scripts():
    g = _guard()
    if g:
        return g
    return ok(FRIDA_SCRIPTS)


# --------------------------------------------------------------------------- #
# 5. 云安全（5 端点）
# --------------------------------------------------------------------------- #
@router.get("/cloud/providers")
def cloud_providers():
    g = _guard()
    if g:
        return g
    return ok({"providers": CLOUD_PROVIDERS,
              "status": _CLD.providers_status()})


@router.get("/cloud/aws/users")
def cloud_aws_users():
    g = _guard()
    if g:
        return g
    return ok(_CLD.aws.iam_users())


@router.get("/cloud/aws/buckets")
def cloud_aws_buckets():
    g = _guard()
    if g:
        return g
    return ok(_CLD.aws.s3_buckets())


@router.get("/cloud/aws/instances")
def cloud_aws_instances():
    g = _guard()
    if g:
        return g
    return ok(_CLD.aws.ec2_instances())


@router.get("/cloud/config/rules")
def cloud_config_rules():
    g = _guard()
    if g:
        return g
    return ok(CONFIG_BASELINE_CHECKS)


@router.post("/cloud/config/audit")
def cloud_config_audit(provider: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_CLD.audit(provider))


# --------------------------------------------------------------------------- #
# 6. 工具状态 / 聚合（2 端点）
# --------------------------------------------------------------------------- #
@router.get("/tools/status")
def tools_status():
    """所有依赖工具真实安装状态。"""
    g = _guard()
    if g:
        return g
    return ok({
        "web": _WEB.tool_status(),
        "internal": _INT.tool_status(),
        "mobile": _MOB.tool_status(),
        "cloud": _CLD.providers_status(),
    })


@router.post("/combined/run")
def combined_run(url: str = Body(..., embed=True)):
    """聚合跑一次（指纹+目录）。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.run_combined(url))
