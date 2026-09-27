# -*- coding: utf-8 -*-
"""
vuln_db_routes.py - FastAPI routes for the deep vulnerability database.

All endpoints wrapped in try/except to avoid 500s.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vuln-db", tags=["漏洞库"])

# Try-import the database modules; on failure we still mount the router but
# every endpoint returns 503.
_DB_AVAILABLE = False
try:
    from vuln_database.cve_database import (
        get_cve, search_cve, match_cve_by_service,
        get_cve_stats, list_cves,
    )
    from vuln_database.exploit_db import (
        get_exploit_by_cve, list_exploits, search_exploits,
    )
    from vuln_database.remediation_db import (
        get_remediation_by_cve, list_remediations, search_remediations,
    )
    _DB_AVAILABLE = True
    logger.info("vuln_db_routes: vulnerability database loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("vuln_db_routes: failed to load vuln_database: %s", e)

    def _unavailable(*_a, **_kw):
        return None


class ServiceMatchRequest(BaseModel):
    service: str = ""
    version: str = ""


def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"code": 0, "data": data})


def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"code": status, "error": message}, status_code=status)


def _guard() -> Optional[JSONResponse]:
    if not _DB_AVAILABLE:
        return _err(503, "漏洞库模块不可用，请检查 vuln_database 加载日志")
    return None


@router.get("/cve")
def cve_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    keyword: Optional[str] = None,
    product: Optional[str] = None,
    vuln_type: Optional[str] = None,
    severity: Optional[str] = None,
    cvss_min: Optional[float] = None,
    year: Optional[int] = None,
    sort_by: str = "cvss_score",
    sort_order: str = "desc",
):
    """CVE 列表（支持搜索 + 分页 + 排序）。"""
    try:
        g = _guard()
        if g is not None:
            return g
        if any([keyword, product, vuln_type, severity, cvss_min, year]):
            items = search_cve(
                keyword=keyword, product=product, vuln_type=vuln_type,
                severity=severity, cvss_min=cvss_min, year=year,
            )
            total = len(items)
            page = max(1, int(page))
            page_size = max(1, min(500, int(page_size)))
            start = (page - 1) * page_size
            end = start + page_size
            items = items[start:end]
            return _ok({
                "total": total, "page": page, "page_size": page_size,
                "total_pages": (total + page_size - 1) // page_size,
                "items": items,
            })
        return _ok(list_cves(page=page, page_size=page_size,
                             sort_by=sort_by, sort_order=sort_order))
    except Exception as e:
        logger.exception("cve_list error")
        return _err(500, f"查询失败: {e}")


@router.get("/cve/search")
def cve_search(q: str = Query("", description="关键词")):
    """按关键词搜索 CVE。"""
    try:
        g = _guard()
        if g is not None:
            return g
        results = search_cve(keyword=q)
        return _ok({"total": len(results), "items": results[:50]})
    except Exception as e:
        logger.exception("cve_search error")
        return _err(500, f"搜索失败: {e}")


@router.get("/cve/{cve_id}")
def cve_detail(cve_id: str):
    """CVE 详情。"""
    try:
        g = _guard()
        if g is not None:
            return g
        rec = get_cve(cve_id)
        if not rec:
            return _err(404, f"未找到 {cve_id}")
        return _ok(rec)
    except Exception as e:
        logger.exception("cve_detail error")
        return _err(500, f"查询失败: {e}")


@router.post("/cve/match")
def cve_match(body: ServiceMatchRequest):
    """按服务名+版本匹配可能存在的 CVE。"""
    try:
        g = _guard()
        if g is not None:
            return g
        items = match_cve_by_service(body.service, body.version or "")
        return _ok({"total": len(items), "items": items})
    except Exception as e:
        logger.exception("cve_match error")
        return _err(500, f"匹配失败: {e}")


@router.get("/exploit")
def exploit_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    keyword: Optional[str] = None,
    vuln_type: Optional[str] = None,
):
    """利用方式列表。"""
    try:
        g = _guard()
        if g is not None:
            return g
        if keyword or vuln_type:
            items = search_exploits(keyword=keyword, vuln_type=vuln_type)
            total = len(items)
            start = (page - 1) * page_size
            return _ok({
                "total": total, "page": page, "page_size": page_size,
                "total_pages": (total + page_size - 1) // page_size,
                "items": items[start:start + page_size],
            })
        return _ok(list_exploits(page=page, page_size=page_size))
    except Exception as e:
        logger.exception("exploit_list error")
        return _err(500, f"查询失败: {e}")


@router.get("/exploit/{cve_id}")
def exploit_detail(cve_id: str):
    """指定 CVE 的利用方式。"""
    try:
        g = _guard()
        if g is not None:
            return g
        rec = get_exploit_by_cve(cve_id)
        if not rec:
            return _err(404, f"未找到 {cve_id} 的利用记录")
        return _ok(rec)
    except Exception as e:
        logger.exception("exploit_detail error")
        return _err(500, f"查询失败: {e}")


@router.get("/remediation")
def remediation_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    keyword: Optional[str] = None,
    vuln_type: Optional[str] = None,
    priority: Optional[str] = None,
):
    """修复方案列表。"""
    try:
        g = _guard()
        if g is not None:
            return g
        if keyword or vuln_type or priority:
            items = search_remediations(keyword=keyword, vuln_type=vuln_type,
                                        priority=priority)
            total = len(items)
            start = (page - 1) * page_size
            return _ok({
                "total": total, "page": page, "page_size": page_size,
                "total_pages": (total + page_size - 1) // page_size,
                "items": items[start:start + page_size],
            })
        return _ok(list_remediations(page=page, page_size=page_size))
    except Exception as e:
        logger.exception("remediation_list error")
        return _err(500, f"查询失败: {e}")


@router.get("/remediation/{cve_id}")
def remediation_detail(cve_id: str):
    """指定 CVE 的修复方案。"""
    try:
        g = _guard()
        if g is not None:
            return g
        rec = get_remediation_by_cve(cve_id)
        if not rec:
            return _err(404, f"未找到 {cve_id} 的修复方案")
        return _ok(rec)
    except Exception as e:
        logger.exception("remediation_detail error")
        return _err(500, f"查询失败: {e}")


@router.get("/stats")
def stats():
    """漏洞库统计。"""
    try:
        g = _guard()
        if g is not None:
            return g
        return _ok(get_cve_stats())
    except Exception as e:
        logger.exception("stats error")
        return _err(500, f"统计失败: {e}")
