# -*- coding: utf-8 -*-
"""
api_server/seed_data_routes.py — 种子数据与初始化体验 REST API（36 个端点）。

路由前缀: /api/v1/seed-manager
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；种子数据存内存字典（不写数据库）。

设计定位：管理/评估/检测视角，提供漏洞库/知识库/工具模板/报告模板/KPI/合规控制项
的浏览、筛选与初始化向导能力，不提供攻击载荷。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/seed-manager", tags=["种子数据与初始化"])

# --------------------------------------------------------------------------- #
# 依赖加载（try-import，缺失回退）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from seed_data.seed_manager import get_manager, MODULES, SEED_VERSION
    from seed_data.initialization_wizard import get_wizard
    from seed_data import vulnerability_seeds as vs
    from seed_data import knowledge_seeds as ks
    from seed_data import tool_template_seeds as ts
    from seed_data import report_kpi_compliance_seeds as rkcs
    _MOD_AVAILABLE = True
    logger.info("seed_data_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("seed_data_routes: load failed: %s", e)


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理控制字符与无效 Unicode，防止响应编码失败。"""
    if isinstance(obj, str):
        out = []
        for ch in obj:
            o = ord(ch)
            if o == 0x7F or (o < 0x20 and ch not in "\n\t"):
                out.append(" ")
            else:
                out.append(ch)
        return "".join(out).encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(i) for i in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("种子数据模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ImportRequest(BaseModel):
    modules: Optional[List[str]] = Field(default=None, description="指定模块列表，空则全部")
    on_duplicate: str = Field(default="skip", description="skip | update")


class SingleImportRequest(BaseModel):
    on_duplicate: str = Field(default="skip")


class ResetRequest(BaseModel):
    modules: Optional[List[str]] = Field(default=None)


class InitRequest(BaseModel):
    with_sample: bool = Field(default=True)


# =========================================================================== #
# 1. 种子管理器（11 个端点）
# =========================================================================== #
@router.get("/status")
def get_status():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_manager().overall_status())
    except Exception as e:  # noqa: BLE001
        logger.exception("seed status error")
        return fail(f"查询失败: {e}", 500)


@router.get("/modules")
def list_modules():
    try:
        g = _guard()
        if g:
            return g
        return ok({"modules": get_manager().module_status()})
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.post("/import")
def import_all(req: ImportRequest):
    try:
        g = _guard()
        if g:
            return g
        result = get_manager().import_all(
            modules=req.modules, on_duplicate=req.on_duplicate)
        return ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("import_all error")
        return fail(f"导入失败: {e}", 500)


@router.post("/import/{module}")
def import_one(module: str, req: SingleImportRequest):
    try:
        g = _guard()
        if g:
            return g
        result = get_manager().import_module(module, on_duplicate=req.on_duplicate)
        if not result.get("success"):
            return fail(result.get("error", "导入失败"), 400)
        return ok(result)
    except Exception as e:  # noqa: BLE001
        return fail(f"导入失败: {e}", 500)


@router.post("/reset")
def reset_seeds(req: ResetRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_manager().reset(modules=req.modules))
    except Exception as e:  # noqa: BLE001
        return fail(f"重置失败: {e}", 500)


@router.get("/progress")
def get_progress():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_manager().progress)
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/logs")
def get_logs(limit: int = Query(default=50, ge=1, le=500)):
    try:
        g = _guard()
        if g:
            return g
        return ok({"logs": get_manager().logs(limit=limit)})
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/export/{module}")
def export_one(module: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_manager().export_module(module)
        if not result.get("success"):
            return fail(result.get("error", "导出失败"), 400)
        return ok(result)
    except Exception as e:  # noqa: BLE001
        return fail(f"导出失败: {e}", 500)


@router.get("/export-all")
def export_all():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_manager().export_all())
    except Exception as e:  # noqa: BLE001
        return fail(f"导出失败: {e}", 500)


@router.get("/version")
def get_version():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_manager().version_info())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/version/compare")
def compare_version(other: str = Query(default="0.0.0")):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_manager().compare_version(other))
    except Exception as e:  # noqa: BLE001
        return fail(f"对比失败: {e}", 500)


# =========================================================================== #
# 2. 初始化向导（6 个端点）
# =========================================================================== #
@router.get("/init/detect")
def init_detect():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_wizard().detect_state())
    except Exception as e:  # noqa: BLE001
        return fail(f"检测失败: {e}", 500)


@router.post("/init/run")
def init_run(req: InitRequest):
    try:
        g = _guard()
        if g:
            return g
        result = get_wizard().run(with_sample=req.with_sample)
        return ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("init_run error")
        return fail(f"初始化失败: {e}", 500)


@router.post("/init/sample/generate")
def init_sample_generate():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_wizard().generate_sample_data())
    except Exception as e:  # noqa: BLE001
        return fail(f"示例数据生成失败: {e}", 500)


@router.post("/init/sample/clear")
def init_sample_clear():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_wizard().clear_sample_data())
    except Exception as e:  # noqa: BLE001
        return fail(f"示例数据清除失败: {e}", 500)


@router.get("/init/sample")
def init_sample_get():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_wizard().get_sample_data())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/init/report")
def init_report():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_wizard().get_report())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 3. 漏洞库（5 个端点）
# =========================================================================== #
@router.get("/vulnerabilities")
def list_vulnerabilities(
    severity: Optional[str] = Query(default=None),
    vtype: Optional[str] = Query(default=None, alias="type"),
    product: Optional[str] = Query(default=None),
    keyword: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    try:
        g = _guard()
        if g:
            return g
        return ok(vs.filter_vulns(severity=severity, vtype=vtype, product=product,
                                  keyword=keyword, limit=limit, offset=offset))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/vulnerabilities/stats")
def vuln_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(vs.stats())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/vulnerabilities/types")
def vuln_types():
    try:
        g = _guard()
        if g:
            return g
        s = vs.stats()
        return ok({"types": s["types"], "products": s["products"],
                   "severities": s["severities"]})
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/vulnerabilities/{cve_id}")
def vuln_detail(cve_id: str):
    try:
        g = _guard()
        if g:
            return g
        v = vs.get_by_id(cve_id)
        if not v:
            return fail("CVE 不存在", 404)
        return ok(v)
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 4. 知识库（4 个端点）
# =========================================================================== #
@router.get("/knowledge")
def list_knowledge(
    category: Optional[str] = Query(default=None),
    difficulty: Optional[str] = Query(default=None),
    keyword: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    try:
        g = _guard()
        if g:
            return g
        return ok(ks.filter_knowledge(category=category, difficulty=difficulty,
                                      keyword=keyword, limit=limit, offset=offset))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/knowledge/stats")
def knowledge_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(ks.stats())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/knowledge/detail/{idx}")
def knowledge_detail(idx: int):
    try:
        g = _guard()
        if g:
            return g
        rows = ks.get_all()
        if idx < 0 or idx >= len(rows):
            return fail("知识条目不存在", 404)
        return ok(rows[idx])
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 5. 工具模板（4 个端点）
# =========================================================================== #
@router.get("/tools")
def list_tools(
    ttype: Optional[str] = Query(default=None, alias="type"),
    risk: Optional[str] = Query(default=None),
    keyword: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    try:
        g = _guard()
        if g:
            return g
        return ok(ts.filter_tools(ttype=ttype, risk=risk, keyword=keyword,
                                  limit=limit, offset=offset))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/tools/stats")
def tool_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(ts.stats())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/tools/{name}")
def tool_detail(name: str):
    try:
        g = _guard()
        if g:
            return g
        for t in ts.get_all():
            if t["name"] == name:
                return ok(t)
        return fail("工具不存在", 404)
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 6. 报告模板 / KPI / 合规控制项（7 个端点）
# =========================================================================== #
@router.get("/reports")
def list_reports(keyword: Optional[str] = Query(default=None),
                 limit: int = Query(default=0, ge=0),
                 offset: int = Query(default=0, ge=0)):
    try:
        g = _guard()
        if g:
            return g
        rows = rkcs.get_report_templates()
        if keyword:
            kw = keyword.lower()
            rows = [r for r in rows if kw in r["name"].lower()
                    or kw in r.get("industry", "").lower()]
        total = len(rows)
        if offset:
            rows = rows[offset:]
        if limit:
            rows = rows[:limit]
        return ok({"items": rows, "total": total})
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/reports/{idx}")
def report_detail(idx: int):
    try:
        g = _guard()
        if g:
            return g
        rows = rkcs.get_report_templates()
        if idx < 0 or idx >= len(rows):
            return fail("报告模板不存在", 404)
        return ok(rows[idx])
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/kpis")
def list_kpis(category: Optional[str] = Query(default=None),
              keyword: Optional[str] = Query(default=None),
              limit: int = Query(default=20, ge=1, le=500),
              offset: int = Query(default=0, ge=0)):
    try:
        g = _guard()
        if g:
            return g
        rows = rkcs.get_kpis()
        if category:
            rows = [r for r in rows if r["category"] == category]
        if keyword:
            kw = keyword.lower()
            rows = [r for r in rows if kw in r["name"].lower()
                    or kw in r["definition"].lower()]
        total = len(rows)
        if offset:
            rows = rows[offset:]
        if limit:
            rows = rows[:limit]
        return ok({"items": rows, "total": total})
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/kpis/stats")
def kpi_stats():
    try:
        g = _guard()
        if g:
            return g
        rows = rkcs.get_kpis()
        by_cat: Dict[str, int] = {}
        for r in rows:
            by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
        return ok({"total": len(rows), "by_category": by_cat})
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/compliance")
def list_compliance(
    framework: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    risk: Optional[str] = Query(default=None),
    keyword: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    try:
        g = _guard()
        if g:
            return g
        return ok(rkcs.filter_controls(framework=framework, category=category,
                                       risk=risk, keyword=keyword,
                                       limit=limit, offset=offset))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/compliance/stats")
def compliance_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(rkcs.stats())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.get("/compliance/frameworks")
def compliance_frameworks():
    try:
        g = _guard()
        if g:
            return g
        s = rkcs.stats()
        return ok({"frameworks": list(s["by_framework"].keys()),
                   "counts": s["by_framework"]})
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)
