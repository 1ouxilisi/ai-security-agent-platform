"""
analytics_routes模块 —— 数据分析 REST API。

模块功能：
    - 提供漏洞趋势 / 风险趋势 / 分布统计 / Top 分析 / 评估对比 / 综合摘要 / 导出等接口
    - 所有端点均做异常兜底，统一返回 JSONResponse，不向外抛出 500

路由前缀：/api/v1/analytics

注意事项：
    - 本模块为授权安全评估 / 防御检测产品的数据分析接口
    - 请勿用于非法用途
"""
import os
import sys
from typing import Any, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

# 保证项目根在 sys.path 中（与其它路由模块保持一致）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.analytics import analytics_engine  # noqa: E402

router = APIRouter(prefix="/api/v1/analytics", tags=["数据分析"])


# ==================== 请求模型 ====================

class ExportRequest(BaseModel):
    """导出请求体。"""

    data: Any = None
    format: str = "json"


# ==================== 统一响应辅助 ====================

def _ok(data: Any, extra: Optional[dict] = None) -> JSONResponse:
    """成功响应。"""
    payload = {"success": True, "data": data}
    if extra:
        payload.update(extra)
    return JSONResponse(content=payload)


def _err(msg: str) -> JSONResponse:
    """失败响应（不抛 500，统一 JSON）。"""
    return JSONResponse(status_code=200, content={"success": False, "error": str(msg)})


# ==================== 趋势分析 ====================

@router.get("/trends/vulnerabilities")
def api_trend_vulnerabilities(days: int = 30, group_by: str = "day"):
    """漏洞数量趋势（按日/周/月）。"""
    try:
        data = analytics_engine.trend_vulnerabilities(days=days, group_by=group_by)
        return _ok(data, {"days": days, "group_by": group_by})
    except Exception as e:  # noqa: BLE001
        return _err(f"漏洞趋势查询失败: {e}")


@router.get("/trends/risk")
def api_trend_risk(days: int = 30):
    """风险分趋势。"""
    try:
        data = analytics_engine.trend_risk(days=days)
        return _ok(data, {"days": days})
    except Exception as e:  # noqa: BLE001
        return _err(f"风险趋势查询失败: {e}")


# ==================== 分布统计 ====================

@router.get("/distribution/severity")
def api_distribution_severity(tenant_id: Optional[str] = None):
    """按严重级别分布。"""
    try:
        data = analytics_engine.distribution_by_severity(tenant_id=tenant_id)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(f"严重级别分布查询失败: {e}")


@router.get("/distribution/type")
def api_distribution_type(tenant_id: Optional[str] = None, limit: int = 20):
    """按漏洞类型分布 Top N。"""
    try:
        data = analytics_engine.distribution_by_type(tenant_id=tenant_id, limit=limit)
        return _ok(data, {"limit": limit})
    except Exception as e:  # noqa: BLE001
        return _err(f"漏洞类型分布查询失败: {e}")


# ==================== Top 分析 ====================

@router.get("/top/vulnerabilities")
def api_top_vulnerabilities(n: int = 10, tenant_id: Optional[str] = None):
    """Top N 漏洞类型。"""
    try:
        data = analytics_engine.top_vulnerabilities(n=n, tenant_id=tenant_id)
        return _ok(data, {"n": n})
    except Exception as e:  # noqa: BLE001
        return _err(f"Top 漏洞查询失败: {e}")


@router.get("/top/targets")
def api_top_targets(n: int = 10, tenant_id: Optional[str] = None):
    """风险最高的 Top N 目标。"""
    try:
        data = analytics_engine.top_targets(n=n, tenant_id=tenant_id)
        return _ok(data, {"n": n})
    except Exception as e:  # noqa: BLE001
        return _err(f"Top 目标查询失败: {e}")


# ==================== 评估对比 ====================

@router.get("/compare/{assessment_id1}/{assessment_id2}")
def api_compare(assessment_id1: str, assessment_id2: str):
    """两次评估对比：新增 / 已修复 / 持续存在。"""
    try:
        data = analytics_engine.compare_assessments(assessment_id1, assessment_id2)
        return _ok(data, {"assessment_id1": assessment_id1, "assessment_id2": assessment_id2})
    except Exception as e:  # noqa: BLE001
        return _err(f"评估对比失败: {e}")


# ==================== 综合摘要 ====================

@router.get("/summary")
def api_summary(tenant_id: Optional[str] = None):
    """综合统计摘要。"""
    try:
        data = analytics_engine.get_summary(tenant_id=tenant_id)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(f"综合摘要查询失败: {e}")


# ==================== 导出 ====================

@router.post("/export")
def api_export(req: ExportRequest):
    """导出数据为 JSON 或 CSV。CSV 返回文件下载，JSON 返回 JSON。"""
    try:
        fmt = (req.format or "json").lower()
        content = analytics_engine.export_results(req.data, format=fmt)
        if fmt == "csv":
            return Response(
                content=content,
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="analytics_export.csv"'},
            )
        # json 直接作为 JSON 返回
        import json as _json

        try:
            parsed = _json.loads(content) if isinstance(content, str) else content
        except Exception:  # noqa: BLE001
            parsed = content
        return _ok(parsed)
    except Exception as e:  # noqa: BLE001
        return _err(f"导出失败: {e}")
