# -*- coding: utf-8 -*-
"""
visualization_v2_routes 模块 —— 数据可视化深化 REST API（第10轮升级）

模块功能：
    - 实时大屏（数据 / 告警 / 指标 / 趋势）
    - 3D 网络拓扑（生成 / 查询 / 导出 / 布局列表）
    - 攻击地图（生成 / 数据 / 统计 / 导出）
    - 自定义仪表盘（CRUD / 分享 / 模板 / 组件库）

路由前缀：/api/v1/visualization-v2
统一 JSON 响应：{"success": bool, "data": ..., "error": ...}
所有端点均做异常兜底，不向外抛出 500。

定位说明：
    本模块为授权安全运营 / 防御检测产品的可视化接口，
    所有数据均为防御视角统计，请勿用于非法用途。
"""

import os
import sys
from typing import Any, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel

# 保证项目根目录在 sys.path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from visualization.realtime_dashboard import realtime_dashboard  # noqa: E402
from visualization.topology_3d import topology_3d, SUPPORTED_LAYOUTS  # noqa: E402
from visualization.attack_map import attack_map  # noqa: E402
from visualization.custom_dashboard import custom_dashboard  # noqa: E402

router = APIRouter(prefix="/api/v1/visualization-v2", tags=["数据可视化V2"])


# ==================== 请求模型 ====================

class GenerateTopologyRequest(BaseModel):
    """生成 3D 拓扑请求体。"""
    nodes: Optional[list] = None
    links: Optional[list] = None
    layout: Optional[str] = "force"
    options: Optional[dict] = None


class GenerateAttackMapRequest(BaseModel):
    """生成攻击地图请求体。"""
    attack_logs: Optional[list] = None
    map_type: Optional[str] = "world"


class CreateDashboardRequest(BaseModel):
    """创建仪表盘请求体。"""
    name: str = "未命名仪表盘"
    template: Optional[str] = None
    config: Optional[dict] = None


class UpdateDashboardRequest(BaseModel):
    """更新仪表盘请求体。"""
    name: Optional[str] = None
    components: Optional[list] = None
    permission: Optional[str] = None
    global_settings: Optional[dict] = None


class ShareDashboardRequest(BaseModel):
    """分享仪表盘请求体。"""
    password: Optional[str] = None
    expires_in_days: Optional[int] = 7


# ==================== 统一响应辅助 ====================

def _ok(data: Any) -> JSONResponse:
    """成功响应。"""
    return JSONResponse(content={"success": True, "data": data})


def _err(msg: str) -> JSONResponse:
    """失败响应（不抛 500，统一 JSON）。"""
    return JSONResponse(status_code=200, content={"success": False, "error": str(msg)})


# ==================== 实时大屏（4个）====================

@router.get("/realtime/data")
def get_realtime_data() -> JSONResponse:
    """实时大屏综合数据。"""
    try:
        return _ok(realtime_dashboard.get_realtime_data())
    except Exception as e:
        return _err(e)


@router.get("/realtime/alerts")
def get_realtime_alerts(limit: int = 20) -> JSONResponse:
    """实时告警滚动列表。"""
    try:
        return _ok({"alerts": realtime_dashboard.get_alerts(limit=limit)})
    except Exception as e:
        return _err(e)


@router.get("/realtime/metrics")
def get_realtime_metrics() -> JSONResponse:
    """实时关键指标。"""
    try:
        return _ok(realtime_dashboard.get_metrics())
    except Exception as e:
        return _err(e)


@router.get("/realtime/trends")
def get_realtime_trends(hours: int = 24) -> JSONResponse:
    """实时趋势（事件/告警/漏洞/流量）。"""
    try:
        return _ok(realtime_dashboard.get_trends(hours=hours))
    except Exception as e:
        return _err(e)


# ==================== 3D 拓扑（4个）====================

@router.post("/topology-3d/generate")
def generate_topology(req: GenerateTopologyRequest) -> JSONResponse:
    """生成 3D 拓扑。"""
    try:
        topo_id = topology_3d.generate(
            nodes=req.nodes, links=req.links,
            layout=req.layout or "force", options=req.options,
        )
        return _ok({"topology_id": topo_id})
    except Exception as e:
        return _err(e)


@router.get("/topology-3d/layouts")
def list_topology_layouts() -> JSONResponse:
    """可用布局列表。"""
    try:
        return _ok({"layouts": SUPPORTED_LAYOUTS})
    except Exception as e:
        return _err(e)


@router.get("/topology-3d/{topology_id}/data")
def get_topology_data(topology_id: str) -> JSONResponse:
    """获取 3D 拓扑数据。"""
    try:
        data = topology_3d.get_data(topology_id)
        if not data:
            return _err("topology not found")
        return _ok(data)
    except Exception as e:
        return _err(e)


@router.get("/topology-3d/{topology_id}/export")
def export_topology(topology_id: str, format: str = "json"):
    """导出 3D 拓扑（json/html/svg）。"""
    try:
        result = topology_3d.export(topology_id, format)
        if isinstance(result, str) and format in ("html", "svg"):
            return HTMLResponse(content=result)
        return _ok(result)
    except Exception as e:
        return _err(e)


# ==================== 攻击地图（4个）====================

@router.post("/attack-map/generate")
def generate_attack_map(req: GenerateAttackMapRequest) -> JSONResponse:
    """生成攻击地图。"""
    try:
        map_id = attack_map.generate(attack_logs=req.attack_logs, map_type=req.map_type or "world")
        return _ok({"map_id": map_id})
    except Exception as e:
        return _err(e)


@router.get("/attack-map/{map_id}/data")
def get_attack_map_data(map_id: str) -> JSONResponse:
    """获取攻击地图数据。"""
    try:
        data = attack_map.get_map_data(map_id)
        if not data:
            return _err("map not found")
        return _ok(data)
    except Exception as e:
        return _err(e)


@router.get("/attack-map/{map_id}/stats")
def get_attack_map_stats(map_id: str) -> JSONResponse:
    """获取攻击统计。"""
    try:
        stats = attack_map.get_stats(map_id)
        return _ok(stats)
    except Exception as e:
        return _err(e)


@router.get("/attack-map/{map_id}/export")
def export_attack_map(map_id: str, format: str = "json"):
    """导出攻击地图（json/html/csv）。"""
    try:
        fmt = (format or "json").lower()
        if fmt == "html":
            return HTMLResponse(content=attack_map.export_html(map_id))
        if fmt == "csv":
            return JSONResponse(content={"success": True,
                                         "data": {"csv": attack_map.export_csv(map_id)}})
        return _ok(attack_map.export_json(map_id))
    except Exception as e:
        return _err(e)


# ==================== 自定义仪表盘（8个）====================

@router.get("/dashboards")
def list_dashboards(page: int = 1, page_size: int = 20) -> JSONResponse:
    """仪表盘列表。"""
    try:
        return _ok(custom_dashboard.list_dashboards(page=page, page_size=page_size))
    except Exception as e:
        return _err(e)


@router.post("/dashboards")
def create_dashboard(req: CreateDashboardRequest) -> JSONResponse:
    """创建仪表盘。"""
    try:
        return _ok(custom_dashboard.create_dashboard(
            name=req.name, template=req.template, config=req.config))
    except Exception as e:
        return _err(e)


@router.get("/dashboards/templates")
def list_dashboard_templates() -> JSONResponse:
    """模板列表。"""
    try:
        return _ok({"templates": custom_dashboard.get_templates()})
    except Exception as e:
        return _err(e)


@router.get("/dashboards/components")
def list_dashboard_components() -> JSONResponse:
    """组件库列表。"""
    try:
        return _ok({"components": custom_dashboard.get_components()})
    except Exception as e:
        return _err(e)


@router.get("/dashboards/{dashboard_id}")
def get_dashboard(dashboard_id: str) -> JSONResponse:
    """仪表盘详情。"""
    try:
        data = custom_dashboard.get_dashboard(dashboard_id)
        if not data:
            return _err("dashboard not found")
        return _ok(data)
    except Exception as e:
        return _err(e)


@router.put("/dashboards/{dashboard_id}")
def update_dashboard(dashboard_id: str, req: UpdateDashboardRequest) -> JSONResponse:
    """更新仪表盘。"""
    try:
        config = {k: v for k, v in req.dict().items() if v is not None}
        data = custom_dashboard.update_dashboard(dashboard_id, config)
        if not data:
            return _err("dashboard not found")
        return _ok(data)
    except Exception as e:
        return _err(e)


@router.delete("/dashboards/{dashboard_id}")
def delete_dashboard(dashboard_id: str) -> JSONResponse:
    """删除仪表盘。"""
    try:
        ok = custom_dashboard.delete_dashboard(dashboard_id)
        return _ok({"deleted": ok})
    except Exception as e:
        return _err(e)


@router.post("/dashboards/{dashboard_id}/share")
def share_dashboard(dashboard_id: str, req: ShareDashboardRequest) -> JSONResponse:
    """分享仪表盘。"""
    try:
        result = custom_dashboard.share_dashboard(
            dashboard_id, password=req.password,
            expires_in_days=req.expires_in_days or 7)
        return _ok(result)
    except Exception as e:
        return _err(e)
