# -*- coding: utf-8 -*-
"""
target_lab_manager_routes.py —— 本地靶场一键部署 API（25 个端点）

统一响应：{success, data, error}。
前端页面路由 /target-lab 由集成脚本统一挂载。
仅限授权环境下的安全测试 / 教学 / 演示。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from target_lab_manager import (
    get_lab_manager,
    get_lab_dashboard,
)
from target_lab_manager.lab_manager import detect_docker, NOTICE

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/target-lab", tags=["本地靶场一键部署"])


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                        "error": message}, status_code=status)


class StartBody(BaseModel):
    lab_id: str = Field(..., description="dvwa / juice-shop / webgoat")
    port: Optional[int] = Field(None, description="指定端口，留空自动分配")
    options: Dict[str, Any] = Field(default_factory=dict)


class QuickStartBody(BaseModel):
    lab_id: str = Field(..., description="要启动的靶场 id")


# ----------------------------------------------------------------------
# 仪表盘 / 概览
# ----------------------------------------------------------------------
@router.get("/overview")
def overview():
    """仪表盘聚合：docker 状态 + 实例 + 统计。"""
    try:
        return _ok(get_lab_dashboard().overview().get("data"))
    except Exception as e:  # noqa: BLE001
        logger.exception("lab overview error")
        return _err(500, f"仪表盘加载失败：{e}")


@router.get("/docker")
def docker_status():
    """检测 Docker 是否可用。"""
    try:
        return _ok(detect_docker())
    except Exception as e:  # noqa: BLE001
        return _err(500, f"docker 检测失败：{e}")


@router.get("/supported")
def supported():
    """支持的靶场列表（元数据）。"""
    try:
        return _ok({"labs": get_lab_manager().list_supported(),
                    "notice": NOTICE})
    except Exception as e:  # noqa: BLE001
        return _err(500, f"靶场列表加载失败：{e}")


@router.get("/instances")
def instances():
    """全部靶场实例状态。"""
    try:
        return _ok(get_lab_manager().status_all())
    except Exception as e:  # noqa: BLE001
        return _err(500, f"实例状态加载失败：{e}")


@router.get("/recommend")
def recommend():
    """推荐先启动哪个靶场。"""
    try:
        return _ok(get_lab_dashboard().quick_pick().get("data"))
    except Exception as e:  # noqa: BLE001
        return _err(500, f"推荐加载失败：{e}")


@router.get("/notice")
def notice():
    """授权声明。"""
    return _ok({"notice": NOTICE})


@router.get("/ping")
def ping():
    return _ok({"pong": True, "module": "target-lab-manager"})


# ----------------------------------------------------------------------
# 单实例操作
# ----------------------------------------------------------------------
@router.post("/start")
def start_lab(body: StartBody):
    """启动指定靶场。"""
    try:
        r = get_lab_manager().start(body.lab_id, body.port)
        if not r.get("success"):
            return _err(400, r.get("error", "启动失败"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        logger.exception("start_lab error")
        return _err(500, f"启动失败：{e}")


@router.post("/stop")
def stop_lab(body: QuickStartBody):
    """停止指定靶场。"""
    try:
        r = get_lab_manager().stop(body.lab_id)
        if not r.get("success"):
            return _err(400, r.get("error", "停止失败"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"停止失败：{e}")


@router.post("/restart")
def restart_lab(body: QuickStartBody):
    """重启靶场（先停再起）。"""
    try:
        mgr = get_lab_manager()
        mgr.stop(body.lab_id)
        r = mgr.start(body.lab_id)
        if not r.get("success"):
            return _err(400, r.get("error", "重启失败"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"重启失败：{e}")


@router.get("/instances/{lab_id}")
def instance_status(lab_id: str):
    """单个靶场状态。"""
    try:
        r = get_lab_manager().status(lab_id)
        if not r.get("success"):
            return _err(404, r.get("error", "实例不存在"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"状态查询失败：{e}")


@router.get("/instances/{lab_id}/logs")
def instance_logs(lab_id: str, tail: int = 200):
    """靶场运行日志。"""
    try:
        r = get_lab_manager().logs(lab_id)
        if not r.get("success"):
            return _err(404, r.get("error", "日志不存在"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"日志加载失败：{e}")


@router.get("/instances/{lab_id}/url")
def instance_url(lab_id: str):
    """获取靶场访问地址。"""
    try:
        r = get_lab_manager().status(lab_id)
        if not r.get("success"):
            return _err(404, r.get("error", "实例不存在"))
        return _ok({"url": r["data"].get("url"),
                    "status": r["data"].get("status")})
    except Exception as e:  # noqa: BLE001
        return _err(500, f"URL 查询失败：{e}")


# ----------------------------------------------------------------------
# 一键快速启动（供 Web 渗透页面自动回填）
# ----------------------------------------------------------------------
@router.post("/quick-start/{lab_id}")
def quick_start(lab_id: str):
    """一键启动靶场，直接返回可访问 URL。"""
    try:
        r = get_lab_manager().quick_start_url(lab_id)
        if not r.get("success"):
            return _err(400, r.get("error", "一键启动失败"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        logger.exception("quick_start error")
        return _err(500, f"一键启动失败：{e}")


@router.get("/running-urls")
def running_urls():
    """所有运行中靶场的访问地址列表。"""
    try:
        all_status = get_lab_manager().status_all()
        urls = [
            {"lab_id": i["lab_id"], "name": i["name"], "url": i["url"]}
            for i in all_status.get("instances", [])
            if i.get("status") == "running"
        ]
        return _ok({"urls": urls, "count": len(urls)})
    except Exception as e:  # noqa: BLE001
        return _err(500, f"URL 列表加载失败：{e}")


# ----------------------------------------------------------------------
# 批量操作
# ----------------------------------------------------------------------
@router.post("/start-all")
def start_all():
    """一键启动全部靶场。"""
    try:
        mgr = get_lab_manager()
        results = []
        for lab in mgr.list_supported():
            r = mgr.start(lab["lab_id"])
            results.append({"lab_id": lab["lab_id"],
                            "success": r.get("success"),
                            "url": (r.get("data") or {}).get("url")})
        return _ok({"results": results})
    except Exception as e:  # noqa: BLE001
        return _err(500, f"批量启动失败：{e}")


@router.post("/stop-all")
def stop_all():
    """一键停止全部靶场。"""
    try:
        mgr = get_lab_manager()
        results = []
        for lab in mgr.list_supported():
            r = mgr.stop(lab["lab_id"])
            results.append({"lab_id": lab["lab_id"],
                            "success": r.get("success")})
        return _ok({"results": results})
    except Exception as e:  # noqa: BLE001
        return _err(500, f"批量停止失败：{e}")


# ----------------------------------------------------------------------
# 辅助信息
# ----------------------------------------------------------------------
@router.get("/vuln-types")
def vuln_types():
    """各靶场覆盖的漏洞类型。"""
    try:
        return _ok({"labs": [
            {"lab_id": i["lab_id"], "vuln_types": i["vuln_types"]}
            for i in get_lab_manager().list_supported()
        ]})
    except Exception as e:  # noqa: BLE001
        return _err(500, f"漏洞类型加载失败：{e}")


@router.get("/docs/{lab_id}")
def lab_docs(lab_id: str):
    """靶场简要说明。"""
    try:
        for lab in get_lab_manager().list_supported():
            if lab["lab_id"] == lab_id:
                return _ok(lab)
        return _err(404, f"未知靶场 {lab_id}")
    except Exception as e:  # noqa: BLE001
        return _err(500, f"文档加载失败：{e}")


@router.get("/logs/all")
def all_logs():
    """汇总所有靶场日志。"""
    try:
        mgr = get_lab_manager()
        out = {}
        for lab in mgr.list_supported():
            r = mgr.logs(lab["lab_id"])
            out[lab["lab_id"]] = (r.get("data") or {}).get("logs", [])
        return _ok({"logs": out})
    except Exception as e:  # noqa: BLE001
        return _err(500, f"日志汇总失败：{e}")


@router.get("/ports")
def port_status():
    """各靶场当前端口占用情况。"""
    try:
        return _ok({"instances": get_lab_manager().status_all()["instances"]})
    except Exception as e:  # noqa: BLE001
        return _err(500, f"端口状态加载失败：{e}")


@router.post("/start-with-options")
def start_with_options(body: StartBody):
    """带 options 的启动（options 预留扩展）。"""
    try:
        r = get_lab_manager().start(body.lab_id, body.port)
        if not r.get("success"):
            return _err(400, r.get("error", "启动失败"))
        data = dict(r["data"])
        data["options"] = body.options
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"带选项启动失败：{e}")


@router.post("/docker-pull/{lab_id}")
def docker_pull(lab_id: str):
    """提示拉取 docker 镜像（实际拉取由管理员手动执行）。"""
    try:
        for lab in get_lab_manager().list_supported():
            if lab["lab_id"] == lab_id:
                return _ok({"message": f"请手动执行：docker pull {lab['docker_image']}",
                            "image": lab["docker_image"]})
        return _err(404, f"未知靶场 {lab_id}")
    except Exception as e:  # noqa: BLE001
        return _err(500, f"拉取提示失败：{e}")


@router.get("/health")
def health():
    """聚合健康检查：docker 可用性 + 实例数量。"""
    try:
        all_status = get_lab_manager().status_all()
        return _ok({
            "docker_available": all_status.get("docker", {}).get("available"),
            "instances": len(all_status.get("instances", [])),
            "running": sum(1 for i in all_status.get("instances", [])
                          if i.get("status") == "running"),
        })
    except Exception as e:  # noqa: BLE001
        return _err(500, f"健康检查失败：{e}")


@router.post("/stop/{lab_id}")
def stop_lab_alt(lab_id: str):
    """按路径参数停止靶场。"""
    try:
        r = get_lab_manager().stop(lab_id)
        if not r.get("success"):
            return _err(400, r.get("error", "停止失败"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"停止失败：{e}")


@router.post("/start/{lab_id}")
def start_lab_alt(lab_id: str, port: Optional[int] = Query(None)):
    """按路径参数启动靶场。"""
    try:
        r = get_lab_manager().start(lab_id, port)
        if not r.get("success"):
            return _err(400, r.get("error", "启动失败"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"启动失败：{e}")
