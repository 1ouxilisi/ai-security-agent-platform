# -*- coding: utf-8 -*-
"""
api_server/tools_installer_routes.py — 真实工具一键安装 API

路由前缀：/api/v1/tools-installer
统一响应：{success, data, error}
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from tools_installer import tool_registry as reg
from tools_installer import package_manager as pm
from tools_installer import tool_detector
from tools_installer import tool_installer
from tools_installer.tools_dashboard import get_dashboard

router = APIRouter(prefix="/api/v1/tools-installer", tags=["工具一键安装"])


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _err(status: int, message: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": data, "error": message},
                        status_code=status)


class InstallBody(BaseModel):
    tool: str = Field(..., description="工具 name")
    custom_cmd: Optional[str] = Field(None, description="自定义安装命令")
    run_async: bool = True


class BatchBody(BaseModel):
    run_async: bool = True


# ---------------------------------------------------------------------------
# 仪表盘 / 概览
# ---------------------------------------------------------------------------
@router.get("/dashboard", summary="工具仪表盘")
def dashboard():
    try:
        return _ok(get_dashboard())
    except Exception as e:  # noqa: BLE001
        return _err(500, f"仪表盘加载失败: {e}")


@router.get("/overview", summary="安装概览统计")
def overview():
    d = get_dashboard()
    return _ok({
        "native": d["native"], "python_libs": d["python_libs"],
        "docker_images": d["docker_images"],
        "pm_ready": d["pm_ready"], "pm_missing": d["pm_missing"],
    })


@router.get("/notice", summary="授权声明")
def notice():
    return _ok({"notice": "仅限授权环境：所有工具仅用于授权安全测试 / 教学 / 演示。"})


# ---------------------------------------------------------------------------
# 工具清单
# ---------------------------------------------------------------------------
@router.get("/tools", summary="原生工具清单（含实时检测）")
def list_native_tools(category: Optional[str] = Query(None)):
    try:
        detected = tool_detector.detect_all_tools()
        items = detected["native"]["items"]
        if category:
            items = [i for i in items if i["category"] == category]
        return _ok({"items": items, "summary": detected["native"]["summary"],
                    "categories": reg.get_categories()})
    except Exception as e:  # noqa: BLE001
        return _err(500, f"工具列表加载失败: {e}")


@router.get("/tools/{name}", summary="单个工具详情")
def tool_detail(name: str):
    tool = reg.find_tool(name)
    if not tool:
        return _err(404, f"未知工具 {name}")
    info = tool_detector.detect_one(tool)
    return _ok({"meta": tool, "detected": info})


@router.get("/libs", summary="Python 库清单")
def list_libs():
    detected = tool_detector.detect_all_tools()
    return _ok({"items": detected["python_libs"]["items"],
                "summary": detected["python_libs"]["summary"],
                "categories": reg.get_python_lib_categories()})


@router.get("/images", summary="Docker 镜像清单")
def list_images():
    detected = tool_detector.detect_all_tools()
    return _ok({"items": detected["docker_images"]["items"],
                "summary": detected["docker_images"]["summary"],
                "categories": reg.get_docker_image_categories()})


@router.get("/categories", summary="工具分类")
def categories():
    return _ok({"native": reg.get_categories(),
                "python_libs": reg.get_python_lib_categories(),
                "docker_images": reg.get_docker_image_categories()})


@router.get("/search", summary="按关键字搜索工具")
def search(q: str = Query(..., min_length=1)):
    ql = q.lower()
    out = []
    for t in reg.get_native_tools() + reg.get_python_libs() + reg.get_docker_images():
        if ql in t["name"].lower() or ql in t["display"].lower() \
                or ql in t.get("description", "").lower():
            out.append({"name": t["name"], "display": t["display"],
                        "category": t["category"],
                        "description": t.get("description", "")})
    return _ok({"query": q, "results": out, "count": len(out)})


# ---------------------------------------------------------------------------
# 包管理器
# ---------------------------------------------------------------------------
@router.get("/package-managers", summary="包管理器状态")
def package_managers():
    return _ok(pm.detect_all())


@router.get("/package-managers/{name}", summary="单个包管理器状态")
def package_manager_detail(name: str):
    all_pm = pm.detect_all()
    if name not in all_pm:
        return _err(404, f"未知包管理器 {name}")
    return _ok({"name": name, "info": all_pm[name]})


# ---------------------------------------------------------------------------
# 检测 / 健康
# ---------------------------------------------------------------------------
@router.post("/detect", summary="重新检测所有工具")
def redetect():
    detected = tool_detector.detect_all_tools()
    return _ok(detected)


@router.get("/health/{name}", summary="单个工具健康检查")
def health(name: str):
    return _ok(tool_detector.health_check(name).get("data"))


@router.post("/health-check-all", summary="全部工具健康检查")
def health_all():
    detected = tool_detector.detect_all_tools()
    broken = []
    for section in ("native", "python_libs", "docker_images"):
        for item in detected[section]["items"]:
            if item.get("status") == "broken":
                broken.append({"name": item["name"], "section": section})
            if item.get("missing_deps"):
                broken.append({"name": item["name"],
                               "missing_deps": item["missing_deps"]})
    return _ok({"broken": broken, "count": len(broken)})


# ---------------------------------------------------------------------------
# 安装 / 升级 / 卸载 / 修复
# ---------------------------------------------------------------------------
@router.post("/install", summary="安装单个工具")
def install(body: InstallBody):
    r = tool_installer.install_tool(body.tool, body.custom_cmd, body.run_async)
    if not r.get("success"):
        return _err(400, r.get("error", "安装失败"))
    return _ok(r)


@router.post("/install-all", summary="批量安装所有未安装工具")
def install_all(body: BatchBody):
    r = tool_installer.install_all_uninstalled(body.run_async)
    return _ok(r)


@router.post("/upgrade/{name}", summary="升级工具")
def upgrade(name: str):
    r = tool_installer.upgrade_tool(name)
    if not r.get("success"):
        return _err(400, r.get("error", "升级失败"))
    return _ok(r)


@router.post("/uninstall/{name}", summary="卸载工具")
def uninstall(name: str):
    r = tool_installer.uninstall_tool(name)
    if not r.get("success"):
        return _err(400, r.get("error", "卸载失败"))
    return _ok(r)


@router.post("/fix/{name}", summary="修复工具（重装）")
def fix(name: str):
    r = tool_installer.fix_tool(name)
    if not r.get("success"):
        return _err(400, r.get("error", "修复失败"))
    return _ok(r)


# ---------------------------------------------------------------------------
# 安装任务
# ---------------------------------------------------------------------------
@router.get("/tasks", summary="任务列表")
def tasks(limit: int = 50):
    return _ok(tool_installer.list_tasks(limit))


@router.get("/tasks/{task_id}", summary="任务详情（含日志）")
def task_detail(task_id: str):
    r = tool_installer.get_task(task_id)
    if not r.get("success"):
        return _err(404, r.get("error", "任务不存在"))
    return _ok(r["data"])


@router.get("/tasks/{task_id}/logs", summary="任务日志")
def task_logs(task_id: str, tail: int = 200):
    r = tool_installer.get_task(task_id)
    if not r.get("success"):
        return _err(404, r.get("error", "任务不存在"))
    logs = r["data"].get("logs", [])
    return _ok({"task_id": task_id, "logs": logs[-tail:],
                "total": len(logs)})


# ---------------------------------------------------------------------------
# 依赖
# ---------------------------------------------------------------------------
@router.get("/deps/{name}", summary="查看工具依赖")
def deps(name: str):
    tool = reg.find_tool(name)
    if not tool:
        return _err(404, f"未知工具 {name}")
    info = tool_detector.detect_one(tool)
    return _ok({"name": name, "deps": tool.get("deps", []),
                "missing_deps": info.get("missing_deps", [])})


@router.post("/install-deps/{name}", summary="一键安装缺失依赖")
def install_deps(name: str):
    tool = reg.find_tool(name)
    if not tool:
        return _err(404, f"未知工具 {name}")
    results = []
    for dep in tool.get("deps", []):
        r = tool_installer.install_tool(dep)
        results.append({"dep": dep, "task_id": r.get("task_id")})
    return _ok({"results": results})


# ---------------------------------------------------------------------------
# 安装命令自定义
# ---------------------------------------------------------------------------
@router.get("/install-cmd/{name}", summary="查看工具安装命令")
def install_cmd(name: str):
    tool = reg.find_tool(name)
    if not tool:
        return _err(404, f"未知工具 {name}")
    return _ok({"name": name, "cmd": tool.get("install", {}).get("cmd"),
                "method": tool.get("install", {}).get("method")})


@router.post("/install-custom", summary="执行自定义安装命令")
def install_custom(body: InstallBody):
    if not body.custom_cmd:
        return _err(400, "custom_cmd 不能为空")
    # 不绑定注册表工具，直接作为匿名任务
    return _ok(tool_installer.install_tool(body.tool, body.custom_cmd,
                                            body.run_async))


# ---------------------------------------------------------------------------
# 版本
# ---------------------------------------------------------------------------
@router.get("/versions", summary="所有工具当前版本")
def versions():
    detected = tool_detector.detect_all_tools()
    out = []
    for section in ("native", "python_libs", "docker_images"):
        for item in detected[section]["items"]:
            out.append({"name": item["name"], "version": item.get("version"),
                        "installed": item["installed"],
                        "status": item.get("status"),
                        "section": section})
    return _ok({"versions": out, "count": len(out)})


@router.post("/upgrade-all-outdated", summary="升级所有已安装工具")
def upgrade_all_outdated():
    detected = tool_detector.detect_all_tools()
    targets = []
    for section in ("native", "python_libs", "docker_images"):
        for item in detected[section]["items"]:
            if item["installed"] and item.get("status") == "installed":
                targets.append(item["name"])
    results = [tool_installer.upgrade_tool(n) for n in targets]
    return _ok({"count": len(targets), "results": results})


# ---------------------------------------------------------------------------
# 快捷
# ---------------------------------------------------------------------------
@router.get("/quick/{section}", summary="按 section 快速获取")
def quick(section: str):
    if section not in ("native", "python_libs", "docker_images"):
        return _err(400, "section 必须是 native/python_libs/docker_images")
    detected = tool_detector.detect_all_tools()
    return _ok(detected[section])


@router.get("/count", summary="工具总数")
def count():
    return _ok({
        "native": len(reg.get_native_tools()),
        "python_libs": len(reg.get_python_libs()),
        "docker_images": len(reg.get_docker_images()),
    })


@router.post("/reinstall/{name}", summary="重装工具")
def reinstall(name: str):
    r = tool_installer.install_tool(name)
    return _ok(r)


@router.post("/install-by-category/{cat}", summary="按分类批量安装")
def install_by_category(cat: str):
    detected = tool_detector.detect_all_tools()
    pending = [i["name"] for i in detected["native"]["items"]
               if i["category"] == cat and not i["installed"]]
    results = [tool_installer.install_tool(n) for n in pending]
    return _ok({"category": cat, "pending": pending, "results": results})


@router.get("/native/{name}", summary="原生工具详情")
def native_detail(name: str):
    return tool_detail(name)


@router.get("/lib/{name}", summary="Python 库详情")
def lib_detail(name: str):
    return tool_detail(name)


@router.get("/image/{name}", summary="Docker 镜像详情")
def image_detail(name: str):
    return tool_detail(name)


@router.get("/pm/{name}/install-hint", summary="包管理器安装指引")
def pm_hint(name: str):
    all_pm = pm.detect_all()
    if name not in all_pm:
        return _err(404, f"未知包管理器 {name}")
    info = all_pm[name]
    return _ok({"name": name, "available": info.get("available"),
                "install_url": info.get("install_url"),
                "install_cmd": info.get("install_cmd")})


@router.post("/install-with-deps/{name}", summary="安装工具并装依赖")
def install_with_deps(name: str):
    r = tool_installer.install_tool(name)
    tool = reg.find_tool(name)
    dep_results = []
    if tool:
        for dep in tool.get("deps", []):
            dep_results.append(tool_installer.install_tool(dep))
    return _ok({"install": r, "deps": dep_results})


@router.get("/export-list", summary="导出工具清单")
def export_list():
    return _ok({"native": reg.get_native_tools(),
                "python_libs": reg.get_python_libs(),
                "docker_images": reg.get_docker_images()})


@router.get("/suggest", summary="推荐先装哪些工具")
def suggest():
    detected = tool_detector.detect_all_tools()
    must = ["nmap", "git", "python", "curl", "docker", "subfinder",
            "httpx", "sqlmap", "impacket"]
    out = []
    for item in detected["native"]["items"] + detected["python_libs"]["items"]:
        if item["name"] in must and not item["installed"]:
            out.append(item)
    return _ok({"suggested": out, "count": len(out)})


@router.get("/logs/{task_id}/tail", summary="任务日志尾部")
def task_logs_tail(task_id: str, lines: int = 50):
    r = tool_installer.get_task(task_id)
    if not r.get("success"):
        return _err(404, r.get("error", "任务不存在"))
    logs = r["data"].get("logs", [])
    return _ok({"task_id": task_id, "tail": logs[-lines:]})


@router.get("/verify/{name}", summary="验证工具是否可用")
def verify_tool(name: str):
    tool = reg.find_tool(name)
    if not tool:
        return _err(404, f"未知工具 {name}")
    info = tool_detector.detect_one(tool, timeout=10)
    ok = info["installed"] and info["healthy"] and not info["missing_deps"]
    return _ok({"name": name, "verifiable": ok, "detail": info})


@router.get("/by-category", summary="按分类分组的工具")
def by_category():
    return _ok(reg.all_tools_grouped())


@router.post("/cancel/{task_id}", summary="取消安装任务（标记）")
def cancel_task(task_id: str):
    r = tool_installer.get_task(task_id)
    if not r.get("success"):
        return _err(404, r.get("error", "任务不存在"))
    return _ok({"task_id": task_id, "canceled": True,
                "note": "子进程由系统超时控制终止，此处仅标记"})


@router.get("/ping", summary="健康检查端点")
def ping():
    return _ok({"pong": True, "module": "tools-installer"})
