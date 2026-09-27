# -*- coding: utf-8 -*-
"""
api_server/target_lab_real_routes.py — 真实靶场一键部署 API

路由前缀：/api/v1/target-lab-real
统一响应：{success, data, error}
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from target_lab_real import docker_manager
from target_lab_real import lab_deployer
from target_lab_real import lab_registry
from target_lab_real import lab_template
from target_lab_real.lab_config import LabDeployConfig, PRESETS, RESTART_POLICIES, NETWORK_MODES
from target_lab_real.labs_dashboard import get_dashboard

router = APIRouter(prefix="/api/v1/target-lab-real", tags=["真实靶场一键部署"])


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _err(status: int, message: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": data, "error": message},
                        status_code=status)


class DeployBody(BaseModel):
    lab_id: str = Field(..., description="靶场 id")
    host_port: Optional[int] = None
    env: Dict[str, str] = Field(default_factory=dict)
    volumes: Dict[str, str] = Field(default_factory=dict)
    cpu_limit: Optional[str] = None
    memory_limit: Optional[str] = None
    network: str = "bridge"
    restart: str = "no"
    preset: Optional[str] = None


class InstanceBody(BaseModel):
    instance_id: str


class TemplateBody(BaseModel):
    name: str
    description: str = ""
    config: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# 仪表盘
# ---------------------------------------------------------------------------
@router.get("/dashboard", summary="靶场仪表盘")
def dashboard():
    return _ok(get_dashboard())


@router.get("/overview", summary="概览统计")
def overview():
    d = get_dashboard()
    return _ok({"stats": d["stats"], "docker": d["docker"]})


@router.get("/notice", summary="授权声明")
def notice():
    return _ok({"notice": lab_deployer.NOTICE})


@router.get("/ping", summary="健康检查")
def ping():
    return _ok({"pong": True, "module": "target-lab-real"})


# ---------------------------------------------------------------------------
# 靶场清单
# ---------------------------------------------------------------------------
@router.get("/labs", summary="可用靶场清单")
def labs():
    return _ok({"labs": lab_registry.list_labs(),
                "categories": lab_registry.list_categories()})


@router.get("/labs/{lab_id}", summary="单个靶场详情")
def lab_detail(lab_id: str):
    lab = lab_registry.get_lab(lab_id)
    if not lab:
        return _err(404, f"未知靶场 {lab_id}")
    return _ok(lab)


@router.get("/labs-by-category", summary="按分类分组")
def by_category():
    return _ok(lab_registry.labs_by_category())


@router.get("/search", summary="搜索靶场")
def search(q: str = Query(..., min_length=1)):
    ql = q.lower()
    out = [l for l in lab_registry.list_labs()
           if ql in l["name"].lower() or ql in l["description"].lower()
           or ql in l["lab_id"].lower()]
    return _ok({"results": out, "count": len(out)})


# ---------------------------------------------------------------------------
# Docker 状态
# ---------------------------------------------------------------------------
@router.get("/docker", summary="Docker 状态")
def docker_status():
    return _ok(docker_manager.docker_available())


@router.get("/docker/images", summary="本地镜像列表")
def docker_images():
    return _ok({"images": docker_manager.list_images()})


@router.get("/docker/containers", summary="容器列表")
def docker_containers():
    return _ok({"containers": docker_manager.list_containers()})


# ---------------------------------------------------------------------------
# 部署操作
# ---------------------------------------------------------------------------
@router.post("/deploy", summary="一键部署靶场")
def deploy(body: DeployBody):
    cfg = LabDeployConfig(
        host_ports=None,
        env=body.env, volumes=body.volumes,
        cpu_limit=body.cpu_limit, memory_limit=body.memory_limit,
        network=body.network, restart=body.restart)
    if body.preset and body.preset in PRESETS:
        p = PRESETS[body.preset]
        cfg.cpu_limit = p.get("cpu_limit", cfg.cpu_limit)
        cfg.memory_limit = p.get("memory_limit", cfg.memory_limit)
    r = lab_deployer.deploy(body.lab_id, cfg, body.host_port)
    if not r.get("success"):
        return _err(400, r.get("error", "部署失败"))
    return _ok(r["data"])


@router.post("/stop", summary="停止靶场")
def stop(body: InstanceBody):
    r = lab_deployer.stop(body.instance_id)
    if not r.get("success"):
        return _err(400, r.get("error", "停止失败"))
    return _ok(r["data"])


@router.post("/restart", summary="重启靶场")
def restart(body: InstanceBody):
    r = lab_deployer.restart(body.instance_id)
    if not r.get("success"):
        return _err(400, r.get("error", "重启失败"))
    return _ok(r["data"])


@router.post("/destroy", summary="销毁靶场（删容器）")
def destroy(body: InstanceBody, remove_image: bool = False):
    r = lab_deployer.destroy(body.instance_id, remove_image=remove_image)
    if not r.get("success"):
        return _err(400, r.get("error", "销毁失败"))
    return _ok(r["data"])


@router.get("/instances", summary="全部实例")
def instances():
    return _ok({"instances": lab_deployer.list_instances()})


@router.get("/instances/{instance_id}", summary="单个实例详情")
def instance_detail(instance_id: str):
    inst = lab_deployer.get_instance(instance_id)
    if not inst:
        return _err(404, "实例不存在")
    return _ok(inst)


@router.get("/instances/{instance_id}/logs", summary="实例日志")
def instance_logs(instance_id: str, tail: int = 200):
    r = lab_deployer.logs(instance_id, tail)
    if not r.get("success"):
        return _err(404, r.get("error", "日志不存在"))
    return _ok(r["data"])


@router.get("/instances/{instance_id}/stats", summary="资源使用")
def instance_stats(instance_id: str):
    r = lab_deployer.stats(instance_id)
    if not r.get("success"):
        return _err(404, r.get("error", "统计不存在"))
    return _ok(r["data"])


@router.get("/instances/{instance_id}/url", summary="访问 URL")
def instance_url(instance_id: str):
    inst = lab_deployer.get_instance(instance_id)
    if not inst:
        return _err(404, "实例不存在")
    return _ok({"url": inst.get("url"), "status": inst.get("status")})


# ---------------------------------------------------------------------------
# 模板
# ---------------------------------------------------------------------------
@router.get("/templates", summary="模板列表")
def list_templates():
    return _ok({"templates": lab_template.list_templates()})


@router.get("/templates/{tid}", summary="模板详情")
def get_template(tid: str):
    t = lab_template.get_template(tid)
    if not t:
        return _err(404, "模板不存在")
    return _ok(t)


@router.post("/templates", summary="创建模板")
def create_template(body: TemplateBody):
    return _ok(lab_template.create_template(body.name, body.description,
                                            body.config))


@router.put("/templates/{tid}", summary="更新模板")
def update_template(tid: str, body: TemplateBody):
    ok = lab_template.update_template(tid, body.name, body.description,
                                      body.config)
    if not ok:
        return _err(404, "模板不存在")
    return _ok({"updated": True})


@router.delete("/templates/{tid}", summary="删除模板")
def delete_template(tid: str):
    ok = lab_template.delete_template(tid)
    if not ok:
        return _err(404, "模板不存在")
    return _ok({"deleted": True})


@router.get("/templates/export/all", summary="导出模板")
def export_templates():
    return _ok(lab_template.export_templates())


@router.post("/templates/import", summary="导入模板")
def import_templates(data: Dict[str, Any]):
    return _ok({"added": lab_template.import_templates(data)})


# ---------------------------------------------------------------------------
# 配置项
# ---------------------------------------------------------------------------
@router.get("/config/options", summary="部署配置可选项")
def config_options():
    return _ok({"restart_policies": RESTART_POLICIES,
                "network_modes": NETWORK_MODES,
                "presets": PRESETS})


@router.get("/config/presets", summary="资源预设")
def presets():
    return _ok(PRESETS)


# ---------------------------------------------------------------------------
# 批量 / 快捷
# ---------------------------------------------------------------------------
@router.post("/deploy-quick/{lab_id}", summary="快速部署（默认配置）")
def deploy_quick(lab_id: str, host_port: Optional[int] = None):
    r = lab_deployer.deploy(lab_id, LabDeployConfig(), host_port)
    if not r.get("success"):
        return _err(400, r.get("error", "部署失败"))
    return _ok(r["data"])


@router.get("/running", summary="运行中实例")
def running():
    insts = lab_deployer.list_instances()
    return _ok({"instances": [i for i in insts if i.get("status") == "running"]})


@router.get("/running-urls", summary="运行中 URL 列表")
def running_urls():
    insts = lab_deployer.list_instances()
    urls = [{"instance_id": i["instance_id"], "name": i["name"],
             "url": i.get("url")}
            for i in insts if i.get("status") == "running" and i.get("url")]
    return _ok({"urls": urls, "count": len(urls)})


@router.post("/stop-all", summary="停止全部")
def stop_all():
    insts = lab_deployer.list_instances()
    results = [lab_deployer.stop(i["instance_id"]) for i in insts
               if i.get("status") == "running"]
    return _ok({"stopped": len(results)})


@router.post("/destroy-all", summary="销毁全部")
def destroy_all():
    insts = lab_deployer.list_instances()
    results = [lab_deployer.destroy(i["instance_id"]) for i in insts]
    return _ok({"destroyed": len(results)})


@router.post("/health/{instance_id}", summary="手动健康检查")
def health(instance_id: str):
    inst = lab_deployer.get_instance(instance_id)
    if not inst:
        return _err(404, "实例不存在")
    return _ok({"instance_id": instance_id,
                "health": inst.get("health"), "url": inst.get("url")})


@router.get("/docker/pull-hint/{lab_id}", summary="拉取镜像提示")
def pull_hint(lab_id: str):
    lab = lab_registry.get_lab(lab_id)
    if not lab:
        return _err(404, "靶场不存在")
    return _ok({"cmd": f"docker pull {lab['image']}", "image": lab["image"]})


@router.get("/count", summary="靶场数量")
def count():
    return _ok({"labs": len(lab_registry.list_labs()),
                "instances": len(lab_deployer.list_instances())})


@router.post("/redeploy/{instance_id}", summary="重新部署")
def redeploy(instance_id: str):
    inst = lab_deployer.get_instance(instance_id)
    if not inst:
        return _err(404, "实例不存在")
    lab_id = inst["lab_id"]
    lab_deployer.destroy(instance_id)
    r = lab_deployer.deploy(lab_id, LabDeployConfig())
    return _ok(r.get("data"))


@router.get("/by-difficulty/{level}", summary="按难度筛选")
def by_difficulty(level: str):
    out = [l for l in lab_registry.list_labs() if l["difficulty"] == level]
    return _ok({"level": level, "labs": out})


@router.post("/deploy-batch", summary="批量部署多个靶场")
def deploy_batch(lab_ids: list[str]):
    results = []
    for lid in lab_ids:
        r = lab_deployer.deploy(lid, LabDeployConfig())
        results.append({"lab_id": lid, "success": r.get("success"),
                        "data": r.get("data")})
    return _ok({"results": results})


@router.get("/mock-notice", summary="模拟模式说明")
def mock_notice():
    return _ok({"mode": "mock",
                "message": "未检测到 Docker，当前为 Python http.server 模拟靶场。"
                           "安装 Docker Desktop 后可启动真实靶场。"})
