# -*- coding: utf-8 -*-
"""
deploy_routes.py — 一键部署与安装包 REST API（35 个端点）。

路由前缀: /api/v1/deploy
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/deploy", tags=["一键部署与安装包"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from deploy import (
        env_detector,
        installer,
        config_wizard,
        backup_recovery,
        multi_env_deploy,
        deploy_dashboard,
    )
    _MOD_AVAILABLE = True
    logger.info("deploy_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("deploy_routes: load failed: %s", e)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    task_id = uuid.uuid4().hex[:16]
    _TASKS[task_id] = {
        "task_id": task_id, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return task_id


def _finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
    if task_id in _TASKS:
        t = _TASKS[task_id]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理数据中的控制字符和无效 Unicode。"""
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(item) for item in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("部署模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class WizardSubmitRequest(BaseModel):
    step: int = 1
    data: Dict[str, Any] = Field(default_factory=dict)


class ConfigValidateRequest(BaseModel):
    config: Dict[str, Any] = Field(default_factory=dict)


class DbInitRequest(BaseModel):
    admin_username: str = "admin"
    admin_password: str = "admin123"


class MigrationRequest(BaseModel):
    from_version: str = "20.0.0"
    to_version: str = "20.1.0"


class UpgradeRequest(BaseModel):
    target_version: str = "20.1.0"


class BackupCreateRequest(BaseModel):
    type: str = "full"
    encrypt: bool = True
    compress: bool = True


class RecoveryRequest(BaseModel):
    backup_id: str = ""
    confirm: bool = False


class DeployRequest(BaseModel):
    environment: str = "production"
    version: str = "20.1.0"


class EnvCompareRequest(BaseModel):
    env_a: str = "development"
    env_b: str = "production"


class InstallerRequest(BaseModel):
    platform: str = "windows"
    port: int = 8000


# =========================================================================== #
# 1. 环境检测（6 个端点）
# =========================================================================== #
@router.get("/env/system")
def env_system():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(env_detector.detect_system())
    except Exception as e:
        logger.exception("env_system error")
        return fail(f"系统环境检测失败: {e}", 500)


@router.get("/env/python-deps")
def env_python_deps():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(env_detector.detect_python_deps())
    except Exception as e:
        logger.exception("env_python_deps error")
        return fail(f"Python 依赖检测失败: {e}", 500)


@router.get("/env/tools")
def env_tools():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(env_detector.detect_external_tools())
    except Exception as e:
        logger.exception("env_tools error")
        return fail(f"外部工具检测失败: {e}", 500)


@router.get("/env/database")
def env_database():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(env_detector.detect_database())
    except Exception as e:
        logger.exception("env_database error")
        return fail(f"数据库检测失败: {e}", 500)


@router.get("/env/ports")
def env_ports():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(env_detector.detect_ports())
    except Exception as e:
        logger.exception("env_ports error")
        return fail(f"端口检测失败: {e}", 500)


@router.get("/env/report")
def env_report():
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("env_report")
        result = env_detector.generate_env_report()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "report": result})
    except Exception as e:
        logger.exception("env_report error")
        return fail(f"环境报告生成失败: {e}", 500)


# =========================================================================== #
# 2. 一键安装（6 个端点）
# =========================================================================== #
@router.get("/installer/{platform}")
def installer_get(platform: str, port: int = Query(8000)):
    try:
        g = _guard()
        if g is not None:
            return g
        result = installer.generate_installer(platform=platform, port=port)
        return ok(result)
    except Exception as e:
        logger.exception("installer_get error")
        return fail(f"生成安装脚本失败: {e}", 500)


@router.post("/installer/generate")
def installer_generate(req: InstallerRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("installer")
        result = installer.generate_installer(platform=req.platform, port=req.port)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "platform": req.platform, "files": result})
    except Exception as e:
        logger.exception("installer_generate error")
        return fail(f"生成安装脚本失败: {e}", 500)


@router.get("/installer/offline-manifest")
def installer_offline_manifest():
    try:
        g = _guard()
        if g is not None:
            return g
        info = installer.generate_offline_package_info()
        return ok(info["manifest"])
    except Exception as e:
        logger.exception("installer_offline_manifest error")
        return fail(f"离线包清单生成失败: {e}", 500)


@router.get("/installer/k8s-manifests")
def installer_k8s(namespace: str = Query("ai-hacking"), port: int = Query(8000)):
    try:
        g = _guard()
        if g is not None:
            return g
        manifests = installer.generate_k8s_manifests(namespace=namespace, port=port)
        return ok(manifests)
    except Exception as e:
        logger.exception("installer_k8s error")
        return fail(f"K8s 清单生成失败: {e}", 500)


@router.get("/installer/docker-files")
def installer_docker(port: int = Query(8000)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({
            "Dockerfile": installer.generate_dockerfile(port),
            "docker-compose.yml": installer.generate_docker_compose(port),
        })
    except Exception as e:
        logger.exception("installer_docker error")
        return fail(f"Docker 文件生成失败: {e}", 500)


@router.get("/installer/task/{task_id}")
def installer_task_status(task_id: str):
    try:
        t = _TASKS.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:
        logger.exception("installer_task_status error")
        return fail(f"查询任务失败: {e}", 500)


# =========================================================================== #
# 3. 配置向导（8 个端点）
# =========================================================================== #
@router.get("/wizard/status")
def wizard_status():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(config_wizard.get_wizard_status())
    except Exception as e:
        logger.exception("wizard_status error")
        return fail(f"获取向导状态失败: {e}", 500)


@router.post("/wizard/step")
def wizard_step(req: WizardSubmitRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        result = config_wizard.wizard_step_submit(req.step, req.data)
        return ok(result)
    except Exception as e:
        logger.exception("wizard_step error")
        return fail(f"向导步骤提交失败: {e}", 500)


@router.post("/wizard/reset")
def wizard_reset():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(config_wizard.wizard_reset())
    except Exception as e:
        logger.exception("wizard_reset error")
        return fail(f"向导重置失败: {e}", 500)


@router.get("/config/template")
def config_template():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"template": config_wizard.CONFIG_TEMPLATE,
                   "env_file_sample": config_wizard.generate_env_file()})
    except Exception as e:
        logger.exception("config_template error")
        return fail(f"获取配置模板失败: {e}", 500)


@router.post("/config/validate")
def config_validate(req: ConfigValidateRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(config_wizard.validate_config(req.config))
    except Exception as e:
        logger.exception("config_validate error")
        return fail(f"配置验证失败: {e}", 500)


@router.post("/config/backup")
def config_backup(label: str = Query("manual")):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(config_wizard.backup_config(config_wizard.CONFIG_TEMPLATE, label))
    except Exception as e:
        logger.exception("config_backup error")
        return fail(f"配置备份失败: {e}", 500)


@router.post("/db/init")
def db_init(req: DbInitRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(config_wizard.init_database(req.admin_username, req.admin_password))
    except Exception as e:
        logger.exception("db_init error")
        return fail(f"数据库初始化失败: {e}", 500)


@router.get("/db/status")
def db_status():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(config_wizard.get_db_init_status())
    except Exception as e:
        logger.exception("db_status error")
        return fail(f"数据库状态查询失败: {e}", 500)


# =========================================================================== #
# 4. 数据迁移与服务管理（4 个端点）
# =========================================================================== #
@router.post("/migration/plan")
def migration_plan(req: MigrationRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(config_wizard.plan_migration(req.from_version, req.to_version))
    except Exception as e:
        logger.exception("migration_plan error")
        return fail(f"生成迁移计划失败: {e}", 500)


@router.post("/migration/run")
def migration_run(req: MigrationRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(config_wizard.run_migration_simulation(req.from_version, req.to_version))
    except Exception as e:
        logger.exception("migration_run error")
        return fail(f"执行迁移失败: {e}", 500)


@router.post("/service/{action}")
def service_control(action: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(config_wizard.service_action(action))
    except Exception as e:
        logger.exception("service_control error")
        return fail(f"服务操作失败: {e}", 500)


@router.get("/service/health")
def service_health():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(config_wizard.service_health_check())
    except Exception as e:
        logger.exception("service_health error")
        return fail(f"健康检查失败: {e}", 500)


# =========================================================================== #
# 5. 版本与升级（4 个端点）
# =========================================================================== #
@router.get("/version/info")
def version_info():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(backup_recovery.get_version_info())
    except Exception as e:
        logger.exception("version_info error")
        return fail(f"版本信息查询失败: {e}", 500)


@router.post("/update/check")
def update_check():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(backup_recovery.check_update())
    except Exception as e:
        logger.exception("update_check error")
        return fail(f"更新检查失败: {e}", 500)


@router.post("/upgrade/plan")
def upgrade_plan(req: UpgradeRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(backup_recovery.upgrade_plan(req.target_version))
    except Exception as e:
        logger.exception("upgrade_plan error")
        return fail(f"生成升级计划失败: {e}", 500)


@router.post("/upgrade/run")
def upgrade_run(req: UpgradeRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(backup_recovery.run_upgrade(req.target_version))
    except Exception as e:
        logger.exception("upgrade_run error")
        return fail(f"执行升级失败: {e}", 500)


# =========================================================================== #
# 6. 备份与恢复（6 个端点）
# =========================================================================== #
@router.post("/backup/create")
def backup_create(req: BackupCreateRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(backup_recovery.create_backup(req.type, req.encrypt, req.compress))
    except Exception as e:
        logger.exception("backup_create error")
        return fail(f"创建备份失败: {e}", 500)


@router.get("/backup/list")
def backup_list():
    try:
        g = _guard()
        if g is not None:
            return ok(backup_recovery.list_backups())
    except Exception as e:
        logger.exception("backup_list error")
        return fail(f"备份列表查询失败: {e}", 500)


@router.post("/backup/verify/{backup_id}")
def backup_verify(backup_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(backup_recovery.verify_backup(backup_id))
    except Exception as e:
        logger.exception("backup_verify error")
        return fail(f"备份验证失败: {e}", 500)


@router.post("/recovery/preview")
def recovery_preview(req: RecoveryRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(backup_recovery.preview_recovery(req.backup_id))
    except Exception as e:
        logger.exception("recovery_preview error")
        return fail(f"恢复预览失败: {e}", 500)


@router.post("/recovery/execute")
def recovery_execute(req: RecoveryRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(backup_recovery.execute_recovery(req.backup_id, req.confirm))
    except Exception as e:
        logger.exception("recovery_execute error")
        return fail(f"执行恢复失败: {e}", 500)


@router.get("/dr/plan")
def dr_plan():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(backup_recovery.get_disaster_recovery_plan())
    except Exception as e:
        logger.exception("dr_plan error")
        return fail(f"灾备计划查询失败: {e}", 500)


# =========================================================================== #
# 7. 多环境部署（6 个端点）
# =========================================================================== #
@router.get("/environments")
def list_envs():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(multi_env_deploy.list_environments())
    except Exception as e:
        logger.exception("list_envs error")
        return fail(f"环境列表查询失败: {e}", 500)


@router.get("/environment/{name}")
def get_env(name: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(multi_env_deploy.get_environment(name))
    except Exception as e:
        logger.exception("get_env error")
        return fail(f"环境详情查询失败: {e}", 500)


@router.post("/environment/compare")
def env_compare(req: EnvCompareRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(multi_env_deploy.compare_environments(req.env_a, req.env_b))
    except Exception as e:
        logger.exception("env_compare error")
        return fail(f"环境对比失败: {e}", 500)


@router.post("/deploy/to")
def deploy_to(req: DeployRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(multi_env_deploy.deploy_to_environment(req.environment, req.version))
    except Exception as e:
        logger.exception("deploy_to error")
        return fail(f"部署失败: {e}", 500)


@router.get("/deployments")
def list_deployments(environment: str = Query("")):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(multi_env_deploy.list_deployments(environment))
    except Exception as e:
        logger.exception("list_deployments error")
        return fail(f"部署历史查询失败: {e}", 500)


@router.get("/cloud/templates")
def cloud_templates():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(multi_env_deploy.list_cloud_templates())
    except Exception as e:
        logger.exception("cloud_templates error")
        return fail(f"云模板查询失败: {e}", 500)


@router.get("/cluster/status")
def cluster_status():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(multi_env_deploy.get_cluster_status())
    except Exception as e:
        logger.exception("cluster_status error")
        return fail(f"集群状态查询失败: {e}", 500)


# =========================================================================== #
# 8. 部署管理控制台（7 个端点）
# =========================================================================== #
@router.get("/dashboard/overview")
def dashboard_overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(deploy_dashboard.get_overview_dashboard())
    except Exception as e:
        logger.exception("dashboard_overview error")
        return fail(f"大屏数据获取失败: {e}", 500)


@router.get("/logs")
def get_logs(level: str = Query(""), source: str = Query(""), limit: int = Query(50)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(deploy_dashboard.get_logs(level, source, limit))
    except Exception as e:
        logger.exception("get_logs error")
        return fail(f"日志查询失败: {e}", 500)


@router.get("/monitoring")
def monitoring():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(deploy_dashboard.get_monitoring_metrics())
    except Exception as e:
        logger.exception("monitoring error")
        return fail(f"监控指标获取失败: {e}", 500)


@router.get("/alerts/rules")
def alert_rules():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(deploy_dashboard.get_alert_rules())
    except Exception as e:
        logger.exception("alert_rules error")
        return fail(f"告警规则查询失败: {e}", 500)


@router.get("/alerts/history")
def alert_history():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(deploy_dashboard.get_alert_history())
    except Exception as e:
        logger.exception("alert_history error")
        return fail(f"告警历史查询失败: {e}", 500)


@router.get("/docs")
def list_docs():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(deploy_dashboard.list_docs())
    except Exception as e:
        logger.exception("list_docs error")
        return fail(f"文档列表查询失败: {e}", 500)


@router.get("/docs/{doc_id}")
def get_doc(doc_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(deploy_dashboard.get_doc(doc_id))
    except Exception as e:
        logger.exception("get_doc error")
        return fail(f"文档详情查询失败: {e}", 500)


# =========================================================================== #
# 控制台 HTML 入口
# =========================================================================== #
@router.get("/console", include_in_schema=False)
def deploy_console():
    """返回部署管理控制台 HTML 页面。"""
    import os
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "deploy_console.html")
    if os.path.exists(html_path):
        return FileResponse(html_path, media_type="text/html; charset=utf-8")
    return JSONResponse({"success": False, "error": "deploy_console.html not found"},
                         status_code=404)
