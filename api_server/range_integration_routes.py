# -*- coding: utf-8 -*-
"""
range_integration_routes.py - 真实靶场集成 API 路由

APIRouter prefix="/api/v1/range-integration"，35+ 端点。
统一响应 {success, data, error}，每端点 try-except 兜底。
不修改 app.py，由集成脚本统一注入。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/range-integration", tags=["靶场集成"])

NOTICE = "仅限授权环境使用：仅用于授权安全测试、教学与演示。"


# ----------------------------------------------------------------------
# 业务模块加载（容错）
# ----------------------------------------------------------------------
_AVAILABLE = False
try:
    from range_integration.range_manager import get_manager as _get_rm, RANGE_CATALOG, DEPLOY_TYPES
    from range_integration.vuln_range import get_vuln_manager as _get_vm
    from range_integration.auto_scanner import get_scanner as _get_sc
    from range_integration.range_report import get_report_generator as _get_rg
    from range_integration.range_learning import get_learning_manager as _get_lm
    from range_integration.range_dashboard import get_dashboard as _get_dash
    _AVAILABLE = True
    logger.info("range_integration_routes: all modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("range_integration_routes load failed: %s", e)


def _get_managers():
    return {
        "rm": _get_rm() if _AVAILABLE else None,
        "vm": _get_vm() if _AVAILABLE else None,
        "sc": _get_sc() if _AVAILABLE else None,
        "rg": _get_rg() if _AVAILABLE else None,
        "lm": _get_lm() if _AVAILABLE else None,
        "dash": _get_dash() if _AVAILABLE else None,
    }


# ----------------------------------------------------------------------
# 统一响应
# ----------------------------------------------------------------------
def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": message},
                        status_code=status)


def _guard() -> Optional[JSONResponse]:
    if not _AVAILABLE:
        return _err(503, "靶场集成模块不可用，请检查 range_integration 加载日志")
    return None


# ======================================================================
# 1. 靶场目录与管理（8 个端点）
# ======================================================================

@router.get("/catalog")
def list_catalog(category: Optional[str] = None,
                 difficulty: Optional[str] = None):
    """获取靶场目录（8 个标准靶场）。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        items = rm.list_catalog(category=category, difficulty=difficulty)
        return _ok({"ranges": items, "total": len(items), "notice": NOTICE})
    except Exception as e:  # noqa: BLE001
        logger.exception("list_catalog error")
        return _err(500, f"获取靶场目录失败: {e}")


@router.get("/catalog/{range_id}")
def get_catalog_item(range_id: str):
    """获取单个靶场详情。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        item = rm.get_catalog_item(range_id)
        if not item:
            return _err(404, f"靶场不存在: {range_id}")
        return _ok(item)
    except Exception as e:  # noqa: BLE001
        logger.exception("get_catalog_item error")
        return _err(500, f"获取靶场详情失败: {e}")


@router.get("/docker/status")
def docker_status():
    """真实检测 Docker 环境状态。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        result = rm.check_docker()
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("docker_status error")
        return _err(500, f"Docker 检测失败: {e}")


class DeployRequest(BaseModel):
    range_id: str = Field(..., description="靶场 ID")
    deploy_type: str = Field("docker", description="部署类型")
    port: Optional[int] = Field(None, description="指定端口")
    options: Dict[str, Any] = Field(default_factory=dict)


@router.post("/ranges/deploy")
def deploy_range(body: DeployRequest):
    """部署靶场实例。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        result = rm.deploy(body.range_id, body.deploy_type, body.port, body.options)
        if not result.get("success"):
            return _err(400, result.get("error", "部署失败"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("deploy_range error")
        return _err(500, f"部署失败: {e}")


class BatchDeployRequest(BaseModel):
    range_ids: List[str] = Field(..., description="靶场 ID 列表")
    deploy_type: str = Field("docker")


@router.post("/ranges/batch-deploy")
def batch_deploy(body: BatchDeployRequest):
    """批量部署靶场。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        result = rm.batch_deploy(body.range_ids, body.deploy_type)
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("batch_deploy error")
        return _err(500, f"批量部署失败: {e}")


@router.get("/ranges/instances")
def list_instances(status: Optional[str] = None):
    """列出所有靶场实例。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        instances = rm.list_instances(status=status)
        return _ok({"instances": instances, "total": len(instances)})
    except Exception as e:  # noqa: BLE001
        logger.exception("list_instances error")
        return _err(500, f"获取实例列表失败: {e}")


@router.get("/ranges/overview")
def ranges_overview():
    """靶场总览统计。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        return _ok(rm.overview())
    except Exception as e:  # noqa: BLE001
        logger.exception("ranges_overview error")
        return _err(500, f"获取总览失败: {e}")


@router.get("/deploy-types")
def list_deploy_types():
    """获取支持的部署类型。"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(DEPLOY_TYPES)
    except Exception as e:  # noqa: BLE001
        logger.exception("list_deploy_types error")
        return _err(500, f"获取部署类型失败: {e}")


# ======================================================================
# 2. 实例生命周期（8 个端点）
# ======================================================================

@router.get("/instances/{instance_id}/status")
def instance_status(instance_id: str):
    """获取实例状态。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        result = rm.status(instance_id)
        if not result.get("success"):
            return _err(404, result.get("error", "实例不存在"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("instance_status error")
        return _err(500, f"状态查询失败: {e}")


@router.post("/instances/{instance_id}/start")
def instance_start(instance_id: str):
    """启动实例。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        result = rm.start(instance_id)
        if not result.get("success"):
            return _err(400, result.get("error", "启动失败"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("instance_start error")
        return _err(500, f"启动失败: {e}")


@router.post("/instances/{instance_id}/stop")
def instance_stop(instance_id: str):
    """停止实例。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        result = rm.stop(instance_id)
        if not result.get("success"):
            return _err(400, result.get("error", "停止失败"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("instance_stop error")
        return _err(500, f"停止失败: {e}")


@router.post("/instances/{instance_id}/restart")
def instance_restart(instance_id: str):
    """重启实例。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        result = rm.restart(instance_id)
        if not result.get("success"):
            return _err(400, result.get("error", "重启失败"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("instance_restart error")
        return _err(500, f"重启失败: {e}")


@router.delete("/instances/{instance_id}")
def instance_delete(instance_id: str):
    """删除实例。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        result = rm.delete(instance_id)
        if not result.get("success"):
            return _err(404, result.get("error", "删除失败"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("instance_delete error")
        return _err(500, f"删除失败: {e}")


class ConfigRequest(BaseModel):
    config: Dict[str, Any] = Field(..., description="配置项")


@router.put("/instances/{instance_id}/config")
def instance_config(instance_id: str, body: ConfigRequest):
    """更新实例配置。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        result = rm.configure(instance_id, body.config)
        if not result.get("success"):
            return _err(404, result.get("error", "配置失败"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("instance_config error")
        return _err(500, f"配置更新失败: {e}")


@router.post("/instances/{instance_id}/snapshot")
def instance_snapshot(instance_id: str, name: Optional[str] = None):
    """创建快照。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        result = rm.snapshot(instance_id, name)
        if not result.get("success"):
            return _err(400, result.get("error", "快照失败"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("instance_snapshot error")
        return _err(500, f"快照失败: {e}")


@router.post("/instances/{instance_id}/clone")
def instance_clone(instance_id: str):
    """克隆实例。"""
    try:
        g = _guard()
        if g:
            return g
        rm = _get_managers()["rm"]
        result = rm.clone(instance_id)
        if not result.get("success"):
            return _err(400, result.get("error", "克隆失败"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("instance_clone error")
        return _err(500, f"克隆失败: {e}")


# ======================================================================
# 3. 漏洞靶场集成（5 个端点）
# ======================================================================

@router.get("/vuln-ranges")
def list_vuln_ranges(category: Optional[str] = None):
    """按类别列出漏洞靶场（web/system/mobile/cloud/api/ics）。"""
    try:
        g = _guard()
        if g:
            return g
        vm = _get_managers()["vm"]
        result = vm.list_by_category(category=category)
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("list_vuln_ranges error")
        return _err(500, f"获取漏洞靶场失败: {e}")


@router.get("/vuln-ranges/{range_id}")
def get_vuln_range_detail(range_id: str):
    """获取漏洞靶场详情。"""
    try:
        g = _guard()
        if g:
            return g
        vm = _get_managers()["vm"]
        item = vm.get_range_detail(range_id)
        if not item:
            return _err(404, f"靶场不存在: {range_id}")
        return _ok(item)
    except Exception as e:  # noqa: BLE001
        logger.exception("get_vuln_range_detail error")
        return _err(500, f"获取详情失败: {e}")


class AutoIdentifyRequest(BaseModel):
    range_id: str = Field(..., description="靶场 ID")
    target_url: str = Field(..., description="目标 URL")


@router.post("/vuln-ranges/auto-identify")
def auto_identify(body: AutoIdentifyRequest):
    """自动识别靶场漏洞。"""
    try:
        g = _guard()
        if g:
            return g
        vm = _get_managers()["vm"]
        result = vm.auto_identify(body.range_id, body.target_url)
        if not result.get("success"):
            return _err(400, result.get("error", "识别失败"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("auto_identify error")
        return _err(500, f"自动识别失败: {e}")


@router.get("/vuln-ranges/scans/list")
def list_vuln_scans():
    """列出所有漏洞扫描。"""
    try:
        g = _guard()
        if g:
            return g
        vm = _get_managers()["vm"]
        return _ok({"scans": vm.list_scans()})
    except Exception as e:  # noqa: BLE001
        logger.exception("list_vuln_scans error")
        return _err(500, f"获取扫描列表失败: {e}")


@router.get("/vuln-ranges/scans/{scan_id}")
def get_vuln_scan(scan_id: str):
    """获取扫描详情。"""
    try:
        g = _guard()
        if g:
            return g
        vm = _get_managers()["vm"]
        result = vm.get_scan(scan_id)
        if not result.get("success"):
            return _err(404, result.get("error", "扫描不存在"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("get_vuln_scan error")
        return _err(500, f"获取扫描详情失败: {e}")


# ======================================================================
# 4. 自动扫描（6 个端点）
# ======================================================================

class ScanStartRequest(BaseModel):
    target: str = Field(..., description="扫描目标")
    profile: str = Field("standard", description="扫描模板")
    options: Dict[str, Any] = Field(default_factory=dict)


@router.post("/scans/start")
def start_scan(body: ScanStartRequest):
    """启动扫描任务。"""
    try:
        g = _guard()
        if g:
            return g
        sc = _get_managers()["sc"]
        result = sc.start_scan(body.target, body.profile, body.options)
        if not result.get("success"):
            return _err(400, result.get("error", "启动失败"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("start_scan error")
        return _err(500, f"扫描启动失败: {e}")


@router.get("/scans/tasks")
def list_scan_tasks():
    """列出扫描任务。"""
    try:
        g = _guard()
        if g:
            return g
        sc = _get_managers()["sc"]
        return _ok({"tasks": sc.list_tasks()})
    except Exception as e:  # noqa: BLE001
        logger.exception("list_scan_tasks error")
        return _err(500, f"获取任务列表失败: {e}")


@router.get("/scans/tasks/{task_id}")
def get_scan_task(task_id: str):
    """获取扫描任务详情。"""
    try:
        g = _guard()
        if g:
            return g
        sc = _get_managers()["sc"]
        result = sc.get_task(task_id)
        if not result.get("success"):
            return _err(404, result.get("error", "任务不存在"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("get_scan_task error")
        return _err(500, f"获取任务详情失败: {e}")


@router.get("/scans/profiles")
def list_scan_profiles():
    """获取扫描模板列表。"""
    try:
        g = _guard()
        if g:
            return g
        sc = _get_managers()["sc"]
        return _ok({"profiles": sc.list_profiles()})
    except Exception as e:  # noqa: BLE001
        logger.exception("list_scan_profiles error")
        return _err(500, f"获取模板失败: {e}")


class ScanCompareRequest(BaseModel):
    task_id_a: str = Field(...)
    task_id_b: str = Field(...)


@router.post("/scans/compare")
def compare_scans(body: ScanCompareRequest):
    """对比两次扫描结果。"""
    try:
        g = _guard()
        if g:
            return g
        sc = _get_managers()["sc"]
        result = sc.compare_scans(body.task_id_a, body.task_id_b)
        if not result.get("success"):
            return _err(400, result.get("error", "对比失败"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("compare_scans error")
        return _err(500, f"扫描对比失败: {e}")


@router.get("/scans/quality")
def scan_quality():
    """获取扫描质量指标。"""
    try:
        g = _guard()
        if g:
            return g
        sc = _get_managers()["sc"]
        return _ok(sc.quality_metrics())
    except Exception as e:  # noqa: BLE001
        logger.exception("scan_quality error")
        return _err(500, f"获取质量指标失败: {e}")


# ======================================================================
# 5. 报告生成（5 个端点）
# ======================================================================

class EvalReportRequest(BaseModel):
    range_id: str = Field(...)
    instance_id: str = Field(...)


@router.post("/reports/evaluation")
def generate_evaluation_report(body: EvalReportRequest):
    """生成靶场评估报告。"""
    try:
        g = _guard()
        if g:
            return g
        rg = _get_managers()["rg"]
        result = rg.evaluation_report(body.range_id, body.instance_id)
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("generate_evaluation_report error")
        return _err(500, f"生成评估报告失败: {e}")


@router.post("/reports/learning-path")
def generate_learning_path_report(user_id: str = "default"):
    """生成学习路径报告。"""
    try:
        g = _guard()
        if g:
            return g
        rg = _get_managers()["rg"]
        result = rg.learning_path_report(user_id)
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("generate_learning_path_report error")
        return _err(500, f"生成学习路径报告失败: {e}")


@router.get("/reports/compliance")
def generate_compliance_report(framework: str = "owasp_top10_2021"):
    """生成合规映射报告。"""
    try:
        g = _guard()
        if g:
            return g
        rg = _get_managers()["rg"]
        result = rg.compliance_report(framework)
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("generate_compliance_report error")
        return _err(500, f"生成合规报告失败: {e}")


@router.post("/reports/coach-feedback")
def generate_coach_feedback(user_id: str = "default"):
    """生成教练反馈报告。"""
    try:
        g = _guard()
        if g:
            return g
        rg = _get_managers()["rg"]
        result = rg.coach_feedback_report(user_id)
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("generate_coach_feedback error")
        return _err(500, f"生成教练反馈失败: {e}")


@router.get("/reports/list")
def list_reports():
    """列出所有报告。"""
    try:
        g = _guard()
        if g:
            return g
        rg = _get_managers()["rg"]
        return _ok({"reports": rg.list_reports()})
    except Exception as e:  # noqa: BLE001
        logger.exception("list_reports error")
        return _err(500, f"获取报告列表失败: {e}")


# ======================================================================
# 6. 学习训练（6 个端点）
# ======================================================================

@router.get("/learning/paths")
def list_learning_paths():
    """获取学习路径列表。"""
    try:
        g = _guard()
        if g:
            return g
        lm = _get_managers()["lm"]
        return _ok({"paths": lm.list_paths()})
    except Exception as e:  # noqa: BLE001
        logger.exception("list_learning_paths error")
        return _err(500, f"获取学习路径失败: {e}")


@router.get("/learning/courses")
def list_courses(path_id: Optional[str] = None):
    """获取课程列表。"""
    try:
        g = _guard()
        if g:
            return g
        lm = _get_managers()["lm"]
        return _ok({"courses": lm.list_courses(path_id)})
    except Exception as e:  # noqa: BLE001
        logger.exception("list_courses error")
        return _err(500, f"获取课程失败: {e}")


@router.get("/learning/practice-modes")
def list_practice_modes():
    """获取练习模式列表。"""
    try:
        g = _guard()
        if g:
            return g
        lm = _get_managers()["lm"]
        return _ok(lm.list_practice_modes())
    except Exception as e:  # noqa: BLE001
        logger.exception("list_practice_modes error")
        return _err(500, f"获取练习模式失败: {e}")


class PracticeStartRequest(BaseModel):
    range_id: str = Field(...)
    mode: str = Field("free")
    user_id: str = Field("default")


@router.post("/learning/practice/start")
def start_practice(body: PracticeStartRequest):
    """开始练习。"""
    try:
        g = _guard()
        if g:
            return g
        lm = _get_managers()["lm"]
        result = lm.start_practice(body.range_id, body.mode, body.user_id)
        if not result.get("success"):
            return _err(400, result.get("error", "开始练习失败"))
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("start_practice error")
        return _err(500, f"开始练习失败: {e}")


@router.get("/learning/competitions")
def list_competitions():
    """列出竞赛。"""
    try:
        g = _guard()
        if g:
            return g
        lm = _get_managers()["lm"]
        return _ok({"competitions": lm.list_competitions()})
    except Exception as e:  # noqa: BLE001
        logger.exception("list_competitions error")
        return _err(500, f"获取竞赛列表失败: {e}")


@router.get("/learning/teams")
def list_teams():
    """列出团队。"""
    try:
        g = _guard()
        if g:
            return g
        lm = _get_managers()["lm"]
        return _ok({"teams": lm.list_teams()})
    except Exception as e:  # noqa: BLE001
        logger.exception("list_teams error")
        return _err(500, f"获取团队列表失败: {e}")


# ======================================================================
# 7. 控制台与设置（3 个端点）
# ======================================================================

@router.get("/dashboard/overview")
def dashboard_overview():
    """控制台总览数据。"""
    try:
        g = _guard()
        if g:
            return g
        dash = _get_managers()["dash"]
        return _ok(dash.overview())
    except Exception as e:  # noqa: BLE001
        logger.exception("dashboard_overview error")
        return _err(500, f"获取总览失败: {e}")


@router.get("/settings")
def get_settings():
    """获取系统设置。"""
    try:
        g = _guard()
        if g:
            return g
        dash = _get_managers()["dash"]
        return _ok(dash.get_settings())
    except Exception as e:  # noqa: BLE001
        logger.exception("get_settings error")
        return _err(500, f"获取设置失败: {e}")


class SettingsUpdateRequest(BaseModel):
    settings: Dict[str, Any] = Field(...)


@router.put("/settings")
def update_settings(body: SettingsUpdateRequest):
    """更新系统设置。"""
    try:
        g = _guard()
        if g:
            return g
        dash = _get_managers()["dash"]
        result = dash.update_settings(body.settings)
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("update_settings error")
        return _err(500, f"更新设置失败: {e}")
