# -*- coding: utf-8 -*-
"""
红蓝对抗（紫队）API路由

模块功能：
    - 红队：攻击场景查询 / 攻击模拟 / 模拟结果 / 攻击路径 / 红队报告
    - 蓝队：检测规则 / 防御检测 / 检测结果 / 检测告警 / 蓝队报告
    - 紫队：演练启动 / 状态 / 对比 / 覆盖率 / 时间线 / 复盘报告 / 改进措施

注意事项：
    - 所有端点用 try-except 包裹，返回 JSON 格式，不返回 500 错误
    - 所有"攻击"均为模拟推演，不执行真实攻击
"""
import os
import sys
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# 确保项目根目录在 sys.path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api_server.auth_integration import verify_auth, require_admin  # noqa: F401
from red_team import red_team
from blue_team import blue_team
from purple_team import purple_team

router = APIRouter(prefix="/api/v1/purple-team", tags=["红蓝对抗"])


def _ok(data: Any) -> JSONResponse:
    """成功响应"""
    return JSONResponse({"code": 0, "data": data})


def _err(status: int, message: str) -> JSONResponse:
    """错误响应（不抛 500）"""
    return JSONResponse({"code": status, "error": message}, status_code=status)


# ==================== 请求体模型 ====================

class SimulateRequest(BaseModel):
    """红队模拟请求"""
    scenario_id: str
    name: str = ""
    target_scope: Optional[Dict[str, Any]] = None


class DetectionRequest(BaseModel):
    """蓝队检测请求"""
    simulation_id: str
    name: str = ""


class ExerciseStartRequest(BaseModel):
    """紫队演练启动请求"""
    name: str
    scenario_id: str
    description: str = ""
    target_scope: Optional[Dict[str, Any]] = None


class ImprovementCreateRequest(BaseModel):
    """创建改进措施请求"""
    title: str
    description: str = ""
    category: str = "detection_rule"
    priority: str = "medium"
    assignee: str = ""
    due_date: str = ""


# ==================== 红队 API ====================

@router.get("/red/scenarios")
def list_red_scenarios(category: Optional[str] = Query(None),
                       severity: Optional[str] = Query(None),
                       difficulty: Optional[str] = Query(None)):
    """获取攻击场景列表"""
    try:
        data = red_team.list_scenarios(category=category, severity=severity, difficulty=difficulty)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"获取攻击场景失败: {e}")


@router.post("/red/simulate")
def red_simulate(req: SimulateRequest):
    """启动攻击模拟（仅模拟，不执行真实攻击）"""
    try:
        data = red_team.start_simulation(req.scenario_id, name=req.name,
                                         target_scope=req.target_scope or {})
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"攻击模拟失败: {e}")


@router.get("/red/{simulation_id}/result")
def red_result(simulation_id: str):
    """获取攻击模拟结果"""
    try:
        data = red_team.get_simulation_result(simulation_id)
        if not data:
            return _err(404, "模拟任务不存在")
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"获取模拟结果失败: {e}")


@router.get("/red/{simulation_id}/attack-paths")
def red_attack_paths(simulation_id: str):
    """获取模拟的攻击路径（可视化数据）"""
    try:
        data = red_team.get_attack_paths(simulation_id)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"获取攻击路径失败: {e}")


@router.post("/red/{simulation_id}/report")
def red_report(simulation_id: str):
    """生成红队评估报告"""
    try:
        data = red_team.generate_red_team_report(simulation_id)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"生成红队报告失败: {e}")


# ==================== 蓝队 API ====================

@router.get("/blue/rules")
def list_blue_rules(rule_type: Optional[str] = Query(None),
                    severity: Optional[str] = Query(None),
                    enabled: Optional[bool] = Query(None)):
    """获取检测规则列表"""
    try:
        data = blue_team.list_rules(rule_type=rule_type, severity=severity, enabled=enabled)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"获取检测规则失败: {e}")


@router.post("/blue/detect")
def blue_detect(req: DetectionRequest):
    """启动防御检测（模拟日志分析与告警关联）"""
    try:
        data = blue_team.start_detection(req.simulation_id, name=req.name)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"防御检测失败: {e}")


@router.get("/blue/{detection_id}/result")
def blue_result(detection_id: str):
    """获取检测结果"""
    try:
        data = blue_team.get_detection_result(detection_id)
        if not data:
            return _err(404, "检测任务不存在")
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"获取检测结果失败: {e}")


@router.get("/blue/{detection_id}/alerts")
def blue_alerts(detection_id: str):
    """获取检测到的告警列表"""
    try:
        data = blue_team.get_detection_alerts(detection_id)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"获取检测告警失败: {e}")


@router.post("/blue/{detection_id}/report")
def blue_report(detection_id: str):
    """生成蓝队评估报告"""
    try:
        data = blue_team.generate_blue_team_report(detection_id)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"生成蓝队报告失败: {e}")


# ==================== 紫队 API ====================

@router.post("/exercise/start")
def exercise_start(req: ExerciseStartRequest):
    """启动演练：关联红队模拟与蓝队检测"""
    try:
        data = purple_team.start_exercise(
            req.name, req.scenario_id,
            target_scope=req.target_scope or {},
            description=req.description,
        )
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"启动演练失败: {e}")


@router.get("/exercise/{exercise_id}/status")
def exercise_status(exercise_id: str):
    """获取演练状态"""
    try:
        data = purple_team.get_exercise_status(exercise_id)
        if not data:
            return _err(404, "演练不存在")
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"获取演练状态失败: {e}")


@router.get("/exercise/{exercise_id}/comparison")
def exercise_comparison(exercise_id: str):
    """对比分析：红队攻击路径 vs 蓝队检测结果"""
    try:
        data = purple_team.get_comparison(exercise_id)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"获取对比分析失败: {e}")


@router.get("/exercise/{exercise_id}/coverage")
def exercise_coverage(exercise_id: str):
    """检测覆盖率矩阵"""
    try:
        data = purple_team.get_coverage(exercise_id)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"获取覆盖率失败: {e}")


@router.get("/exercise/{exercise_id}/timeline")
def exercise_timeline(exercise_id: str):
    """时间线分析与检测延迟"""
    try:
        data = purple_team.get_timeline(exercise_id)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"获取时间线失败: {e}")


@router.post("/exercise/{exercise_id}/report")
def exercise_report(exercise_id: str):
    """生成紫队复盘报告"""
    try:
        data = purple_team.generate_debrief_report(exercise_id)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"生成复盘报告失败: {e}")


@router.get("/exercise/{exercise_id}/improvements")
def exercise_improvements(exercise_id: str, status: Optional[str] = Query(None)):
    """改进措施列表"""
    try:
        data = purple_team.list_improvements(exercise_id, status=status)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"获取改进措施失败: {e}")


@router.post("/exercise/{exercise_id}/improvements/{improvement_id}/complete")
def exercise_improvement_complete(exercise_id: str, improvement_id: str,
                                 verification_result: str = ""):
    """标记改进措施完成，记录验证结果"""
    try:
        data = purple_team.complete_improvement(improvement_id,
                                                verification_result=verification_result)
        if not data:
            return _err(404, "改进措施不存在")
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(500, f"完成改进措施失败: {e}")
