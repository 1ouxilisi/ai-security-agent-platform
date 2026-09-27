# -*- coding: utf-8 -*-
"""
red_blue_team_routes.py — 自动化红蓝对抗与攻击模拟平台 REST API（第24轮升级方向1）。

路由前缀：/api/v1/red-blue-team
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。
任务用内存字典 TASKS 模拟异步任务。

覆盖：
    - 攻击模拟：战术/技术/场景/攻击链/执行/评估
    - 防御验证：规则/覆盖率/告警/有效性/紫队/改进建议
    - 对抗管理：项目/红队/蓝队/过程/评分/复盘
    - 可视化：拓扑/时间线/攻击树/杀伤链/热力图/3D 地图
    - 工具集成：Metasploit/Cobalt Strike/Nmap/SQLMap/编排
    - 控制台/设置：总览/管理/设置
"""

from __future__ import annotations

import os
import re
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging as log  # type: ignore

try:
    from red_blue_team.attack_simulator import (
        ATTACK_TACTICS, ATTACK_TECHNIQUES, ATTACK_SCENARIOS,
        get_attack_simulator,
    )
    from red_blue_team.defense_validator import (
        DEFENSE_RULES, ALERTS, get_defense_validator,
    )
    from red_blue_team.exercise_manager import (
        EXERCISES, get_exercise_manager,
    )
    from red_blue_team.attack_visualization import get_attack_visualization
    from red_blue_team.attack_tools import get_attack_tools
    from red_blue_team.exercise_dashboard import get_exercise_dashboard, SYSTEM_SETTINGS
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    log.warning("red_blue_team_routes: 模块导入失败: %s", _e)
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/red-blue-team", tags=["红蓝对抗与攻击模拟"])


# ==================== 响应工具 ====================

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理无效控制字符，避免 JSON 序列化异常"""
    if isinstance(obj, str):
        return _CTRL_RE.sub("", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(x) for x in obj]
    return obj


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": _clean(data), "error": str(err)})


# ==================== 内存任务存储 ====================

TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(task_type: str) -> str:
    tid = f"{task_type}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {
        "task_id": tid, "type": task_type,
        "status": "pending", "result": None, "error": None,
        "created_at": datetime.now().isoformat(),
    }
    return tid


def _run_task(task_type: str, func, *args, **kwargs) -> str:
    tid = _new_task(task_type)
    TASKS[tid]["status"] = "running"
    try:
        result = func(*args, **kwargs)
        TASKS[tid]["status"] = "success"
        TASKS[tid]["result"] = result
    except Exception as e:  # pragma: no cover
        TASKS[tid]["status"] = "failed"
        TASKS[tid]["error"] = str(e)
    return tid


def _require() -> bool:
    return _MODULES_OK


# ==================== 请求模型 ====================

class ChainBuildReq(BaseModel):
    scenario_id: str = "scenario-apt29"
    target: str = "10.0.0.0/24"
    objective: str = "data_exfiltration"


class TechniqueExecReq(BaseModel):
    technique_id: str = "T1059.001"
    target: str = "10.0.0.5"
    params: Dict[str, Any] = {}


class ExerciseCreateReq(BaseModel):
    name: str = "2026 Q3 红蓝对抗演练"
    scope: str = "10.0.0.0/8"
    start: str = "2026-10-01T09:00:00"
    end: str = "2026-10-03T18:00:00"
    red_team_name: str = "红队-Ares"
    blue_team_name: str = "蓝队-Athena"
    rules_of_engagement: List[str] = []
    scoring_criteria: Dict[str, float] = {}


class MemberReq(BaseModel):
    name: str = "新成员"
    role: str = "operator"


class TaskAssignReq(BaseModel):
    member_id: str
    task: str = "侦察目标"
    target: str = "10.0.0.0/24"


class PurpleStartReq(BaseModel):
    name: str = "紫队联合演练"
    red_team: List[str] = []
    blue_team: List[str] = []


class PurpleIntelReq(BaseModel):
    intel: str = ""
    from_team: str = "red"


class NmapReq(BaseModel):
    target: str = "10.0.0.5"
    ports: str = "1-1000"


class SQLMapReq(BaseModel):
    url: str = "http://example.com/vuln?id=1"


class MSFReq(BaseModel):
    module: str = "multi/handler"
    target: str = "10.0.0.5"
    options: Dict[str, str] = {}


class BeaconReq(BaseModel):
    target: str = "10.0.0.5"
    command: str = "sleep 0"


class ChainExecReq(BaseModel):
    steps: List[Dict[str, Any]] = []
    parallel: bool = False


class SettingUpdateReq(BaseModel):
    section: str = "scoring"
    values: Dict[str, Any] = {}


# ============================================================
# A. 控制台总览 / 仪表盘
# ============================================================

@router.get("/dashboard/overview", summary="对抗总览")
def dashboard_overview():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dash = get_exercise_dashboard()
        return _ok(dash["overview"].summary())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/score-trend", summary="综合评分趋势")
def dashboard_score_trend():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dash = get_exercise_dashboard()
        return _ok(dash["overview"].score_trend())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/stats", summary="平台模块统计")
def dashboard_stats():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        from red_blue_team.attack_simulator import stats as s1
        from red_blue_team.defense_validator import stats as s2
        from red_blue_team.exercise_manager import stats as s3
        from red_blue_team.attack_tools import stats as s4
        return _ok({
            "attack_simulator": s1(),
            "defense_validator": s2(),
            "exercise_manager": s3(),
            "attack_tools": s4(),
        })
    except Exception as e:
        return _fail(str(e))


# ============================================================
# B. 攻击模拟 — 战术 / 技术 / 场景
# ============================================================

@router.get("/attack/tactics", summary="ATT&CK 战术列表")
def list_tactics():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        return _ok(list(ATTACK_TACTICS.values()))
    except Exception as e:
        return _fail(str(e))


@router.get("/attack/tactics/{tactic_id}", summary="单个战术详情")
def get_tactic(tactic_id: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        t = ATTACK_TACTICS.get(tactic_id)
        if not t:
            return _fail(f"未知战术: {tactic_id}")
        return _ok(t)
    except Exception as e:
        return _fail(str(e))


@router.get("/attack/techniques", summary="攻击技术库列表")
def list_techniques(tactic: Optional[str] = Query(None, description="按战术过滤")):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        techs = list(ATTACK_TECHNIQUES.values())
        if tactic:
            techs = [t for t in techs if t["tactic"] == tactic]
        return _ok({"total": len(techs), "techniques": techs})
    except Exception as e:
        return _fail(str(e))


@router.get("/attack/techniques/{tid}", summary="单个技术详情")
def get_technique(tid: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        t = ATTACK_TECHNIQUES.get(tid)
        if not t:
            return _fail(f"未知技术: {tid}")
        return _ok(t)
    except Exception as e:
        return _fail(str(e))


@router.get("/attack/scenarios", summary="攻击场景库")
def list_scenarios():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        return _ok(list(ATTACK_SCENARIOS.values()))
    except Exception as e:
        return _fail(str(e))


@router.get("/attack/scenarios/{sid}", summary="单个场景详情")
def get_scenario(sid: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        s = ATTACK_SCENARIOS.get(sid)
        if not s:
            return _fail(f"未知场景: {sid}")
        return _ok(s)
    except Exception as e:
        return _fail(str(e))


# ============================================================
# C. 攻击链构建 / 执行 / 评估
# ============================================================

@router.post("/attack/chains/build", summary="自动构建攻击链")
def build_chain(req: ChainBuildReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        sim = get_attack_simulator()
        chain = sim["builder"].build_chain(req.scenario_id, req.target, req.objective)
        return _ok(chain)
    except Exception as e:
        return _fail(str(e))


@router.get("/attack/chains", summary="攻击链列表")
def list_chains():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        sim = get_attack_simulator()
        return _ok(sim["builder"].list_chains())
    except Exception as e:
        return _fail(str(e))


@router.get("/attack/chains/{cid}", summary="攻击链详情")
def get_chain(cid: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        sim = get_attack_simulator()
        c = sim["builder"].get_chain(cid)
        if not c:
            return _fail(f"未知攻击链: {cid}")
        return _ok(c)
    except Exception as e:
        return _fail(str(e))


@router.post("/attack/execute/technique", summary="执行单个攻击技术")
def execute_technique(req: TechniqueExecReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        sim = get_attack_simulator()
        result = sim["executor"].execute_technique(req.technique_id, req.target, req.params)
        eval_result = sim["evaluator"].evaluate_run(result)
        return _ok({"execution": result, "evaluation": eval_result})
    except Exception as e:
        return _fail(str(e))


@router.post("/attack/execute/chain/{cid}", summary="执行整条攻击链")
def execute_chain(cid: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        sim = get_attack_simulator()
        chain_run = sim["executor"].execute_chain(cid, sim["builder"])
        eval_result = sim["evaluator"].evaluate_chain(chain_run)
        return _ok({"chain_run": chain_run, "evaluation": eval_result})
    except Exception as e:
        return _fail(str(e))


@router.get("/attack/runs", summary="攻击执行记录")
def list_runs():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        sim = get_attack_simulator()
        return _ok(sim["executor"].list_runs())
    except Exception as e:
        return _fail(str(e))


@router.post("/attack/evaluate/run/{run_id}", summary="评估单次攻击效果")
def evaluate_run(run_id: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        sim = get_attack_simulator()
        run = next((r for r in sim["executor"].list_runs()
                    if r.get("run_id") == run_id), None)
        if not run:
            return _fail(f"未知运行: {run_id}")
        return _ok(sim["evaluator"].evaluate_run(run))
    except Exception as e:
        return _fail(str(e))


# ============================================================
# D. 防御验证 — 规则 / 覆盖率 / 告警
# ============================================================

@router.get("/defense/rules", summary="防御规则库")
def list_defense_rules(layer: Optional[str] = Query(None)):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        rules = list(DEFENSE_RULES.values())
        if layer:
            rules = [r for r in rules if r["layer"] == layer]
        return _ok({"total": len(rules), "rules": rules})
    except Exception as e:
        return _fail(str(e))


@router.get("/defense/coverage", summary="ATT&CK 检测覆盖率分析")
def defense_coverage():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dv = get_defense_validator()
        return _ok(dv["analyzer"].analyze())
    except Exception as e:
        return _fail(str(e))


@router.get("/defense/alerts", summary="防御告警列表")
def list_alerts():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        return _ok(list(ALERTS.values()))
    except Exception as e:
        return _fail(str(e))


@router.get("/defense/alerts/quality", summary="告警质量评估")
def alert_quality(exercise_id: str = "default"):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dv = get_defense_validator()
        return _ok(dv["validator"].evaluate_alert_quality(exercise_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/defense/validate/run/{run_id}", summary="验证攻击触发的防御告警")
def validate_alert(run_id: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        sim = get_attack_simulator()
        run = next((r for r in sim["executor"].list_runs()
                    if r.get("run_id") == run_id), {})
        dv = get_defense_validator()
        alerts = dv["validator"].trigger_alerts(run)
        return _ok({"run_id": run_id, "alerts_triggered": len(alerts), "alerts": alerts})
    except Exception as e:
        return _fail(str(e))


@router.get("/defense/effectiveness", summary="防御有效性评估")
def defense_effectiveness(attack_success: float = 0.6, detection: float = 0.7):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dv = get_defense_validator()
        return _ok(dv["effectiveness"].evaluate(attack_success, detection))
    except Exception as e:
        return _fail(str(e))


@router.get("/defense/improvements", summary="防御改进建议")
def defense_improvements():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dv = get_defense_validator()
        sim = get_attack_simulator()
        coverage = dv["analyzer"].analyze()
        imp = dv["improver"].generate(sim["executor"].list_runs(), coverage)
        return _ok(imp)
    except Exception as e:
        return _fail(str(e))


# ============================================================
# E. 紫队协作
# ============================================================

@router.post("/purple/sessions", summary="创建紫队协作会话")
def purple_start(req: PurpleStartReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dv = get_defense_validator()
        s = dv["purple"].start_session(req.name, req.red_team, req.blue_team)
        return _ok(s)
    except Exception as e:
        return _fail(str(e))


@router.post("/purple/sessions/{sid}/intel", summary="紫队情报共享")
def purple_intel(sid: str, req: PurpleIntelReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dv = get_defense_validator()
        return _ok(dv["purple"].share_intel(sid, req.intel, req.from_team))
    except Exception as e:
        return _fail(str(e))


@router.post("/purple/sessions/{sid}/action-items", summary="紫队改进行动项")
def purple_action(sid: str, item: str = Query(...), owner: str = "blue"):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dv = get_defense_validator()
        return _ok(dv["purple"].add_action_item(sid, item, owner))
    except Exception as e:
        return _fail(str(e))


@router.post("/purple/sessions/{sid}/close", summary="结束紫队会话")
def purple_close(sid: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dv = get_defense_validator()
        return _ok(dv["purple"].close_session(sid))
    except Exception as e:
        return _fail(str(e))


# ============================================================
# F. 对抗项目管理
# ============================================================

@router.post("/exercises", summary="创建红蓝对抗项目")
def create_exercise(req: ExerciseCreateReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        em = get_exercise_manager()
        e = em["project"].create(
            req.name, req.scope, req.start, req.end,
            req.red_team_name, req.blue_team_name,
            req.rules_of_engagement, req.scoring_criteria,
        )
        return _ok(e)
    except Exception as e:
        return _fail(str(e))


@router.get("/exercises", summary="对抗项目列表")
def list_exercises():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        em = get_exercise_manager()
        return _ok(em["project"].list())
    except Exception as e:
        return _fail(str(e))


@router.get("/exercises/{eid}", summary="对抗项目详情")
def get_exercise(eid: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        em = get_exercise_manager()
        e = em["project"].get(eid)
        if not e:
            return _fail(f"未知对抗: {eid}")
        return _ok(e)
    except Exception as e:
        return _fail(str(e))


@router.post("/exercises/{eid}/control", summary="对抗控制（开始/暂停/终止）")
def control_exercise(eid: str, action: str = Query("start")):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        em = get_exercise_manager()
        return _ok(em["project"].control(eid, action))
    except Exception as e:
        return _fail(str(e))


@router.get("/exercises/{eid}/config", summary="对抗配置")
def exercise_config(eid: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dash = get_exercise_dashboard()
        return _ok(dash["exercises"].config(eid))
    except Exception as e:
        return _fail(str(e))


# ============================================================
# G. 红队 / 蓝队成员管理
# ============================================================

@router.post("/exercises/{eid}/teams/{side}/members", summary="添加红/蓝队成员")
def add_member(eid: str, side: str, req: MemberReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        em = get_exercise_manager()
        return _ok(em["teams"].add_member(eid, side, req.name, req.role))
    except Exception as e:
        return _fail(str(e))


@router.get("/exercises/{eid}/teams/{side}", summary="获取红/蓝队成员")
def get_team(eid: str, side: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        em = get_exercise_manager()
        return _ok(em["teams"].get_team(eid, side))
    except Exception as e:
        return _fail(str(e))


@router.post("/exercises/{eid}/teams/{side}/tasks", summary="分配任务")
def assign_task(eid: str, side: str, req: TaskAssignReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        em = get_exercise_manager()
        return _ok(em["teams"].assign_task(eid, side, req.member_id, req.task, req.target))
    except Exception as e:
        return _fail(str(e))


@router.post("/exercises/{eid}/teams/{side}/results", summary="记录成员成果")
def record_result(eid: str, side: str, member_id: str = Query(...),
                  result: str = Query("任务完成"), score: int = 10):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        em = get_exercise_manager()
        return _ok(em["teams"].record_result(eid, side, member_id, result, score))
    except Exception as e:
        return _fail(str(e))


# ============================================================
# H. 过程记录 / 评分 / 复盘
# ============================================================

@router.get("/exercises/{eid}/timeline", summary="对抗过程时间线")
def get_timeline(eid: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        em = get_exercise_manager()
        return _ok(em["recorder"].get_timeline(eid))
    except Exception as e:
        return _fail(str(e))


@router.post("/exercises/{eid}/timeline", summary="记录对抗过程事件")
def log_event(eid: str, side: str = Query("red"), action: str = Query("attack"),
              detail: str = Query(""), technique_id: Optional[str] = Query(None)):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        em = get_exercise_manager()
        return _ok(em["recorder"].log(eid, side, action, detail, technique_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/exercises/{eid}/score", summary="对抗评分")
def score_exercise(eid: str, attack_success: float = 0.6,
                   detection: float = 0.7, response_time: float = 30.0):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        em = get_exercise_manager()
        return _ok(em["scoring"].score_exercise(eid, attack_success, detection, response_time))
    except Exception as e:
        return _fail(str(e))


@router.post("/exercises/{eid}/debrief", summary="对抗复盘")
def debrief_exercise(eid: str):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        em = get_exercise_manager()
        dv = get_defense_validator()
        coverage = dv["analyzer"].analyze()
        return _ok(em["debrief"].debrief(eid, None, coverage))
    except Exception as e:
        return _fail(str(e))


# ============================================================
# I. 攻击可视化
# ============================================================

@router.get("/viz/topology", summary="攻击拓扑图")
def viz_topology():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dash = get_exercise_dashboard()
        return _ok(dash["visualizations"].topology())
    except Exception as e:
        return _fail(str(e))


@router.get("/viz/timeline", summary="攻击链时间线")
def viz_timeline():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dash = get_exercise_dashboard()
        return _ok(dash["visualizations"].timeline())
    except Exception as e:
        return _fail(str(e))


@router.get("/viz/attack-tree", summary="攻击树可视化")
def viz_tree(goal: str = "获取域管理员权限"):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dash = get_exercise_dashboard()
        return _ok(dash["visualizations"].attack_tree(goal))
    except Exception as e:
        return _fail(str(e))


@router.get("/viz/killchain", summary="杀伤链分析")
def viz_killchain():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dash = get_exercise_dashboard()
        return _ok(dash["visualizations"].killchain())
    except Exception as e:
        return _fail(str(e))


@router.get("/viz/heatmap", summary="攻击热力图")
def viz_heatmap():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dash = get_exercise_dashboard()
        return _ok(dash["visualizations"].heatmap())
    except Exception as e:
        return _fail(str(e))


@router.get("/viz/map3d", summary="3D 全球攻击地图")
def viz_map3d():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dash = get_exercise_dashboard()
        return _ok(dash["visualizations"].map3d())
    except Exception as e:
        return _fail(str(e))


# ============================================================
# J. 攻击工具集成
# ============================================================

@router.get("/tools/market", summary="工具市场")
def tool_market():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        tools = get_attack_tools()
        return _ok(tools["orchestrator"].market())
    except Exception as e:
        return _fail(str(e))


@router.post("/tools/nmap/scan", summary="Nmap 端口扫描")
def nmap_scan(req: NmapReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        tools = get_attack_tools()
        return _ok(tools["nmap"].scan(req.target, req.ports))
    except Exception as e:
        return _fail(str(e))


@router.post("/tools/sqlmap/detect", summary="SQLMap 注入检测")
def sqlmap_detect(req: SQLMapReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        tools = get_attack_tools()
        return _ok(tools["sqlmap"].detect(req.url))
    except Exception as e:
        return _fail(str(e))


@router.post("/tools/metasploit/run", summary="Metasploit 模块执行")
def msf_run(req: MSFReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        tools = get_attack_tools()
        return _ok(tools["metasploit"].execute_module(req.module, req.target, req.options))
    except Exception as e:
        return _fail(str(e))


@router.get("/tools/metasploit/modules", summary="Metasploit 模块列表")
def msf_modules():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        tools = get_attack_tools()
        return _ok(tools["metasploit"].list_modules())
    except Exception as e:
        return _fail(str(e))


@router.get("/tools/metasploit/sessions", summary="Metasploit 会话列表")
def msf_sessions():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        tools = get_attack_tools()
        return _ok(tools["metasploit"].list_sessions())
    except Exception as e:
        return _fail(str(e))


@router.post("/tools/cobaltstrike/deploy", summary="部署 Cobalt Strike Beacon")
def cs_deploy(req: BeaconReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        tools = get_attack_tools()
        return _ok(tools["cobalt_strike"].deploy_beacon(req.target))
    except Exception as e:
        return _fail(str(e))


@router.get("/tools/cobaltstrike/beacons", summary="Cobalt Strike Beacon 列表")
def cs_beacons():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        tools = get_attack_tools()
        return _ok(tools["cobalt_strike"].list_beacons())
    except Exception as e:
        return _fail(str(e))


@router.post("/tools/orchestration/chain", summary="工具链式编排执行")
def tool_chain(req: ChainExecReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        tools = get_attack_tools()
        return _ok(tools["orchestrator"].chain_run(req.steps, req.parallel))
    except Exception as e:
        return _fail(str(e))


# ============================================================
# K. 系统设置
# ============================================================

@router.get("/settings", summary="获取系统设置")
def get_settings():
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        return _ok(SYSTEM_SETTINGS)
    except Exception as e:
        return _fail(str(e))


@router.put("/settings", summary="更新系统设置")
def update_settings(req: SettingUpdateReq):
    try:
        if not _require():
            return _fail("红蓝对抗模块未加载")
        dash = get_exercise_dashboard()
        return _ok(dash["settings"].update(req.section, req.values))
    except Exception as e:
        return _fail(str(e))


# ============================================================
# L. 健康检查
# ============================================================

@router.get("/health", summary="模块健康检查")
def health():
    try:
        return _ok({
            "status": "healthy" if _MODULES_OK else "degraded",
            "modules_loaded": _MODULES_OK,
            "techniques": len(ATTACK_TECHNIQUES),
            "tactics": len(ATTACK_TACTICS),
            "scenarios": len(ATTACK_SCENARIOS),
            "defense_rules": len(DEFENSE_RULES),
            "tasks_in_memory": len(TASKS),
            "time": datetime.now().isoformat(),
        })
    except Exception as e:
        return _fail(str(e))
