# -*- coding: utf-8 -*-
"""
demo_mode/quick_experience.py — 3 分钟快速体验。

职责：
    1. 快速体验流程（3分钟体验设计/核心功能展示/关键操作/即时反馈/成就感）
    2. 快速体验场景（一键扫描/报告/靶场/监控/演练 Demo）
    3. 快速体验引导（极简引导/大按钮/清晰步骤/即时反馈/进度条/完成庆祝）
    4. 快速体验数据（预置数据/即时生成/真实感/无需配置/无需等待）
    5. 快速体验转化（注册/试用/购买/联系销售/案例展示）
    6. 快速体验分析（完成率/每步流失/转化漏斗/体验时长/反馈/优化建议）
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from . import demo_dataset as ds


# --------------------------------------------------------------------------- #
# 内存存储
# --------------------------------------------------------------------------- #
QUICK_SCENARIOS: Dict[str, Dict[str, Any]] = {}
SESSIONS: Dict[str, Dict[str, Any]] = {}
FUNNEL: Dict[str, int] = {
    "view": 0, "start": 0, "step1": 0, "step2": 0,
    "step3": 0, "finish": 0, "convert_register": 0,
    "convert_trial": 0, "convert_contact_sales": 0,
}


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _rid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- #
# 1. 3 分钟快速体验场景
# --------------------------------------------------------------------------- #
def _build_default_scenarios() -> None:
    raw = [
        {
            "id": "qe_scan", "name": "一键扫描 Demo",
            "duration_sec": 60,
            "headline": "60 秒扫描一个靶场目标",
            "description": "预置靶场，自动完成端口/Web/弱口令扫描，即时出结果。",
            "steps": ["输入预置目标", "点击开始扫描", "查看漏洞列表"],
            "celebration": "发现 3 个漏洞，报告已生成！",
        },
        {
            "id": "qe_report", "name": "一键报告 Demo",
            "duration_sec": 45,
            "headline": "45 秒生成专业渗透报告",
            "description": "预置数据，一键生成 PDF/Word 报告。",
            "steps": ["选择预置数据集", "选择报告模板", "下载报告"],
            "celebration": "报告导出成功，可直接发给客户！",
        },
        {
            "id": "qe_range", "name": "一键靶场 Demo",
            "duration_sec": 90,
            "headline": "90 秒打完一个 CTF 靶场",
            "description": "从信息收集到 flag，全流程自动演示。",
            "steps": ["启动靶场", "自动利用", "拿到 flag"],
            "celebration": "Flag 拿下！用时 1 分 23 秒！",
        },
        {
            "id": "qe_monitor", "name": "一键监控 Demo",
            "duration_sec": 75,
            "headline": "75 秒看懂告警分诊",
            "description": "预置 30 条告警，一键分诊并标注误报。",
            "steps": ["加载告警流", "AI 分诊", "处置确认"],
            "celebration": "分诊完成，误报率 12%！",
        },
        {
            "id": "qe_drill", "name": "一键演练 Demo",
            "duration_sec": 120,
            "headline": "120 秒红蓝对抗演练",
            "description": "红队攻击链 + 蓝队检测响应全链路。",
            "steps": ["红队初始访问", "横向移动", "蓝队告警封堵"],
            "celebration": "演练完成，检出率 92%！",
        },
    ]
    for s in raw:
        QUICK_SCENARIOS[s["id"]] = s


def list_quick_scenarios() -> List[Dict[str, Any]]:
    return list(QUICK_SCENARIOS.values())


def get_quick_scenario(scenario_id: str) -> Optional[Dict[str, Any]]:
    return QUICK_SCENARIOS.get(scenario_id)


# --------------------------------------------------------------------------- #
# 2. 快速体验会话（真实追踪用户进度）
# --------------------------------------------------------------------------- #
def start_session(scenario_id: str,
                  user: str = "anonymous") -> Dict[str, Any]:
    sc = QUICK_SCENARIOS.get(scenario_id)
    if not sc:
        raise KeyError(scenario_id)
    sid = _rid("qe")
    FUNNEL["view"] += 1
    FUNNEL["start"] += 1
    sess = {
        "session_id": sid,
        "scenario_id": scenario_id,
        "scenario_name": sc["name"],
        "user": user,
        "status": "running",
        "step_index": 0,
        "total_steps": len(sc["steps"]),
        "started_at": _now(),
        "finished_at": None,
        "duration_sec": 0,
        "events": [{"at": _now(), "event": "start"}],
        "dataset_id": None,
    }
    SESSIONS[sid] = sess
    return sess


def advance_session(session_id: str,
                    action: str = "next") -> Dict[str, Any]:
    s = SESSIONS.get(session_id)
    if not s:
        raise KeyError(session_id)
    if action == "next":
        s["step_index"] = min(s["step_index"] + 1, s["total_steps"])
        s["events"].append({"at": _now(),
                            "event": f"step_{s['step_index']}"})
        # 漏斗埋点
        if s["step_index"] == 1:
            FUNNEL["step1"] += 1
        elif s["step_index"] == 2:
            FUNNEL["step2"] += 1
        elif s["step_index"] == 3:
            FUNNEL["step3"] += 1
    elif action == "generate_data":
        # 即时生成预置数据
        ds_id = ds.generate_dataset(
            s["scenario_id"],
            {"asset_count": 10, "vuln_count": 6,
             "alert_count": 15, "event_count": 20,
             "user_count": 4, "step_count": 6},
        )["dataset_id"]
        s["dataset_id"] = ds_id
        s["events"].append({"at": _now(), "event": "data_generated",
                            "dataset_id": ds_id})
    elif action == "finish":
        s["step_index"] = s["total_steps"]
        s["status"] = "completed"
        s["finished_at"] = _now()
        s["events"].append({"at": _now(), "event": "finish"})
        FUNNEL["finish"] += 1
    elif action == "abandon":
        s["status"] = "abandoned"
        s["finished_at"] = _now()
        s["events"].append({"at": _now(), "event": "abandon"})
    return s


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    return SESSIONS.get(session_id)


def list_sessions(status: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(SESSIONS.values())
    if status:
        items = [x for x in items if x.get("status") == status]
    return items


# --------------------------------------------------------------------------- #
# 3. 转化漏斗
# --------------------------------------------------------------------------- #
def track_conversion(session_id: str,
                    ctype: str) -> Dict[str, Any]:
    """ctype: register / trial / contact_sales."""
    s = SESSIONS.get(session_id)
    if not s:
        raise KeyError(session_id)
    key = f"convert_{ctype}"
    if key in FUNNEL:
        FUNNEL[key] += 1
    s.setdefault("conversions", []).append(
        {"type": ctype, "at": _now()})
    return {"session_id": session_id, "conversion": ctype, "recorded": True}


def get_funnel() -> Dict[str, Any]:
    f = dict(FUNNEL)
    view = max(1, f["view"])
    f["conversion_pct"] = round(f["finish"] / view * 100, 1)
    f["register_pct"] = round(f["convert_register"] / view * 100, 1)
    f["trial_pct"] = round(f["convert_trial"] / view * 100, 1)
    return f


# --------------------------------------------------------------------------- #
# 4. 快速体验分析
# --------------------------------------------------------------------------- #
def get_analytics() -> Dict[str, Any]:
    total = len(SESSIONS)
    completed = sum(1 for x in SESSIONS.values()
                   if x["status"] == "completed")
    abandoned = sum(1 for x in SESSIONS.values()
                    if x["status"] == "abandoned")
    durations = [x.get("duration_sec", 0) for x in SESSIONS.values()]
    avg_dur = round(sum(durations) / len(durations), 1) if durations else 0.0
    return {
        "total_sessions": total,
        "completed": completed,
        "abandoned": abandoned,
        "completion_rate_pct": round(completed / total * 100, 1) if total else 0.0,
        "avg_duration_sec": avg_dur,
        "funnel": get_funnel(),
        "drop_off": [
            {"step": "进入", "pct": 100.0},
            {"step": "开始",
             "pct": round(FUNNEL["start"] / max(1, FUNNEL["view"]) * 100, 1)},
            {"step": "步骤1",
             "pct": round(FUNNEL["step1"] / max(1, FUNNEL["view"]) * 100, 1)},
            {"step": "步骤2",
             "pct": round(FUNNEL["step2"] / max(1, FUNNEL["view"]) * 100, 1)},
            {"step": "完成",
             "pct": round(FUNNEL["finish"] / max(1, FUNNEL["view"]) * 100, 1)},
        ],
        "optimization_suggestions": [
            "首屏 3 秒内必须展示大按钮，避免加载等待",
            "步骤1 流失最高，考虑自动填充目标",
            "完成页加大「注册后继续使用」按钮曝光",
        ],
    }


# 初始化
if not QUICK_SCENARIOS:
    _build_default_scenarios()
