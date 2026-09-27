# -*- coding: utf-8 -*-
"""
scenario_practice.py — 场景化实战演练。

能力：
  - 真实场景（渗透/漏洞评估/应急响应/安全运维/合规审计/红蓝对抗/护网）
  - 场景配置（目标环境/拓扑/漏洞/数据/时间/资源/评估标准）
  - 引导式演练（步骤引导/提示/帮助/示例/参考答案/进度/完成条件）
  - 自由探索（无引导/自主发现/最佳实践对比）
  - 攻防对抗（红队/蓝队/紫队/检测/响应/复盘）
  - 演练评估（操作记录/步骤/结果/时间/资源/错误/评分/排名/证书）
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _rid(p: str) -> str:
    return f"{p}_{uuid.uuid4().hex[:10]}"


SCENARIO_TYPES = ["penetration", "vuln_assessment", "incident_response",
                  "security_ops", "compliance_audit", "red_blue", "hvv"]
MODES = ["guided", "free_explore", "attack_defense"]


class ScenarioStore:
    def __init__(self) -> None:
        self.scenarios: Dict[str, Dict[str, Any]] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.evaluations: Dict[str, Dict[str, Any]] = {}
        self._seed()

    def _seed(self) -> None:
        sid = _rid("scn")
        self.scenarios[sid] = {
            "id": sid, "type": "penetration",
            "name": "靶场Web应用渗透演练",
            "description": "在隔离靶场中完成从信息收集到getflag的全流程",
            "target_env": {"os": "Ubuntu 22.04", "services": ["nginx", "mysql"]},
            "network_topology": {"hosts": 3, "segments": ["DMZ", "内网"]},
            "vuln_settings": [{"name": "SQL注入", "severity": "high"},
                              {"name": "文件上传", "severity": "medium"}],
            "data_settings": {"db": "demo", "rows": 1000},
            "time_limit_min": 60, "resource_limit": {"cpu": 2, "mem": "2G"},
            "criteria": [
                {"step": "信息收集", "points": 10,
                 "hint": "先做端口扫描", "answer": "nmap -sV target"},
                {"step": "漏洞识别", "points": 20,
                 "hint": "尝试注入点", "answer": "' OR 1=1--"},
                {"step": "权限提升", "points": 30,
                 "hint": "查找SUID", "answer": "find / -perm -4000"},
                {"step": "获取Flag", "points": 40,
                 "hint": "在/root下", "answer": "cat /root/flag.txt"},
            ],
            "created_at": _now(),
        }


STORE = ScenarioStore()


# ---------------- 场景 CRUD ---------------- #
def create_scenario(payload: Dict[str, Any]) -> Dict[str, Any]:
    sid = _rid("scn")
    rec = {
        "id": sid, "type": payload.get("type", "penetration"),
        "name": payload.get("name", "新场景"),
        "description": payload.get("description", ""),
        "target_env": payload.get("target_env", {}),
        "network_topology": payload.get("network_topology", {}),
        "vuln_settings": list(payload.get("vuln_settings", [])),
        "data_settings": payload.get("data_settings", {}),
        "time_limit_min": int(payload.get("time_limit_min", 60)),
        "resource_limit": payload.get("resource_limit", {}),
        "criteria": list(payload.get("criteria", [])),
        "created_at": _now(),
    }
    STORE.scenarios[sid] = rec
    return rec


def list_scenarios(stype: Optional[str] = None) -> List[Dict[str, Any]]:
    out = list(STORE.scenarios.values())
    if stype:
        out = [s for s in out if s["type"] == stype]
    return out


def get_scenario(sid: str) -> Optional[Dict[str, Any]]:
    return STORE.scenarios.get(sid)


# ---------------- 演练会话 ---------------- #
def start_session(scenario_id: str, user_id: str,
                  mode: str = "guided") -> Optional[Dict[str, Any]]:
    sc = STORE.scenarios.get(scenario_id)
    if not sc:
        return None
    sess_id = _rid("sess")
    rec = {
        "id": sess_id, "scenario_id": scenario_id, "user_id": user_id,
        "mode": mode, "started_at": _now(), "elapsed_seconds": 0,
        "steps_done": [], "actions": [], "completed": False,
        "hint_level": 0, "role": "attacker" if mode != "attack_defense" else "red",
    }
    STORE.sessions[sess_id] = rec
    return rec


def session_action(sess_id: str, action: Dict[str, Any]) -> Dict[str, Any]:
    s = STORE.sessions.get(sess_id)
    if not s:
        return {"error": "会话不存在"}
    s["actions"].append({"at": _now(), **action})
    step = action.get("step")
    if step:
        sc = STORE.scenarios.get(s["scenario_id"], {})
        criteria = {c["step"]: c for c in sc.get("criteria", [])}
        if step in criteria and step not in s["steps_done"]:
            s["steps_done"].append(step)
            s["elapsed_seconds"] += action.get("cost_seconds", 0)
            done = len(s["steps_done"]) == len(criteria)
            if done:
                s["completed"] = True
            return {"step": step, "accepted": True,
                    "done_steps": list(s["steps_done"]),
                    "remaining": len(criteria) - len(s["steps_done"]),
                    "completed": s["completed"]}
    return {"step": step, "accepted": False,
            "done_steps": list(s["steps_done"])}


def get_hint(sess_id: str) -> Dict[str, Any]:
    s = STORE.sessions.get(sess_id)
    if not s:
        return {"error": "会话不存在"}
    sc = STORE.scenarios.get(s["scenario_id"], {})
    pending = [c for c in sc.get("criteria", []) if c["step"] not in s["steps_done"]]
    if not pending:
        return {"hint": "全部步骤已完成", "answer": None}
    nxt = pending[0]
    s["hint_level"] += 1
    penalty = min(10 * s["hint_level"], 30)
    return {"next_step": nxt["step"], "hint": nxt["hint"],
            "answer": nxt["answer"], "score_penalty": penalty}


def session_status(sess_id: str) -> Optional[Dict[str, Any]]:
    return STORE.sessions.get(sess_id)


# ---------------- 攻防对抗 ---------------- #
def start_duel(scenario_id: str, red_user: str, blue_user: str) -> Optional[Dict[str, Any]]:
    sc = STORE.scenarios.get(scenario_id)
    if not sc:
        return None
    did = _rid("duel")
    rec = {"id": did, "scenario_id": scenario_id,
           "red_team": red_user, "blue_team": blue_user,
           "events": [], "red_score": 0, "blue_score": 0,
           "status": "ongoing", "started_at": _now()}
    STORE.sessions[did] = rec
    return rec


def duel_event(duel_id: str, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    d = STORE.sessions.get(duel_id)
    if not d or d.get("status") != "ongoing":
        return None
    d["events"].append({"at": _now(), **event})
    if event.get("side") == "red":
        d["red_score"] += int(event.get("points", 0))
    else:
        d["blue_score"] += int(event.get("points", 0))
    if event.get("end"):
        d["status"] = "ended"
        d["ended_at"] = _now()
    return d


# ---------------- 演练评估 ---------------- #
def evaluate_session(sess_id: str) -> Optional[Dict[str, Any]]:
    s = STORE.sessions.get(sess_id)
    if not s:
        return None
    sc = STORE.scenarios.get(s["scenario_id"], {})
    total_points = sum(c.get("points", 0) for c in sc.get("criteria", []))
    earned = sum(c.get("points", 0) for c in sc.get("criteria", [])
                 if c["step"] in s["steps_done"])
    hints_penalty = min(30 * s.get("hint_level", 0), 60)
    score = max(0, round(earned - hints_penalty, 1))
    ev_id = _rid("evl")
    ev = {
        "id": ev_id, "session_id": sess_id, "user_id": s["user_id"],
        "scenario_id": s["scenario_id"],
        "steps_done": list(s["steps_done"]),
        "steps_total": len(sc.get("criteria", [])),
        "earned_points": earned, "total_points": total_points,
        "hints_used": s.get("hint_level", 0),
        "hint_penalty": hints_penalty,
        "time_seconds": s.get("elapsed_seconds", 0),
        "score": score,
        "errors": [a for a in s["actions"] if not a.get("accepted", True)],
        "rank": None,
        "certificate_issued": score >= 60,
        "evaluated_at": _now(),
    }
    STORE.evaluations[ev_id] = ev
    # 简单排名
    all_evs = [e for e in STORE.evaluations.values()
               if e["scenario_id"] == s["scenario_id"]]
    all_evs.sort(key=lambda x: x["score"], reverse=True)
    for i, e in enumerate(all_evs, start=1):
        e["rank"] = i
    return ev


def list_evaluations(scenario_id: Optional[str] = None) -> List[Dict[str, Any]]:
    out = list(STORE.evaluations.values())
    if scenario_id:
        out = [e for e in out if e["scenario_id"] == scenario_id]
    out.sort(key=lambda x: x.get("rank") or 999)
    return out


def best_practice_compare(scenario_id: str,
                          sess_id: str) -> Dict[str, Any]:
    """自由探索后与最佳实践对比。"""
    s = STORE.sessions.get(sess_id)
    sc = STORE.scenarios.get(scenario_id)
    if not s or not sc:
        return {"error": "不存在"}
    best_steps = [c["step"] for c in sc.get("criteria", [])]
    user_steps = s["steps_done"]
    return {
        "scenario_id": scenario_id,
        "best_practice_steps": best_steps,
        "your_steps": user_steps,
        "missing": [st for st in best_steps if st not in user_steps],
        "coverage": round(len(user_steps) / max(1, len(best_steps)) * 100, 1),
    }
