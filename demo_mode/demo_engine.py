# -*- coding: utf-8 -*-
"""
demo_mode/demo_engine.py — 自动演示引擎。

职责：
    1. 演示脚本（脚本定义/步骤/动作/等待/断言/变量/条件/循环/并行）
    2. 演示执行（自动/手动/半自动/步骤控制/暂停/继续/跳过/重播）
    3. 演示控制（播放/暂停/停止/快进/慢放/倍速/全屏/画中画/旁白）
    4. 演示录制（屏幕/操作/语音录制/格式/质量/编辑/导出）
    5. 演示旁白（自动旁白/TTS/语音合成/旁白脚本/timing/多语言）
    6. 演示交互（观众提问/实时投票/演示分支/互动环节/反馈收集）
"""

from __future__ import annotations

import copy
import time
import uuid
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# 第三方库 try-import
# --------------------------------------------------------------------------- #
try:  # pragma: no cover
    import pyttsx3  # type: ignore
    _TTS_OK = True
except Exception:  # noqa: BLE001
    _TTS_OK = False


# --------------------------------------------------------------------------- #
# 内存存储
# --------------------------------------------------------------------------- #
SCRIPTS: Dict[str, Dict[str, Any]] = {}
EXECUTIONS: Dict[str, Dict[str, Any]] = {}
RECORDINGS: Dict[str, Dict[str, Any]] = {}
NARRATIONS: Dict[str, Dict[str, Any]] = {}
INTERACTIONS: Dict[str, Dict[str, Any]] = {}


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _rid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- #
# 1. 演示脚本
# --------------------------------------------------------------------------- #
def list_scripts() -> List[Dict[str, Any]]:
    return [{"script_id": s["script_id"], "name": s["name"],
             "scenario_id": s.get("scenario_id"),
             "steps": len(s.get("steps", [])),
             "version": s.get("version", "1.0"),
             "updated_at": s.get("updated_at")}
            for s in SCRIPTS.values()]


def get_script(script_id: str) -> Optional[Dict[str, Any]]:
    return SCRIPTS.get(script_id)


def create_script(payload: Dict[str, Any]) -> Dict[str, Any]:
    sid = payload.get("script_id") or _rid("scr")
    steps = payload.get("steps") or [
        {"id": "s1", "action": "navigate", "target": "/", "wait_ms": 500},
        {"id": "s2", "action": "click", "target": "#scan-btn", "wait_ms": 800},
        {"id": "s3", "action": "assert", "target": ".vuln-list",
         "expect": "exists"},
    ]
    script = {
        "script_id": sid,
        "name": payload.get("name", "未命名脚本"),
        "scenario_id": payload.get("scenario_id"),
        "steps": steps,
        "variables": payload.get("variables", {}),
        "version": payload.get("version", "1.0"),
        "loop": payload.get("loop", False),
        "parallel": payload.get("parallel", False),
        "created_at": _now(),
        "updated_at": _now(),
    }
    SCRIPTS[sid] = script
    return script


def update_script(script_id: str,
                  payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    s = SCRIPTS.get(script_id)
    if not s:
        return None
    for k in ("name", "steps", "variables", "loop", "parallel"):
        if k in payload:
            s[k] = payload[k]
    s["updated_at"] = _now()
    return s


def delete_script(script_id: str) -> bool:
    return SCRIPTS.pop(script_id, None) is not None


# --------------------------------------------------------------------------- #
# 2. 演示执行
# --------------------------------------------------------------------------- #
def start_execution(script_id: str, mode: str = "auto",
                   variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    s = SCRIPTS.get(script_id)
    if not s:
        raise KeyError(f"script not found: {script_id}")
    eid = _rid("exe")
    steps = copy.deepcopy(s.get("steps", []))
    for i, st in enumerate(steps):
        st["_index"] = i
    exe = {
        "execution_id": eid,
        "script_id": script_id,
        "script_name": s["name"],
        "mode": mode,  # auto | manual | semi
        "status": "running",
        "step_index": 0,
        "total_steps": len(steps),
        "steps": steps,
        "variables": {**s.get("variables", {}), **(variables or {})},
        "speed": 1.0,
        "started_at": _now(),
        "finished_at": None,
        "log": [],
    }
    EXECUTIONS[eid] = exe
    _log_step(eid, 0, "开始执行")
    return exe


def _log_step(eid: str, idx: int, msg: str) -> None:
    e = EXECUTIONS.get(eid)
    if e:
        e["log"].append({"idx": idx, "at": _now(), "msg": msg})


def _advance(e: Dict[str, Any]) -> None:
    """推进一个步骤（内存模拟，真实执行动作只记录日志）。"""
    idx = e["step_index"]
    if idx >= e["total_steps"]:
        e["status"] = "finished"
        e["finished_at"] = _now()
        return
    step = e["steps"][idx]
    action = step.get("action", "noop")
    target = step.get("target", "")
    wait = step.get("wait_ms", 0)
    if action == "assert":
        expect = step.get("expect", "exists")
        ok = True  # 模拟断言恒真
        e["variables"]["last_assert_ok"] = ok
        _log_step(e["execution_id"], idx,
                  f"断言 {target} → {expect} {'通过' if ok else '失败'}")
    elif action == "wait":
        _log_step(e["execution_id"], idx,
                  f"等待 {step.get('ms', wait)}ms")
    else:
        _log_step(e["execution_id"], idx,
                  f"执行 {action} @ {target} (等待{wait}ms)")
    e["step_index"] += 1
    if e["step_index"] >= e["total_steps"]:
        e["status"] = "finished"
        e["finished_at"] = _now()


def control_execution(eid: str, action: str,
                      payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    e = EXECUTIONS.get(eid)
    if not e:
        raise KeyError(eid)
    p = payload or {}
    if action == "play":
        e["status"] = "running"
        _advance(e)
    elif action == "pause":
        e["status"] = "paused"
        _log_step(eid, e["step_index"], "暂停")
    elif action == "resume":
        e["status"] = "running"
        _advance(e)
    elif action == "stop":
        e["status"] = "stopped"
        e["finished_at"] = _now()
    elif action == "next":
        _advance(e)
    elif action == "skip":
        e["step_index"] = min(e["step_index"] + 1, e["total_steps"])
        _log_step(eid, e["step_index"], "跳过")
    elif action == "replay":
        e["step_index"] = 0
        e["status"] = "running"
        e["log"] = []
        _log_step(eid, 0, "重播")
    elif action == "set_speed":
        e["speed"] = float(p.get("speed", 1.0))
        _log_step(eid, e["step_index"], f"倍速 → {e['speed']}x")
    elif action == "fast_forward":
        e["speed"] = min(e["speed"] * 2, 8.0)
    elif action == "slow_motion":
        e["speed"] = max(e["speed"] / 2, 0.25)
    else:
        raise ValueError(f"unknown control: {action}")
    return e


def get_execution(eid: str) -> Optional[Dict[str, Any]]:
    return EXECUTIONS.get(eid)


def list_executions(status: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(EXECUTIONS.values())
    if status:
        items = [x for x in items if x.get("status") == status]
    return [{"execution_id": e["execution_id"],
             "script_id": e["script_id"],
             "script_name": e["script_name"],
             "status": e["status"],
             "step_index": e["step_index"],
             "total_steps": e["total_steps"],
             "started_at": e["started_at"],
             "finished_at": e["finished_at"]} for e in items]


# --------------------------------------------------------------------------- #
# 3. 演示控制（播放/暂停/快进/倍速/全屏/画中画/旁白）
# --------------------------------------------------------------------------- #
PRESETS: Dict[str, Dict[str, Any]] = {
    "play": {"action": "play", "label": "播放"},
    "pause": {"action": "pause", "label": "暂停"},
    "stop": {"action": "stop", "label": "停止"},
    "ff": {"action": "fast_forward", "label": "快进"},
    "slow": {"action": "slow_motion", "label": "慢放"},
    "speed_1x": {"action": "set_speed", "speed": 1.0, "label": "1.0x"},
    "speed_2x": {"action": "set_speed", "speed": 2.0, "label": "2.0x"},
    "speed_4x": {"action": "set_speed", "speed": 4.0, "label": "4.0x"},
    "fullscreen": {"action": "fullscreen", "label": "全屏"},
    "pip": {"action": "picture_in_picture", "label": "画中画"},
    "narration_toggle": {"action": "narration_toggle", "label": "旁白"},
}


def list_control_presets() -> Dict[str, Any]:
    return PRESETS


# --------------------------------------------------------------------------- #
# 4. 演示录制
# --------------------------------------------------------------------------- #
def start_recording(execution_id: str,
                    options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    opts = options or {}
    rid = _rid("rec")
    rec = {
        "recording_id": rid,
        "execution_id": execution_id,
        "format": opts.get("format", "mp4"),
        "quality": opts.get("quality", "1080p"),
        "capture": opts.get("capture",
                             {"screen": True, "actions": True,
                              "voice": True}),
        "started_at": _now(),
        "status": "recording",
        "frames": 0,
    }
    RECORDINGS[rid] = rec
    return rec


def stop_recording(recording_id: str) -> Dict[str, Any]:
    r = RECORDINGS.get(recording_id)
    if not r:
        raise KeyError(recording_id)
    r["status"] = "finished"
    r["finished_at"] = _now()
    r["file_url"] = f"/media/recordings/{recording_id}.{r['format']}"
    return r


def list_recordings() -> List[Dict[str, Any]]:
    return [{"recording_id": r["recording_id"],
             "execution_id": r["execution_id"],
             "status": r["status"],
             "format": r["format"],
             "quality": r["quality"],
             "started_at": r["started_at"],
             "file_url": r.get("file_url")} for r in RECORDINGS.values()]


# --------------------------------------------------------------------------- #
# 5. 演示旁白
# --------------------------------------------------------------------------- #
def generate_narration(script_id: str,
                      lang: str = "zh-CN") -> Dict[str, Any]:
    s = SCRIPTS.get(script_id)
    if not s:
        raise KeyError(script_id)
    lines = []
    total_ms = 0
    for i, st in enumerate(s.get("steps", [])):
        wait = st.get("wait_ms", 500)
        text = f"第 {i+1} 步：执行 {st.get('action')}，目标 {st.get('target')}。"
        lines.append({
            "step": i, "text": text,
            "start_ms": total_ms,
            "duration_ms": wait,
        })
        total_ms += wait
    nid = _rid("nar")
    nar = {
        "narration_id": nid,
        "script_id": script_id,
        "language": lang,
        "lines": lines,
        "total_ms": total_ms,
        "tts_available": _TTS_OK,
        "created_at": _now(),
    }
    NARRATIONS[nid] = nar
    return nar


def list_narrations() -> List[Dict[str, Any]]:
    return [{"narration_id": n["narration_id"],
             "script_id": n["script_id"],
             "language": n["language"],
             "total_ms": n["total_ms"],
             "tts_available": n["tts_available"]} for n in NARRATIONS.values()]


# --------------------------------------------------------------------------- #
# 6. 演示交互
# --------------------------------------------------------------------------- #
def create_poll(execution_id: str, question: str,
               options: List[str]) -> Dict[str, Any]:
    pid = _rid("pol")
    poll = {
        "poll_id": pid,
        "execution_id": execution_id,
        "question": question,
        "options": [{"text": o, "votes": 0} for o in options],
        "status": "open",
        "created_at": _now(),
    }
    INTERACTIONS[pid] = poll
    return poll


def vote_poll(poll_id: str, option_index: int) -> Dict[str, Any]:
    p = INTERACTIONS.get(poll_id)
    if not p:
        raise KeyError(poll_id)
    if 0 <= option_index < len(p["options"]):
        p["options"][option_index]["votes"] += 1
    return p


def ask_question(execution_id: str, user: str,
                 question: str) -> Dict[str, Any]:
    qid = _rid("ask")
    qa = {
        "qa_id": qid,
        "execution_id": execution_id,
        "user": user,
        "question": question,
        "answer": None,
        "status": "open",
        "asked_at": _now(),
    }
    INTERACTIONS[qid] = qa
    return qa


def answer_question(qa_id: str, answer: str) -> Dict[str, Any]:
    q = INTERACTIONS.get(qa_id)
    if not q:
        raise KeyError(qa_id)
    q["answer"] = answer
    q["status"] = "answered"
    q["answered_at"] = _now()
    return q


def branch_demo(execution_id: str, branch_name: str) -> Dict[str, Any]:
    e = EXECUTIONS.get(execution_id)
    if not e:
        raise KeyError(execution_id)
    e["branch"] = branch_name
    _log_step(execution_id, e["step_index"], f"分支切换 → {branch_name}")
    return {"execution_id": execution_id, "branch": branch_name,
            "at": _now()}


def collect_feedback(execution_id: str, score: int,
                    comment: str = "") -> Dict[str, Any]:
    fid = _rid("fb")
    fb = {
        "feedback_id": fid,
        "execution_id": execution_id,
        "score": max(1, min(5, int(score))),
        "comment": comment,
        "at": _now(),
    }
    INTERACTIONS[fid] = fb
    return fb


def list_interactions(execution_id: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(INTERACTIONS.values())
    if execution_id:
        items = [x for x in items if x.get("execution_id") == execution_id]
    return items
