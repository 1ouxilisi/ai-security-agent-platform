# -*- coding: utf-8 -*-
"""
autonomous_agent.py — 自主智能体编排器。

把 planner_engine / thinking_visualizer / dynamic_adjuster / task_decomposer
串成一条“无需人工干预”的全自动执行闭环：

    用户目标
      → TaskDecomposer 拆解子任务 DAG
      → PlannerEngine 决定下一步
      → (模拟)执行该步
      → report_result（失败自动换策略）
      → 循环直到完成 → 产出报告

为了在演示/测试环境下“全自动跑通”，执行环节用确定性的模拟结果
（按概率/配置模拟成功或失败），并把每一步事件对外暴露为可订阅事件流。
真实工具接入时，只需要替换 _execute_step 的实现。
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .planner_engine import engine, PIPELINE
from .thinking_visualizer import visualizer
from .dynamic_adjuster import adjuster
from .task_decomposer import decomposer


@dataclass
class AgentEvent:
    """一条对外可订阅的智能体事件。"""

    seq: int
    event_type: str       # step_planned / step_started / step_done / step_failed
                           # / adjusted / stage_changed / completed / finding
    session_id: str
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "event_type": self.event_type,
            "session_id": self.session_id,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }


# 模拟“漏洞发现”样例，按阶段给出
_MOCK_FINDINGS = {
    "sql_injection": [
        {"title": "登录框 SQL 注入", "severity": "high",
         "evidence": "单引号触发数据库报错"},
        {"title": "搜索接口盲注", "severity": "medium",
         "evidence": "布尔盲注可布尔推断"},
    ],
    "xss": [
        {"title": "搜索反射型 XSS", "severity": "medium",
         "evidence": "<script> 原样回显"},
    ],
    "directory_traversal": [
        {"title": "/etc/passwd 可读", "severity": "high",
         "evidence": "../../etc/passwd 回显 root"},
    ],
    "auth_bypass": [
        {"title": "水平越权访问他人订单", "severity": "high",
         "evidence": "改 id 即可看他人数据"},
    ],
}


class AutonomousAgent:
    """编排器：在后台线程里自动跑完整流程。"""

    def __init__(self, *, step_delay: float = 0.4,
                 success_rate: float = 0.65) -> None:
        self._lock = threading.RLock()
        self._threads: Dict[str, threading.Thread] = {}
        self._events: Dict[str, List[AgentEvent]] = {}
        self._seq = 0
        # 事件订阅回调（给 realtime_visualization / WebSocket 用）
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        # 模拟行为配置
        self.step_delay = step_delay
        self.success_rate = success_rate

    # ------------------------------------------------------------------ #
    # 订阅
    # ------------------------------------------------------------------ #
    def subscribe(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        self._subscribers.append(cb)

    def _emit(self, session_id: str, event_type: str,
              payload: Dict[str, Any]) -> None:
        with self._lock:
            self._seq += 1
            ev = AgentEvent(seq=self._seq, event_type=event_type,
                            session_id=session_id, payload=payload)
        self._events.setdefault(session_id, []).append(ev)
        d = ev.to_dict()
        for cb in list(self._subscribers):
            try:
                cb(d)
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # 启动一个自主渗透任务
    # ------------------------------------------------------------------ #
    def run(self, goal: str, target: str = "",
            template: str = "",
            auto: bool = True) -> Dict[str, Any]:
        sess = engine.start(goal=goal, target=target, template=template)
        sess.status = "running"
        info = {
            "session_id": sess.session_id,
            "target": sess.target,
            "goal_id": sess.goal_id,
            "status": sess.status,
            "auto": auto,
        }
        self._emit(sess.session_id, "agent_started", info)
        if auto:
            t = threading.Thread(target=self._run_loop,
                                 args=(sess.session_id,), daemon=True)
            self._threads[sess.session_id] = t
            t.start()
        return info

    # ------------------------------------------------------------------ #
    # 主循环（后台线程）
    # ------------------------------------------------------------------ #
    def _run_loop(self, session_id: str, max_steps: int = 40) -> None:
        for _ in range(max_steps):
            sess = engine.get(session_id)
            if sess is None or sess.status in ("completed", "paused", "failed"):
                break

            nxt = engine.plan_next(session_id)
            if nxt is None:
                break

            self._emit(session_id, "step_planned", nxt)
            time.sleep(self.step_delay)

            ok, result, findings, reason = self._execute_step(nxt)
            engine.report_result(
                session_id, nxt["step_no"],
                success=ok, result=result,
                findings=findings, failure_reason=reason,
            )

            if ok:
                self._emit(session_id, "step_done",
                           {"step_no": nxt["step_no"], "result": result,
                            "findings": findings})
                for f in (findings or []):
                    self._emit(session_id, "finding",
                               {"step_no": nxt["step_no"], **f})
            else:
                self._emit(session_id, "step_failed",
                           {"step_no": nxt["step_no"],
                            "direction": nxt["direction"],
                            "reason": reason})
                adj = adjuster.get_events(session_id)
                if adj:
                    self._emit(session_id, "adjusted", adj[-1])

            time.sleep(self.step_delay)

        # 收尾
        sess = engine.get(session_id)
        if sess is not None and sess.status != "completed":
            engine._complete(sess)  # type: ignore[attr-defined]
        self._emit(session_id, "completed",
                   {"session_id": session_id,
                    "steps": len(sess.steps) if sess else 0,
                    "findings": len(sess.findings) if sess else 0})

    # ------------------------------------------------------------------ #
    # 单步执行（模拟；真实环境替换为真实工具调用）
    # ------------------------------------------------------------------ #
    def _execute_step(self, step: Dict[str, Any]
                      ) -> tuple[bool, str, List[Dict[str, Any]], str]:
        direction = step.get("direction", "")
        # 按成功率决定成败
        ok = random.random() < self.success_rate
        findings: List[Dict[str, Any]] = []
        if ok:
            pool = _MOCK_FINDINGS.get(direction, [])
            if pool:
                findings = [dict(f) for f in random.sample(
                    pool, k=min(len(pool), random.randint(1, len(pool))))]
            result = f"[{step['stage']}] {step['action']} 完成，" \
                     f"命中 {len(findings)} 项。"
            return True, result, findings, ""
        else:
            reason = random.choice([
                "目标无回显，无法确认",
                "WAF 拦截了探测 payload",
                "参数被服务端过滤",
                "该路径不存在/无权限",
                "服务超时",
            ])
            return False, "", [], reason

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def events(self, session_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        evs = self._events.get(session_id, [])
        return [e.to_dict() for e in evs[-limit:]]

    def status(self, session_id: str) -> Dict[str, Any]:
        s = engine.get(session_id)
        if s is None:
            return {}
        d = s.to_dict()
        d["think_timeline"] = visualizer.get_timeline(
            getattr(s, "think_session", ""))
        d["adjustments"] = adjuster.get_events(
            getattr(s, "think_session", ""))
        dg = decomposer.get_goal(s.goal_id)
        d["goal"] = dg.to_dict() if dg else None
        return d

    def list_running(self) -> List[str]:
        return [k for k, t in self._threads.items() if t.is_alive()]


agent = AutonomousAgent()
