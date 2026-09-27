# -*- coding: utf-8 -*-
"""
planner_engine.py — 规划引擎。

这是 AI 自主规划的核心状态机。它按固定的阶段流水线推进：
    探测(recon) → 资产枚举(enum) → 漏洞检测(vuln) → AI分析(analysis) → 报告(report)
每完成一步，引擎会根据“当前已知事实”自动决定下一步：
    - 该阶段是否还有子任务未做；
    - 是否需要在同阶段内切换技术方向（交给 dynamic_adjuster）；
    - 是否可以进入下一阶段；
    - 何时结束并产出报告。

引擎本身不真正发包，它维护一个“任务计划 + 阶段状态 + 决策历史”，
由 autonomous_agent 驱动，并把每一步决策推给 thinking_visualizer。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .task_decomposer import decomposer, DecomposedGoal, SubTask
from .thinking_visualizer import visualizer, SAMPLE_THOUGHTS
from .dynamic_adjuster import adjuster


# 阶段流水线定义
PIPELINE: List[Dict[str, Any]] = [
    {"stage": "recon", "label": "探测",
     "goal": "摸清目标攻击面", "weight": 0.2},
    {"stage": "enum", "label": "资产枚举",
     "goal": "枚举目录/资产/技术栈", "weight": 0.25},
    {"stage": "vuln", "label": "漏洞检测",
     "goal": "按方向尝试常见 Web 漏洞", "weight": 0.3},
    {"stage": "analysis", "label": "AI 分析",
     "goal": "关联发现、误报过滤、优先级排序", "weight": 0.15},
    {"stage": "report", "label": "报告",
     "goal": "产出结构化渗透报告", "weight": 0.1},
]


@dataclass
class PlanStep:
    """引擎规划出的一个执行步骤。"""

    step_no: int
    stage: str
    action: str
    direction: str
    reason: str
    evidence: List[str] = field(default_factory=list)
    expected: str = ""
    status: str = "planned"   # planned / running / done / failed / adjusted
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    result: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PlanSession:
    """一次自主规划会话。"""

    session_id: str
    target: str
    goal_id: str
    stage_index: int = 0
    steps: List[PlanStep] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "created"     # created / running / paused / completed / failed
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    progress: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        stage = PIPELINE[self.stage_index] if self.stage_index < len(PIPELINE) else None
        return {
            "session_id": self.session_id,
            "target": self.target,
            "goal_id": self.goal_id,
            "status": self.status,
            "stage_index": self.stage_index,
            "stage": stage,
            "progress": round(self.progress, 3),
            "step_count": len(self.steps),
            "findings_count": len(self.findings),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "steps": [s.to_dict() for s in self.steps],
        }


class PlannerEngine:
    """规划引擎：决定下一步做什么。"""

    def __init__(self) -> None:
        self._sessions: Dict[str, PlanSession] = {}

    # ------------------------------------------------------------------ #
    # 启动
    # ------------------------------------------------------------------ #
    def start(self, goal: str, target: str = "",
              template: str = "") -> PlanSession:
        """基于用户目标创建一个自主规划会话。"""
        dg: DecomposedGoal = decomposer.decompose(goal, target=target,
                                                  template=template)
        sid = "plan_" + uuid.uuid4().hex[:10]
        sess = PlanSession(
            session_id=sid,
            target=dg.target,
            goal_id=dg.goal_id,
        )
        self._sessions[sid] = sess

        # 同时建一个思考会话
        tsess = visualizer.create_session(dg.target)
        sess.think_session = tsess.session_id  # type: ignore[attr-defined]

        # 初始思考
        visualizer.add_step(
            tsess.session_id,
            phase="meta",
            observation=f"用户目标：{goal}",
            reasoning="需要把模糊目标拆解成可执行子任务，并按流水线自动推进。",
            decision=f"选择 {dg.template} 模板拆解为 {len(dg.subtasks)} 个子任务",
            expectation="从探测阶段开始，逐步自动推进到报告。",
            evidence=[f"模板={dg.template}", f"子任务数={len(dg.subtasks)}"],
            confidence=0.9,
            emotion="confident",
        )
        self._touch(sess)
        return sess

    # ------------------------------------------------------------------ #
    # 核心：决定下一步
    # ------------------------------------------------------------------ #
    def plan_next(self, session_id: str) -> Optional[Dict[str, Any]]:
        """返回下一步要执行的动作；若全部完成则返回 None。"""
        sess = self._sessions.get(session_id)
        if sess is None or sess.status in ("completed",):
            return None

        dg = decomposer.get_goal(sess.goal_id)

        # 从当前阶段向后扫描：找到第一个“有就绪子任务”的阶段并执行。
        # 这样即便当前阶段有任务被失败阻塞，也能跳到后续可推进的阶段。
        picked_sub: Optional[SubTask] = None
        picked_stage_idx = sess.stage_index
        for i in range(sess.stage_index, len(PIPELINE)):
            stage_name = PIPELINE[i]["stage"]
            ready = decomposer.next_ready_subtask(sess.goal_id)
            # 只关心本阶段的就绪子任务
            if ready is not None and ready.category == stage_name:
                picked_sub = ready
                picked_stage_idx = i
                break
            # 本阶段无就绪任务：若本阶段还有未终态任务，则视为被阻塞 → 标记为 skipped 并前进
            if dg is not None:
                pending_in_stage = [s for s in dg.subtasks
                                    if s.category == stage_name
                                    and s.status not in ("done", "failed", "skipped")]
                if pending_in_stage:
                    for s in pending_in_stage:
                        decomposer.update_subtask(
                            sess.goal_id, s.task_id,
                            status="skipped",
                            result_summary="阶段切换时被跳过")
                # 继续看下一阶段
                continue

        if picked_sub is None:
            # 没有任何可执行子任务 → 全部阶段完成，收尾
            self._complete(sess)
            return None

        # 推进到命中阶段
        sess.stage_index = picked_stage_idx
        stage = PIPELINE[picked_stage_idx]

        # 构造执行步骤
        decomposer.update_subtask(sess.goal_id, picked_sub.task_id,
                                  status="running")
        step = PlanStep(
            step_no=len(sess.steps) + 1,
            stage=stage["stage"],
            action=picked_sub.name,
            direction=self._direction_of(picked_sub),
            reason=picked_sub.description,
            evidence=[f"子任务={picked_sub.task_id}",
                      f"优先级={picked_sub.priority}",
                      f"依赖={picked_sub.depends_on or '无'}"],
            expected=picked_sub.expected_output,
            status="running",
            started_at=time.time(),
        )
        sess.steps.append(step)

        # 同步写一条 AI 思考
        stage_name = stage["stage"]
        thought_pool = SAMPLE_THOUGHTS.get(stage_name, SAMPLE_THOUGHTS["analysis"])
        obs = thought_pool[len(sess.steps) % len(thought_pool)]
        visualizer.add_step(
            sess.think_session,  # type: ignore[attr-defined]
            phase=stage_name,
            observation=obs,
            reasoning=f"当前阶段是「{stage['label']}」，子任务「{picked_sub.name}」依赖已满足。",
            decision=f"执行：{picked_sub.name}",
            expectation=picked_sub.expected_output,
            evidence=step.evidence,
            confidence=0.75,
            emotion="curious" if stage_name == "vuln" else "neutral",
        )
        self._touch(sess)
        return step.to_dict()

    # ------------------------------------------------------------------ #
    # 结果回写
    # ------------------------------------------------------------------ #
    def report_result(self, session_id: str, step_no: int, *,
                      success: bool, result: str = "",
                      findings: Optional[List[Dict[str, Any]]] = None,
                      failure_reason: str = "") -> Dict[str, Any]:
        """回写某一步的结果；失败时自动触发动态调整。"""
        sess = self._sessions.get(session_id)
        if sess is None:
            return {}
        step = next((s for s in sess.steps if s.step_no == step_no), None)
        if step is None:
            return {}
        step.finished_at = time.time()
        step.result = result
        step.status = "done" if success else "failed"

        # 更新子任务状态
        dg = decomposer.get_goal(sess.goal_id)
        if dg is not None:
            for st in dg.subtasks:
                if st.name == step.action:
                    decomposer.update_subtask(
                        sess.goal_id, st.task_id,
                        status="done" if success else "failed",
                        result_summary=result)

        if success:
            for f in (findings or []):
                sess.findings.append({
                    "step_no": step_no, **f,
                    "found_at": time.time(),
                })
            visualizer.add_step(
                sess.think_session,  # type: ignore[attr-defined]
                phase=step.stage,
                observation=f"步骤「{step.action}」完成，产出：{result[:120]}",
                reasoning="该方向有收获，继续沿同阶段深入或推进下一阶段。",
                decision="记录发现并继续规划",
                expectation="根据已发现信息优化后续步骤",
                evidence=[f.get("title", "") for f in (findings or [])][:3],
                confidence=0.85,
                emotion="confident",
            )
        else:
            # 失败 → 动态调整
            adj = adjuster.record_failure(
                sess.think_session,  # type: ignore[arg-type]
                step.direction,
                failure_reason or "未命中预期",
            )
            step.status = "adjusted"
            visualizer.add_step(
                sess.think_session,  # type: ignore[attr-defined]
                phase=step.stage,
                observation=f"步骤「{step.action}」失败：{failure_reason or '未命中预期'}",
                reasoning="该方向未奏效，需要切换技术方向继续尝试。",
                decision=f"切换到替代策略：{adj.get('chosen')}",
                expectation=f"按降级链尝试：{adj.get('chosen')}",
                evidence=[f"失败方向={step.direction}",
                          f"降级链={adj.get('fallback_chain')}"],
                confidence=0.6,
                emotion="concerned",
            )

        self._refresh_progress(sess)
        self._touch(sess)
        return {
            "step_no": step_no,
            "success": success,
            "adjustment": adj if not success else None,
            "progress": sess.progress,
        }

    # ------------------------------------------------------------------ #
    # 控制
    # ------------------------------------------------------------------ #
    def pause(self, session_id: str) -> bool:
        s = self._sessions.get(session_id)
        if s is None:
            return False
        s.status = "paused"
        self._touch(s)
        return True

    def resume(self, session_id: str) -> bool:
        s = self._sessions.get(session_id)
        if s is None:
            return False
        s.status = "running"
        self._touch(s)
        return True

    def get(self, session_id: str) -> Optional[PlanSession]:
        return self._sessions.get(session_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._sessions.values()]

    # ------------------------------------------------------------------ #
    # 内部工具
    # ------------------------------------------------------------------ #
    @staticmethod
    def _direction_of(st: SubTask) -> str:
        name = st.name.lower()
        if "sql" in name or "注入" in name:
            return "sql_injection"
        if "xss" in name:
            return "xss"
        if "目录遍历" in name or "文件包含" in name:
            return "directory_traversal"
        if "越权" in name or "访问控制" in name:
            return "auth_bypass"
        if "端口" in name:
            return "port_scan_empty"
        return "recon_refresh"

    def _stage_done(self, sess: PlanSession) -> bool:
        dg = decomposer.get_goal(sess.goal_id)
        if dg is None:
            return True
        stage_name = PIPELINE[sess.stage_index]["stage"]
        for st in dg.subtasks:
            if st.category == stage_name and st.status not in ("done", "failed", "skipped"):
                return False
        return True

    def _refresh_progress(self, sess: PlanSession) -> None:
        done_weight = 0.0
        for i, stg in enumerate(PIPELINE):
            if i < sess.stage_index:
                done_weight += stg["weight"]
            elif i == sess.stage_index:
                # 当前阶段按已完成步骤估算
                dg = decomposer.get_goal(sess.goal_id)
                if dg is not None:
                    total = [s for s in dg.subtasks if s.category == stg["stage"]]
                    if total:
                        finished = sum(1 for s in total
                                       if s.status in ("done", "failed", "skipped"))
                        done_weight += stg["weight"] * finished / len(total)
        sess.progress = round(min(1.0, done_weight), 3)

    def _complete(self, sess: PlanSession) -> None:
        sess.status = "completed"
        sess.progress = 1.0
        visualizer.add_step(
            sess.think_session,  # type: ignore[attr-defined]
            phase="report",
            observation=f"全部阶段完成，共 {len(sess.steps)} 步，发现 {len(sess.findings)} 项。",
            reasoning="侦察到报告闭环完成，可以交付。",
            decision="生成最终报告",
            expectation="输出完整渗透报告",
            confidence=0.95,
            emotion="confident",
        )
        self._touch(sess)

    @staticmethod
    def _touch(sess: PlanSession) -> None:
        sess.updated_at = time.time()


engine = PlannerEngine()
