#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar/soar_workflow.py — SOAR 综合工作流编排。

端到端流水线：
    告警接入 → 分诊丰富 → 剧本匹配 → 自动化执行 → 案例管理 → 度量分析 → 持续优化

把 alert_triage / playbook_engine / execution_engine / action_library /
case_manager / soar_metrics 串成一条可观测的流水线。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional

from .action_library import get_action_executor
from .alert_triage import get_alert_triage
from .case_manager import get_case_manager
from .execution_engine import get_execution_engine
from .playbook_engine import get_playbook_engine
from .soar_metrics import get_soar_metrics


WORKFLOW_STEPS = [
    {"step": 1, "key": "ingest",     "name": "告警接入",      "desc": "归一化接收外部告警"},
    {"step": 2, "key": "triage",     "name": "分诊与丰富",    "desc": "情报/资产/用户富化并评分"},
    {"step": 3, "key": "match",      "name": "剧本匹配",      "desc": "按触发条件匹配候选剧本"},
    {"step": 4, "key": "execute",    "name": "自动化执行",    "desc": "在执行引擎中运行剧本"},
    {"step": 5, "key": "case",       "name": "案例管理",      "desc": "必要时升级为案例"},
    {"step": 6, "key": "metrics",    "name": "度量分析",      "desc": "回写运营指标"},
    {"step": 7, "key": "improve",    "name": "持续优化",      "desc": "反馈到剧本/规则调优"},
]


class SOARWorkflow:
    """SOAR 端到端工作流。"""

    def __init__(self) -> None:
        self.triage = get_alert_triage()
        self.playbooks = get_playbook_engine()
        self.executor = get_execution_engine()
        self.actions = get_action_executor()
        self.cases = get_case_manager()
        self.metrics = get_soar_metrics()
        self.runs: Dict[str, Dict[str, Any]] = {}

    # ---- 主入口 ----
    def run_pipeline(self, raw_alert: Dict[str, Any],
                     auto_execute: bool = True,
                     create_case: bool = True) -> Dict[str, Any]:
        run_id = f"WF-{uuid.uuid4().hex[:10]}"
        log: list = []
        started = time.strftime("%Y-%m-%d %H:%M:%S")

        # 1) 接入
        alert = self.triage.ingest(raw_alert)
        log.append({"step": "ingest", "alert_id": alert["alert_id"],
                    "severity": alert["severity"]})

        # 2) 分诊
        self.triage.correlate(alert["alert_id"])
        decision = self.triage.auto_triage(alert["alert_id"])
        log.append({"step": "triage", "score": alert["triage"]["score"],
                    "priority": alert["triage"]["priority"],
                    "decision": decision["decision"]})

        # 3) 剧本匹配
        candidates = self._match_playbooks(alert)
        chosen = candidates[0] if candidates else None
        log.append({"step": "match", "candidates": len(candidates),
                    "chosen": chosen["template_id"] if chosen else None})

        case_ref: Optional[Dict[str, Any]] = None
        exec_ref: Optional[Dict[str, Any]] = None

        # 4) 自动化执行
        if chosen and auto_execute and decision["decision"] in ("auto_respond", "assign_analyst"):
            steps = []
            for s in chosen["steps"]:
                ref = s.get("n")
                if ref and "." in ref:
                    steps.append({"step_id": f"s{len(steps)}",
                                  "action_id": ref,
                                  "params": {"alert_id": alert["alert_id"]},
                                  "approval": s["t"] == "approval"})
            task = self.executor.submit(f"WF {alert['alert_id']}", steps)
            exec_ref = self.executor.run(task["task_id"])
            log.append({"step": "execute", "task_id": task["task_id"],
                        "status": exec_ref["status"]})

        # 5) 案例管理（高分或失败时升级为案例）
        score_val = alert["triage"].get("score", {})
        score_num = score_val.get("score", 0) if isinstance(score_val, dict) else score_val
        need_case = (create_case and score_num >= 60) or \
                    (exec_ref and exec_ref["status"] in ("failed", "waiting_approval"))
        if need_case:
            case = self.cases.create(
                title=f"{alert['title']} ({alert['alert_id']})",
                severity=alert["severity"],
                category=chosen["category"] if chosen else "其他",
                related_alerts=[alert["alert_id"]],
            )
            if exec_ref:
                self.cases.add_evidence(case["case_id"], exec_ref["task_id"],
                                       source="execution_engine")
            case_ref = {"case_id": case["case_id"], "status": case["status"]}
            log.append({"step": "case", "case_id": case["case_id"]})

        # 6) 度量
        m = self.metrics.summary()
        log.append({"step": "metrics", "automation_rate": m["today"].get("automation_rate")})

        # 7) 持续优化建议
        suggestions = self._suggest_improvements(alert, decision, exec_ref)
        log.append({"step": "improve", "suggestions": suggestions})

        record = {
            "run_id": run_id, "alert_id": alert["alert_id"],
            "started_at": started,
            "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "log": log, "playbook_used": chosen["template_id"] if chosen else None,
            "execution": exec_ref, "case": case_ref,
            "suggestions": suggestions,
        }
        self.runs[run_id] = record
        return record

    # ---- 剧本匹配（按触发条件命中）----
    def _match_playbooks(self, alert: Dict[str, Any]) -> list:
        hits = []
        rule = (alert.get("rule") or "").lower()
        sev = alert.get("severity", "")
        for tpl in self.playbooks.list_templates():
            score = 0
            for cond in tpl["trigger_conditions"]:
                if cond.lower() in rule or rule in cond.lower():
                    score += 2
            if tpl["severity"] == sev:
                score += 1
            if score > 0:
                hits.append((score, tpl))
        hits.sort(key=lambda x: -x[0])
        return [t for _, t in hits[:5]]

    # ---- 优化建议 ----
    @staticmethod
    def _suggest_improvements(alert: Dict[str, Any],
                              decision: Dict[str, Any],
                              exec_ref: Optional[Dict[str, Any]]) -> list:
        out = []
        if decision["decision"] == "auto_respond":
            out.append("已自动化闭环，建议把该规则加入下季度成熟剧本")
        if exec_ref and exec_ref["status"] == "waiting_approval":
            out.append("审批节点过多导致 SLA 压力，评估是否可自动通过低风险动作")
        fp = alert_triage_fp_ratio()
        if fp > 0.3:
            out.append(f"该规则误报率 {fp:.0%} 偏高，建议调优检测阈值")
        sc = alert["triage"].get("score", {})
        score_num = sc.get("score", 0) if isinstance(sc, dict) else sc
        if score_num >= 80:
            out.append("高分事件频发，建议检查资产暴露面")
        return out[:5]

    # ---- 查询 ----
    def list_runs(self, limit: int = 50) -> list:
        return sorted(self.runs.values(),
                      key=lambda r: r["finished_at"], reverse=True)[:limit]

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        return self.runs.get(run_id)

    def overview(self) -> Dict[str, Any]:
        return {
            "workflow_steps": WORKFLOW_STEPS,
            "total_runs": len(self.runs),
            "triage": self.triage.dashboard(),
            "playbooks": self.playbooks.stats(),
            "execution": self.executor.performance(),
            "cases": self.cases.stats(),
            "metrics": self.metrics.dashboard(),
        }


def alert_triage_fp_ratio() -> float:
    """辅助：返回当前误报率（来自 triage 模块）。"""
    t = get_alert_triage()
    if not t.alerts:
        return 0.0
    fp = len(t.false_positives)
    return fp / max(1, len(t.alerts))


_SINGLETON: Optional[SOARWorkflow] = None


def get_soar_workflow() -> SOARWorkflow:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = SOARWorkflow()
    return _SINGLETON


if __name__ == "__main__":  # pragma: no cover
    wf = get_soar_workflow()
    r = wf.run_pipeline({"title": "C2 beacon", "rule": "c2_beacon",
                         "severity": "critical", "src_ip": "203.0.113.66",
                         "asset": "WEB-EXT-01", "user": "wang.wu"})
    print(r["run_id"], r["playbook_used"])
