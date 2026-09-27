#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
delivery_workflow.py — 综合交付工作流。

全流程编排：
    项目启动 → 资源分配 → 执行交付 → 质量审核 → 客户验收 → 归档结算

组合 project_manager / customer_portal / time_billing /
       sla_manager / deliverable_manager / team_resource。
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Any, Dict, List, Optional


DELIVERY_STAGES: List[Dict[str, Any]] = [
    {"code": "kickoff", "name": "项目启动", "weight": 0.10,
     "actions": ["立项审批", "组建团队", "签订 SOW", "kickoff"]},
    {"code": "resource", "name": "资源分配", "weight": 0.10,
     "actions": ["人员分配", "环境准备", "权限开通", "排期确认"]},
    {"code": "execution", "name": "执行交付", "weight": 0.40,
     "actions": ["现场作业", "工时记录", "风险跟踪", "周报输出"]},
    {"code": "qa", "name": "质量审核", "weight": 0.15,
     "actions": ["交付物内审", "质量检查", "整改闭环"]},
    {"code": "acceptance", "name": "客户验收", "weight": 0.15,
     "actions": ["客户评审", "满意度回访", "签收确认书"]},
    {"code": "archive", "name": "归档结算", "weight": 0.10,
     "actions": ["文档归档", "开票", "收款", "项目复盘"]},
]


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class DeliveryWorkflow:
    """综合交付工作流编排器。"""

    def __init__(self) -> None:
        self.instances: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    # ------------------------- 启动 ------------------------- #
    def kickoff(self, workflow_id: str, project_id: str,
                customer_id: str, manager: str) -> Dict[str, Any]:
        with self._lock:
            inst = {
                "workflow_id": workflow_id, "project_id": project_id,
                "customer_id": customer_id, "manager": manager,
                "current_stage": "kickoff", "stage_index": 0,
                "progress": 0.0, "status": "running",
                "log": [{"time": _now(), "stage": "kickoff",
                         "event": "工作流启动"}],
                "created_at": _now(),
            }
            self.instances[workflow_id] = inst
            return inst

    # ------------------------- 阶段推进 ------------------------- #
    def advance(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            inst = self.instances.get(workflow_id)
            if not inst or inst["status"] != "running":
                return None
            idx = inst["stage_index"] + 1
            if idx >= len(DELIVERY_STAGES):
                inst["status"] = "completed"
                inst["progress"] = 100.0
                inst["log"].append({"time": _now(),
                                    "stage": "done",
                                    "event": "工作流完成"})
                return inst
            stage = DELIVERY_STAGES[idx]
            inst["stage_index"] = idx
            inst["current_stage"] = stage["code"]
            inst["progress"] = round(
                sum(DELIVERY_STAGES[i]["weight"] for i in range(idx + 1)) * 100, 1)
            inst["log"].append({"time": _now(), "stage": stage["code"],
                                "event": f"进入阶段: {stage['name']}"})
            return inst

    def get(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        return self.instances.get(workflow_id)

    def list(self) -> List[Dict[str, Any]]:
        return list(self.instances.values())

    # ------------------------- 阶段详情 ------------------------- #
    def stage_detail(self, code: str) -> Optional[Dict[str, Any]]:
        for s in DELIVERY_STAGES:
            if s["code"] == code:
                return s
        return None

    # ------------------------- 综合报告 ------------------------- #
    def report(self, workflow_id: str,
               project_dash: Optional[Dict[str, Any]] = None,
               billing_dash: Optional[Dict[str, Any]] = None,
               sla_dash: Optional[Dict[str, Any]] = None,
               deliverable_stats: Optional[Dict[str, Any]] = None,
               team_dash: Optional[Dict[str, Any]] = None,
               customer_dash: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        inst = self.instances.get(workflow_id)
        if not inst:
            return {}
        return {
            "workflow": inst,
            "stages": DELIVERY_STAGES,
            "snapshots": {
                "project": project_dash,
                "billing": billing_dash,
                "sla": sla_dash,
                "deliverable": deliverable_stats,
                "team": team_dash,
                "customer": customer_dash,
            },
            "generated_at": _now(),
        }


_singleton: Optional[DeliveryWorkflow] = None
_singleton_lock = threading.Lock()


def get_delivery_workflow() -> DeliveryWorkflow:
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = DeliveryWorkflow()
        return _singleton
