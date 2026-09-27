#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
project_manager.py — 安全服务项目管理器。

覆盖：
    - 8 种项目类型：渗透测试 / 合规审计 / 应急响应 / 安全培训 /
                    护网支撑 / 风险评估 / 代码审计 / 云安全评估
    - 5 阶段：启动 / 规划 / 执行 / 监控 / 收尾
    - 里程碑、WBS 任务分解、甘特图数据、进度跟踪
    - 风险登记册（识别 / 评估 / 缓解 / 跟踪）
    - 项目状态聚合（仪表盘）

全部内存字典模拟，不依赖数据库。
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 项目类型字典（8 种）
# --------------------------------------------------------------------------- #
PROJECT_TYPES: Dict[str, Dict[str, Any]] = {
    "pentest": {
        "code": "PT", "name": "渗透测试", "default_duration_days": 20,
        "default_team_size": 4, "default_budget_range": (80000, 300000),
        "deliverables": ["渗透测试报告", "漏洞修复建议", "复测报告"],
        "color": "#ff6b6b",
    },
    "compliance_audit": {
        "code": "CA", "name": "合规审计", "default_duration_days": 35,
        "default_team_size": 5, "default_budget_range": (150000, 600000),
        "deliverables": ["合规差距分析", "整改路线图", "合规证明材料"],
        "color": "#1890ff",
    },
    "incident_response": {
        "code": "IR", "name": "应急响应", "default_duration_days": 7,
        "default_team_size": 3, "default_budget_range": (50000, 200000),
        "deliverables": ["事件分析报告", "取证日志", "加固建议"],
        "color": "#fa541c",
    },
    "security_training": {
        "code": "ST", "name": "安全培训", "default_duration_days": 10,
        "default_team_size": 2, "default_budget_range": (30000, 120000),
        "deliverables": ["培训课件", "考核题库", "培训成效报告"],
        "color": "#722ed1",
    },
    "hw_support": {
        "code": "HW", "name": "护网支撑", "default_duration_days": 30,
        "default_team_size": 8, "default_budget_range": (300000, 1500000),
        "deliverables": ["护网值守日报", "应急处置记录", "护网总结报告"],
        "color": "#faad14",
    },
    "risk_assessment": {
        "code": "RA", "name": "风险评估", "default_duration_days": 25,
        "default_team_size": 4, "default_budget_range": (100000, 400000),
        "deliverables": ["资产清单", "风险评估报告", "风险处置建议"],
        "color": "#13c2c2",
    },
    "code_audit": {
        "code": "SC", "name": "代码审计", "default_duration_days": 30,
        "default_team_size": 3, "default_budget_range": (120000, 500000),
        "deliverables": ["代码审计报告", "漏洞清单", "修复建议"],
        "color": "#eb2f96",
    },
    "cloud_assessment": {
        "code": "CA2", "name": "云安全评估", "default_duration_days": 22,
        "default_team_size": 4, "default_budget_range": (100000, 450000),
        "deliverables": ["云配置基线报告", "权限矩阵", "云安全加固建议"],
        "color": "#2f54eb",
    },
}


# 项目阶段（5 阶段）
PROJECT_STAGES: List[Dict[str, Any]] = [
    {"code": "init", "name": "启动", "weight": 0.10,
     "tasks": ["立项审批", "组建团队", "kickoff 会议", "签订 SOW"]},
    {"code": "planning", "name": "规划", "weight": 0.20,
     "tasks": ["范围确认", "WBS 分解", "排期", "风险识别", "环境准备"]},
    {"code": "execution", "name": "执行", "weight": 0.45,
     "tasks": ["现场作业", "工具扫描", "人工验证", "数据采集", "初步分析"]},
    {"code": "monitoring", "name": "监控", "weight": 0.15,
     "tasks": ["进度跟踪", "质量检查", "风险复盘", "周报输出"]},
    {"code": "closing", "name": "收尾", "weight": 0.10,
     "tasks": ["报告交付", "客户验收", "知识库归档", "项目复盘", "结算开票"]},
]


# 风险登记册种子数据
RISK_REGISTER: Dict[str, Dict[str, Any]] = {
    "RK-001": {"code": "RK-001", "project_id": "all", "title": "客户环境授权不完整",
               "category": "scope", "probability": 0.4, "impact": 0.7,
               "level": "high", "mitigation": "开工前签署授权书并二次确认范围",
               "owner": "项目经理", "status": "active"},
    "RK-002": {"code": "RK-002", "project_id": "all", "title": "关键人员离职/病假",
               "category": "resource", "probability": 0.2, "impact": 0.6,
               "level": "medium", "mitigation": "AB 角备份 + 知识库沉淀",
               "owner": "资源经理", "status": "active"},
    "RK-003": {"code": "RK-003", "project_id": "all", "title": "客户配合度低导致延期",
               "category": "communication", "probability": 0.3, "impact": 0.5,
               "level": "medium", "mitigation": "周会升级机制 + SLA 约束",
               "owner": "客户经理", "status": "active"},
    "RK-004": {"code": "RK-004", "project_id": "all", "title": "扫描触发业务告警",
               "category": "technical", "probability": 0.35, "impact": 0.8,
               "level": "high", "mitigation": "限流窗口 + 灰度扫描 + 回滚预案",
               "owner": "技术负责人", "status": "active"},
    "RK-005": {"code": "RK-005", "project_id": "all", "title": "数据泄露/越权",
               "category": "security", "probability": 0.05, "impact": 1.0,
               "level": "critical", "mitigation": "保密协议 + 最小权限 + 全程审计",
               "owner": "安全负责人", "status": "active"},
}


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class ProjectManager:
    """项目管理器：内存字典 CRUD + 进度 / 甘特 / 风险计算。"""

    def __init__(self) -> None:
        self.projects: Dict[str, Dict[str, Any]] = {}
        self.milestones: Dict[str, List[Dict[str, Any]]] = {}
        self.wbs: Dict[str, List[Dict[str, Any]]] = {}
        self.risks: Dict[str, List[Dict[str, Any]]] = {}
        self._seed()

    # ------------------------- 种子数据 ------------------------- #
    def _seed(self) -> None:
        seeds = [
            ("PRJ-DEMO-001", "某股份制银行核心系统渗透测试", "pentest",
             "2026-08-01", "2026-08-25", "进行中"),
            ("PRJ-DEMO-002", "某车企等保2.0三级合规审计", "compliance_audit",
             "2026-07-10", "2026-08-25", "执行中"),
            ("PRJ-DEMO-003", "某电商平台突发勒索事件应急响应", "incident_response",
             "2026-09-01", "2026-09-07", "已收尾"),
            ("PRJ-DEMO-004", "某证券公司全员安全意识培训", "security_training",
             "2026-09-05", "2026-09-15", "规划中"),
            ("PRJ-DEMO-005", "某政府单位护网行动支撑", "hw_support",
             "2026-09-10", "2026-10-10", "启动中"),
        ]
        for pid, name, ptype, start, end, status in seeds:
            self._create_project(pid, name, ptype, start, end, status)

    def _create_project(self, pid: str, name: str, ptype: str,
                        start: str, end: str, status: str) -> Dict[str, Any]:
            meta = PROJECT_TYPES.get(ptype, {})
            proj = {
                "project_id": pid, "name": name, "type": ptype,
                "type_name": meta.get("name", ptype), "code": meta.get("code", "XX"),
                "start_date": start, "end_date": end, "status": status,
                "current_stage": "execution", "progress": 35,
                "manager": "张工", "customer": "某客户",
                "budget": 200000, "actual_cost": 68000,
                "created_at": _now(), "updated_at": _now(),
                "tags": [ptype], "description": f"{meta.get('name','')}项目示例",
            }
            self.projects[pid] = proj
            # 默认里程碑
            self.milestones[pid] = [
                {"name": "Kickoff", "due": start, "completed": True},
                {"name": "WBS 评审", "due": _offset(start, 3), "completed": True},
                {"name": "中期报告", "due": _offset(start, 10), "completed": False},
                {"name": "终稿交付", "due": end, "completed": False},
                {"name": "客户验收", "due": _offset(end, 3), "completed": False},
            ]
            # 默认 WBS
            self.wbs[pid] = [
                {"id": f"{pid}-W1", "name": "需求确认", "owner": "张工",
                 "start": start, "end": _offset(start, 2), "progress": 100,
                 "stage": "planning"},
                {"id": f"{pid}-W2", "name": "现场作业", "owner": "李工",
                 "start": _offset(start, 3), "end": _offset(start, 12),
                 "progress": 40, "stage": "execution"},
                {"id": f"{pid}-W3", "name": "报告撰写", "owner": "王工",
                 "start": _offset(start, 12), "end": _offset(start, 18),
                 "progress": 10, "stage": "execution"},
                {"id": f"{pid}-W4", "name": "客户验收", "owner": "张工",
                 "start": end, "end": _offset(end, 3), "progress": 0,
                 "stage": "closing"},
            ]
            # 默认风险
            self.risks[pid] = [
                dict(r, project_id=pid) for r in list(RISK_REGISTER.values())[:3]
            ]
            return proj

    # ------------------------- CRUD ------------------------- #
    def create_project(self, name: str, ptype: str, customer: str,
                       start_date: str, end_date: str,
                       budget: float = 0.0, manager: str = "未分配",
                       description: str = "") -> Dict[str, Any]:
        pid = _uid("PRJ")
        proj = self._create_project(pid, name, ptype, start_date, end_date, "启动中")
        proj["customer"] = customer
        proj["budget"] = budget or PROJECT_TYPES.get(ptype, {}).get(
            "default_budget_range", (100000,))[0]
        proj["manager"] = manager
        proj["description"] = description
        return proj

    def list_projects(self, status: Optional[str] = None,
                      ptype: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.projects.values())
        if status:
            items = [p for p in items if p["status"] == status]
        if ptype:
            items = [p for p in items if p["type"] == ptype]
        return items

    def get_project(self, pid: str) -> Optional[Dict[str, Any]]:
        return self.projects.get(pid)

    def update_progress(self, pid: str, progress: int,
                        stage: Optional[str] = None) -> Optional[Dict[str, Any]]:
        p = self.projects.get(pid)
        if not p:
            return None
        p["progress"] = max(0, min(100, int(progress)))
        if stage:
            p["current_stage"] = stage
        p["updated_at"] = _now()
        return p

    # ------------------------- WBS / 甘特 ------------------------- #
    def get_wbs(self, pid: str) -> List[Dict[str, Any]]:
        return self.wbs.get(pid, [])

    def add_wbs_task(self, pid: str, name: str, owner: str,
                     start: str, end: str, stage: str = "execution") -> Dict[str, Any]:
        task = {"id": _uid("W"), "name": name, "owner": owner,
                "start": start, "end": end, "progress": 0, "stage": stage}
        self.wbs.setdefault(pid, []).append(task)
        return task

    def gantt_data(self, pid: str) -> Dict[str, Any]:
        tasks = self.wbs.get(pid, [])
        bars = []
        for t in tasks:
            bars.append({
                "id": t["id"], "name": t["name"], "owner": t["owner"],
                "start": t["start"], "end": t["end"],
                "progress": t["progress"], "stage": t["stage"],
            })
        return {"project_id": pid, "tasks": bars, "total": len(bars)}

    # ------------------------- 里程碑 ------------------------- #
    def get_milestones(self, pid: str) -> List[Dict[str, Any]]:
        return self.milestones.get(pid, [])

    def complete_milestone(self, pid: str, name: str) -> bool:
        for m in self.milestones.get(pid, []):
            if m["name"] == name:
                m["completed"] = True
                return True
        return False

    # ------------------------- 风险登记册 ------------------------- #
    def list_risks(self, pid: Optional[str] = None) -> List[Dict[str, Any]]:
        if pid:
            return self.risks.get(pid, [])
        out: List[Dict[str, Any]] = []
        for plist in self.risks.values():
            out.extend(plist)
        return out

    def add_risk(self, pid: str, title: str, category: str,
                 probability: float, impact: float,
                 mitigation: str, owner: str) -> Dict[str, Any]:
        level = "low"
        score = probability * impact
        if score >= 0.6:
            level = "critical"
        elif score >= 0.4:
            level = "high"
        elif score >= 0.2:
            level = "medium"
        risk = {"code": _uid("RK"), "project_id": pid, "title": title,
                "category": category, "probability": probability,
                "impact": impact, "level": level,
                "mitigation": mitigation, "owner": owner, "status": "active",
                "created_at": _now()}
        self.risks.setdefault(pid, []).append(risk)
        return risk

    # ------------------------- 仪表盘 ------------------------- #
    def dashboard(self) -> Dict[str, Any]:
        projects = list(self.projects.values())
        by_status: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        total_budget = 0.0
        total_cost = 0.0
        for p in projects:
            by_status[p["status"]] = by_status.get(p["status"], 0) + 1
            by_type[p["type_name"]] = by_type.get(p["type_name"], 0) + 1
            total_budget += float(p.get("budget", 0))
            total_cost += float(p.get("actual_cost", 0))
        active_risks = sum(len(v) for v in self.risks.values())
        critical_risks = sum(1 for v in self.risks.values()
                             for r in v if r.get("level") == "critical")
        avg_progress = (sum(p["progress"] for p in projects) / len(projects)
                        if projects else 0)
        return {
            "total_projects": len(projects),
            "by_status": by_status,
            "by_type": by_type,
            "avg_progress": round(avg_progress, 1),
            "total_budget": total_budget,
            "total_actual_cost": total_cost,
            "budget_utilization": round(total_cost / total_budget, 3)
                if total_budget else 0,
            "active_risks": active_risks,
            "critical_risks": critical_risks,
            "updated_at": _now(),
        }


def _offset(date_str: str, days: int) -> str:
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d") + timedelta(days=days)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return date_str
