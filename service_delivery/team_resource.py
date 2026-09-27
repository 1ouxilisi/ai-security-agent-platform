#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
team_resource.py — 团队与资源管理。

覆盖：
    - 人员管理、20+ 安全技能矩阵
    - 角色权限、资源分配（按项目 / 按任务）
    - 利用率统计、团队绩效、知识库、最佳实践
    - 综合运营仪表盘
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


# 20+ 安全技能矩阵
SECURITY_SKILLS: Dict[str, Dict[str, Any]] = {
    "pentest_web": {"name": "Web 渗透测试", "domain": "红队", "required_cert": "OSCP"},
    "pentest_internal": {"name": "内网渗透", "domain": "红队", "required_cert": "CRTO"},
    "red_team": {"name": "红队演练", "domain": "红队", "required_cert": "CRTO"},
    "reverse": {"name": "逆向工程", "domain": "攻防", "required_cert": ""},
    "malware_analysis": {"name": "恶意代码分析", "domain": "攻防", "required_cert": ""},
    "digital_forensics": {"name": "电子取证", "domain": "应急", "required_cert": "CEH"},
    "ir_playbook": {"name": "应急响应", "domain": "应急", "required_cert": "GCIH"},
    "threat_hunting": {"name": "威胁狩猎", "domain": "蓝军", "required_cert": ""},
    "soc_operations": {"name": "SOC 运营", "domain": "蓝军", "required_cert": "SCP"},
    "siem_admin": {"name": "SIEM 运维", "domain": "蓝军", "required_cert": ""},
    "compliance_iso27001": {"name": "ISO27001 合规", "domain": "合规", "required_cert": "LA"},
    "compliance_djcp": {"name": "等保2.0", "domain": "合规", "required_cert": "测评师"},
    "compliance_pipl": {"name": "个保法合规", "domain": "合规", "required_cert": ""},
    "cloud_aws": {"name": "AWS 安全", "domain": "云安全", "required_cert": "AWS Security"},
    "cloud_ali": {"name": "阿里云安全", "domain": "云安全", "required_cert": ""},
    "code_audit": {"name": "代码审计", "domain": "研发安全", "required_cert": ""},
    "devsecops": {"name": "DevSecOps", "domain": "研发安全", "required_cert": ""},
    "mobile_security": {"name": "移动安全", "domain": "研发安全", "required_cert": ""},
    "iot_security": {"name": "物联网安全", "domain": "IoT", "required_cert": ""},
    "ics_security": {"name": "工控安全", "domain": "ICS", "required_cert": ""},
    "wireless_security": {"name": "无线安全", "domain": "无线", "required_cert": ""},
    "social_engineering": {"name": "社会工程(授权)", "domain": "红队", "required_cert": "OSCE"},
    "security_training": {"name": "安全培训授课", "domain": "培训", "required_cert": ""},
    "project_management": {"name": "项目管理", "domain": "管理", "required_cert": "PMP"},
}

ROLE_PERMISSIONS: Dict[str, Dict[str, Any]] = {
    "admin": {"name": "系统管理员", "perms": ["*"],
              "scope": "全部项目 / 全部数据"},
    "project_manager": {"name": "项目经理",
                        "perms": ["project:read", "project:write",
                                  "timesheet:read", "deliverable:write"],
                        "scope": "所负责项目"},
    "consultant": {"name": "安全顾问",
                   "perms": ["project:read", "deliverable:write",
                             "knowledge:write"],
                   "scope": "所参与项目"},
    "qc": {"name": "质量审核",
           "perms": ["deliverable:read", "deliverable:review"],
           "scope": "全部交付物"},
    "customer": {"name": "客户",
                 "perms": ["project:read", "deliverable:read",
                           "ticket:write"],
                 "scope": "本客户项目"},
}


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class TeamResourceManager:
    """人员 / 技能矩阵 / 分配 / 利用率 / 知识库。"""

    def __init__(self) -> None:
        self.staff: Dict[str, Dict[str, Any]] = {}
        self.assignments: List[Dict[str, Any]] = []
        self.knowledge: List[Dict[str, Any]] = []
        self._seed()

    def _seed(self) -> None:
        staff_seeds = [
            ("EMP-001", "张工", "project_manager", "高级",
             ["pentest_web", "project_management", "compliance_djcp"]),
            ("EMP-002", "李工", "consultant", "高级",
             ["pentest_web", "pentest_internal", "red_team"]),
            ("EMP-003", "王工", "consultant", "中级",
             ["code_audit", "devsecops", "mobile_security"]),
            ("EMP-004", "赵工", "consultant", "专家",
             ["digital_forensics", "ir_playbook", "malware_analysis"]),
            ("EMP-005", "钱工", "qc", "高级",
             ["compliance_iso27001", "compliance_djcp", "compliance_pipl"]),
            ("EMP-006", "孙工", "consultant", "中级",
             ["cloud_aws", "cloud_ali", "devsecops"]),
        ]
        for eid, name, role, level, skills in staff_seeds:
            self.staff[eid] = {
                "emp_id": eid, "name": name, "role": role,
                "role_name": ROLE_PERMISSIONS.get(role, {}).get("name", role),
                "level": level, "skills": skills,
                "utilization": 0.6 + (hash(name) % 30) / 100,
                "projects": [], "perf_score": 80 + (hash(name) % 15),
                "joined": "2022-03-01",
            }
        # 分配示例
        self.assignments = [
            {"emp_id": "EMP-001", "project_id": "PRJ-DEMO-001",
             "role": "项目经理", "allocation_pct": 80,
             "start": "2026-08-01", "end": "2026-08-25"},
            {"emp_id": "EMP-002", "project_id": "PRJ-DEMO-001",
             "role": "主测", "allocation_pct": 100,
             "start": "2026-08-01", "end": "2026-08-25"},
            {"emp_id": "EMP-003", "project_id": "PRJ-DEMO-002",
             "role": "代码审计", "allocation_pct": 60,
             "start": "2026-07-10", "end": "2026-08-25"},
        ]
        # 知识库示例
        self.knowledge = [
            {"kb_id": "KB-001", "title": "护网行动应急预案模板",
             "author": "赵工", "domain": "应急", "views": 320,
             "rating": 4.8, "updated": "2026-08-20"},
            {"kb_id": "KB-002", "title": "Web 渗透测试检查清单 v3",
             "author": "李工", "domain": "红队", "views": 510,
             "rating": 4.9, "updated": "2026-09-01"},
            {"kb_id": "KB-003", "title": "等保2.0三级整改指南",
             "author": "钱工", "domain": "合规", "views": 280,
             "rating": 4.7, "updated": "2026-08-15"},
        ]

    # ------------------------- 人员 ------------------------- #
    def list_staff(self, role: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.staff.values())
        if role:
            items = [x for x in items if x["role"] == role]
        return items

    def get_staff(self, eid: str) -> Optional[Dict[str, Any]]:
        return self.staff.get(eid)

    def add_staff(self, name: str, role: str, level: str,
                  skills: List[str]) -> Dict[str, Any]:
        eid = _uid("EMP")
        s = {"emp_id": eid, "name": name, "role": role,
             "role_name": ROLE_PERMISSIONS.get(role, {}).get("name", role),
             "level": level, "skills": skills,
             "utilization": 0.0, "projects": [], "perf_score": 0,
             "joined": _now()[:10]}
        self.staff[eid] = s
        return s

    # ------------------------- 技能矩阵 ------------------------- #
    def skill_matrix(self) -> Dict[str, Any]:
        rows = []
        for eid, s in self.staff.items():
            rows.append({
                "emp_id": eid, "name": s["name"], "level": s["level"],
                "role": s["role_name"],
                "skills": [{"code": sk,
                            "name": SECURITY_SKILLS.get(sk, {}).get("name", sk)}
                           for sk in s["skills"]],
                "skill_count": len(s["skills"]),
            })
        return {"staff": rows, "all_skills": SECURITY_SKILLS,
                "roles": ROLE_PERMISSIONS}

    # ------------------------- 分配 / 利用率 ------------------------- #
    def assign(self, emp_id: str, project_id: str, role: str,
               allocation_pct: int, start: str, end: str) -> Optional[Dict[str, Any]]:
        if emp_id not in self.staff:
            return None
        a = {"emp_id": emp_id, "project_id": project_id, "role": role,
             "allocation_pct": allocation_pct, "start": start, "end": end}
        self.assignments.append(a)
        self.staff[emp_id].setdefault("projects", []).append(project_id)
        return a

    def list_assignments(self, project_id: Optional[str] = None,
                         emp_id: Optional[str] = None) -> List[Dict[str, Any]]:
        items = self.assignments
        if project_id:
            items = [x for x in items if x["project_id"] == project_id]
        if emp_id:
            items = [x for x in items if x["emp_id"] == emp_id]
        return items

    def utilization(self) -> Dict[str, Any]:
        rows = []
        for eid, s in self.staff.items():
            rows.append({
                "emp_id": eid, "name": s["name"],
                "utilization": s["utilization"],
                "projects": len(s.get("projects", [])),
                "perf_score": s["perf_score"],
            })
        avg_util = round(sum(r["utilization"] for r in rows) / len(rows), 3) \
            if rows else 0
        return {"per_staff": rows, "avg_utilization": avg_util}

    # ------------------------- 知识库 ------------------------- #
    def list_knowledge(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        items = self.knowledge
        if domain:
            items = [x for x in items if x["domain"] == domain]
        return items

    def add_knowledge(self, title: str, author: str, domain: str,
                      content: str = "") -> Dict[str, Any]:
        k = {"kb_id": _uid("KB"), "title": title, "author": author,
             "domain": domain, "views": 0, "rating": 5.0,
             "updated": _now()[:10], "excerpt": content[:120]}
        self.knowledge.append(k)
        return k

    # ------------------------- 仪表盘 ------------------------- #
    def dashboard(self) -> Dict[str, Any]:
        staff = list(self.staff.values())
        roles: Dict[str, int] = {}
        for s in staff:
            roles[s["role_name"]] = roles.get(s["role_name"], 0) + 1
        avg_perf = round(sum(s["perf_score"] for s in staff) / len(staff), 1) \
            if staff else 0
        return {
            "total_staff": len(staff),
            "by_role": roles,
            "avg_perf_score": avg_perf,
            "active_assignments": len(self.assignments),
            "kb_articles": len(self.knowledge),
            "utilization": self.utilization(),
            "updated_at": _now(),
        }
