# -*- coding: utf-8 -*-
"""
project_tracker.py — SRC 项目跟踪管理模块。

功能：
- SRC 项目跟踪：每个目标的进度
- 已提交漏洞清单
- 赏金状态跟踪（已提交/审核中/已确认/已修复/已忽略）
- 统计：本月提交数/确认数/赏金总额
"""
from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_PROJECTS: Dict[str, Dict[str, Any]] = {}

# 状态流转
VALID_STATUSES = ["draft", "submitted", "reviewing", "confirmed", "fixed", "ignored"]

# 平台
VALID_PLATFORMS = ["butian", "hackerone", "bugcrowd", "aliyun", "tencent", "qianxin", "other"]


class ProjectTracker:
    """SRC 项目跟踪器。"""

    # ------------------------------------------------------------------ #
    # 创建项目
    # ------------------------------------------------------------------ #
    def create_project(self, name: str, domain: str,
                       platform: str = "butian",
                       description: str = "") -> Dict[str, Any]:
        project_id = f"PRJ-{int(time.time())}-{abs(hash(name + domain)) % 10000}"
        project = {
            "project_id": project_id,
            "name": name,
            "domain": domain,
            "platform": platform,
            "description": description,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "status": "active",  # active / paused / completed
            "progress": {
                "recon_completed": False,
                "port_scan_completed": False,
                "vuln_scan_completed": False,
                "reports_generated": False,
                "reports_submitted": False,
            },
            "stats": {
                "total_subdomains": 0,
                "live_hosts": 0,
                "open_ports": 0,
                "vulns_found": 0,
                "reports_submitted": 0,
                "reports_confirmed": 0,
                "bounty_total": 0.0,
            },
            "findings": [],
            "report_ids": [],
            "timeline": [
                {"time": datetime.now().isoformat(), "event": "项目创建"},
            ],
        }
        _PROJECTS[project_id] = project
        return project

    # ------------------------------------------------------------------ #
    # 更新项目进度
    # ------------------------------------------------------------------ #
    def update_progress(self, project_id: str, step: str,
                        data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        p = _PROJECTS.get(project_id)
        if not p:
            return {}

        if step in p["progress"]:
            p["progress"][step] = True

        if data:
            if "subdomains_count" in data:
                p["stats"]["total_subdomains"] = data["subdomains_count"]
            if "live_hosts_count" in data:
                p["stats"]["live_hosts"] = data["live_hosts_count"]
            if "open_ports_count" in data:
                p["stats"]["open_ports"] = data["open_ports_count"]
            if "findings_count" in data:
                p["stats"]["vulns_found"] = data["findings_count"]

        p["updated_at"] = datetime.now().isoformat()
        p["timeline"].append({
            "time": datetime.now().isoformat(),
            "event": f"进度更新: {step}",
        })
        return p

    # ------------------------------------------------------------------ #
    # 添加发现到项目
    # ------------------------------------------------------------------ #
    def add_finding(self, project_id: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        p = _PROJECTS.get(project_id)
        if not p:
            return {}
        finding["added_at"] = datetime.now().isoformat()
        p["findings"].append(finding)
        p["stats"]["vulns_found"] = len(p["findings"])
        p["timeline"].append({
            "time": datetime.now().isoformat(),
            "event": f"新发现: {finding.get('name', 'unknown')}",
        })
        return p

    # ------------------------------------------------------------------ #
    # 添加报告关联
    # ------------------------------------------------------------------ #
    def link_report(self, project_id: str, report_id: str) -> Dict[str, Any]:
        p = _PROJECTS.get(project_id)
        if not p:
            return {}
        if report_id not in p["report_ids"]:
            p["report_ids"].append(report_id)
        return p

    # ------------------------------------------------------------------ #
    # 更新报告状态（并更新项目统计）
    # ------------------------------------------------------------------ #
    def update_report_status(self, project_id: str, report_id: str,
                             status: str, bounty: float = 0.0) -> Dict[str, Any]:
        p = _PROJECTS.get(project_id)
        if not p:
            return {}

        if status not in VALID_STATUSES:
            return {"error": f"Invalid status: {status}. Valid: {VALID_STATUSES}"}

        # 更新项目统计
        if status == "submitted":
            p["stats"]["reports_submitted"] += 1
        elif status == "confirmed":
            p["stats"]["reports_confirmed"] += 1
            p["stats"]["bounty_total"] += bounty

        p["timeline"].append({
            "time": datetime.now().isoformat(),
            "event": f"报告 {report_id} 状态 → {status}"
                     + (f" (赏金 ¥{bounty})" if bounty > 0 else ""),
        })
        return p

    # ------------------------------------------------------------------ #
    # 项目 CRUD
    # ------------------------------------------------------------------ #
    def get_project(self, project_id: str) -> Dict[str, Any]:
        return _PROJECTS.get(project_id, {})

    def list_projects(self, status: Optional[str] = None,
                      platform: Optional[str] = None) -> List[Dict[str, Any]]:
        projects = sorted(
            _PROJECTS.values(),
            key=lambda x: x.get("updated_at", ""),
            reverse=True,
        )
        if status:
            projects = [p for p in projects if p.get("status") == status]
        if platform:
            projects = [p for p in projects if p.get("platform") == platform]
        return projects

    def delete_project(self, project_id: str) -> bool:
        if project_id in _PROJECTS:
            del _PROJECTS[project_id]
            return True
        return False

    def pause_project(self, project_id: str) -> Dict[str, Any]:
        p = _PROJECTS.get(project_id)
        if p:
            p["status"] = "paused"
            p["updated_at"] = datetime.now().isoformat()
        return p or {}

    def complete_project(self, project_id: str) -> Dict[str, Any]:
        p = _PROJECTS.get(project_id)
        if p:
            p["status"] = "completed"
            p["updated_at"] = datetime.now().isoformat()
            p["timeline"].append({
                "time": datetime.now().isoformat(),
                "event": "项目标记为完成",
            })
        return p or {}

    # ------------------------------------------------------------------ #
    # 全局统计
    # ------------------------------------------------------------------ #
    def get_stats(self) -> Dict[str, Any]:
        now = datetime.now()
        current_month = now.strftime("%Y-%m")

        total_projects = len(_PROJECTS)
        active_projects = len([p for p in _PROJECTS.values() if p.get("status") == "active"])
        total_submitted = 0
        total_confirmed = 0
        total_bounty = 0.0
        month_submitted = 0
        month_confirmed = 0
        month_bounty = 0.0

        for p in _PROJECTS.values():
            total_submitted += p["stats"].get("reports_submitted", 0)
            total_confirmed += p["stats"].get("reports_confirmed", 0)
            total_bounty += p["stats"].get("bounty_total", 0.0)

        # 按平台统计
        by_platform: Dict[str, int] = {}
        for p in _PROJECTS.values():
            plat = p.get("platform", "other")
            by_platform[plat] = by_platform.get(plat, 0) + 1

        # 按严重程度统计 finding
        severity_breakdown: Dict[str, int] = {}
        for p in _PROJECTS.values():
            for f in p.get("findings", []):
                sev = f.get("severity", "unknown")
                severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        # 确认率
        confirm_rate = round(total_confirmed / total_submitted * 100, 1) if total_submitted > 0 else 0.0

        return {
            "total_projects": total_projects,
            "active_projects": active_projects,
            "total_submitted": total_submitted,
            "total_confirmed": total_confirmed,
            "total_bounty": total_bounty,
            "current_month": current_month,
            "month_submitted": month_submitted,
            "month_confirmed": month_confirmed,
            "month_bounty": month_bounty,
            "confirm_rate_pct": confirm_rate,
            "by_platform": by_platform,
            "severity_breakdown": severity_breakdown,
        }
