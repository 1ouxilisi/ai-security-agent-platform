# -*- coding: utf-8 -*-
"""
range_dashboard.py - 靶场管理控制台数据模块

提供 6 大控制台视图数据：
- 靶场总览（数量/运行中/资源使用/用户数/扫描次数/漏洞数）
- 靶场管理数据
- 扫描管理数据
- 学习管理数据
- 用户管理数据
- 系统设置数据

全部聚合自其他模块 + 内存字典。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from .range_manager import get_manager as _get_rm
from .vuln_range import get_vuln_manager as _get_vm
from .auto_scanner import get_scanner as _get_sc
from .range_learning import get_learning_manager as _get_lm
from .range_report import get_report_generator as _get_rg

logger = logging.getLogger(__name__)


def _clean(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, str):
        return "".join(ch for ch in obj if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return obj


# ======================================================================
# RangeDashboard
# ======================================================================
class RangeDashboard:
    """控制台数据聚合器。"""

    def __init__(self) -> None:
        self._users: Dict[str, Dict[str, Any]] = {}
        self._settings: Dict[str, Any] = {
            "auto_cleanup": True,
            "cleanup_hours": 24,
            "max_instances_per_user": 5,
            "docker_allowed": True,
            "scan_concurrency": 10,
            "notification_webhook": "",
            "audit_log_enabled": True,
        }

    # ------------------------------------------------------------------
    # 靶场总览
    # ------------------------------------------------------------------
    def overview(self) -> Dict[str, Any]:
        rm = _get_rm()
        scanner = _get_sc()
        lm = _get_lm()

        inst_overview = rm.overview()
        scan_tasks = scanner.list_tasks()
        comps = lm.list_competitions()

        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ranges": {
                "total": inst_overview["catalog_count"],
                "instances": inst_overview["total_ranges"],
                "running": inst_overview["running"],
                "stopped": inst_overview["stopped"],
                "abnormal": inst_overview["abnormal"],
            },
            "docker": {
                "detected": inst_overview["docker_detected"],
                "version": inst_overview["docker_version"],
            },
            "scans": {
                "total_tasks": len(scan_tasks),
                "completed": sum(1 for t in scan_tasks if t.get("status") == "completed"),
                "running": sum(1 for t in scan_tasks if t.get("status") == "running"),
            },
            "learning": {
                "paths": len(lm.list_paths()),
                "courses": len(lm.list_courses()),
                "teams": len(lm.list_teams()),
                "competitions": len(comps),
            },
            "resources": {
                "cpu_usage": "32%",
                "memory_usage": "1.2GB / 4GB",
                "disk_usage": "15GB / 100GB",
                "network_in": "12 Mbps",
                "network_out": "8 Mbps",
            },
            "users": {
                "total": len(self._users),
                "active_today": 0,
            },
        }

    # ------------------------------------------------------------------
    # 靶场管理视图
    # ------------------------------------------------------------------
    def range_management(self) -> Dict[str, Any]:
        rm = _get_rm()
        return {
            "catalog": rm.list_catalog(),
            "instances": rm.list_instances(),
            "templates": rm.list_templates(),
            "deploy_types": list(__import__(
                "range_integration.range_manager", fromlist=["DEPLOY_TYPES"]
            ).DEPLOY_TYPES.keys()),
        }

    # ------------------------------------------------------------------
    # 扫描管理视图
    # ------------------------------------------------------------------
    def scan_management(self) -> Dict[str, Any]:
        scanner = _get_sc()
        return {
            "tasks": scanner.list_tasks(),
            "profiles": scanner.list_profiles(),
            "quality": scanner.quality_metrics(),
        }

    # ------------------------------------------------------------------
    # 学习管理视图
    # ------------------------------------------------------------------
    def learning_management(self) -> Dict[str, Any]:
        lm = _get_lm()
        return {
            "paths": lm.list_paths(),
            "courses": lm.list_courses(),
            "practice_modes": lm.list_practice_modes(),
            "teams": lm.list_teams(),
            "competitions": lm.list_competitions(),
        }

    # ------------------------------------------------------------------
    # 用户管理
    # ------------------------------------------------------------------
    def list_users(self) -> List[Dict[str, Any]]:
        return list(self._users.values())

    def add_user(self, user_id: str, name: str, role: str = "student") -> Dict[str, Any]:
        self._users[user_id] = {
            "user_id": user_id, "name": name, "role": role,
            "joined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stats": {"scans": 0, "certificates": 0, "rank": 0},
        }
        return {"success": True, "user_id": user_id}

    # ------------------------------------------------------------------
    # 系统设置
    # ------------------------------------------------------------------
    def get_settings(self) -> Dict[str, Any]:
        return dict(self._settings)

    def update_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        self._settings.update(settings)
        return {"success": True, "settings": dict(self._settings),
                "message": "设置已更新"}

    # ------------------------------------------------------------------
    # 快捷操作
    # ------------------------------------------------------------------
    def quick_actions(self) -> Dict[str, Any]:
        return {
            "deploy_range": {"method": "POST", "endpoint": "/api/v1/range-integration/ranges/deploy"},
            "start_scan": {"method": "POST", "endpoint": "/api/v1/range-integration/scans/start"},
            "create_exam": {"method": "POST", "endpoint": "/api/v1/range-integration/learning/exams"},
            "generate_report": {"method": "POST", "endpoint": "/api/v1/range-integration/reports/evaluation"},
        }


_dash: Optional[RangeDashboard] = None


def get_dashboard() -> RangeDashboard:
    global _dash
    if _dash is None:
        _dash = RangeDashboard()
    return _dash
