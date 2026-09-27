# -*- coding: utf-8 -*-
"""
real_tools_dashboard.py — 真实工具控制台数据聚合层。

聚合 Nmap/SQLMap/Metasploit/Nikto/Hydra/John/nuclei/工具编排的所有数据，
为前端控制台提供统一的数据接口。

纯内存字典，不依赖数据库。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

from real_tools_deep import nmap_deep, sqlmap_deep, metasploit_deep, other_tools, tool_orchestration


# --------------------------------------------------------------------------- #
# 控制台数据聚合器
# --------------------------------------------------------------------------- #
class RealToolsDashboard:
    """聚合所有真实工具模块的数据，提供控制台视图。"""

    def __init__(self) -> None:
        self.scan_history: List[Dict[str, Any]] = []
        self.vulnerability_tracker: List[Dict[str, Any]] = []
        self.asset_tracker: List[Dict[str, Any]] = []
        self.performance_summary: Dict[str, Any] = {}
        self.task_queue: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []

    def get_overview(self) -> Dict[str, Any]:
        """获取工具总览数据。"""
        nmap_tool = nmap_deep.get_tool_manager().detect_version()
        sqlmap_tool = sqlmap_deep.get_tool_manager().detect_version()
        msf_tool = metasploit_deep.get_tool_manager().detect_version()
        other_tools_ver = other_tools.get_manager().get_all_versions()

        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tools": {
                "nmap": nmap_tool,
                "sqlmap": sqlmap_tool,
                "metasploit": msf_tool,
                "nikto": other_tools_ver.get("nikto", {}),
                "hydra": other_tools_ver.get("hydra", {}),
                "john": other_tools_ver.get("john", {}),
                "nuclei": other_tools_ver.get("nuclei", {}),
            },
            "statistics": {
                "total_scans": len(self.scan_history),
                "total_vulns": len(self.vulnerability_tracker),
                "total_assets": len(self.asset_tracker),
                "active_workflows": len([
                    i for i in tool_orchestration.get_engine().list_instances()
                    if i.get("status") == "running"
                ]),
                "completed_workflows": len([
                    i for i in tool_orchestration.get_engine().list_instances()
                    if i.get("status") == "done"
                ]),
            },
            "recent_alerts": self.alerts[-5:] if self.alerts else [],
            "system_status": "healthy",
        }

    def get_nmap_summary(self) -> Dict[str, Any]:
        """获取 Nmap 模块摘要。"""
        scanner = nmap_deep.get_scanner()
        tool_mgr = nmap_deep.get_tool_manager()
        nse_mgr = nmap_deep.get_nse_manager()

        return {
            "version": scanner.version,
            "available": scanner.available,
            "last_scan": scanner.last_scan_result,
            "nse_scripts_count": len(nse_mgr.script_db),
            "nse_categories": list(nmap_deep.NSE_CATEGORIES),
            "tool_status": tool_mgr.get_status(),
            "scan_history": self.scan_history[-10:] if self.scan_history else [],
        }

    def get_sqlmap_summary(self) -> Dict[str, Any]:
        """获取 SQLMap 模块摘要。"""
        scanner = sqlmap_deep.get_scanner()
        tool_mgr = sqlmap_deep.get_tool_manager()

        return {
            "version": scanner.version,
            "available": scanner.available,
            "last_result": scanner.last_result,
            "techniques": sqlmap_deep.INJECTION_TECHNIQUES,
            "dbms_types": sqlmap_deep.DBMS_TYPES,
            "tool_status": tool_mgr.get_status(),
        }

    def get_metasploit_summary(self) -> Dict[str, Any]:
        """获取 Metasploit 模块摘要。"""
        client = metasploit_deep.get_client()
        tool_mgr = metasploit_deep.get_tool_manager()

        return {
            "version": client.version,
            "connected": client.connected,
            "module_categories": metasploit_deep.MODULE_CATEGORIES,
            "payload_types": metasploit_deep.PAYLOAD_TYPES,
            "active_sessions": client.list_sessions(),
            "common_exploits": list(metasploit_deep.COMMON_EXPLOITS.keys()),
            "common_auxiliary": list(metasploit_deep.COMMON_AUXILIARY.keys()),
            "common_post": list(metasploit_deep.COMMON_POST.keys()),
            "tool_status": tool_mgr.get_status(),
        }

    def get_other_tools_summary(self) -> Dict[str, Any]:
        """获取其他工具摘要。"""
        mgr = other_tools.get_manager()
        return {
            "versions": mgr.get_all_versions(),
            "batch_jobs": len(mgr.batch_jobs),
            "scheduled_jobs": len(mgr.scheduled_jobs),
            "nikto_vuln_types": other_tools.NIKTO_VULN_TYPES,
            "hydra_services": other_tools.HYDRA_SERVICES,
            "john_hash_formats": other_tools.JOHN_HASH_FORMATS,
            "nuclei_categories": other_tools.NUCLEI_TEMPLATE_CATEGORIES,
        }

    def get_workflow_summary(self) -> Dict[str, Any]:
        """获取工作流摘要。"""
        engine = tool_orchestration.get_engine()
        monitor = tool_orchestration.get_monitor()
        optimizer = tool_orchestration.get_optimizer()

        return {
            "templates": tool_orchestration.WORKFLOW_TEMPLATES,
            "instances": engine.list_instances(),
            "dashboard": monitor.get_dashboard(),
            "bottlenecks": monitor.analyze_bottlenecks(),
            "recommendations": optimizer.recommend_optimizations(engine),
            "best_practices": optimizer.get_best_practices(),
        }

    def record_scan(self, tool: str, target: str, result: Dict[str, Any]) -> None:
        """记录扫描历史。"""
        self.scan_history.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tool": tool,
            "target": target,
            "result_summary": str(result)[:500],
            "scan_id": uuid.uuid4().hex[:12],
        })

    def track_vulnerability(self, vuln: Dict[str, Any]) -> None:
        """记录漏洞。"""
        vuln["tracked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        vuln["vuln_id"] = uuid.uuid4().hex[:12]
        self.vulnerability_tracker.append(vuln)

    def track_asset(self, asset: Dict[str, Any]) -> None:
        """记录资产。"""
        asset["tracked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.asset_tracker.append(asset)

    def get_vulnerability_list(self) -> List[Dict[str, Any]]:
        """获取漏洞清单。"""
        return self.vulnerability_tracker

    def get_asset_list(self) -> List[Dict[str, Any]]:
        """获取资产清单。"""
        return self.asset_tracker

    def get_task_queue(self) -> List[Dict[str, Any]]:
        """获取任务队列。"""
        return self.task_queue

    def add_alert(self, level: str, message: str, source: str = "") -> None:
        """添加告警。"""
        self.alerts.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "level": level,
            "message": message,
            "source": source,
        })


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_dashboard: Optional[RealToolsDashboard] = None


def get_dashboard() -> RealToolsDashboard:
    global _dashboard
    if _dashboard is None:
        _dashboard = RealToolsDashboard()
    return _dashboard
