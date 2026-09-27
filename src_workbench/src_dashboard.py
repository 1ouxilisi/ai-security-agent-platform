# -*- coding: utf-8 -*-
"""
src_dashboard.py — SRC 工作台聚合模块。

串联完整工作流：
资产发现 → 端口扫描 → 漏洞扫描 → 生成报告 → 项目跟踪
"""
from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from src_workbench.asset_discovery import AssetDiscovery
from src_workbench.port_scan import PortScanner
from src_workbench.vuln_scan import VulnScanner
from src_workbench.report_generator import SRCReportGenerator
from src_workbench.project_tracker import ProjectTracker

logger = logging.getLogger(__name__)

# 全局单例
_asset = AssetDiscovery()
_port = PortScanner()
_vuln = VulnScanner()
_report = SRCReportGenerator()
_tracker = ProjectTracker()

# 完整流水线任务
_PIPELINE_TASKS: Dict[str, Dict[str, Any]] = {}


class SRCDashboard:
    """SRC 工作台聚合控制器。"""

    def __init__(self) -> None:
        self.asset = _asset
        self.port = _port
        self.vuln = _vuln
        self.report = _report
        self.tracker = _tracker

    # ------------------------------------------------------------------ #
    # 一键完整流水线
    # ------------------------------------------------------------------ #
    def run_full_pipeline(self, domain: str,
                          project_name: Optional[str] = None,
                          platform: str = "butian",
                          do_port_scan: bool = True,
                          do_vuln_scan: bool = True,
                          auto_report: bool = True) -> Dict[str, Any]:
        """
        执行完整 SRC 挖洞流水线：
        1. 创建项目
        2. 子域名发现 + 存活检测
        3. 端口扫描（可选）
        4. 漏洞扫描（可选）
        5. 自动生成 SRC 报告（可选）
        """
        pipeline_id = f"pipe_{int(time.time())}"
        _PIPELINE_TASKS[pipeline_id] = {
            "pipeline_id": pipeline_id,
            "domain": domain,
            "status": "running",
            "stage": "init",
            "started_at": time.time(),
            "project_id": None,
            "recon_task_id": None,
            "port_scan_task_id": None,
            "vuln_scan_task_id": None,
            "generated_reports": [],
            "error": None,
        }

        try:
            # Step 0: 创建项目
            pname = project_name or f"SRC-{domain}"
            project = self.tracker.create_project(pname, domain, platform)
            project_id = project["project_id"]
            _PIPELINE_TASKS[pipeline_id]["project_id"] = project_id
            _PIPELINE_TASKS[pipeline_id]["stage"] = "recon"

            # Step 1: 资产发现
            logger.info("[Pipeline %s] Step 1: Asset discovery for %s", pipeline_id, domain)
            recon = self.asset.run_recon(domain)
            _PIPELINE_TASKS[pipeline_id]["recon_task_id"] = recon.get("task_id")
            self.tracker.update_progress(project_id, "recon_completed", {
                "subdomains_count": len(recon.get("subdomains", [])),
                "live_hosts_count": len(recon.get("live_hosts", [])),
            })

            live_hosts = recon.get("live_hosts", [])
            alive_hosts = [h for h in live_hosts if h.get("is_live")]

            port_results: List[Dict[str, Any]] = []
            if do_port_scan and alive_hosts:
                _PIPELINE_TASKS[pipeline_id]["stage"] = "port_scan"
                logger.info("[Pipeline %s] Step 2: Port scan on %d hosts",
                            pipeline_id, len(alive_hosts))
                port_scan_result = self.port.scan_hosts(alive_hosts)
                _PIPELINE_TASKS[pipeline_id]["port_scan_task_id"] = port_scan_result.get("task_id")
                port_results = port_scan_result.get("results", [])
                self.tracker.update_progress(project_id, "port_scan_completed", {
                    "open_ports_count": len(port_results),
                })

            findings: List[Dict[str, Any]] = []
            if do_vuln_scan:
                _PIPELINE_TASKS[pipeline_id]["stage"] = "vuln_scan"
                urls = self.vuln._build_urls(alive_hosts, port_results)
                logger.info("[Pipeline %s] Step 3: Vuln scan on %d URLs",
                            pipeline_id, len(urls))
                vuln_result = self.vuln.run_scan(urls)
                _PIPELINE_TASKS[pipeline_id]["vuln_scan_task_id"] = vuln_result.get("task_id")
                findings = vuln_result.get("findings", [])
                self.tracker.update_progress(project_id, "vuln_scan_completed", {
                    "findings_count": len(findings),
                })
                # 添加 finding 到项目
                for f in findings:
                    self.tracker.add_finding(project_id, f)

            generated_reports: List[Dict[str, Any]] = []
            if auto_report and findings:
                _PIPELINE_TASKS[pipeline_id]["stage"] = "report"
                logger.info("[Pipeline %s] Step 4: Generating %d reports",
                            pipeline_id, len(findings))
                # 只对 high/critical/medium 生成报告
                reports = self.report.generate_batch(
                    findings, platform=platform, project_name=pname,
                    severity_filter=["critical", "high", "medium"],
                )
                for r in reports:
                    self.tracker.link_report(project_id, r["report_id"])
                    generated_reports.append(r)
                self.tracker.update_progress(project_id, "reports_generated")

            _PIPELINE_TASKS[pipeline_id]["generated_reports"] = [
                r["report_id"] for r in generated_reports
            ]
            _PIPELINE_TASKS[pipeline_id]["status"] = "completed"
            _PIPELINE_TASKS[pipeline_id]["stage"] = "done"

        except Exception as e:
            logger.exception("Pipeline %s failed", pipeline_id)
            _PIPELINE_TASKS[pipeline_id]["status"] = "failed"
            _PIPELINE_TASKS[pipeline_id]["error"] = str(e)

        _PIPELINE_TASKS[pipeline_id]["finished_at"] = time.time()
        return _PIPELINE_TASKS[pipeline_id]

    # ------------------------------------------------------------------ #
    # Pipeline 查询
    # ------------------------------------------------------------------ #
    def get_pipeline(self, pipeline_id: str) -> Dict[str, Any]:
        return _PIPELINE_TASKS.get(pipeline_id, {})

    def list_pipelines(self) -> List[Dict[str, Any]]:
        return sorted(
            _PIPELINE_TASKS.values(),
            key=lambda x: x.get("started_at", 0),
            reverse=True,
        )

    # ------------------------------------------------------------------ #
    # 工具状态
    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        """返回各安全工具的可用性状态。"""
        from src_workbench.asset_discovery import SUBFINDER_BIN, HTTPX_BIN
        from src_workbench.port_scan import NMAP_BIN
        from src_workbench.vuln_scan import NUCLEI_BIN
        return {
            "subfinder": {"available": SUBFINDER_BIN is not None, "path": SUBFINDER_BIN},
            "httpx": {"available": HTTPX_BIN is not None, "path": HTTPX_BIN},
            "nmap": {"available": NMAP_BIN is not None, "path": NMAP_BIN},
            "nuclei": {"available": NUCLEI_BIN is not None, "path": NUCLEI_BIN},
        }
