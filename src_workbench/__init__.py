# -*- coding: utf-8 -*-
"""
src_workbench — SRC 挖洞辅助工作台包。

完整工作流：输入域名 → 子域名发现 → 存活检测 → 端口扫描 → Web服务识别 → 漏洞扫描 → 生成SRC报告 → 项目跟踪
"""
from __future__ import annotations

from src_workbench.asset_discovery import AssetDiscovery
from src_workbench.port_scan import PortScanner
from src_workbench.vuln_scan import VulnScanner
from src_workbench.report_generator import SRCReportGenerator
from src_workbench.project_tracker import ProjectTracker
from src_workbench.src_dashboard import SRCDashboard

__all__ = [
    "AssetDiscovery",
    "PortScanner",
    "VulnScanner",
    "SRCReportGenerator",
    "ProjectTracker",
    "SRCDashboard",
]

__version__ = "1.0.0"
