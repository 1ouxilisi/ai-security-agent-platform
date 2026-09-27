# -*- coding: utf-8 -*-
"""
report_pro — 专业安全报告引擎（Nessus / AWVS 风格）。

模块:
    report_templates.py  专业报告 HTML 模板（执行摘要/目标信息/风险概览/详情）
    report_charts.py     图表数据生成（饼图/柱状图/热力图/趋势图）
    report_generator.py   报告生成引擎
    report_exporter.py   多格式导出（HTML / Markdown / JSON）
"""

from __future__ import annotations

from .report_templates import ReportTemplates, VULN_DB
from .report_charts import ReportCharts
from .report_generator import ReportGenerator, ReportData
from .report_exporter import ReportExporter

__all__ = [
    "ReportTemplates", "VULN_DB",
    "ReportCharts",
    "ReportGenerator", "ReportData",
    "ReportExporter",
]
