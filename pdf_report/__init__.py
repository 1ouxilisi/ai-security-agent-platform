# -*- coding: utf-8 -*-
"""
pdf_report — 统一 PDF 报告导出引擎与统一报告中心。

模块：
    - pdf_engine          : 统一 PDF 生成（weasyprint 优先，reportlab 兜底）
    - pdf_templates      : 模板管理
    - pdf_styles          : 样式定义
    - chart_generator    : matplotlib 图表
    - domain_pdf_adapters : 十六大领域适配器
    - report_center       : 统一报告中心
"""

from __future__ import annotations

from . import pdf_engine, pdf_styles, chart_generator  # noqa: F401
from .pdf_templates import get_template_manager  # noqa: F401
from .report_center import get_report_center, REPORT_ROOT  # noqa: F401
from .domain_pdf_adapters import (  # noqa: F401
    DOMAINS, list_domains, build_domain_content)

__all__ = [
    "pdf_engine", "pdf_styles", "chart_generator",
    "get_template_manager", "get_report_center", "REPORT_ROOT",
    "DOMAINS", "list_domains", "build_domain_content",
]
