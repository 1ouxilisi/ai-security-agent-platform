# -*- coding: utf-8 -*-
"""report_engine_deep — 专业级报告引擎深化（第20轮升级方向4）。

在第14轮 report_engine/ 基础上做深，独立不覆盖已有模块。

6 大核心模块：
- template_system       专业报告模板体系（类型/行业/标准框架/结构/品牌/多语言）
- content_generator     报告内容自动生成（摘要/漏洞详情/风险评级/修复/趋势/合规映射）
- chart_visualization    图表与可视化数据规格（统计/风险矩阵/攻击链/拓扑/时间线/表格）
- quality_review         报告质量与审核（质检/去重/误报/审核流/版本/评分）
- export_distribution    多格式导出与分发（PDF/Word/Excel/HTML/JSON/分发）
- report_dashboard       报告管理控制台（库/向导/模板/指标/客户门户/自动化）

安全定位：全部为授权安全服务的报告生成、管理与质量视角能力。
"""

from __future__ import annotations

__version__ = "20.4.0"
__all__ = [
    "template_system",
    "content_generator",
    "chart_visualization",
    "quality_review",
    "export_distribution",
    "report_dashboard",
]
